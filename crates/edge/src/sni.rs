//! TLS SNI extraction for the Browser Plane (#23, sub-packet 1).
//!
//! The Edge routes a browser's TLS connection to a tunnel **by the SNI hostname
//! in its ClientHello**, without terminating TLS: the ClientHello is sent in the
//! clear at the start of a TLS connection, so the Edge can read the `server_name`
//! extension, look up the target tunnel, and then pass the raw TLS bytes through
//! to the Origin (which holds the certificate). The Edge therefore sees only the
//! hostname and ciphertext — the payload stays blind (ADR-0010 trade-off: the
//! Browser Plane reveals the hostname the Mesh Plane hides).

use tokio::io::{AsyncRead, AsyncReadExt};

/// ALPN protocol id the tunnel data plane advertises on the unified :443 front
/// door (#31): a ClientHello carrying it is routed to the edge TLS-TCP relay.
pub const CT_EDGE_ALPN: &str = "ct-edge";

/// ALPN protocol id an Agent-Fabric **channel** member advertises on the unified
/// :443 front door (#106): a ClientHello carrying it is routed to the channel broker
/// (rendezvous + relay), the `:443` fallback for members on restrictive networks that
/// cannot reach the channel port (`:4435`). The channel-service analog of
/// [`CT_EDGE_ALPN`], mirroring the #31/#46 classic-tunnel fallback.
pub const CT_EDGE_CHANNEL_ALPN: &str = "ct-edge-channel";

/// ALPN protocol id a real NAT-to-NAT hole-punch relay client advertises on the
/// unified :443 front door: a ClientHello carrying it is routed to the gated
/// Circuit-Relay v2 relay (`RelayGate` — grant + possession pre-auth, then a raw
/// byte splice to the internal relay-node process). Multiplexed onto :443 rather
/// than a dedicated port so the relay stays reachable only through the same TLS
/// front door every other :443 leg uses, with no new public listener.
pub const CT_EDGE_RELAY_ALPN: &str = "ct-edge-relay";

/// Return the raw `extensions` block of a buffered TLS ClientHello record, or
/// `None` if `buf` is not a ClientHello. Fully bounds-checked — never panics.
fn client_hello_extensions(buf: &[u8]) -> Option<&[u8]> {
    // TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hs = buf.get(5..5 + rec_len)?;
    // Handshake: msg_type(1)=0x01 ClientHello, length(3), then the body.
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let body = hs.get(4..)?;
    // client_version(2) + random(32).
    let mut p = 34usize;
    // session_id: len(1) + id.
    let sid = *body.get(p)? as usize;
    p += 1 + sid;
    // cipher_suites: len(2) + suites.
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods: len(1) + methods.
    let cm = *body.get(p)? as usize;
    p += 1 + cm;
    // extensions: len(2) + extensions.
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    body.get(p..p + ext_total)
}

/// Find the first extension of type `want` in `exts` and map its data with `f`.
// #339: `'a` is explicit (not an elided/higher-ranked lifetime) and shared between
// `exts` and the closure's own parameter, so `T` is allowed to borrow from it --
// e.g. `T = &'a str`, which `sni_from_extensions` below needs. A `for<'r> Fn(&'r
// [u8]) -> Option<T>` bound (what eliding the lifetime here produces) can't
// express that, since `T` is fixed before any particular `'r` is chosen.
fn find_extension<'a, T>(exts: &'a [u8], want: u16, f: impl FnOnce(&'a [u8]) -> Option<T>) -> Option<T> {
    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let etype = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let elen = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        let edata = exts.get(q + 4..q + 4 + elen)?;
        if etype == want {
            return f(edata);
        }
        q += 4 + elen;
    }
    None
}

/// Zero-allocation core of [`peek_sni`]: the SNI hostname borrowed directly from
/// `exts` (already-extracted extensions, see [`client_hello_extensions`]), in its
/// **original case** — the caller lowercases only if/when it actually needs to
/// (#339: `classify_front_door` compares case-insensitively and only allocates a
/// lowercased copy for the one hostname it ends up returning, never for a
/// rejected candidate).
fn sni_from_extensions(exts: &[u8]) -> Option<&str> {
    // server_name (0x0000): list len(2) + first entry type(1)=0 host_name,
    // name_len(2), name.
    find_extension(exts, 0x0000, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        if list.len() < 3 || list[0] != 0x00 {
            return None;
        }
        let name_len = u16::from_be_bytes([list[1], list[2]]) as usize;
        let name = list.get(3..3 + name_len)?;
        std::str::from_utf8(name).ok()
    })
}

/// Parse the SNI `host_name` from a buffered TLS ClientHello record (the raw
/// bytes starting at the TLS record header). Returns the lowercased hostname, or
/// `None` if `buf` is not a ClientHello record or carries no SNI. Fully
/// bounds-checked — never panics on malformed input. Real callers needing only a
/// yes/no ALPN check or the SNI to compare (not own) should prefer
/// [`classify_front_door`], which parses the extensions block once and never
/// allocates for a candidate that doesn't end up mattering.
pub fn peek_sni(buf: &[u8]) -> Option<String> {
    let exts = client_hello_extensions(buf)?;
    sni_from_extensions(exts).map(|s| s.to_ascii_lowercase())
}

/// Zero-allocation core of [`peek_alpn`]/[`classify_front_door`]'s ALPN checks:
/// does the already-extracted extensions block `exts` advertise `want`? Scans the
/// raw protocol-name entries and compares bytes directly — never materializes a
/// `String` for any entry, matching or not (#339: `peek_alpn` below still builds
/// the full `Vec<String>` for callers that genuinely need to enumerate every
/// advertised protocol; `classify_front_door` only ever needs membership checks
/// against a handful of known constants, so it uses this instead).
fn alpn_extension_has(exts: &[u8], want: &str) -> bool {
    let want = want.as_bytes();
    find_extension(exts, 0x0010, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        let mut i = 0usize;
        while i < list.len() {
            let l = *list.get(i)? as usize;
            let name = list.get(i + 1..i + 1 + l)?;
            if name == want {
                return Some(true);
            }
            i += 1 + l;
        }
        Some(false)
    })
    .unwrap_or(false)
}

/// Parse the ALPN protocol list from a buffered TLS ClientHello (#31 FD1).
/// Returns the advertised protocols in order, or an empty vec if absent/malformed.
/// For a simple "is protocol X present" check, prefer [`classify_front_door`] (or
/// `alpn_extension_has` internally) — this allocates a `String` per advertised
/// protocol, which is only worth paying for when the caller genuinely needs the
/// full list (e.g. diagnostics), not just membership.
pub fn peek_alpn(buf: &[u8]) -> Vec<String> {
    let Some(exts) = client_hello_extensions(buf) else {
        return Vec::new();
    };
    // application_layer_protocol_negotiation (0x0010): ProtocolNameList =
    // list_len(2) + entries of len(1) + name.
    find_extension(exts, 0x0010, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < list.len() {
            let l = *list.get(i)? as usize;
            let name = list.get(i + 1..i + 1 + l)?;
            if let Ok(s) = std::str::from_utf8(name) {
                out.push(s.to_string());
            }
            i += 1 + l;
        }
        Some(out)
    })
    .unwrap_or_default()
}

/// Where the unified :443 front door should route a peeked ClientHello (#31 FD1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontDoorRoute {
    /// Tunnel data plane — the client advertised the `ct-edge` ALPN: hand off to
    /// the edge TLS-TCP relay (the ADR-0004 fallback rung on :443).
    EdgeRelay,
    /// Agent-Fabric channel service — the client advertised the `ct-edge-channel`
    /// ALPN (#106): hand off to the channel broker (rendezvous + relay), the `:443`
    /// fallback for members that cannot reach the channel port `:4435`.
    ChannelBroker,
    /// Real NAT-to-NAT hole-punch relay — the client advertised the `ct-edge-relay`
    /// ALPN: hand off to the gated Circuit-Relay v2 relay after a grant + possession
    /// pre-auth (see `relay_gate.rs`). Distinct from `ChannelBroker`: this leg never
    /// interprets the bytes it forwards past the pre-auth handshake — it splices raw
    /// libp2p protocol bytes to an internal relay-node process.
    RelayGate,
    /// Terminate TLS + reverse-proxy to a configured terminate-host's upstream —
    /// the Portal (control plane) or, since #48, any additional host such as the
    /// Keycloak IdP (`auth.<zone>`). The `String` is the matched, lowercased host;
    /// the caller looks up its upstream address + cert.
    Proxy(String),
    /// Browser-Plane passthrough, routed by this SNI hostname against the host
    /// registry (an unknown host is rejected downstream, not here).
    BrowserTunnel(String),
    /// Nothing matched — refuse the connection.
    Reject,
}

/// Classify a peeked ClientHello for the unified :443 front door (#31 FD1, #48).
///
/// Precedence: the tunnel data-plane ALPN wins; then any **terminate-host** (SNI
/// matches a configured proxy target — Portal or Auth IdP) is a `Proxy`; then any
/// other SNI is a Browser-Plane passthrough candidate; a web ALPN with no SNI
/// (e.g. `curl https://<ip>/`) lands on `default_host` (the Portal); anything else
/// is refused. `terminate_hosts` and `default_host` are compared case-insensitively.
///
/// #339: takes the raw buffered ClientHello directly (rather than a pre-parsed
/// `alpn: Vec<String>` + `sni: Option<&str>`, the shape before this fix) and
/// parses its extensions block exactly once, reused for every ALPN/SNI check
/// below — this is the single real classification path every `:443` front-door
/// connection goes through, so per-connection allocation there was measurable
/// under a connection storm: previously a `Vec<String>` (one heap string per
/// advertised ALPN protocol) plus a `String` for the SNI, on EVERY connection,
/// almost always just to run a handful of equality checks against constants and
/// then get thrown away. Now: zero allocations for `EdgeRelay`/`ChannelBroker`/
/// `RelayGate`/`Reject` (the majority of real front-door traffic is the tunnel
/// data-plane ALPN, which needs no SNI or hostname at all), and exactly one
/// `String` allocation for `Proxy`/`BrowserTunnel` — the final matched hostname,
/// never a rejected candidate.
///
/// `is_terminate_host` is a case-insensitive membership check (the real caller
/// passes a closure over its own host registry, e.g. `proxies.contains_key`) —
/// deliberately not a `&[&str]` slice, since that shape forced a fresh `Vec`
/// collected from the registry's keys on every single connection (the third
/// allocation this issue named) just to hand this function something to
/// iterate. A callback needs no per-connection collection at all.
pub fn classify_front_door(hello: &[u8], is_terminate_host: impl Fn(&str) -> bool, default_host: Option<&str>) -> FrontDoorRoute {
    let exts = client_hello_extensions(hello);
    let alpn_has = |want: &str| exts.map(|e| alpn_extension_has(e, want)).unwrap_or(false);
    if alpn_has(CT_EDGE_ALPN) {
        return FrontDoorRoute::EdgeRelay;
    }
    // #106: a channel member on a `:4435`-blocked network falls back to `:443` with
    // the channel ALPN. Like the `ct-edge` data-plane leg, it carries no SNI, so the
    // ALPN discriminator wins ahead of any SNI-based routing.
    if alpn_has(CT_EDGE_CHANNEL_ALPN) {
        return FrontDoorRoute::ChannelBroker;
    }
    // Same ALPN-before-SNI precedence as the channel leg above -- a relay client
    // carries no SNI either.
    if alpn_has(CT_EDGE_RELAY_ALPN) {
        return FrontDoorRoute::RelayGate;
    }
    if let Some(sni) = exts.and_then(sni_from_extensions) {
        if is_terminate_host(sni) {
            return FrontDoorRoute::Proxy(sni.to_ascii_lowercase());
        }
        return FrontDoorRoute::BrowserTunnel(sni.to_ascii_lowercase());
    }
    // No SNI: a plain web client (curl https://<ip>/) defaults to the Portal.
    if alpn_has("http/1.1") || alpn_has("h2") {
        if let Some(d) = default_host {
            return FrontDoorRoute::Proxy(d.to_ascii_lowercase());
        }
    }
    FrontDoorRoute::Reject
}

/// Read the first TLS record (the ClientHello) from `stream` and return the
/// buffered bytes plus the SNI hostname. The buffered bytes must be forwarded
/// verbatim to the Origin so the TLS handshake completes end-to-end. Returns
/// `None` if the stream does not start with a ClientHello carrying SNI.
pub async fn read_client_hello<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(Vec<u8>, String)> {
    let buf = read_client_hello_bytes(stream).await?;
    let sni = peek_sni(&buf)?;
    Some((buf, sni))
}

/// Read the raw ClientHello TLS record into a buffer without requiring an SNI
/// extension (#31 FD2): the `:443` front door classifies by ALPN *then* SNI, and
/// the `ct-edge` data-plane leg carries no SNI at all. Returns the buffered
/// handshake bytes so the caller can [`peek_alpn`]/[`peek_sni`] and then replay
/// them to the chosen backend. Bounds-checked and panic-free like the parsers.
pub async fn read_client_hello_bytes<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 5];
    stream.read_exact(&mut buf).await.ok()?;
    if buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // A ClientHello fits in one TLS record; cap at the record-size maximum.
    if rec_len == 0 || rec_len > 16384 {
        return None;
    }
    buf.resize(5 + rec_len, 0);
    stream.read_exact(&mut buf[5..]).await.ok()?;
    Some(buf)
}

/// Build a minimal but well-formed TLS ClientHello record carrying the given SNI
/// and ALPN list — a test fixture shared across the edge's SNI/front-door tests
/// (`#31` FD1/FD2). Test-only; kept at module scope so `serve`'s front-door tests
/// can synthesize a handshake without a real TLS client.
#[cfg(test)]
pub(crate) fn synth_client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(host) = sni {
        let h = host.as_bytes();
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
        entry.extend_from_slice(h);
        let mut snl = (entry.len() as u16).to_be_bytes().to_vec();
        snl.extend_from_slice(&entry);
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(snl.len() as u16).to_be_bytes());
        exts.extend_from_slice(&snl);
    }
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for p in alpn {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        exts.extend_from_slice(&[0x00, 0x10]);
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&data);
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(0x01);
    body.push(0x00);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![0x01];
    let bl = body.len();
    hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello record carrying `host` as its only SNI.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        // server_name entry: type(0) + name_len(2) + name.
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
        entry.extend_from_slice(h);
        // server_name_list: list_len(2) + entry.
        let mut snl = (entry.len() as u16).to_be_bytes().to_vec();
        snl.extend_from_slice(&entry);
        // extension: type(0x0000) + len(2) + data.
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(snl.len() as u16).to_be_bytes());
        ext.extend_from_slice(&snl);
        // ClientHello body: version(2)+random(32)+sid_len(0)+cs_len(2)+cs(2)
        // +cm_len(1)+cm(1)+ext_total(2)+ext.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session_id length 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one suite
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        // Handshake header: msg_type(0x01) + length(3).
        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        // Record header: type(0x16) + version(2) + length(2).
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Build a ClientHello with an optional SNI and an optional ALPN list.
    use super::synth_client_hello as client_hello;

    #[test]
    fn peek_sni_extracts_and_lowercases_the_hostname() {
        let ch = client_hello_with_sni("App.Example.Test");
        assert_eq!(peek_sni(&ch).as_deref(), Some("app.example.test"));
    }

    #[test]
    fn peek_alpn_parses_the_protocol_list_alongside_sni() {
        // #31 FD1: ALPN list parsed in order; SNI still readable in the same hello.
        let ch = client_hello(Some("h.test"), &["h2", "http/1.1"]);
        assert_eq!(peek_alpn(&ch), vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(peek_sni(&ch).as_deref(), Some("h.test"));
        // Absent / malformed -> empty, never a panic.
        assert!(peek_alpn(&client_hello(Some("h.test"), &[])).is_empty());
        assert!(peek_alpn(b"").is_empty());
    }

    /// #339: `classify_front_door` now takes the raw ClientHello directly, so
    /// these tests build one via the same `synth_client_hello` fixture
    /// `peek_sni`/`peek_alpn`'s own tests use, instead of pre-parsed
    /// `Vec<String>`/`Option<&str>` values. `terminate_host` mirrors the real
    /// caller's closure (case-insensitive membership over a small fixed set).
    fn terminate_host(h: &str) -> bool {
        ["portal.z", "auth.z"].iter().any(|t| t.eq_ignore_ascii_case(h))
    }

    #[test]
    fn classify_front_door_routes_by_alpn_then_sni() {
        // #31 FD1 / #48: the demux precedence for the unified :443 front door.
        let default = Some("portal.z");
        // Tunnel data-plane ALPN wins, even with an SNI present.
        assert_eq!(
            classify_front_door(&client_hello(Some("whatever.z"), &["ct-edge"]), terminate_host, default),
            FrontDoorRoute::EdgeRelay
        );
        // A configured terminate host -> Proxy(host) (case-insensitive) — Portal…
        assert_eq!(
            classify_front_door(&client_hello(Some("Portal.Z"), &["h2"]), terminate_host, default),
            FrontDoorRoute::Proxy("portal.z".into())
        );
        // …and the #48 Auth IdP host, the second terminate target.
        assert_eq!(
            classify_front_door(&client_hello(Some("Auth.Z"), &["h2"]), terminate_host, default),
            FrontDoorRoute::Proxy("auth.z".into())
        );
        // Any other SNI -> Browser-Plane passthrough candidate.
        assert_eq!(
            classify_front_door(&client_hello(Some("app1.z"), &[]), terminate_host, default),
            FrontDoorRoute::BrowserTunnel("app1.z".into())
        );
        // Web ALPN, no SNI (curl to the bare IP) -> the default (Portal).
        assert_eq!(
            classify_front_door(&client_hello(None, &["http/1.1"]), terminate_host, default),
            FrontDoorRoute::Proxy("portal.z".into())
        );
        // Nothing usable -> reject.
        assert_eq!(classify_front_door(&client_hello(None, &[]), terminate_host, default), FrontDoorRoute::Reject);
    }

    #[test]
    fn classify_front_door_routes_the_channel_alpn_to_the_broker() {
        // #106: a channel member blocked on :4435 falls back to :443 with the
        // ct-edge-channel ALPN; the front door routes it to the channel broker.
        let default = Some("portal.z");
        // The channel ALPN -> ChannelBroker, and (like the ct-edge leg) it wins ahead
        // of any SNI-based routing.
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_CHANNEL_ALPN]), terminate_host, default),
            FrontDoorRoute::ChannelBroker
        );
        assert_eq!(
            classify_front_door(&client_hello(Some("portal.z"), &["ct-edge-channel"]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "channel ALPN wins over a terminate-host SNI"
        );
        // The classic tunnel ALPN is unaffected — still routes to the edge relay.
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_ALPN]), terminate_host, default),
            FrontDoorRoute::EdgeRelay
        );
        // The two data-plane ALPN ids are distinct.
        assert_ne!(CT_EDGE_ALPN, CT_EDGE_CHANNEL_ALPN);
    }

    #[test]
    fn classify_front_door_routes_the_relay_alpn_to_the_relay_gate() {
        // A NAT-to-NAT hole-punch relay client -> RelayGate, winning ahead of SNI just
        // like the other two data-plane ALPN ids.
        let default = Some("portal.z");
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_RELAY_ALPN]), terminate_host, default),
            FrontDoorRoute::RelayGate
        );
        assert_eq!(
            classify_front_door(&client_hello(Some("portal.z"), &[CT_EDGE_RELAY_ALPN]), terminate_host, default),
            FrontDoorRoute::RelayGate,
            "relay ALPN wins over a terminate-host SNI"
        );
        // All three data-plane ALPN ids are pairwise distinct.
        assert_ne!(CT_EDGE_ALPN, CT_EDGE_RELAY_ALPN);
        assert_ne!(CT_EDGE_CHANNEL_ALPN, CT_EDGE_RELAY_ALPN);
    }

    #[test]
    fn peek_sni_rejects_non_clienthello_and_malformed() {
        assert_eq!(peek_sni(b""), None);
        assert_eq!(peek_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None); // not handshake
        let mut ch = client_hello_with_sni("x.test");
        ch.truncate(ch.len() - 3); // chop the SNI name -> out of bounds
        assert_eq!(peek_sni(&ch), None);
    }

    #[tokio::test]
    async fn read_client_hello_buffers_the_record_and_returns_sni() {
        let ch = client_hello_with_sni("host.test");
        let mut stream = std::io::Cursor::new(ch.clone());
        let (buf, sni) = read_client_hello(&mut stream).await.expect("sni");
        assert_eq!(sni, "host.test");
        assert_eq!(buf, ch, "the full ClientHello is buffered for passthrough");
    }
}

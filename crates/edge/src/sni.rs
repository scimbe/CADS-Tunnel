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

/// #500 K2: the park-keepalive-capable variant of [`CT_EDGE_CHANNEL_ALPN`]. A client
/// offering `[ct-edge-channel-ka, ct-edge-channel]` negotiates keepalive against a
/// current edge (server preference selects this id) and degrades byte-for-byte to the
/// plain leg against an older one -- the whole capability handshake lives in the TLS
/// ALPN selection, zero wire-format changes. The boring twin has no `-ka` id (it would
/// destroy the low-DPI camouflage): there the client offers `[h2, http/1.1]` and a
/// current edge deliberately selects `http/1.1` as the same keepalive signal -- both
/// ids ubiquitous, the selection unremarkable to any observer.
pub const CT_EDGE_CHANNEL_KA_ALPN: &str = "ct-edge-channel-ka";

/// ALPN protocol id a real NAT-to-NAT hole-punch relay client advertises on the
/// unified :443 front door: a ClientHello carrying it is routed to the gated
/// Circuit-Relay v2 relay (`RelayGate` — grant + possession pre-auth, then a raw
/// byte splice to the internal relay-node process). Multiplexed onto :443 rather
/// than a dedicated port so the relay stays reachable only through the same TLS
/// front door every other :443 leg uses, with no new public listener.
pub const CT_EDGE_RELAY_ALPN: &str = "ct-edge-relay";

/// Reserved SNI hostname that routes a `:443` front-door ClientHello to the channel
/// broker **without** requiring the distinctive [`CT_EDGE_CHANNEL_ALPN`] — the
/// low-DPI-visibility twin of the #106 fallback, for members whose network drops or
/// stalls the ALPN-discriminated one.
///
/// Why it exists: ALPN travels in PLAINTEXT in the ClientHello, before any encryption
/// applies, so `ct-edge-channel` is a trivially greppable tunnel fingerprint. Corporate
/// DPI/middleboxes commonly allowlist only the ordinary web ALPN values (`h2`,
/// `http/1.1`) and silently drop or black-hole anything else — observed in the field as
/// a channel-join admission exchange that stalls with no bytes ever reaching the broker,
/// identically on the direct `:4435` QUIC dial AND on the `:443` ALPN fallback. Carrying
/// the discriminator in the `server_name` extension instead lets the client offer a
/// perfectly boring `h2`, so the handshake looks like any other HTTPS connection on the
/// wire.
///
/// Why a synthetic RFC 2606 `.invalid` name rather than a real hostname: `.invalid` is
/// reserved by the RFC and can never be a registrable domain, which buys two properties
/// this route needs. It is **portable** — identical across every CADS-Tunnel deployment
/// regardless of the operator's own zone, so a client needs no per-deployment
/// configuration to use it — and it can **never collide** with a customer's real
/// terminate-host or Browser-Plane tunnel hostname (see `classify_front_door`, which
/// claims this name ahead of both). It is never resolved via DNS: the client already
/// holds the edge's `SocketAddr` and dials it directly, presenting this purely as a
/// routing token. The name's shape is deliberately unremarkable (and carries none of
/// this project's own distinctive strings) so a superficial DPI keyword match finds
/// nothing to flag.
pub const CT_EDGE_CHANNEL_FALLBACK_SNI: &str = "edge-cdn.invalid";

/// Return the ClientHello **handshake body** of a buffered TLS record (the bytes
/// starting right after the 4-byte handshake header: `client_version(2) +
/// random(32) + session_id + cipher_suites + compression_methods + extensions`),
/// or `None` if `buf` is not a ClientHello. Fully bounds-checked — never panics.
///
/// Factored out of [`client_hello_extensions`] (which used to do this same
/// record/handshake-header parse inline) so [`client_hello_ja4_fields`] — the JA4
/// TLS fingerprinter's entry point (`crate::ja4`) — can reach `client_version`/
/// `cipher_suites` too, from the SAME bounds-checked walk `client_hello_extensions`
/// already relied on: one parse of the risky record/handshake-header prefix, not
/// two independently-maintained copies of it.
pub(crate) fn client_hello_body(buf: &[u8]) -> Option<&[u8]> {
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
    hs.get(4..)
}

/// Return the raw `extensions` block of a buffered TLS ClientHello record, or
/// `None` if `buf` is not a ClientHello. Fully bounds-checked — never panics.
fn client_hello_extensions(buf: &[u8]) -> Option<&[u8]> {
    let body = client_hello_body(buf)?;
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

/// Everything the JA4 fingerprinter (`crate::ja4`) needs from a buffered
/// ClientHello in one bounds-checked pass — the legacy `client_version` field, the
/// raw `cipher_suites` bytes (pairs of big-endian `u16`), and the `extensions`
/// block ([`client_hello_extensions`]'s own return value, reached via the exact
/// same offset walk so the two can never silently disagree on where the
/// ClientHello's fields actually are). `None` under the same conditions
/// [`client_hello_extensions`] returns `None` — not a ClientHello, or truncated.
pub(crate) fn client_hello_ja4_fields(buf: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let body = client_hello_body(buf)?;
    let version = u16::from_be_bytes([*body.get(0)?, *body.get(1)?]);
    let mut p = 34usize;
    let sid = *body.get(p)? as usize;
    p += 1 + sid;
    let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let cipher_suites = body.get(p..p + cs_len)?;
    p += cs_len;
    let cm = *body.get(p)? as usize;
    p += 1 + cm;
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let extensions = body.get(p..p + ext_total)?;
    Some((version, cipher_suites, extensions))
}

/// Find the first extension of type `want` in `exts` and map its data with `f`.
// #339: `'a` is explicit (not an elided/higher-ranked lifetime) and shared between
// `exts` and the closure's own parameter, so `T` is allowed to borrow from it --
// e.g. `T = &'a str`, which `sni_from_extensions` below needs. A `for<'r> Fn(&'r
// [u8]) -> Option<T>` bound (what eliding the lifetime here produces) can't
// express that, since `T` is fixed before any particular `'r` is chosen.
pub(crate) fn find_extension<'a, T>(exts: &'a [u8], want: u16, f: impl FnOnce(&'a [u8]) -> Option<T>) -> Option<T> {
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

/// Visit every `(extension_type, extension_data)` pair in `exts`, in wire order --
/// the JA4 fingerprinter's extension-count/extension-id-list source. Same
/// bounds-checked walk as [`find_extension`] (which stops at the first match);
/// this one calls `f` for every extension instead. Returns `None` the moment a
/// length disagrees with the bytes actually present (a malformed extensions
/// block), matching this module's fail-closed parsing posture -- whatever `f` was
/// already called with for extensions BEFORE the corrupt one stays valid data, not
/// fabricated past the real buffer. An empty `exts` (zero extensions) is not
/// malformed; the loop simply calls `f` zero times and returns `Some(())`.
pub(crate) fn each_extension(exts: &[u8], mut f: impl FnMut(u16, &[u8])) -> Option<()> {
    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let etype = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let elen = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        let edata = exts.get(q + 4..q + 4 + elen)?;
        f(etype, edata);
        q += 4 + elen;
    }
    Some(())
}

/// Zero-allocation core of [`peek_sni`]: the SNI hostname borrowed directly from
/// `exts` (already-extracted extensions, see [`client_hello_extensions`]), in its
/// **original case** — the caller lowercases only if/when it actually needs to
/// (#339: `classify_front_door` compares case-insensitively and only allocates a
/// lowercased copy for the one hostname it ends up returning, never for a
/// rejected candidate).
pub(crate) fn sni_from_extensions(exts: &[u8]) -> Option<&str> {
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

/// The JA4 fingerprinter's ALPN field needs only the FIRST advertised protocol's
/// raw bytes (unlike [`peek_alpn`]'s full list) -- zero-allocation, matching
/// [`alpn_extension_has`]'s style. `None` if the extension is absent, its protocol
/// list is empty, or the bytes are malformed (a length disagreeing with the data
/// present) -- the caller ([`crate::ja4`]) treats that the same as "no ALPN
/// offered", never fabricating a value past the real buffer.
pub(crate) fn alpn_first_value(exts: &[u8]) -> Option<&[u8]> {
    find_extension(exts, 0x0010, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        if list.is_empty() {
            return None;
        }
        let l = *list.first()? as usize;
        list.get(1..1 + l)
    })
}

/// Where the unified :443 front door should route a peeked ClientHello (#31 FD1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontDoorRoute {
    /// Tunnel data plane — the client advertised the `ct-edge` ALPN: hand off to
    /// the edge TLS-TCP relay (the ADR-0004 fallback rung on :443).
    EdgeRelay,
    /// Agent-Fabric channel service — the client advertised the `ct-edge-channel`
    /// ALPN (#106) **or** presented the reserved [`CT_EDGE_CHANNEL_FALLBACK_SNI`]
    /// hostname: hand off to the channel broker (rendezvous + relay), the `:443`
    /// fallback for members that cannot reach the channel port `:4435`. The two
    /// discriminators reach the identical destination; the SNI one exists so a member
    /// behind ALPN-fingerprinting DPI can offer an ordinary `h2` instead.
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
/// Precedence: the tunnel data-plane ALPN wins; then the reserved
/// [`CT_EDGE_CHANNEL_FALLBACK_SNI`] is a `ChannelBroker`; then any **terminate-host**
/// (SNI matches a configured proxy target — Portal or Auth IdP) is a `Proxy`; then any
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
    if alpn_has(CT_EDGE_CHANNEL_ALPN) || alpn_has(CT_EDGE_CHANNEL_KA_ALPN) {
        return FrontDoorRoute::ChannelBroker;
    }
    // Same ALPN-before-SNI precedence as the channel leg above -- a relay client
    // carries no SNI either.
    if alpn_has(CT_EDGE_RELAY_ALPN) {
        return FrontDoorRoute::RelayGate;
    }
    if let Some(sni) = exts.and_then(sni_from_extensions) {
        // The channel leg's low-DPI-visibility twin: a member whose network stalls the
        // distinctive `ct-edge-channel` ALPN reaches the SAME broker by presenting the
        // reserved hostname with an ordinary `h2` (or no ALPN at all). Checked BEFORE
        // the terminate-host and BrowserTunnel arms so the reserved name is claimed
        // here and can never be shadowed by — or collide with — a customer's own
        // routing: it is an RFC 2606 `.invalid` name, so no operator could legitimately
        // own it, and a confused or malicious client presenting it reaches the broker's
        // own grant + possession admission gate rather than someone else's tunnel.
        // Case-insensitive, like the hostname comparisons below (ALPN matching above
        // stays exact-byte per RFC 7301).
        if sni.eq_ignore_ascii_case(CT_EDGE_CHANNEL_FALLBACK_SNI) {
            return FrontDoorRoute::ChannelBroker;
        }
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
    fn classify_front_door_routes_the_ka_channel_alpn_to_the_broker_500() {
        // #500 K2: a keepalive-capable client offers [ct-edge-channel-ka, ct-edge-channel];
        // BOTH ids must classify to the broker (an old client's bare-id offer already did).
        let default = Some("portal.z");
        assert_eq!(
            classify_front_door(
                &client_hello(None, &[CT_EDGE_CHANNEL_KA_ALPN, CT_EDGE_CHANNEL_ALPN]),
                terminate_host,
                default
            ),
            FrontDoorRoute::ChannelBroker
        );
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_CHANNEL_KA_ALPN]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "the -ka id alone classifies too (a future client may drop the legacy id)"
        );
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

    // The low-DPI-visibility channel route. Motivated by a real support case: a tester
    // on a corporate/sandbox network could not complete channel admission against a
    // production edge on EITHER the direct `:4435` QUIC dial or the `:443`
    // `ct-edge-channel` ALPN fallback -- both stalled mid-exchange with zero
    // server-side reception evidence, i.e. the join bytes never arrived, which is
    // packet-level interference rather than a plain port block. The distinctive
    // plaintext ALPN is the leading suspect, so the same broker is now reachable with
    // an ordinary `h2` plus a reserved SNI instead.
    #[test]
    fn classify_front_door_routes_the_reserved_fallback_sni_to_the_channel_broker() {
        let default = Some("portal.z");
        // The whole point: a boring `h2` ALPN -- indistinguishable from ordinary HTTPS
        // to a DPI box reading the plaintext ClientHello -- still reaches the broker.
        assert_eq!(
            classify_front_door(&client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &["h2"]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "the reserved SNI routes to the channel broker with a plain `h2` ALPN"
        );
        // …and with no ALPN extension at all, or the other ordinary web ALPN.
        assert_eq!(
            classify_front_door(&client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &[]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "the reserved SNI alone suffices -- no ALPN required"
        );
        assert_eq!(
            classify_front_door(
                &client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &["h2", "http/1.1"]),
                terminate_host,
                default
            ),
            FrontDoorRoute::ChannelBroker
        );

        // The pre-existing ALPN route is completely unaffected: it still works
        // standalone, carrying no SNI at all, exactly as before this route existed.
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_CHANNEL_ALPN]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "the ct-edge-channel ALPN route still works without the new SNI"
        );
        // A client offering BOTH discriminators lands on the same route -- no conflict.
        assert_eq!(
            classify_front_door(
                &client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &[CT_EDGE_CHANNEL_ALPN]),
                terminate_host,
                default
            ),
            FrontDoorRoute::ChannelBroker
        );
        // Ordinary traffic is untouched: a normal SNI with a web ALPN still classifies
        // by hostname exactly as before.
        assert_eq!(
            classify_front_door(&client_hello(Some("app1.z"), &["h2"]), terminate_host, default),
            FrontDoorRoute::BrowserTunnel("app1.z".into())
        );
        assert_eq!(
            classify_front_door(&client_hello(Some("Portal.Z"), &["h2"]), terminate_host, default),
            FrontDoorRoute::Proxy("portal.z".into())
        );
        // The documented ALPN-before-SNI precedence still holds ahead of this branch:
        // a data-plane ALPN wins even when the reserved SNI is also present (a client
        // would never send this combination, but the ordering must be deterministic).
        assert_eq!(
            classify_front_door(
                &client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &[CT_EDGE_ALPN]),
                terminate_host,
                default
            ),
            FrontDoorRoute::EdgeRelay,
            "the ct-edge data-plane ALPN still wins ahead of any SNI-based routing"
        );
        assert_eq!(
            classify_front_door(
                &client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &[CT_EDGE_RELAY_ALPN]),
                terminate_host,
                default
            ),
            FrontDoorRoute::RelayGate
        );
    }

    #[test]
    fn reserved_fallback_sni_is_claimed_before_terminate_host_and_browser_tunnel() {
        // Precedence, deliberately chosen: the reserved name is claimed by the channel
        // route ahead of BOTH the terminate-host (`Proxy`) and Browser-Plane
        // (`BrowserTunnel`) arms. Safe because RFC 2606 guarantees `.invalid` can never
        // be a registrable domain, so no operator can legitimately own this name -- and
        // claiming it here means a customer who somehow configured it (by accident or
        // to hijack the route) can never shadow the channel fallback, nor capture a
        // channel member's connection into their own tunnel.
        let default = Some("portal.z");
        // A terminate_hosts registry that *does* claim the reserved name: the channel
        // route still wins, so the fallback can never be broken by configuration.
        let claims_reserved =
            |h: &str| h.eq_ignore_ascii_case(CT_EDGE_CHANNEL_FALLBACK_SNI) || terminate_host(h);
        assert_eq!(
            classify_front_door(&client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &["h2"]), claims_reserved, default),
            FrontDoorRoute::ChannelBroker,
            "the reserved SNI beats a terminate host that claims the same name"
        );
        // With no terminate hosts at all it must NOT fall through to BrowserTunnel.
        let never_terminate = |_: &str| false;
        assert_eq!(
            classify_front_door(&client_hello(Some(CT_EDGE_CHANNEL_FALLBACK_SNI), &[]), never_terminate, default),
            FrontDoorRoute::ChannelBroker,
            "the reserved SNI is never treated as a Browser-Plane tunnel hostname"
        );
        // The constant itself is an RFC 2606 `.invalid` name -- the property the whole
        // precedence argument rests on, guarded here so it survives any future rename.
        assert!(
            CT_EDGE_CHANNEL_FALLBACK_SNI.ends_with(".invalid"),
            "the reserved SNI must stay in the RFC 2606 `.invalid` TLD so it can never collide with a real domain"
        );
        assert_eq!(
            CT_EDGE_CHANNEL_FALLBACK_SNI,
            CT_EDGE_CHANNEL_FALLBACK_SNI.to_ascii_lowercase(),
            "the constant is stored lowercased, matching this module's hostname convention"
        );
    }

    #[test]
    fn reserved_fallback_sni_matching_is_case_insensitive_like_every_other_hostname() {
        // Mirrors `classify_front_door_alpn_matching_is_case_sensitive_sni_matching_is_
        // not_329`: SNI comparisons in this module are case-insensitive (a client's TLS
        // stack may normalize casing differently), while ALPN stays exact-byte.
        let default = Some("portal.z");
        // Derived from the constant rather than hardcoded, so a future rename of the
        // reserved name can't silently turn these into vacuous assertions.
        let alternating: String = CT_EDGE_CHANNEL_FALLBACK_SNI
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
            .collect();
        for variant in [
            CT_EDGE_CHANNEL_FALLBACK_SNI.to_string(),
            CT_EDGE_CHANNEL_FALLBACK_SNI.to_ascii_uppercase(),
            alternating,
        ] {
            let variant = variant.as_str();
            assert_eq!(
                classify_front_door(&client_hello(Some(variant), &["h2"]), terminate_host, default),
                FrontDoorRoute::ChannelBroker,
                "reserved-SNI matching must be case-insensitive for {variant:?}"
            );
        }
        // A near-miss must NOT match -- it falls through to the ordinary SNI routing.
        let suffixed = format!("{CT_EDGE_CHANNEL_FALLBACK_SNI}.z");
        assert_eq!(
            classify_front_door(&client_hello(Some(suffixed.as_str()), &["h2"]), terminate_host, default),
            FrontDoorRoute::BrowserTunnel(suffixed.clone()),
            "only an exact (case-insensitive) hostname match claims the channel route"
        );
        let prefixed = format!("not-{CT_EDGE_CHANNEL_FALLBACK_SNI}");
        assert_eq!(
            classify_front_door(&client_hello(Some(prefixed.as_str()), &["h2"]), terminate_host, default),
            FrontDoorRoute::BrowserTunnel(prefixed.clone())
        );
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

    // #329 area 1: multi-ALPN precedence. A real client can offer several ALPN
    // protocol ids in one ClientHello (e.g. a library trying several fallbacks);
    // the documented precedence (data-plane > channel > relay > SNI-based >
    // default-host) must hold even when more than one of our own ALPN ids is
    // present at once, not just when exactly one is offered as every existing
    // test above does.
    #[test]
    fn classify_front_door_precedence_holds_with_multiple_alpn_ids_offered_at_once_329() {
        let default = Some("portal.z");
        // ct-edge beats ct-edge-channel beats ct-edge-relay, regardless of the
        // ORDER they're offered in.
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_CHANNEL_ALPN, CT_EDGE_ALPN, CT_EDGE_RELAY_ALPN]), terminate_host, default),
            FrontDoorRoute::EdgeRelay,
            "ct-edge wins even offered after the others"
        );
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_ALPN, CT_EDGE_CHANNEL_ALPN]), terminate_host, default),
            FrontDoorRoute::EdgeRelay,
            "ct-edge wins over ct-edge-channel"
        );
        // ct-edge-channel beats ct-edge-relay when ct-edge is absent.
        assert_eq!(
            classify_front_door(&client_hello(None, &[CT_EDGE_RELAY_ALPN, CT_EDGE_CHANNEL_ALPN]), terminate_host, default),
            FrontDoorRoute::ChannelBroker,
            "ct-edge-channel wins over ct-edge-relay"
        );
        // Any of the three data-plane ALPNs beats a terminate-host SNI and a web ALPN
        // offered in the SAME hello.
        assert_eq!(
            classify_front_door(&client_hello(Some("Portal.Z"), &["h2", "http/1.1", CT_EDGE_RELAY_ALPN]), terminate_host, default),
            FrontDoorRoute::RelayGate,
            "a data-plane ALPN wins over web ALPNs and a terminate-host SNI in the same hello"
        );
        // Two web ALPNs together with an SNI: SNI-based routing still wins over the
        // web-ALPN default-host fallback (the SNI branch is checked before the
        // no-SNI web-ALPN branch).
        assert_eq!(
            classify_front_door(&client_hello(Some("app1.z"), &["h2", "http/1.1"]), terminate_host, default),
            FrontDoorRoute::BrowserTunnel("app1.z".into()),
            "SNI-based routing wins over the web-ALPN default-host fallback when both are present"
        );
    }

    // #329 area 2: case sensitivity asymmetry. TLS ALPN protocol ids are exact-byte
    // match per RFC 7301; SNI/terminate_hosts/default_host matching is deliberately
    // case-insensitive. Both halves of this asymmetry must hold, not just the
    // SNI-insensitivity half the existing tests already cover.
    #[test]
    fn classify_front_door_alpn_matching_is_case_sensitive_sni_matching_is_not_329() {
        let default = Some("portal.z");
        // A differently-cased ALPN id must NOT match -- falls through to Reject
        // (no SNI, no matching web ALPN either).
        assert_eq!(
            classify_front_door(&client_hello(None, &["CT-EDGE"]), terminate_host, default),
            FrontDoorRoute::Reject,
            "ALPN matching is exact-byte, RFC 7301 -- \"CT-EDGE\" must not match \"ct-edge\""
        );
        assert_eq!(
            classify_front_door(&client_hello(None, &["Ct-Edge-Channel"]), terminate_host, default),
            FrontDoorRoute::Reject,
            "mixed-case ct-edge-channel must not match either"
        );
        assert_eq!(
            classify_front_door(&client_hello(None, &["HTTP/1.1"]), terminate_host, default),
            FrontDoorRoute::Reject,
            "the web ALPN check (\"http/1.1\"/\"h2\") is also exact-byte -- differently-cased must not match"
        );
        // SNI matching against terminate_hosts stays case-insensitive (already proven
        // for one case in classify_front_door_routes_by_alpn_then_sni; this proves
        // several more casings agree on the SAME lowercased result).
        for variant in ["portal.z", "Portal.Z", "PORTAL.Z", "PoRtAl.z"] {
            assert_eq!(
                classify_front_door(&client_hello(Some(variant), &[]), terminate_host, default),
                FrontDoorRoute::Proxy("portal.z".into()),
                "terminate-host SNI matching must be case-insensitive for {variant:?}"
            );
        }
        // default_host is compared case-insensitively too -- covered here since no
        // existing test exercises a non-lowercase default_host.
        assert_eq!(
            classify_front_door(&client_hello(None, &["http/1.1"]), terminate_host, Some("Portal.Z")),
            FrontDoorRoute::Proxy("portal.z".into()),
            "default_host is lowercased regardless of its own casing"
        );
    }

    // #329 area 3: adversarial/malformed ClientHello parsing. Every parser here
    // (client_hello_extensions, find_extension, sni_from_extensions,
    // alpn_extension_has, peek_alpn) reads bytes from an unauthenticated remote
    // peer BEFORE any other check runs. "Doesn't panic" isn't the bar -- these
    // assert the actual resulting behavior (clean None/Reject/empty, not a
    // misroute) for each malformed shape.
    #[test]
    fn parsers_reject_cleanly_rather_than_misroute_on_malformed_input_329() {
        let default = Some("portal.z");

        // Truncated at every offset of a real, well-formed hello: never a panic,
        // and never silently returns a *plausible-looking-but-wrong* SNI/ALPN --
        // any truncation must fail closed (route to Reject, or peek_* -> None/empty).
        let good = client_hello(Some("app1.z"), &[CT_EDGE_ALPN]);
        for cut in 1..good.len() {
            let truncated = &good[..cut];
            // Must never panic (the real assertion -- a panic here would abort the
            // whole edge process on one malformed connection).
            let _ = classify_front_door(truncated, terminate_host, default);
            let _ = peek_sni(truncated);
            let _ = peek_alpn(truncated);
        }
        // A specific truncation that chops mid-ALPN-entry: fails closed to Reject,
        // not a partial/garbage route.
        let mut chopped = client_hello(None, &[CT_EDGE_ALPN]);
        chopped.truncate(chopped.len() - 2); // chop the last 2 bytes of the "ct-edge" entry
        assert_eq!(
            classify_front_door(&chopped, terminate_host, default),
            FrontDoorRoute::Reject,
            "a truncated ALPN entry must never be misread as a match"
        );

        // Not a ClientHello at all (wrong content type / wrong handshake type).
        assert_eq!(classify_front_door(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00], terminate_host, default), FrontDoorRoute::Reject);
        assert_eq!(classify_front_door(b"", terminate_host, default), FrontDoorRoute::Reject);
        assert_eq!(classify_front_door(b"GET / HTTP/1.1\r\n", terminate_host, default), FrontDoorRoute::Reject);

        // A length field that overflows the buffer: the TLS record length claims far
        // more data than is actually present. `client_hello_extensions` must return
        // None (via `.get()`, not index-and-panic), not read past the real buffer.
        let mut overflow = client_hello(Some("x.z"), &[]);
        overflow[3] = 0xFF;
        overflow[4] = 0xFF; // rec_len now claims 65535 bytes, buffer is much shorter
        assert_eq!(classify_front_door(&overflow, terminate_host, default), FrontDoorRoute::Reject);
        assert_eq!(peek_sni(&overflow), None);

        // An extensions-length that disagrees with the actual bytes present (claims
        // more extension bytes than the record actually carries).
        let mut ext_overflow = client_hello(Some("x.z"), &[CT_EDGE_ALPN]);
        let n = ext_overflow.len();
        ext_overflow[n - 200.min(n)] = 0xFF; // corrupt somewhere in the extensions area
        // Must not panic; whatever it resolves to is acceptable as long as it's a
        // clean route (fails closed rather than fabricating a match past the real
        // data). The real assertion is the earlier "never panics" sweep above; this
        // just adds one more concrete corrupted-length shape to that sweep.
        let _ = classify_front_door(&ext_overflow, terminate_host, default);

        // A duplicate SNI extension: two server_name extensions in the same hello.
        // find_extension returns the FIRST match it scans -- assert that's genuinely
        // what happens (deterministic, not "whichever the allocator felt like"),
        // by building one by hand with two distinct hostnames back to back.
        // Build a hello whose extensions block carries a raw, hand-assembled
        // sequence rather than going through `client_hello`/`synth_client_hello`
        // (which only ever emit one of each extension) -- needed for the
        // duplicate-extension and empty-ALPN-list cases below.
        fn hello_with_raw_extensions(exts: &[u8]) -> Vec<u8> {
            let mut body = vec![0x03, 0x03];
            body.extend_from_slice(&[0u8; 32]);
            body.push(0x00);
            body.extend_from_slice(&2u16.to_be_bytes());
            body.extend_from_slice(&[0x13, 0x01]);
            body.push(0x01);
            body.push(0x00);
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(exts);
            let mut hs = vec![0x01];
            let bl = body.len();
            hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
            hs.extend_from_slice(&body);
            let mut rec = vec![0x16, 0x03, 0x01];
            rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
            rec.extend_from_slice(&hs);
            rec
        }
        fn sni_extension(host: &str) -> Vec<u8> {
            let h = host.as_bytes();
            let mut entry = vec![0x00];
            entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
            entry.extend_from_slice(h);
            let mut snl = (entry.len() as u16).to_be_bytes().to_vec();
            snl.extend_from_slice(&entry);
            let mut ext = vec![0x00, 0x00];
            ext.extend_from_slice(&(snl.len() as u16).to_be_bytes());
            ext.extend_from_slice(&snl);
            ext
        }

        // Two server_name extensions concatenated in the extensions block.
        let mut dup_exts = sni_extension("first.z");
        dup_exts.extend_from_slice(&sni_extension("second.z"));
        let dup_sni = hello_with_raw_extensions(&dup_exts);
        assert_eq!(
            peek_sni(&dup_sni).as_deref(),
            Some("first.z"),
            "a duplicate SNI extension deterministically resolves to the FIRST one scanned, not the last or a panic"
        );

        // Non-UTF8 bytes in the SNI hostname field: must yield None, not a lossy
        // conversion or a panic (std::str::from_utf8 rejects, peek_sni returns None).
        let mut bad_utf8 = client_hello_with_sni("x");
        // Overwrite the single-byte hostname ("x", at a known fixed offset in this
        // fixture: TLS record header(5) + handshake header(4) + version(2) +
        // random(32) + session_id_len(1) + cipher_suites(2+2) + compression(1+1) +
        // ext_total(2) + ext_type(2) + ext_len(2) + list_len(2) + name_type(1) +
        // name_len(2) = last byte is the hostname itself).
        let last = bad_utf8.len() - 1;
        bad_utf8[last] = 0xFF; // invalid UTF-8 continuation byte with no lead byte
        assert_eq!(peek_sni(&bad_utf8), None, "non-UTF8 SNI bytes must yield None, not a panic or lossy string");

        // Empty ALPN protocol list (the extension is present but carries zero
        // entries): must behave exactly like "no ALPN offered", not panic or match
        // anything.
        // An ALPN extension with list_len=0 and no entries.
        let mut empty_alpn_ext = vec![0x00, 0x10]; // ALPN extension type
        empty_alpn_ext.extend_from_slice(&2u16.to_be_bytes()); // ext data len = 2 (just the list len)
        empty_alpn_ext.extend_from_slice(&0u16.to_be_bytes()); // protocol list len = 0
        let empty_alpn_hello = hello_with_raw_extensions(&empty_alpn_ext);
        assert!(peek_alpn(&empty_alpn_hello).is_empty(), "an empty ALPN list parses to an empty Vec, not a panic");
        assert_eq!(
            classify_front_door(&empty_alpn_hello, terminate_host, default),
            FrontDoorRoute::Reject,
            "an empty ALPN list with no SNI and no matching web ALPN rejects cleanly"
        );
    }

    // #329 area 4: boundary/absence cases.
    #[test]
    fn classify_front_door_boundary_and_absence_cases_329() {
        // Empty terminate_hosts (closure always returns false): every SNI becomes a
        // BrowserTunnel candidate, never a Proxy -- proving the classifier doesn't
        // implicitly special-case "no terminate hosts configured" into a reject.
        let never_terminate = |_: &str| false;
        assert_eq!(
            classify_front_door(&client_hello(Some("portal.z"), &[]), never_terminate, Some("portal.z")),
            FrontDoorRoute::BrowserTunnel("portal.z".into()),
            "with an empty terminate_hosts set, even the configured default_host's own name is just a BrowserTunnel SNI, not a Proxy"
        );

        // default_host: None with only a web ALPN (no SNI at all): must Reject, not
        // panic or silently fall back to some other host.
        assert_eq!(
            classify_front_door(&client_hello(None, &["http/1.1"]), terminate_host, None),
            FrontDoorRoute::Reject,
            "no SNI, web ALPN, but no default_host configured -> Reject, never a panic or an implicit fallback"
        );
        assert_eq!(
            classify_front_door(&client_hello(None, &["h2"]), terminate_host, None),
            FrontDoorRoute::Reject
        );

        // SNI present but matching neither a terminate host nor (from this pure
        // classifier's point of view) any registered tunnel: always BrowserTunnel(sni).
        // This classifier is deliberately permissive here -- it's only safe because
        // `serve_front_door`'s BrowserTunnel arm gates on `state.route_host(&host)`
        // before serving anything (see crates/edge/src/serve.rs, the
        // `if state.route_host(&host).is_none()` check right after the BrowserTunnel
        // arm is entered) -- an unregistered host never reaches an actual backend,
        // it falls through to the mesh-relay-or-reject path there instead. This test
        // documents the classifier's own permissive-by-design contract; the downstream
        // gate itself is exercised by serve.rs's own front-door integration tests.
        assert_eq!(
            classify_front_door(&client_hello(Some("never-registered.z"), &[]), terminate_host, Some("portal.z")),
            FrontDoorRoute::BrowserTunnel("never-registered.z".into()),
            "an unknown/unregistered SNI is still classified as a BrowserTunnel candidate -- rejecting it is serve_front_door's job, not this pure function's"
        );
    }
}

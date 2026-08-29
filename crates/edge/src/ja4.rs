//! JA4 TLS ClientHello fingerprinting (FoxIO spec:
//! `github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md`), computed
//! passively from the same buffered ClientHello bytes `sni.rs` already
//! hand-parses for `:443` front-door routing.
//!
//! ## Why this exists, and why it stops here
//!
//! The operator asked for JA4 fingerprinting with an explicit "no follow-on
//! cost" constraint. That fixes the scope: this module computes the
//! fingerprint string and nothing else. [`crate::serve::serve_front_door`] calls
//! [`compute_ja4`] as a **pure side observation** (see `state.rs`'s
//! `Ja4Observations`, which the fingerprint feeds — a bounded Prometheus
//! counter), and nothing in this codebase ever makes an admission, routing, or
//! blocking decision from a JA4 value. That is deliberate, not an oversight:
//! JA4 alone cannot reliably distinguish a legitimate-but-unusual TLS stack
//! from a bot (FoxIO's own documentation says so) — treating it as anything
//! but an informational counter risks false-positive blocking of real
//! customers. No reputation database, no external lookup service, no
//! commercial threat-intel feed, no active enforcement of any kind: all
//! explicitly out of scope here.
//!
//! ## Ground truth for this implementation
//!
//! Verified against FoxIO's own reference implementation (not just the prose
//! spec document, which is not byte-exact on one point — see below):
//! `github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py` (`to_ja4()`) and
//! `.../python/common.py` (`get_hex_sorted`, `sha_encode`, `GREASE_TABLE`,
//! `TLS_MAPPER`, `get_supported_version`), fetched and read in full.
//!
//! **Correction versus the prose spec doc**: the extension-**count** digit in
//! JA4_a counts every non-GREASE extension INCLUDING SNI (`0x0000`) and ALPN
//! (`0x0010`) — only the JA4_c *hashed extension-id list* excludes those two.
//! The reference code is unambiguous (`to_ja4()`: `ext_len =
//! '{:02d}'.format(min(len([x for x in x['extensions'] if x not in
//! GREASE_TABLE]), 99))`, run against the RAW extension list, before the
//! SNI/ALPN removal that only happens later, inside `get_hex_sorted`'s
//! `field == 'extensions'` branch, for the hashed list). This module follows
//! the code. It is also independently confirmable from the spec doc's own
//! published example: the famous Chrome-108 fingerprint
//! `t13d1516h2_8daaf6152771_e5627efa2ab1` has a JA4_a extension-count digit of
//! `16`, while its own worked JA4_c hashed-extension-list example
//! (`0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01`)
//! has exactly 14 entries — 14 + 2 (SNI, ALPN) = 16, not 14. See
//! [`tests::the_published_chrome_108_ja4_example_round_trips`] below, which
//! reconstructs that exact ClientHello from the two example lists the spec
//! doc publishes and asserts the full JA4 string matches byte-for-byte.
//!
//! Only the standard "JA4" string is computed (sorted ciphers + sorted
//! extensions) — the raw/original-order debugging variants (`JA4_r`/`JA4_o`/
//! `JA4_ro`) the reference tool also emits are out of scope here.

use sha2::{Digest, Sha256};

use crate::sni::{client_hello_ja4_fields, each_extension, find_extension, sni_from_extensions};

/// RFC 8701 GREASE values — the exact 16-entry set FoxIO's own `GREASE_TABLE`
/// enumerates. Deliberately an explicit list, not the looser `value & 0x0f0f
/// == 0x0a0a` bitmask some other TLS tooling uses for the same check: that
/// mask also matches values like `0x0a1a` (bytes `0x0a`, `0x1a` — nibble `a`
/// in each byte, but the two bytes are NOT equal) that are not real GREASE
/// values, and would silently over-filter/miscount against real JA4 tooling.
const GREASE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool {
    GREASE.contains(&v)
}

/// `TLS_MAPPER`: the legacy/negotiated version `u16` -> JA4's 2-char version
/// code. `"00"` for anything unrecognized (a future TLS version this table
/// hasn't been updated for, or attacker-controlled garbage) — never a panic,
/// matching this parser family's "unknown input fails closed to a documented
/// sentinel" posture (`sni.rs`'s `classify_front_door` does the same).
fn version_code(v: u16) -> &'static str {
    match v {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    }
}

/// SHA256 of `input`, truncated to the first 12 lowercase hex characters —
/// JA4_b/JA4_c's hash. `input` is always plain ASCII (comma-joined lowercase
/// hex, plus an occasional `_`), so byte-vs-char truncation is not an issue.
fn sha256_hex12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("{digest:x}")[..12].to_string()
}

/// The ClientHello's negotiated TLS version: the highest non-GREASE entry of
/// the `supported_versions` extension (`0x002b`, RFC 8446 §4.2.1: a
/// `versions<2..254>` vector — ONE-byte length, unlike most TLS extension
/// vectors) if present and it has at least one non-GREASE entry, else the
/// legacy `client_version` handshake field. Mirrors `get_supported_version` in
/// FoxIO's `common.py`, except it never panics on an all-GREASE/empty
/// `supported_versions` list — the reference script's `versions[-1]` would
/// raise `IndexError` there (an extension a real client would never send, but
/// this parser runs on unauthenticated attacker-controlled bytes at a
/// production TLS front door, so it must not crash on it); falling back to
/// the legacy field for that case is the same fallback a real TLS peer uses
/// when a version-negotiation extension carries nothing it understands.
fn negotiated_version(legacy_version: u16, exts: &[u8]) -> u16 {
    find_extension(exts, 0x002b, |edata| {
        let list_len = *edata.first()? as usize;
        let list = edata.get(1..1 + list_len)?;
        let mut best: Option<u16> = None;
        let mut i = 0usize;
        while i + 2 <= list.len() {
            let v = u16::from_be_bytes([list[i], list[i + 1]]);
            i += 2;
            if is_grease(v) {
                continue;
            }
            best = Some(best.map_or(v, |b| b.max(v)));
        }
        best
    })
    .unwrap_or(legacy_version)
}

/// The `signature_algorithms` extension's (`0x000d`) raw values, in ORIGINAL
/// wire order (JA4_c appends them unsorted, unlike the extension-id list
/// itself) — `None` if the extension is absent or its bytes are malformed
/// (fails closed to "not present", same as everywhere else in this parser
/// family; a real client's extension is never malformed).
fn signature_algorithm_ids(exts: &[u8]) -> Option<Vec<u16>> {
    find_extension(exts, 0x000d, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 2 <= list.len() {
            out.push(u16::from_be_bytes([list[i], list[i + 1]]));
            i += 2;
        }
        Some(out)
    })
}

/// JA4_a's cipher-count digit and JA4_b's hash, from the raw `cipher_suites`
/// bytes (pairs of big-endian `u16`).
///
/// Mirrors a genuinely two-branch spec rule (`to_ja4()` lines ~255-261): if
/// the ClientHello offered **zero** cipher suites at all (illegal per RFC
/// 8446, but this parses attacker-controlled bytes, so it must be handled,
/// not assumed away), both the count and the hash are the literal
/// `"000000000000"` sentinel. Otherwise the count/hash are computed from the
/// GREASE-filtered list even if filtering empties it out (a ClientHello whose
/// cipher suites are ALL GREASE) — that produces `sha256("")` truncated
/// (`"e3b0c44298fc"`), NOT the sentinel, because the reference script's
/// `not x['ciphers']` guard checks the RAW pre-filter list, not the filtered
/// one. See [`tests::all_grease_ciphers_hash_the_empty_string_not_the_zero_sentinel`].
fn cipher_fields(cipher_suites: &[u8]) -> (String, String) {
    if cipher_suites.is_empty() {
        return ("00".to_string(), "000000000000".to_string());
    }
    let mut ids = Vec::with_capacity(cipher_suites.len() / 2);
    let mut i = 0usize;
    while i + 2 <= cipher_suites.len() {
        ids.push(u16::from_be_bytes([cipher_suites[i], cipher_suites[i + 1]]));
        i += 2;
    }
    let mut filtered: Vec<u16> = ids.into_iter().filter(|v| !is_grease(*v)).collect();
    let count = format!("{:02}", filtered.len().min(99));
    filtered.sort_unstable();
    let joined = filtered.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");
    (count, sha256_hex12(&joined))
}

/// JA4_a's extension-count digit and JA4_c's hash, from the `extensions`
/// block.
///
/// Count: every non-GREASE extension, **including** SNI/ALPN (see the module
/// doc's "correction versus the prose spec doc"). Hash input: the SORTED,
/// GREASE/SNI/ALPN-filtered extension-id list, joined by commas, plus — only
/// when `0x000d` (`signature_algorithms`) is present at all — an underscore
/// and the GREASE-filtered `signature_algorithms` values in their ORIGINAL
/// (unsorted) wire order. Hashed as `"000000000000"` only when that combined
/// string ends up completely empty (no real extensions AND no
/// `signature_algorithms` extension present at all).
fn extension_fields(exts: &[u8]) -> (String, String) {
    let mut all_count = 0usize;
    let mut for_hash: Vec<u16> = Vec::new();
    // A malformed extensions block (a length that disagrees with the bytes
    // present) makes `each_extension` stop early -- whatever it already
    // collected before the corrupt entry is genuine, validated data, so it is
    // kept rather than discarded (the same "fail closed on the corrupted
    // part, not on data already validated" posture `classify_front_door`
    // uses for its own truncation handling).
    let _ = each_extension(exts, |etype, _data| {
        if !is_grease(etype) {
            all_count += 1;
        }
        if !is_grease(etype) && etype != 0x0000 && etype != 0x0010 {
            for_hash.push(etype);
        }
    });
    let count = format!("{:02}", all_count.min(99));
    for_hash.sort_unstable();
    let ext_joined = for_hash.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");
    let combined = match signature_algorithm_ids(exts) {
        Some(ids) => {
            let filtered: Vec<u16> = ids.into_iter().filter(|v| !is_grease(*v)).collect();
            let sig_joined = filtered.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");
            format!("{ext_joined}_{sig_joined}")
        }
        None => ext_joined,
    };
    let hash = if combined.is_empty() { "000000000000".to_string() } else { sha256_hex12(&combined) };
    (count, hash)
}

/// JA4_a's ALPN field: the first advertised protocol's first-and-last
/// character (verbatim if the value is 1-2 characters long), or `"99"` if
/// the first byte is non-ASCII, or `"00"` if no ALPN was advertised at all.
///
/// Mirrors `to_ja4()`'s literal Python string-indexing rule. Real IANA-
/// registered ALPN protocol ids (`h2`, `http/1.1`, `h3`, …) are always plain
/// ASCII, so the UTF-8 decode below always succeeds for a real client; a
/// non-UTF-8 first byte is only reachable from an adversarial ClientHello,
/// where `"99"` (JA4's own "non-ASCII" sentinel) is the closest faithful
/// answer without decoding garbage into a fabricated character.
fn alpn_code(exts: &[u8]) -> String {
    let Some(bytes) = crate::sni::alpn_first_value(exts) else {
        return "00".to_string();
    };
    if bytes.is_empty() {
        return "00".to_string();
    }
    let Ok(s) = std::str::from_utf8(bytes) else {
        return "99".to_string();
    };
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return "00".to_string();
    };
    if (first as u32) > 127 {
        return "99".to_string();
    }
    if s.chars().count() > 2 {
        let last = s.chars().next_back().unwrap_or(first);
        format!("{first}{last}")
    } else {
        s.to_string()
    }
}

/// Compute the JA4 fingerprint string for a buffered TLS ClientHello record —
/// the same bytes [`crate::sni::read_client_hello_bytes`] already buffers for
/// `:443` front-door routing.
///
/// The protocol indicator is always `"t"` (TCP/TLS): this parser only ever
/// sees the front door's TLS-over-TCP ClientHellos — QUIC connections never
/// reach `sni::read_client_hello_bytes` at all (they terminate in the
/// `quinn`-based Agent/channel paths instead), so JA4's `"q"` (QUIC) and
/// `"d"` (DTLS) protocol indicators never apply here.
///
/// Returns `None` if `buf` is not a well-formed-enough ClientHello to parse
/// at all — the same gate [`crate::sni::classify_front_door`] uses via
/// [`client_hello_ja4_fields`]. Never panics on malformed/truncated input:
/// this runs on every unauthenticated inbound `:443` connection, so it must
/// be at least as defensive as the routing parser it shares its byte-reading
/// helpers with.
pub fn compute_ja4(buf: &[u8]) -> Option<String> {
    let (legacy_version, cipher_suites, exts) = client_hello_ja4_fields(buf)?;
    let version = version_code(negotiated_version(legacy_version, exts));
    let sni = if sni_from_extensions(exts).is_some() { "d" } else { "i" };
    let (cipher_count, cipher_hash) = cipher_fields(cipher_suites);
    let (ext_count, ext_hash) = extension_fields(exts);
    let alpn = alpn_code(exts);
    Some(format!("t{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append one raw TLS extension entry (`type(2) + len(2) + data`) to `out`.
    fn push_ext(out: &mut Vec<u8>, etype: u16, data: &[u8]) {
        out.extend_from_slice(&etype.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// A `server_name` (SNI, `0x0000`) extension's data for `host`.
    fn sni_ext_data(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
        entry.extend_from_slice(h);
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        data
    }

    /// An `application_layer_protocol_negotiation` (ALPN, `0x0010`) extension's
    /// data carrying the protocols in `protos`, in order (first = negotiation
    /// preference, which is what JA4's ALPN field reads).
    fn alpn_ext_data(protos: &[&str]) -> Vec<u8> {
        let mut list = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        data
    }

    /// A `supported_versions` (`0x002b`) extension's data for the given 2-byte
    /// version codes (RFC 8446 §4.2.1: ONE-byte length prefix, not two).
    fn supported_versions_ext_data(versions: &[u16]) -> Vec<u8> {
        let mut data = vec![(versions.len() * 2) as u8];
        for v in versions {
            data.extend_from_slice(&v.to_be_bytes());
        }
        data
    }

    /// A `signature_algorithms` (`0x000d`) extension's data for the given
    /// 2-byte SignatureScheme ids, in the exact order given (JA4_c appends
    /// this list unsorted).
    fn sig_algs_ext_data(ids: &[u16]) -> Vec<u8> {
        let mut data = ((ids.len() * 2) as u16).to_be_bytes().to_vec();
        for id in ids {
            data.extend_from_slice(&id.to_be_bytes());
        }
        data
    }

    /// Build a complete, well-formed TLS ClientHello record: `legacy_version`
    /// as the handshake body's `client_version` field, the given raw
    /// `cipher_suites` ids, and `extensions` as the already-assembled raw
    /// extensions block (built via `push_ext`/the `*_ext_data` helpers above).
    /// Mirrors `sni.rs`'s own `synth_client_hello`/`hello_with_raw_extensions`
    /// test fixtures, generalized to cover the extra extensions
    /// (`supported_versions`, `signature_algorithms`) and explicit cipher
    /// suite ids JA4 needs that those fixtures don't carry.
    fn build_client_hello(legacy_version: u16, cipher_suites: &[u16], extensions: &[u8]) -> Vec<u8> {
        let mut body = legacy_version.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id length 0
        body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
        for c in cipher_suites {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    // ---- Hash primitive, checked directly against the FoxIO spec doc's own
    // published worked examples (technical_details/JA4.md) -- the single
    // riskiest piece to get subtly wrong, verified independent of this
    // module's own ClientHello parsing. ----

    #[test]
    fn sha256_hex12_matches_the_published_ja4_b_example() {
        // JA4.md's own JA4_b worked example.
        let ciphers = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
        assert_eq!(sha256_hex12(ciphers), "8daaf6152771");
    }

    #[test]
    fn sha256_hex12_matches_the_published_ja4_c_example() {
        // JA4.md's own JA4_c worked example (sorted extension ids, underscore,
        // then signature_algorithms in ORIGINAL order).
        let combined = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";
        assert_eq!(sha256_hex12(combined), "e5627efa2ab1");
    }

    /// The full end-to-end proof: reconstruct a real ClientHello carrying
    /// EXACTLY the cipher list and extension/signature-algorithm lists from
    /// JA4.md's own two worked examples (plus SNI, ALPN=h2, and
    /// supported_versions=TLS1.3, which the doc's headline example
    /// `t13d1516h2_8daaf6152771_e5627efa2ab1` implies but doesn't spell out
    /// as raw bytes), through `compute_ja4`, and assert the result is
    /// byte-for-byte that exact published string. This is the test that
    /// would fail if the wire-parsing (GREASE filtering, sorting, SNI/ALPN
    /// exclusion, extension counting, signature_algorithms ordering) were
    /// subtly wrong even though the bare hash primitive above is right.
    #[test]
    fn the_published_chrome_108_ja4_example_round_trips() {
        let ciphers: [u16; 15] = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        // One GREASE cipher, Chrome-style (first offered, must not change the
        // "15" count digit or the hash).
        let mut cipher_suites = vec![0x0a0a];
        cipher_suites.extend_from_slice(&ciphers);

        // The 14 real extension ids from the JA4_c example, minus 0x000d and
        // 0x002b which get their own dedicated (non-empty-data) extensions
        // below -- still counted/hashed exactly like any other extension.
        let plain_ext_ids: [u16; 12] = [0x0005, 0x000a, 0x000b, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002d, 0x0033, 0x4469, 0xff01];
        let sig_algs: [u16; 8] = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0a0a, &[]); // GREASE extension, must not affect the "16" count
        push_ext(&mut extensions, 0x0000, &sni_ext_data("example.test")); // SNI -> excluded from the hash list, included in the count
        push_ext(&mut extensions, 0x0010, &alpn_ext_data(&["h2"])); // ALPN -> excluded from the hash list, included in the count
        push_ext(&mut extensions, 0x000d, &sig_algs_ext_data(&sig_algs));
        push_ext(&mut extensions, 0x002b, &supported_versions_ext_data(&[0x0a0a, 0x0304])); // GREASE + TLS1.3
        for id in plain_ext_ids {
            push_ext(&mut extensions, id, &[]);
        }

        let hello = build_client_hello(0x0303, &cipher_suites, &extensions);
        assert_eq!(compute_ja4(&hello).as_deref(), Some("t13d1516h2_8daaf6152771_e5627efa2ab1"));
    }

    // ---- Component-level correctness, including the exact discrepancy this
    // module's doc comment calls out against the prose spec. ----

    #[test]
    fn extension_count_includes_sni_and_alpn_unlike_the_hashed_list() {
        // A ClientHello with ONLY SNI + ALPN (no other extensions at all): the
        // count digit must be "02" (both counted), while the hash must be the
        // all-zero sentinel (both excluded from the hashed list, nothing else
        // to hash).
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0000, &sni_ext_data("only.test"));
        push_ext(&mut extensions, 0x0010, &alpn_ext_data(&["h2"]));
        let (count, hash) = extension_fields(&extensions);
        assert_eq!(count, "02", "SNI and ALPN both count toward JA4_a's extension digit");
        assert_eq!(hash, "000000000000", "but neither appears in the JA4_c hashed list");
    }

    #[test]
    fn grease_extensions_are_excluded_from_counts_and_hashes() {
        let with_grease = {
            let mut e = Vec::new();
            push_ext(&mut e, 0x0a0a, &[]);
            push_ext(&mut e, 0x1a1a, &[]);
            push_ext(&mut e, 0xff01, &[]);
            e
        };
        let without_grease = {
            let mut e = Vec::new();
            push_ext(&mut e, 0xff01, &[]);
            e
        };
        assert_eq!(
            extension_fields(&with_grease),
            extension_fields(&without_grease),
            "two GREASE extensions must not change the count or the hash"
        );
    }

    #[test]
    fn grease_ciphers_are_excluded_from_counts_and_hashes() {
        let mut with_grease = Vec::new();
        with_grease.extend_from_slice(&0x0a0au16.to_be_bytes());
        with_grease.extend_from_slice(&0x1a1au16.to_be_bytes());
        with_grease.extend_from_slice(&0x002fu16.to_be_bytes());
        let without_grease = 0x002fu16.to_be_bytes().to_vec();
        assert_eq!(cipher_fields(&with_grease), cipher_fields(&without_grease), "GREASE ciphers must not change the count or the hash");
    }

    #[test]
    fn zero_ciphers_and_zero_extensions_hash_to_the_all_zero_sentinel() {
        assert_eq!(cipher_fields(&[]), ("00".to_string(), "000000000000".to_string()));
        assert_eq!(extension_fields(&[]), ("00".to_string(), "000000000000".to_string()));
    }

    /// A genuinely obscure spec corner, but load-bearing for byte-exact
    /// matching against real JA4 tooling: a NON-EMPTY cipher list that
    /// happens to consist ENTIRELY of GREASE values hashes `sha256("")`
    /// truncated (`"e3b0c44298fc"`), not the `"000000000000"` sentinel --
    /// because the reference implementation's sentinel guard checks the RAW
    /// pre-filter list length (`not x['ciphers']`), not the filtered one. A
    /// ClientHello can never legally do this (TLS requires >=1 real cipher
    /// suite), but this parser sees attacker-controlled bytes, so the
    /// distinction has to be implemented correctly rather than assumed
    /// unreachable.
    #[test]
    fn all_grease_ciphers_hash_the_empty_string_not_the_zero_sentinel() {
        let all_grease: Vec<u8> = [0x0a0au16, 0x1a1a].iter().flat_map(|v| v.to_be_bytes()).collect();
        let (count, hash) = cipher_fields(&all_grease);
        assert_eq!(count, "00");
        assert_eq!(hash, "e3b0c44298fc", "sha256(\"\") truncated -- the RAW list was non-empty, only the filtered one is");
        assert_ne!(hash, "000000000000", "must NOT be confused with the true zero-ciphers sentinel");
    }

    #[test]
    fn version_falls_back_to_the_legacy_field_without_supported_versions() {
        let hello = build_client_hello(0x0303, &[0x00, 0x2f], &[]);
        assert_eq!(compute_ja4(&hello).unwrap().chars().take(3).collect::<String>(), "t12", "TLS1.2 legacy_version, no supported_versions extension");
    }

    #[test]
    fn supported_versions_overrides_the_legacy_field_and_ignores_grease() {
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x002b, &supported_versions_ext_data(&[0xeaea, 0x0303, 0x0304]));
        let hello = build_client_hello(0x0301, &[0x00, 0x2f], &extensions);
        assert_eq!(
            compute_ja4(&hello).unwrap().chars().take(3).collect::<String>(),
            "t13",
            "the highest non-GREASE supported_versions entry (TLS1.3) wins over both GREASE and the legacy field"
        );
    }

    #[test]
    fn supported_versions_present_but_all_grease_falls_back_to_legacy_without_panicking() {
        // The reference script's `versions[-1]` would raise IndexError here --
        // this must instead degrade gracefully to the legacy field, never panic.
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x002b, &supported_versions_ext_data(&[0x0a0a]));
        let hello = build_client_hello(0x0302, &[0x00, 0x2f], &extensions);
        assert_eq!(compute_ja4(&hello).unwrap().chars().take(3).collect::<String>(), "t11");
    }

    #[test]
    fn sni_indicator_reflects_presence() {
        let mut with_sni = Vec::new();
        push_ext(&mut with_sni, 0x0000, &sni_ext_data("host.test"));
        let hello = build_client_hello(0x0303, &[0x00, 0x2f], &with_sni);
        assert_eq!(compute_ja4(&hello).unwrap().chars().nth(3), Some('d'));

        let hello_no_sni = build_client_hello(0x0303, &[0x00, 0x2f], &[]);
        assert_eq!(compute_ja4(&hello_no_sni).unwrap().chars().nth(3), Some('i'));
    }

    #[test]
    fn alpn_code_reflects_length_and_absence_rules() {
        // Exactly-2-char protocol: used verbatim.
        let mut two = Vec::new();
        push_ext(&mut two, 0x0010, &alpn_ext_data(&["h2"]));
        assert_eq!(alpn_code(&two), "h2");

        // Longer than 2 chars: first + last character.
        let mut long = Vec::new();
        push_ext(&mut long, 0x0010, &alpn_ext_data(&["http/1.1"]));
        assert_eq!(alpn_code(&long), "h1");

        // No ALPN extension at all -> the "00" sentinel.
        assert_eq!(alpn_code(&[]), "00");
    }

    #[test]
    fn compute_ja4_rejects_non_clienthello_input_without_panicking() {
        assert_eq!(compute_ja4(b""), None);
        assert_eq!(compute_ja4(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None); // not a handshake record
        assert_eq!(compute_ja4(b"GET / HTTP/1.1\r\n"), None);
    }

    /// The production-critical property: NEVER panic, on any truncation of a
    /// real, well-formed ClientHello -- mirrors `sni.rs`'s own
    /// `parsers_reject_cleanly_rather_than_misroute_on_malformed_input_329`.
    /// This runs on every unauthenticated `:443` connection.
    #[test]
    fn never_panics_on_any_truncation_of_a_well_formed_hello() {
        let sig_algs: [u16; 4] = [0x0403, 0x0804, 0x0401, 0x0503];
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0000, &sni_ext_data("trunc.test"));
        push_ext(&mut extensions, 0x0010, &alpn_ext_data(&["h2", "http/1.1"]));
        push_ext(&mut extensions, 0x000d, &sig_algs_ext_data(&sig_algs));
        push_ext(&mut extensions, 0x002b, &supported_versions_ext_data(&[0x0304]));
        let good = build_client_hello(0x0303, &[0x0a0a, 0x1301, 0x1302, 0xc02f], &extensions);
        for cut in 0..good.len() {
            let _ = compute_ja4(&good[..cut]);
        }
        // And the un-truncated hello parses to something, proving the loop
        // above wasn't vacuously trivial.
        assert!(compute_ja4(&good).is_some());
    }

    /// A JA4 label rendered into `/metrics` embeds up to 2 raw ALPN-derived
    /// characters straight from attacker-controlled bytes (everything else in
    /// the string is hex/digits/`t`/`d`/`i`/`_`, a fixed safe charset). A
    /// malicious ALPN value whose first byte is `"` or `\` must still produce
    /// a value the metrics-rendering escaping (see `observe.rs`) can quote
    /// safely -- this test just pins that such characters DO reach the
    /// fingerprint string unescaped at this layer, so the metrics renderer
    /// cannot skip escaping on the assumption that JA4 output is always a
    /// safe charset.
    #[test]
    fn alpn_derived_characters_can_be_prometheus_unsafe_and_are_passed_through_verbatim() {
        let mut extensions = Vec::new();
        push_ext(&mut extensions, 0x0010, &alpn_ext_data(&["\"quote"]));
        let hello = build_client_hello(0x0303, &[0x00, 0x2f], &extensions);
        let fp = compute_ja4(&hello).expect("parses despite the unusual ALPN value");
        assert!(fp.contains('"'), "the raw quote character reaches the fingerprint string: {fp}");
    }
}

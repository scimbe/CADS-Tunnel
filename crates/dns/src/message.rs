//! Minimal DNS message codec for the ACME DNS-01 responder (#31 FD4 / #23 BP4c).
//!
//! Only what an authoritative `_acme-challenge` responder needs: parse a single
//! question and build a response carrying TXT answers (or an empty NOERROR when
//! there is nothing to serve). Hand-rolled and fully bounds-checked — never
//! panics on malformed input (like the edge's TLS ClientHello parser).

/// DNS TXT record type.
pub const TYPE_TXT: u16 = 16;
/// DNS `IN` class.
pub const CLASS_IN: u16 = 1;

/// A parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction id (echoed in the response).
    pub id: u16,
    /// Lowercased query name (labels joined by `.`), e.g. `_acme-challenge.host`.
    pub name: String,
    /// Query type (16 = TXT).
    pub qtype: u16,
    /// Query class (1 = IN).
    pub qclass: u16,
}

/// Parse the first question from a raw DNS query datagram. Returns `None` on a
/// truncated/malformed packet or a name that uses compression (a query's qname
/// never does). Fully bounds-checked.
pub fn parse_query(buf: &[u8]) -> Option<Query> {
    // Header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2).
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount < 1 {
        return None;
    }
    // Question qname: sequence of length-prefixed labels ending in a 0 length.
    // Folded directly into one pre-reserved, lowercased String (one allocation)
    // instead of a Vec<String> of per-label heap strings joined afterward
    // (N+1 allocations) -- #357, real cost on a high-rate small-query path.
    let mut p = 12usize;
    let mut name = String::with_capacity(buf.len().saturating_sub(p));
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer is illegal in a question qname
        }
        let label = buf.get(p + 1..p + 1 + len)?;
        let label = std::str::from_utf8(label).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.chars().map(|c| c.to_ascii_lowercase()));
        p += 1 + len;
    }
    let qtype = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(p + 2)?, *buf.get(p + 3)?]);
    Some(Query { id, name, qtype, qclass })
}

/// #299: classic DNS-over-UDP payload ceiling (no EDNS0 OPT support here, so no
/// larger advertised buffer to honor) — a response over this must set TC=1 and
/// drop trailing answers rather than emit an oversized datagram a resolver that
/// strictly honors TC never retries over TCP for, or that a plain IP layer
/// fragments/drops outright.
const MAX_UDP_RESPONSE_BYTES: usize = 512;

/// Build an authoritative response for `query`, carrying one TXT answer per entry
/// in `txts` (only for a TXT question; other qtypes get an empty NOERROR). Sets
/// QR + AA and echoes the question. TXT strings longer than 255 bytes are split
/// into DNS character-strings per the wire format.
///
/// #299: if the full answer set would exceed [`MAX_UDP_RESPONSE_BYTES`], only as
/// many whole answers as fit are included, TC (truncation) is set, and ancount
/// reflects the answers actually present — never a partial/corrupt answer record.
pub fn build_response(query: &Query, txts: &[String]) -> Vec<u8> {
    // Encode each answer RR independently first so truncation can drop whole
    // answers by byte budget without ever splitting one mid-record.
    let answer_rrs: Vec<Vec<u8>> = if query.qtype == TYPE_TXT {
        txts.iter()
            .map(|txt| {
                let mut rr = Vec::new();
                rr.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to the question qname
                rr.extend_from_slice(&TYPE_TXT.to_be_bytes());
                rr.extend_from_slice(&CLASS_IN.to_be_bytes());
                rr.extend_from_slice(&60u32.to_be_bytes()); // TTL
                let mut rdata = Vec::new();
                for chunk in txt.as_bytes().chunks(255) {
                    rdata.push(chunk.len() as u8);
                    rdata.extend_from_slice(chunk);
                }
                rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                rr.extend_from_slice(&rdata);
                rr
            })
            .collect()
    } else {
        Vec::new()
    };

    let header_and_question_len = 12 + name_wire_len(&query.name) + 4; // qtype + qclass
    let mut included = 0usize;
    let mut budget = MAX_UDP_RESPONSE_BYTES.saturating_sub(header_and_question_len);
    for rr in &answer_rrs {
        if rr.len() > budget {
            break;
        }
        budget -= rr.len();
        included += 1;
    }
    let truncated = included < answer_rrs.len();

    let mut out = Vec::new();
    out.extend_from_slice(&query.id.to_be_bytes());
    // flags: QR=1, opcode=0, AA=1, TC=truncated, RD=0, RA=0, rcode=0.
    let flags: u16 = if truncated { 0x8600 } else { 0x8400 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&(included as u16).to_be_bytes()); // ancount: answers actually present
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount

    // Question, re-encoded from the parsed name (the qname starts at offset 12).
    encode_name(&mut out, &query.name);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());

    for rr in answer_rrs.into_iter().take(included) {
        out.extend_from_slice(&rr);
    }
    out
}

/// Wire length of `name` as [`encode_name`] would write it: one length byte + the
/// label's bytes per dot-separated label, plus the trailing zero-length root label.
/// `""` (the root/apex) encodes as just the trailing zero byte.
fn name_wire_len(name: &str) -> usize {
    if name.is_empty() {
        return 1;
    }
    name.split('.').map(|label| 1 + label.len()).sum::<usize>() + 1
}

/// Build a DNS query datagram for `name` / `qtype` (RD set, one question).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
    encode_name(&mut b, name);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    b
}

/// Extract the TXT record value(s) from a DNS response, one `String` per TXT
/// answer (multi-part character-strings within one record are concatenated).
/// Fully bounds-checked; returns empty on anything malformed or without TXT.
pub fn parse_txt_answers(buf: &[u8]) -> Vec<String> {
    fn parse(buf: &[u8]) -> Option<Vec<String>> {
        if buf.len() < 12 {
            return None;
        }
        let qd = u16::from_be_bytes([buf[4], buf[5]]);
        let an = u16::from_be_bytes([buf[6], buf[7]]);
        let mut p = 12usize;
        for _ in 0..qd {
            p = skip_name(buf, p)?;
            p += 4; // qtype + qclass
        }
        let mut out = Vec::new();
        for _ in 0..an {
            p = skip_name(buf, p)?;
            let rtype = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]);
            let rdlen = u16::from_be_bytes([*buf.get(p + 8)?, *buf.get(p + 9)?]) as usize;
            let rdata = buf.get(p + 10..p + 10 + rdlen)?;
            if rtype == TYPE_TXT {
                let mut i = 0usize;
                let mut s = String::new();
                while i < rdata.len() {
                    let l = *rdata.get(i)? as usize;
                    s.push_str(std::str::from_utf8(rdata.get(i + 1..i + 1 + l)?).ok()?);
                    i += 1 + l;
                }
                out.push(s);
            }
            p += 10 + rdlen;
        }
        Some(out)
    }
    parse(buf).unwrap_or_default()
}

/// Advance past a DNS name at `p` (labels, or a compression pointer which ends
/// the name in 2 bytes). Returns the offset just after the name.
fn skip_name(buf: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            return Some(p + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(p + 2); // pointer terminates the name
        }
        p += 1 + len;
    }
}

/// Encode a dotted name as length-prefixed labels ending in a zero byte.
fn encode_name(out: &mut Vec<u8>, name: &str) {
    if !name.is_empty() {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw query datagram for `name` / `qtype`.
    fn query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
        encode_name(&mut b, name);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn parse_query_reads_the_question() {
        let q = parse_query(&query_bytes(0x1234, "_acme-challenge.Example.Org", TYPE_TXT)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "_acme-challenge.example.org", "lowercased");
        assert_eq!(q.qtype, TYPE_TXT);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn parse_query_rejects_truncated_and_compressed() {
        assert!(parse_query(b"").is_none());
        assert!(parse_query(&[0u8; 8]).is_none(), "shorter than a header");
        // A compression pointer where the qname must start is rejected.
        let mut b = query_bytes(1, "x.test", TYPE_TXT);
        b[12] = 0xC0;
        assert!(parse_query(&b).is_none());
    }

    #[test]
    fn build_response_carries_the_txt_answer() {
        let q = parse_query(&query_bytes(0xABCD, "_acme-challenge.host.test", TYPE_TXT)).unwrap();
        let resp = build_response(&q, &["token-value-123".to_string()]);
        // Header: echoed id, QR+AA set, one answer.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xABCD);
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(resp[2] & 0x04, 0x04, "AA set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
        // The TXT value appears in the response rdata.
        let needle = b"token-value-123";
        assert!(
            resp.windows(needle.len()).any(|w| w == needle),
            "response contains the TXT value"
        );
        // The answer RR name is a compression pointer to the question (0xC00C).
        assert!(
            resp.windows(2).any(|w| w == [0xC0, 0x0C]),
            "answer name compresses to the question"
        );
    }

    #[test]
    fn build_response_sets_tc_and_drops_trailing_answers_when_the_full_set_exceeds_512_bytes_299() {
        // #299: many/large TXT answers must not produce an oversized UDP datagram with
        // TC=0 -- resolvers that strictly honor TC never retry over TCP for one, and a
        // plain IP layer can fragment/drop it outright, both breaking DNS-01 validation.
        let q = parse_query(&query_bytes(0x1234, "_acme-challenge.host.test", TYPE_TXT)).unwrap();
        // Twenty ~200-byte TXT values -- the full set is far over 512 bytes.
        let txts: Vec<String> = (0..20).map(|i| format!("{i:03}-{}", "x".repeat(200))).collect();
        let resp = build_response(&q, &txts);

        assert!(resp.len() <= MAX_UDP_RESPONSE_BYTES, "response fits the UDP ceiling: {} bytes", resp.len());
        assert_eq!(resp[2] & 0x02, 0x02, "TC bit set");
        let ancount = u16::from_be_bytes([resp[6], resp[7]]);
        assert!((ancount as usize) < txts.len(), "fewer answers than requested were included");
        assert!(ancount > 0, "at least the small early answers still fit and are included");

        // Every included answer is a complete, well-formed record -- parse_txt_answers
        // recovers exactly `ancount` values with no panic/garbage from a split record.
        let parsed = parse_txt_answers(&resp);
        assert_eq!(parsed.len(), ancount as usize, "no partially-written answer snuck in");
    }

    #[test]
    fn build_response_does_not_truncate_when_the_answer_set_fits_299() {
        // The common case (a handful of small TXT values, the actual ACME DNS-01 shape)
        // must be completely unaffected by the truncation logic.
        let q = parse_query(&query_bytes(1, "_acme-challenge.host.test", TYPE_TXT)).unwrap();
        let resp = build_response(&q, &["a-normal-challenge-token".to_string()]);
        assert_eq!(resp[2] & 0x02, 0, "TC bit NOT set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "the one answer is present");
    }

    #[test]
    fn build_query_and_parse_txt_answers_round_trip() {
        // A query built by build_query parses back; a response's TXT answers are
        // recovered by parse_txt_answers (incl. multiple records).
        let raw = build_query(0x55, "_acme-challenge.host.test", TYPE_TXT);
        let q = parse_query(&raw).unwrap();
        assert_eq!(q.name, "_acme-challenge.host.test");
        assert_eq!(q.qtype, TYPE_TXT);

        let resp = build_response(&q, &["tok-a".to_string(), "tok-b".to_string()]);
        assert_eq!(parse_txt_answers(&resp), vec!["tok-a".to_string(), "tok-b".to_string()]);

        // A response with no answers -> empty; malformed -> empty (no panic).
        assert!(parse_txt_answers(&build_response(&q, &[])).is_empty());
        assert!(parse_txt_answers(b"\x00").is_empty());
    }

    #[test]
    fn build_response_is_empty_for_a_non_txt_or_unknown_name() {
        let q = parse_query(&query_bytes(1, "host.test", TYPE_TXT)).unwrap();
        // Unknown name -> NOERROR with zero answers.
        let resp = build_response(&q, &[]);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
        // Non-TXT question -> no answers even if TXT values exist.
        let a = parse_query(&query_bytes(1, "host.test", 1 /* A */)).unwrap();
        let resp = build_response(&a, &["ignored".to_string()]);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "TXT not served for an A query");
    }
}

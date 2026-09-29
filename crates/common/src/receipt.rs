//! #782: signed forensic receipts -- the hash-chained, ed25519-signed record of a
//! tunnel's metadata events an edge emits, and the offline verifier for it.
//!
//! **What a receipt chain proves.** Given the edge's receipts public key, a verified chain
//! proves that *this edge* attested *these metadata events* (session opened, session
//! closed, an hourly byte snapshot) *in this order*, each with the timestamp the edge's
//! own clock read at the time, and that no receipt between the first and the last was
//! removed, reordered, or altered after signing: every receipt carries a SHA-256 over
//! its own content, the previous receipt's hash, and an ed25519 signature over that
//! hash by the edge's dedicated receipts key.
//!
//! **What it does not prove.** Nothing about payload contents: the edge relays
//! ciphertext it cannot read (ADR-0016), so a receipt names byte *volumes*, transports,
//! and close reasons -- never a hostname, request, or source address. Nothing about
//! wall-clock accuracy beyond the edge's own clock: `ts` is what the edge believed the
//! time was. Nothing before the first receipt in hand: an export starting mid-chain
//! (`since=<seq>`, or after retention pruned the head) is verified from its first
//! receipt's `prev_hash` forward, and only a caller holding the preceding export can
//! anchor that link (see [`verify_chain_anchored`]). And nothing about events the edge
//! never observed -- an edge that is down emits nothing, so the *absence* of receipts
//! over an interval is evidence only together with the surrounding receipts' `seq`
//! contiguity, which this verifier does check.
//!
//! The routing token itself never appears in a receipt (it is a bearer credential):
//! `routing_token_hash` is SHA-256 over the raw 32 token bytes, which lets a holder of
//! the token match its own receipts without the receipt disclosing it.
//!
//! **Canonical form.** `hash` is SHA-256 over the canonical JSON of the receipt WITHOUT
//! its `hash` and `sig` fields -- an object with exactly the keys `edge_id`, `kind`,
//! `payload`, `prev_hash`, `routing_token_hash`, `seq`, `ts`. Canonical JSON here means:
//! object keys sorted bytewise ascending at every nesting level, no whitespace, strings
//! and numbers as `serde_json` renders them. [`canonical_json`] implements that sort
//! explicitly rather than relying on `serde_json::Map`'s ordering, so the result does
//! not depend on whether `serde_json`'s `preserve_order` feature is enabled anywhere in
//! the dependency graph -- that feature must nevertheless stay OFF in this workspace,
//! because a payload built with it would carry insertion-ordered keys into an edge's
//! *log line*, and a human diffing the stored text against the canonical form would be
//! misled. Payloads must not contain floating-point numbers (their text form is not
//! canonical across implementations); the edge's payloads are integers and strings only.
//! `sig` is ed25519 over the 32 RAW bytes of `hash` (not its hex text).
//!
//! wasm32-safe: no I/O, no clock, no randomness -- bytes and strings in, results out.
//! Signing (`ReceiptSigner`) needs only `ed25519_dalek::SigningKey::from_bytes`, which
//! has no `rand` dependency; the edge draws the seed itself.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `prev_hash` of the very first receipt an edge ever emits (64 hex zeros).
pub const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// `kind` of the receipt emitted when a session row is opened. Payload:
/// `{"connected_at":<unix secs>,"transport":"quic"|"tcp-fallback"}`.
pub const KIND_SESSION_OPEN: &str = "session_open";
/// `kind` of the receipt emitted when a session row is closed. Payload:
/// `{"bytes_in":n,"bytes_out":n,"connected_at":n,"disconnected_at":n,"reason":"..."}`.
pub const KIND_SESSION_CLOSE: &str = "session_close";
/// `kind` of the hourly byte snapshot for a still-open session (only emitted when the
/// counters moved since the last one). Payload:
/// `{"bytes_in":n,"bytes_out":n,"connected_at":n}` -- cumulative for the session.
pub const KIND_BYTES: &str = "bytes";

/// One signed, chained receipt. The wire/JSONL shape is exactly this struct's serde form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Position in the edge's chain, starting at 1, contiguous.
    pub seq: u64,
    /// The previous receipt's `hash` (hex), or [`GENESIS_PREV_HASH`] for `seq == 1`.
    pub prev_hash: String,
    /// Unix seconds by the edge's clock.
    pub ts: i64,
    /// The emitting edge's `CT_EDGE_ID`.
    pub edge_id: String,
    /// One of the `KIND_*` constants (an unknown kind still verifies -- forward compatible).
    pub kind: String,
    /// SHA-256 (hex) over the raw routing token bytes -- see [`routing_token_hash`].
    pub routing_token_hash: String,
    /// Kind-specific metadata; integers and strings only (module doc).
    pub payload: Value,
    /// SHA-256 (hex) over [`canonical_json`] of the receipt without `hash`/`sig`.
    pub hash: String,
    /// ed25519 signature (hex, 128 chars) over the 32 raw bytes of `hash`.
    pub sig: String,
}

/// The first line of a receipts export (`GET /portal/tunnels/:id/receipts.jsonl`):
/// the key the chain verifies under, the edge that emitted it, and the tunnel's display
/// name -- never its routing token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportHeader {
    /// The edge's receipts public key, 64 hex chars.
    pub pubkey: String,
    pub edge_id: String,
    /// The tunnel's display name (absent in an edge-local export).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
}

/// Why a chain failed to verify. `seq` is the FIRST receipt at which verification
/// failed; every receipt before it verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The supplied public key is not a valid ed25519 point.
    BadPubkey,
    /// A hex field (`prev_hash`, `hash`, `sig`) is malformed at `seq`.
    Malformed { seq: u64, field: &'static str },
    /// The receipt's `hash` does not match the SHA-256 of its canonical content.
    HashMismatch { seq: u64 },
    /// The signature over `hash` does not verify under the public key.
    BadSignature { seq: u64 },
    /// `prev_hash` does not equal the previous receipt's `hash` (or the anchor).
    BrokenLink { seq: u64 },
    /// `seq` is not the previous receipt's `seq + 1` -- a receipt is missing or the
    /// order was changed. `expected` is the seq that should have followed.
    SeqGap { seq: u64, expected: u64 },
    /// The receipt names a different `edge_id` than the first one in the chain.
    EdgeIdMismatch { seq: u64 },
}

impl VerifyError {
    /// The seq of the first failing receipt, `None` for a key problem.
    pub fn seq(&self) -> Option<u64> {
        match self {
            VerifyError::BadPubkey => None,
            VerifyError::Malformed { seq, .. }
            | VerifyError::HashMismatch { seq }
            | VerifyError::BadSignature { seq }
            | VerifyError::BrokenLink { seq }
            | VerifyError::SeqGap { seq, .. }
            | VerifyError::EdgeIdMismatch { seq } => Some(*seq),
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadPubkey => write!(f, "public key is not a valid ed25519 key"),
            VerifyError::Malformed { seq, field } => write!(f, "receipt seq {seq}: malformed field `{field}`"),
            VerifyError::HashMismatch { seq } => write!(f, "receipt seq {seq}: hash does not match its content"),
            VerifyError::BadSignature { seq } => write!(f, "receipt seq {seq}: signature does not verify"),
            VerifyError::BrokenLink { seq } => {
                write!(f, "receipt seq {seq}: prev_hash does not link to the previous receipt")
            }
            VerifyError::SeqGap { seq, expected } => {
                write!(f, "receipt seq {seq}: expected seq {expected} (a receipt is missing or out of order)")
            }
            VerifyError::EdgeIdMismatch { seq } => write!(f, "receipt seq {seq}: edge_id differs from the chain's"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// What a verified chain attests, aggregated for a human summary.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedSummary {
    /// Receipts verified (0 for an empty input, which is `Ok`).
    pub count: usize,
    /// `edge_id` shared by every receipt (`None` when empty).
    pub edge_id: Option<String>,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    /// The first receipt's `prev_hash` -- what a preceding export's `last_hash` must
    /// equal for the two to chain.
    pub first_prev_hash: Option<String>,
    /// The last receipt's `hash` -- the anchor for the next export.
    pub last_hash: Option<String>,
    /// Whether the chain starts at the edge's genesis (`seq == 1`, zero `prev_hash`).
    pub from_genesis: bool,
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    /// Summed from `session_close` payloads (final per-session totals), so `bytes`
    /// snapshots are not double-counted.
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Verify `receipts` (ascending, contiguous) under `pubkey`. The first receipt's
/// `prev_hash` must be [`GENESIS_PREV_HASH`] when its `seq` is 1; otherwise it is
/// accepted as given (the export starts mid-chain) and reported in
/// [`VerifiedSummary::first_prev_hash`]. See [`verify_chain_anchored`] to pin it.
/// An empty slice is `Ok` with a zero summary.
pub fn verify_chain(receipts: &[Receipt], pubkey: &[u8; 32]) -> Result<VerifiedSummary, VerifyError> {
    verify_chain_anchored(receipts, pubkey, None)
}

/// [`verify_chain`] with the first receipt's `prev_hash` required to equal `anchor`
/// (hex) -- the previous export's `last_hash`, or [`GENESIS_PREV_HASH`] to insist the
/// chain starts at the edge's genesis. `None` behaves exactly like [`verify_chain`].
pub fn verify_chain_anchored(
    receipts: &[Receipt],
    pubkey: &[u8; 32],
    anchor: Option<&str>,
) -> Result<VerifiedSummary, VerifyError> {
    let key = VerifyingKey::from_bytes(pubkey).map_err(|_| VerifyError::BadPubkey)?;
    let mut summary = VerifiedSummary::default();
    let mut prev: Option<(u64, String)> = None;
    for r in receipts {
        let seq = r.seq;
        if hex_decode(&r.prev_hash).filter(|b| b.len() == 32).is_none() {
            return Err(VerifyError::Malformed { seq, field: "prev_hash" });
        }
        let Some(hash_bytes) = hex_decode(&r.hash).filter(|b| b.len() == 32) else {
            return Err(VerifyError::Malformed { seq, field: "hash" });
        };
        let Some(sig_bytes) = hex_decode(&r.sig).filter(|b| b.len() == 64) else {
            return Err(VerifyError::Malformed { seq, field: "sig" });
        };
        // Linkage first: a broken chain is the more specific finding than a receipt
        // whose own hash still checks out.
        match &prev {
            Some((prev_seq, prev_hash)) => {
                let expected = prev_seq.wrapping_add(1);
                if seq != expected {
                    return Err(VerifyError::SeqGap { seq, expected });
                }
                if r.prev_hash != *prev_hash {
                    return Err(VerifyError::BrokenLink { seq });
                }
                if summary.edge_id.as_deref() != Some(r.edge_id.as_str()) {
                    return Err(VerifyError::EdgeIdMismatch { seq });
                }
            }
            None => {
                let required = match anchor {
                    Some(a) => Some(a),
                    None if seq == 1 => Some(GENESIS_PREV_HASH),
                    None => None,
                };
                if let Some(required) = required {
                    if !r.prev_hash.eq_ignore_ascii_case(required) {
                        return Err(VerifyError::BrokenLink { seq });
                    }
                }
                summary.edge_id = Some(r.edge_id.clone());
                summary.first_seq = Some(seq);
                summary.first_ts = Some(r.ts);
                summary.first_prev_hash = Some(r.prev_hash.clone());
                summary.from_genesis = seq == 1 && r.prev_hash.eq_ignore_ascii_case(GENESIS_PREV_HASH);
            }
        }
        if content_hash(r) != hash_bytes.as_slice() {
            return Err(VerifyError::HashMismatch { seq });
        }
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::Malformed { seq, field: "sig" })?;
        if key.verify(&hash_bytes, &sig).is_err() {
            return Err(VerifyError::BadSignature { seq });
        }
        tally(&mut summary, r);
        summary.count += 1;
        summary.last_seq = Some(seq);
        summary.last_ts = Some(r.ts);
        summary.last_hash = Some(r.hash.clone());
        prev = Some((seq, r.hash.clone()));
    }
    Ok(summary)
}

fn tally(summary: &mut VerifiedSummary, r: &Receipt) {
    match r.kind.as_str() {
        KIND_SESSION_OPEN => summary.sessions_opened += 1,
        KIND_SESSION_CLOSE => {
            summary.sessions_closed += 1;
            summary.bytes_in = summary.bytes_in.saturating_add(payload_u64(&r.payload, "bytes_in"));
            summary.bytes_out = summary.bytes_out.saturating_add(payload_u64(&r.payload, "bytes_out"));
        }
        _ => {}
    }
}

fn payload_u64(payload: &Value, key: &str) -> u64 {
    payload.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// Signs receipts for one edge. Holds the ed25519 key derived from the edge's 32-byte
/// receipts seed (`edge-receipts-key.bin`); the seed never leaves the edge.
pub struct ReceiptSigner {
    key: SigningKey,
    edge_id: String,
}

impl ReceiptSigner {
    /// Build the signer from a 32-byte ed25519 seed (as persisted by the edge).
    pub fn from_seed(seed: &[u8; 32], edge_id: impl Into<String>) -> Self {
        Self { key: SigningKey::from_bytes(seed), edge_id: edge_id.into() }
    }

    pub fn edge_id(&self) -> &str {
        &self.edge_id
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The public key as 64 lowercase hex chars -- what `GET /internal/receipts/pubkey`
    /// publishes and what an export header carries.
    pub fn pubkey_hex(&self) -> String {
        hex_encode(&self.pubkey_bytes())
    }

    /// Produce receipt `seq` linking to `prev_hash` (hex): canonicalize, hash, sign.
    pub fn sign(
        &self,
        seq: u64,
        prev_hash: &str,
        ts: i64,
        kind: &str,
        routing_token_hash: &str,
        payload: Value,
    ) -> Receipt {
        let mut r = Receipt {
            seq,
            prev_hash: prev_hash.to_string(),
            ts,
            edge_id: self.edge_id.clone(),
            kind: kind.to_string(),
            routing_token_hash: routing_token_hash.to_string(),
            payload,
            hash: String::new(),
            sig: String::new(),
        };
        let hash = content_hash(&r);
        r.sig = hex_encode(&self.key.sign(&hash).to_bytes());
        r.hash = hex_encode(&hash);
        r
    }
}

impl std::fmt::Debug for ReceiptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptSigner")
            .field("edge_id", &self.edge_id)
            .field("pubkey", &self.pubkey_hex())
            .finish()
    }
}

/// SHA-256 (hex) over the raw routing token bytes -- the only form of the token a
/// receipt ever carries.
pub fn routing_token_hash(token: &[u8]) -> String {
    hex_encode(&Sha256::digest(token))
}

/// SHA-256 over [`canonical_json`] of `r` without `hash`/`sig`.
pub fn content_hash(r: &Receipt) -> [u8; 32] {
    let mut obj = serde_json::Map::new();
    obj.insert("edge_id".into(), Value::String(r.edge_id.clone()));
    obj.insert("kind".into(), Value::String(r.kind.clone()));
    obj.insert("payload".into(), r.payload.clone());
    obj.insert("prev_hash".into(), Value::String(r.prev_hash.clone()));
    obj.insert("routing_token_hash".into(), Value::String(r.routing_token_hash.clone()));
    obj.insert("seq".into(), Value::from(r.seq));
    obj.insert("ts".into(), Value::from(r.ts));
    Sha256::digest(canonical_json(&Value::Object(obj)).as_bytes()).into()
}

/// Canonical JSON text of `v`: object keys sorted bytewise at every level, no
/// whitespace, scalars as `serde_json` renders them (module doc).
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // A key is a JSON string; `to_string` on a `Value::String` escapes it.
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // `Value::to_string` for scalars is already whitespace-free and deterministic.
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// A parsed `.jsonl` export: the header line plus every receipt line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExport {
    pub header: ExportHeader,
    pub receipts: Vec<Receipt>,
}

/// Why an export file could not be parsed. `line` is 1-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    BadHeader(String),
    BadReceipt { line: usize, error: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty export: no header line"),
            ParseError::BadHeader(e) => write!(f, "line 1: not a receipts export header ({e})"),
            ParseError::BadReceipt { line, error } => write!(f, "line {line}: not a receipt ({error})"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse an export as written by the control plane: one JSON object per line, the
/// first being an [`ExportHeader`], each following one a [`Receipt`]. Blank lines are
/// skipped.
pub fn parse_jsonl(text: &str) -> Result<ParsedExport, ParseError> {
    let mut lines = text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty());
    let (_, header_line) = lines.next().ok_or(ParseError::Empty)?;
    let header: ExportHeader = serde_json::from_str(header_line).map_err(|e| ParseError::BadHeader(e.to_string()))?;
    let mut receipts = Vec::new();
    for (idx, line) in lines {
        let r: Receipt =
            serde_json::from_str(line).map_err(|e| ParseError::BadReceipt { line: idx + 1, error: e.to_string() })?;
        receipts.push(r);
    }
    Ok(ParsedExport { header, receipts })
}

/// Render an export: the header line, then one receipt per line, `\n`-terminated.
pub fn to_jsonl(header: &ExportHeader, receipts: &[Receipt]) -> String {
    let mut out = serde_json::to_string(header).unwrap_or_default();
    out.push('\n');
    for r in receipts {
        out.push_str(&serde_json::to_string(r).unwrap_or_default());
        out.push('\n');
    }
    out
}

/// Decode a 64-hex public key.
pub fn pubkey_from_hex(s: &str) -> Option<[u8; 32]> {
    hex_decode(s.trim()).and_then(|b| b.try_into().ok())
}

pub use crate::hex::encode as hex_encode;

/// Same hazard as `channel.rs::from_hex` (#417): check every byte is an ASCII hex digit
/// before slicing, so a multi-byte char can never land a slice mid-character.
pub use crate::hex::decode as hex_decode;

/// Fixtures for dependents' tests (`ct-agent-tools`'s `verify_receipts` bin): a small
/// deterministic chain from a fixed seed. Enabled by the `test-support` feature on a
/// dev-dependency, never in a production build.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    /// The fixed seed every fixture signs with.
    pub const SEED: [u8; 32] = [0x42u8; 32];
    pub const EDGE_ID: &str = "edge-test";

    /// A signer over [`SEED`].
    pub fn signer() -> ReceiptSigner {
        ReceiptSigner::from_seed(&SEED, EDGE_ID)
    }

    /// A five-receipt chain from genesis for one token: open, bytes, close, open, close.
    pub fn sample_chain() -> Vec<Receipt> {
        let s = signer();
        let tok = routing_token_hash(&[0x7au8; 32]);
        let mut out: Vec<Receipt> = Vec::new();
        let mut prev = GENESIS_PREV_HASH.to_string();
        let events: [(&str, i64, Value); 5] = [
            (KIND_SESSION_OPEN, 1_000, serde_json::json!({ "connected_at": 1_000, "transport": "quic" })),
            (KIND_BYTES, 4_600, serde_json::json!({ "bytes_in": 100, "bytes_out": 40, "connected_at": 1_000 })),
            (
                KIND_SESSION_CLOSE,
                5_000,
                serde_json::json!({
                    "bytes_in": 150, "bytes_out": 60, "connected_at": 1_000, "disconnected_at": 5_000,
                    "reason": "registration-closed"
                }),
            ),
            (KIND_SESSION_OPEN, 6_000, serde_json::json!({ "connected_at": 6_000, "transport": "tcp-fallback" })),
            (
                KIND_SESSION_CLOSE,
                6_500,
                serde_json::json!({
                    "bytes_in": 5, "bytes_out": 7, "connected_at": 6_000, "disconnected_at": 6_500,
                    "reason": "removed"
                }),
            ),
        ];
        for (i, (kind, ts, payload)) in events.into_iter().enumerate() {
            let r = s.sign(i as u64 + 1, &prev, ts, kind, &tok, payload);
            prev = r.hash.clone();
            out.push(r);
        }
        out
    }

    /// [`sample_chain`] rendered as an export with a header naming the tunnel `demo`.
    pub fn sample_jsonl() -> String {
        let header =
            ExportHeader { pubkey: signer().pubkey_hex(), edge_id: EDGE_ID.into(), tunnel: Some("demo".into()) };
        to_jsonl(&header, &sample_chain())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{sample_chain, sample_jsonl, signer, EDGE_ID};
    use super::*;

    fn pubkey() -> [u8; 32] {
        signer().pubkey_bytes()
    }

    #[test]
    fn a_valid_chain_verifies_and_the_summary_tallies_sessions_and_bytes() {
        let chain = sample_chain();
        let s = verify_chain(&chain, &pubkey()).expect("valid chain");
        assert_eq!(s.count, 5);
        assert_eq!(s.edge_id.as_deref(), Some(EDGE_ID));
        assert_eq!((s.first_seq, s.last_seq), (Some(1), Some(5)));
        assert_eq!((s.first_ts, s.last_ts), (Some(1_000), Some(6_500)));
        assert!(s.from_genesis);
        assert_eq!(s.first_prev_hash.as_deref(), Some(GENESIS_PREV_HASH));
        assert_eq!(s.last_hash.as_deref(), Some(chain[4].hash.as_str()));
        assert_eq!((s.sessions_opened, s.sessions_closed), (2, 2));
        // Bytes come from the CLOSE receipts' final totals, not the hourly snapshot.
        assert_eq!((s.bytes_in, s.bytes_out), (155, 67));
    }

    #[test]
    fn an_empty_chain_is_ok_with_a_zero_summary() {
        let s = verify_chain(&[], &pubkey()).unwrap();
        assert_eq!(s, VerifiedSummary::default());
    }

    #[test]
    fn a_tampered_payload_is_a_hash_mismatch_at_that_seq() {
        let mut chain = sample_chain();
        chain[2].payload["bytes_in"] = Value::from(999_999u64);
        let e = verify_chain(&chain, &pubkey()).unwrap_err();
        assert_eq!(e, VerifyError::HashMismatch { seq: 3 });
        assert_eq!(e.seq(), Some(3));
    }

    #[test]
    fn a_tampered_signature_is_a_signature_failure_at_that_seq() {
        let mut chain = sample_chain();
        // Flip one byte of the signature; hash and content still agree.
        let mut sig = hex_decode(&chain[1].sig).unwrap();
        sig[10] ^= 0x01;
        chain[1].sig = hex_encode(&sig);
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::BadSignature { seq: 2 });

        // A receipt re-hashed and "signed" by someone else: hash matches, signature does not.
        let other = ReceiptSigner::from_seed(&[0x99u8; 32], EDGE_ID);
        let chain = sample_chain();
        let forged = other.sign(
            chain[0].seq,
            &chain[0].prev_hash,
            chain[0].ts,
            &chain[0].kind,
            &chain[0].routing_token_hash,
            chain[0].payload.clone(),
        );
        assert_eq!(forged.hash, chain[0].hash, "same content -> same hash");
        let mut chain = chain;
        chain[0] = forged;
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::BadSignature { seq: 1 });
    }

    #[test]
    fn broken_linkage_a_gap_and_a_bad_genesis_are_link_failures_at_the_right_seq() {
        // A removed middle receipt: seq 3 follows seq 1.
        let mut chain = sample_chain();
        chain.remove(1);
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::SeqGap { seq: 3, expected: 2 });

        // A replaced middle receipt with a consistent seq but the wrong prev_hash: the
        // forger re-signs seq 2 under the real key... which they don't have -- so use the
        // real signer to model an edge that skipped a link.
        let s = signer();
        let mut chain = sample_chain();
        let wrong_prev = hex_encode(&[0xeeu8; 32]);
        let r = &chain[1];
        chain[1] = s.sign(2, &wrong_prev, r.ts, &r.kind, &r.routing_token_hash, r.payload.clone());
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::BrokenLink { seq: 2 });

        // seq 1 must start from the zero hash.
        let mut chain = sample_chain();
        let r = &chain[0];
        chain[0] = s.sign(1, &wrong_prev, r.ts, &r.kind, &r.routing_token_hash, r.payload.clone());
        assert_eq!(verify_chain(&chain[..1], &pubkey()).unwrap_err(), VerifyError::BrokenLink { seq: 1 });
    }

    #[test]
    fn a_mid_chain_export_verifies_from_its_first_prev_hash_and_can_be_anchored() {
        let chain = sample_chain();
        let tail = &chain[2..];
        let s = verify_chain(tail, &pubkey()).expect("a tail export is fine without an anchor");
        assert!(!s.from_genesis);
        assert_eq!(s.first_seq, Some(3));
        assert_eq!(s.first_prev_hash.as_deref(), Some(chain[1].hash.as_str()));
        // Anchored to the preceding export's last hash: ok; to anything else: broken link.
        assert!(verify_chain_anchored(tail, &pubkey(), Some(&chain[1].hash)).is_ok());
        assert_eq!(
            verify_chain_anchored(tail, &pubkey(), Some(GENESIS_PREV_HASH)).unwrap_err(),
            VerifyError::BrokenLink { seq: 3 }
        );
    }

    #[test]
    fn a_wrong_key_fails_at_seq_1_and_a_malformed_key_is_bad_pubkey() {
        let chain = sample_chain();
        let other = ReceiptSigner::from_seed(&[0x01u8; 32], EDGE_ID).pubkey_bytes();
        assert_eq!(verify_chain(&chain, &other).unwrap_err(), VerifyError::BadSignature { seq: 1 });
        // Not every 32-byte string is a valid compressed Edwards point.
        let bad = [0xffu8; 32];
        assert!(matches!(
            verify_chain(&chain, &bad),
            Err(VerifyError::BadPubkey) | Err(VerifyError::BadSignature { seq: 1 })
        ));
    }

    #[test]
    fn malformed_hex_fields_and_a_foreign_edge_id_are_reported_at_their_seq() {
        let mut chain = sample_chain();
        chain[3].sig = "zz".repeat(64);
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::Malformed { seq: 4, field: "sig" });
        let mut chain = sample_chain();
        chain[0].hash.truncate(10);
        assert_eq!(verify_chain(&chain, &pubkey()).unwrap_err(), VerifyError::Malformed { seq: 1, field: "hash" });
        let s = signer();
        let foreign = ReceiptSigner::from_seed(&test_support::SEED, "other-edge");
        let mut chain = sample_chain();
        let (prev, r) = (chain[3].hash.clone(), chain[4].clone());
        chain[4] = foreign.sign(5, &prev, r.ts, &r.kind, &r.routing_token_hash, r.payload);
        assert_eq!(verify_chain(&chain, &s.pubkey_bytes()).unwrap_err(), VerifyError::EdgeIdMismatch { seq: 5 });
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level_and_is_whitespace_free() {
        let v = serde_json::json!({ "z": 1, "a": { "y": [1, { "b": "x", "a": null }], "b": "q\"uote" }, "m": true });
        assert_eq!(canonical_json(&v), r#"{"a":{"b":"q\"uote","y":[1,{"a":null,"b":"x"}]},"m":true,"z":1}"#);
        // Parsing the canonical text back and re-canonicalizing is a fixed point.
        let back: Value = serde_json::from_str(&canonical_json(&v)).unwrap();
        assert_eq!(canonical_json(&back), canonical_json(&v));
    }

    #[test]
    fn the_hash_covers_exactly_the_documented_fields_and_the_signature_is_over_raw_hash_bytes() {
        let r = &sample_chain()[0];
        let expected_text = format!(
            r#"{{"edge_id":"{EDGE_ID}","kind":"session_open","payload":{{"connected_at":1000,"transport":"quic"}},"#
        ) + &format!(
            r#""prev_hash":"{GENESIS_PREV_HASH}","routing_token_hash":"{}","seq":1,"ts":1000}}"#,
            r.routing_token_hash
        );
        assert_eq!(hex_encode(&Sha256::digest(expected_text.as_bytes())), r.hash);
        let key = VerifyingKey::from_bytes(&pubkey()).unwrap();
        let sig = Signature::from_slice(&hex_decode(&r.sig).unwrap()).unwrap();
        assert!(key.verify(&hex_decode(&r.hash).unwrap(), &sig).is_ok(), "signature is over the raw hash bytes");
        assert!(key.verify(r.hash.as_bytes(), &sig).is_err(), "...not over the hex text");
        // A wire round trip (serde) preserves everything the hash covers.
        let json = serde_json::to_string(r).unwrap();
        let back: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
        assert_eq!(hex_encode(&content_hash(&back)), r.hash);
    }

    #[test]
    fn routing_token_hash_is_sha256_of_the_raw_bytes_and_the_pubkey_hex_round_trips() {
        assert_eq!(routing_token_hash(&[0u8; 32]), hex_encode(&Sha256::digest([0u8; 32])));
        assert_eq!(routing_token_hash(&[0u8; 32]).len(), 64);
        let s = signer();
        assert_eq!(pubkey_from_hex(&s.pubkey_hex()), Some(s.pubkey_bytes()));
        assert_eq!(pubkey_from_hex("nope"), None);
        assert_eq!(pubkey_from_hex(&"ab".repeat(31)), None, "wrong length");
        // Same seed -> same key, stably.
        assert_eq!(ReceiptSigner::from_seed(&test_support::SEED, "x").pubkey_hex(), s.pubkey_hex());
    }

    #[test]
    fn jsonl_export_round_trips_and_parse_reports_the_bad_line() {
        let text = sample_jsonl();
        let parsed = parse_jsonl(&text).unwrap();
        assert_eq!(parsed.header.tunnel.as_deref(), Some("demo"));
        assert_eq!(parsed.header.pubkey, signer().pubkey_hex());
        assert_eq!(parsed.receipts, sample_chain());
        assert_eq!(text.lines().count(), 6, "header + 5 receipts");
        assert!(verify_chain(&parsed.receipts, &pubkey_from_hex(&parsed.header.pubkey).unwrap()).is_ok());

        assert_eq!(parse_jsonl("").unwrap_err(), ParseError::Empty);
        assert!(matches!(parse_jsonl("{\"nope\":1}\n").unwrap_err(), ParseError::BadHeader(_)));
        let mut lines: Vec<&str> = text.lines().collect();
        lines[3] = "{\"seq\":3}";
        let broken = lines.join("\n");
        assert!(matches!(parse_jsonl(&broken).unwrap_err(), ParseError::BadReceipt { line: 4, .. }));
        // Blank lines are tolerated.
        let spaced = text.replace('\n', "\n\n");
        assert_eq!(parse_jsonl(&spaced).unwrap().receipts.len(), 5);
    }
}

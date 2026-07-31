//! Proof-of-work gating (ADR-0018).
//!
//! Expensive Edge operations (rendezvous, relay-slot allocation) are gated
//! behind a small proof-of-work so floods and sybil creation carry a cost
//! without KYC. The Edge issues a Challenge; the Client solves it; the Edge
//! verifies cheaply. P4.1 is the primitive.

use crate::RoutingToken;
use sha2::{Digest, Sha256};

/// A proof-of-work challenge: find a `solution` such that
/// `SHA-256(nonce || token || solution)` has at least `difficulty` leading zero bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 16],
    pub difficulty: u8,
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// #251: `token` is folded into the hash — see [`verify`] for why.
fn hash(nonce: &[u8; 16], token: &RoutingToken, solution: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(token.0);
    hasher.update(solution.to_le_bytes());
    hasher.finalize().into()
}

/// Verify that `solution` satisfies `challenge` **for `token`**. Cheap — a single hash.
///
/// #251: `token` is part of the hashed preimage (not just appended on the wire after PoW is
/// checked separately) — previously the PoW hash covered only `nonce || solution`, so a single
/// solved `(challenge, solution)` pair verified for ANY token, not just the one it was solved
/// for. If the edge ever issues the same challenge nonce more than once (or an attacker can
/// observe/predict one), that let a single ~2^difficulty solve be replayed across many distinct
/// tokens, collapsing the per-token flood/sybil cost ADR-0018 exists to guarantee. Binding the
/// token into the hash makes a solve valid for exactly the token it was computed against,
/// regardless of the edge's own nonce-issuance lifecycle — defense in depth, not reliant on
/// nonces never repeating.
pub fn verify(challenge: &Challenge, token: &RoutingToken, solution: u64) -> bool {
    leading_zero_bits(&hash(&challenge.nonce, token, solution)) >= challenge.difficulty as u32
}

/// Solve `challenge` for `token` by brute force. Expected cost grows ~2^difficulty.
pub fn solve(challenge: &Challenge, token: &RoutingToken) -> u64 {
    let mut solution = 0u64;
    loop {
        if verify(challenge, token, solution) {
            return solution;
        }
        solution += 1;
    }
}

/// Why a gated rendezvous request was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum GateError {
    Malformed,
    BadProofOfWork,
}

/// Assemble the PoW-gated rendezvous request wire form from an already-computed
/// `solution` and `token`: `solution(8 LE) | token(32)` = 40 bytes. Split out from
/// [`build_request`] so an async caller can offload the CPU-bound [`solve`] to a
/// blocking thread (#202) and then assemble here — the single source of truth for the
/// wire layout, so the sync and offloaded paths cannot drift.
pub fn assemble_request(solution: u64, token: &RoutingToken) -> Vec<u8> {
    let mut req = Vec::with_capacity(40);
    req.extend_from_slice(&solution.to_le_bytes());
    req.extend_from_slice(&token.0);
    req
}

/// Build a PoW-gated rendezvous request for `token` by solving `challenge`.
/// Wire form: `solution(8 LE) | token(32)`. Synchronous — CPU-bound; async callers on a
/// Tokio runtime should offload the solve via `tokio::task::spawn_blocking` (#202) rather
/// than calling this inline (see `ct_client`'s `build_request_blocking`).
pub fn build_request(challenge: &Challenge, token: &RoutingToken) -> Vec<u8> {
    assemble_request(solve(challenge, token), token)
}

/// Verify a PoW-gated rendezvous request against `challenge` and extract the
/// Routing Token. Rejects malformed requests and insufficient proof of work.
///
/// #251: the token is extracted from the wire form FIRST so it can be included in the PoW
/// hash check — a solution is only valid for the exact token it accompanies.
pub fn check_request(challenge: &Challenge, request: &[u8]) -> Result<RoutingToken, GateError> {
    if request.len() != 40 {
        return Err(GateError::Malformed);
    }
    let solution = u64::from_le_bytes(request[..8].try_into().unwrap());
    let mut token = [0u8; 32];
    token.copy_from_slice(&request[8..40]);
    let token = RoutingToken(token);
    if !verify(challenge, &token, solution) {
        return Err(GateError::BadProofOfWork);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(difficulty: u8) -> Challenge {
        Challenge {
            nonce: [0xAB; 16],
            difficulty,
        }
    }

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn solve_then_verify() {
        let c = challenge(12);
        let t = token(1);
        let s = solve(&c, &t);
        assert!(verify(&c, &t, s));
    }

    #[test]
    fn solution_meets_difficulty() {
        let c = challenge(12);
        let t = token(1);
        let s = solve(&c, &t);
        assert!(leading_zero_bits(&hash(&c.nonce, &t, s)) >= 12);
    }

    #[test]
    fn zero_difficulty_always_valid() {
        assert!(verify(&challenge(0), &token(1), 0));
    }

    #[test]
    fn verify_rejects_insufficient_bits() {
        // Solve an easy challenge, then demand one more leading-zero bit than
        // this solution actually provides — it must be rejected. Deterministic.
        let c = challenge(4);
        let t = token(1);
        let s = solve(&c, &t);
        let actual = leading_zero_bits(&hash(&c.nonce, &t, s));
        let harder = Challenge {
            nonce: c.nonce,
            difficulty: (actual + 1) as u8,
        };
        assert!(!verify(&harder, &t, s));
    }

    #[test]
    fn a_solution_for_one_token_does_not_verify_for_another() {
        // #251: this is the exact vulnerability — before binding the token into the hash, a
        // single solved (challenge, solution) verified for ANY token, collapsing the per-token
        // flood/sybil cost ADR-0018 exists to guarantee. Reusing the same challenge/solution
        // against a different token must now fail.
        let c = challenge(12);
        let a = token(0xAA);
        let b = token(0xBB);
        let s = solve(&c, &a);
        assert!(verify(&c, &a, s), "solution verifies for the token it was solved against");
        assert!(!verify(&c, &b, s), "the same solution must not verify for a different token");
    }

    #[test]
    fn check_request_rejects_a_solution_replayed_onto_a_different_token_in_the_wire_form() {
        // The end-to-end version of the above: solve+assemble for token A, then splice in
        // token B's bytes before check_request — must be rejected, not silently admitted.
        let c = challenge(12);
        let a = token(0xAA);
        let b = token(0xBB);
        let mut req = build_request(&c, &a);
        req[8..40].copy_from_slice(&b.0);
        assert_eq!(check_request(&c, &req), Err(GateError::BadProofOfWork));
    }

    #[test]
    fn build_then_check_roundtrips() {
        let c = challenge(12);
        let token = RoutingToken([3u8; 32]);
        let req = build_request(&c, &token);
        assert_eq!(check_request(&c, &req), Ok(token));
    }

    #[test]
    fn check_rejects_malformed_length() {
        assert_eq!(check_request(&challenge(8), &[0u8; 10]), Err(GateError::Malformed));
    }

    #[test]
    fn check_rejects_insufficient_pow() {
        // Solve at difficulty 4, then check against a challenge demanding more
        // bits than that solution provides — deterministically rejected.
        let easy = challenge(4);
        let token = RoutingToken([4u8; 32]);
        let req = build_request(&easy, &token);
        let solution = u64::from_le_bytes(req[..8].try_into().unwrap());
        let actual = leading_zero_bits(&hash(&easy.nonce, &token, solution));
        let harder = Challenge {
            nonce: easy.nonce,
            difficulty: (actual + 1) as u8,
        };
        assert_eq!(check_request(&harder, &req), Err(GateError::BadProofOfWork));
    }
}

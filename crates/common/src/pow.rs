//! Proof-of-work gating (ADR-0018).
//!
//! Expensive Edge operations (rendezvous, relay-slot allocation) are gated
//! behind a small proof-of-work so floods and sybil creation carry a cost
//! without KYC. The Edge issues a Challenge; the Client solves it; the Edge
//! verifies cheaply. P4.1 is the primitive.

use crate::RoutingToken;
use sha2::{Digest, Sha256};

/// A proof-of-work challenge: find a `solution` such that
/// `SHA-256(nonce || solution)` has at least `difficulty` leading zero bits.
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

fn hash(nonce: &[u8; 16], solution: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(solution.to_le_bytes());
    hasher.finalize().into()
}

/// Verify that `solution` satisfies `challenge`. Cheap — a single hash.
pub fn verify(challenge: &Challenge, solution: u64) -> bool {
    leading_zero_bits(&hash(&challenge.nonce, solution)) >= challenge.difficulty as u32
}

/// Solve `challenge` by brute force. Expected cost grows ~2^difficulty.
pub fn solve(challenge: &Challenge) -> u64 {
    let mut solution = 0u64;
    loop {
        if verify(challenge, solution) {
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
    assemble_request(solve(challenge), token)
}

/// Verify a PoW-gated rendezvous request against `challenge` and extract the
/// Routing Token. Rejects malformed requests and insufficient proof of work.
pub fn check_request(challenge: &Challenge, request: &[u8]) -> Result<RoutingToken, GateError> {
    if request.len() != 40 {
        return Err(GateError::Malformed);
    }
    let solution = u64::from_le_bytes(request[..8].try_into().unwrap());
    if !verify(challenge, solution) {
        return Err(GateError::BadProofOfWork);
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&request[8..40]);
    Ok(RoutingToken(token))
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

    #[test]
    fn solve_then_verify() {
        let c = challenge(12);
        let s = solve(&c);
        assert!(verify(&c, s));
    }

    #[test]
    fn solution_meets_difficulty() {
        let c = challenge(12);
        let s = solve(&c);
        assert!(leading_zero_bits(&hash(&c.nonce, s)) >= 12);
    }

    #[test]
    fn zero_difficulty_always_valid() {
        assert!(verify(&challenge(0), 0));
    }

    #[test]
    fn verify_rejects_insufficient_bits() {
        // Solve an easy challenge, then demand one more leading-zero bit than
        // this solution actually provides — it must be rejected. Deterministic.
        let c = challenge(4);
        let s = solve(&c);
        let actual = leading_zero_bits(&hash(&c.nonce, s));
        let harder = Challenge {
            nonce: c.nonce,
            difficulty: (actual + 1) as u8,
        };
        assert!(!verify(&harder, s));
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
        let actual = leading_zero_bits(&hash(&easy.nonce, solution));
        let harder = Challenge {
            nonce: easy.nonce,
            difficulty: (actual + 1) as u8,
        };
        assert_eq!(check_request(&harder, &req), Err(GateError::BadProofOfWork));
    }
}

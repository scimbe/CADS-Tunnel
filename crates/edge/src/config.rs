//! Edge daemon configuration (M5.1a).
//!
//! Parsed from environment variables so the Edge runs as a configurable
//! container node in the Docker testbed.

use std::net::SocketAddr;

/// Runtime configuration for the Edge daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeConfig {
    /// UDP/TCP address to listen on (e.g. `0.0.0.0:4433`).
    pub listen: SocketAddr,
    /// Proof-of-work difficulty (leading zero bits) required at rendezvous.
    pub pow_difficulty: u8,
}

impl EdgeConfig {
    /// Parse from explicit strings (used by tests and by [`EdgeConfig::from_env`]).
    pub fn parse(listen: &str, difficulty: &str) -> Result<EdgeConfig, String> {
        let listen = listen
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid CT_EDGE_LISTEN '{listen}': {e}"))?;
        let pow_difficulty = difficulty
            .parse::<u8>()
            .map_err(|e| format!("invalid CT_EDGE_POW_DIFFICULTY '{difficulty}': {e}"))?;
        if pow_difficulty > ct_common::pow::MAX_CLIENT_SOLVABLE_DIFFICULTY {
            return Err(format!(
                "invalid CT_EDGE_POW_DIFFICULTY '{difficulty}': exceeds the client's max solvable difficulty {} (#413) -- no client could ever pass rendezvous",
                ct_common::pow::MAX_CLIENT_SOLVABLE_DIFFICULTY
            ));
        }
        Ok(EdgeConfig {
            listen,
            pow_difficulty,
        })
    }

    /// Read from `CT_EDGE_LISTEN` (default `0.0.0.0:4433`) and
    /// `CT_EDGE_POW_DIFFICULTY` (default `16`).
    pub fn from_env() -> Result<EdgeConfig, String> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (`from_env` passes `std::env::var`). Split out
    /// so the defaults and error branches are testable without mutating the
    /// global process environment (which races across parallel tests).
    fn from_env_with(get: impl Fn(&str) -> Option<String>) -> Result<EdgeConfig, String> {
        let listen = get("CT_EDGE_LISTEN").unwrap_or_else(|| "0.0.0.0:4433".to_string());
        let difficulty = get("CT_EDGE_POW_DIFFICULTY").unwrap_or_else(|| "16".to_string());
        Self::parse(&listen, &difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let c = EdgeConfig::parse("127.0.0.1:4433", "18").unwrap();
        assert_eq!(c.listen, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(c.pow_difficulty, 18);
    }

    #[test]
    fn rejects_bad_listen() {
        assert!(EdgeConfig::parse("not-an-addr", "16").is_err());
    }

    #[test]
    fn rejects_bad_difficulty() {
        assert!(EdgeConfig::parse("127.0.0.1:4433", "300").is_err());
    }

    #[test]
    fn rejects_a_difficulty_no_client_can_ever_solve() {
        // #1013: 32 is MAX_CLIENT_SOLVABLE_DIFFICULTY and must still be accepted;
        // 33 is one past it and must be rejected at config-parse time, not left to
        // surface only as every client's DifficultyTooHigh error at rendezvous.
        assert!(EdgeConfig::parse("127.0.0.1:4433", "32").is_ok());
        let err = EdgeConfig::parse("127.0.0.1:4433", "33").unwrap_err();
        assert!(err.contains("CT_EDGE_POW_DIFFICULTY"), "{err}");
        assert!(err.contains("32"), "{err}");
    }

    // #21 WC2: cover from_env via the from_env_with getter seam (no global-env
    // mutation) — edge/config.rs was the worst testable file at 72%.
    fn get_from<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn from_env_defaults_when_unset() {
        let c = EdgeConfig::from_env_with(|_| None).unwrap();
        assert_eq!(c.listen, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(c.pow_difficulty, 16);
    }

    #[test]
    fn from_env_reads_both_vars() {
        let c = EdgeConfig::from_env_with(get_from(&[
            ("CT_EDGE_LISTEN", "127.0.0.1:5000"),
            ("CT_EDGE_POW_DIFFICULTY", "20"),
        ]))
        .unwrap();
        assert_eq!(c.listen, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(c.pow_difficulty, 20);
    }

    #[test]
    fn from_env_rejects_each_invalid_value() {
        let bad_listen = EdgeConfig::from_env_with(get_from(&[("CT_EDGE_LISTEN", "nope")]))
            .unwrap_err();
        assert!(bad_listen.contains("CT_EDGE_LISTEN"), "{bad_listen}");
        let bad_diff =
            EdgeConfig::from_env_with(get_from(&[("CT_EDGE_POW_DIFFICULTY", "300")])).unwrap_err();
        assert!(bad_diff.contains("CT_EDGE_POW_DIFFICULTY"), "{bad_diff}");
    }

    #[test]
    fn from_env_wrapper_reads_the_process_environment() {
        // Thin wrapper over std::env::var; no test sets CT_EDGE_* and the gate
        // container has none, so it resolves the documented defaults.
        assert!(EdgeConfig::from_env().is_ok());
    }
}

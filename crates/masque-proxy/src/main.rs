//! `masque-proxy` daemon entry point. Reads `Config` from the environment and runs
//! for the process's lifetime -- see `lib.rs` for the actual proxy logic and
//! `docs/adr/0024-masque-connect-udp-fallback.md` for the design this implements.

use masque_proxy::Config;
use std::time::Duration;

fn env_socket_addr(key: &str, default: &str) -> Result<std::net::SocketAddr, String> {
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse().map_err(|e| format!("invalid {key} '{raw}': {e}"))
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key).ok().and_then(|s| s.trim().parse().ok()).filter(|&n| n > 0).unwrap_or(default)
}

fn env_secs(key: &str, default: u64) -> Duration {
    Duration::from_secs(std::env::var(key).ok().and_then(|s| s.trim().parse().ok()).filter(|&n| n > 0).unwrap_or(default))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Fail-closed, same posture as CT_EDGE_ADMIN_TOKEN: this proxy's one target is
    // the edge's own INTERNAL QUIC listener, so it must never start without a real
    // shared secret gating who may open a tunnel at all (see lib.rs's crate doc).
    let raw_token = std::env::var("CT_MASQUE_PROXY_TOKEN")
        .map_err(|_| "CT_MASQUE_PROXY_TOKEN not set -- refusing to start without it (see crate docs)")?;
    let shared_token = masque_proxy::parse_token_hex(&raw_token)
        .ok_or("CT_MASQUE_PROXY_TOKEN must be 64 hex characters")?;

    let config = Config {
        listen: env_socket_addr("CT_MASQUE_PROXY_LISTEN", "127.0.0.1:4434")?,
        // Defaults to CT_EDGE_LISTEN's own default (config.rs) -- see this crate's
        // README/ADR-0024 for why these two must be kept in sync at deploy time.
        target: env_socket_addr("CT_MASQUE_PROXY_TARGET_ADDR", "127.0.0.1:4433")?,
        max_concurrent_tunnels: env_usize("CT_MASQUE_PROXY_MAX_TUNNELS", 256),
        idle_timeout: env_secs("CT_MASQUE_PROXY_IDLE_TIMEOUT_SECS", 120),
        shared_token,
    };
    eprintln!(
        "masque-proxy: listening on {} (target={}, max_tunnels={}, idle_timeout={:?})",
        config.listen, config.target, config.max_concurrent_tunnels, config.idle_timeout
    );
    masque_proxy::run(config).await
}

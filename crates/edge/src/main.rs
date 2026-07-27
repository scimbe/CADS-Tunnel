//! CADS Tunnel Edge daemon (M5.4c).
//!
//! Reads [`EdgeConfig`] from the environment, writes its certificate to a shared
//! path (so Agents/Clients can trust it), and runs the serve loop.

use ct_edge::config::EdgeConfig;
use ct_edge::serve::run_edge;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = EdgeConfig::from_env()?;
    let cert_out =
        std::env::var("CT_EDGE_CERT_OUT").unwrap_or_else(|_| "/shared/edge-cert.der".to_string());
    eprintln!(
        "ct-edge: listening on {} (pow_difficulty={}, cert_out={})",
        config.listen, config.pow_difficulty, cert_out
    );
    run_edge(&config, &cert_out).await
}

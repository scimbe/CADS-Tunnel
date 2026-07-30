//! Fixed-port UDP echo origin for the testbed (M16.3).
//!
//! Binds `CT_UDP_ECHO_LISTEN` (default `0.0.0.0:8080`) and echoes each datagram
//! back to its sender **from the bound port**. Unlike a forking `socat`, one
//! socket serves every (sequential) bench iteration, and the reply always comes
//! from :8080 — which is what the Agent's connected UDP socket
//! (`serve_noise_udp`) requires. Used by the UDP bench overlay.

use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen = std::env::var("CT_UDP_ECHO_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let sock = UdpSocket::bind(&listen).await?;
    eprintln!("udp_echo: listening on {listen}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let _ = sock.send_to(&buf[..n], peer).await;
    }
}

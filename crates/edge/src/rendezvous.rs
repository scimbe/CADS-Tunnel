//! Edge rendezvous — token resolution (ADR-0006, ADR-0015).
//!
//! P2.3a: a Client presents a Routing Token; the Edge resolves it against the
//! Tunnel Registry — via a caller-supplied `is_known` predicate, so the Edge
//! stays decoupled from the control-plane registry type — and replies OK/NO.
//! The actual byte relay to the Agent (relay-first path) is P2.4.

use ct_common::pow::{check_request, Challenge};
use ct_common::RoutingToken;
use quinn::Endpoint;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Accept one connection, read the 32-byte Routing Token the Client presents,
/// resolve it via `is_known`, reply `OK`/`NO`, and return the token on success.
pub async fn resolve_rendezvous<F>(endpoint: &Endpoint, is_known: F) -> Result<RoutingToken, BoxError>
where
    F: Fn(&RoutingToken) -> bool,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    let (mut send, mut recv) = conn.accept_bi().await?;
    let bytes = recv.read_to_end(64).await?;
    if bytes.len() != 32 {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        return Err("routing token must be 32 bytes".into());
    }
    let mut token = [0u8; 32];
    token.copy_from_slice(&bytes);
    let token = RoutingToken(token);

    if is_known(&token) {
        send.write_all(b"OK").await?;
        send.finish()?;
        conn.closed().await; // hold the connection so the Client reads the ack
        Ok(token)
    } else {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        Err("unknown routing token".into())
    }
}

/// PoW-gated rendezvous (ADR-0018): the Edge sends `challenge`, the Client must
/// return a valid proof-of-work solution plus the Routing Token before the Edge
/// resolves it. Wire: Edge sends `nonce(16) | difficulty(1)`; Client replies
/// `solution(8 LE) | token(32)`; Edge replies `OK`/`NO`.
pub async fn resolve_rendezvous_gated<F>(
    endpoint: &Endpoint,
    challenge: Challenge,
    is_known: F,
) -> Result<RoutingToken, BoxError>
where
    F: Fn(&RoutingToken) -> bool,
{
    let incoming = endpoint
        .accept()
        .await
        .ok_or("endpoint closed with no incoming")?;
    let conn = incoming.await?;
    // Edge-initiated stream: writing the challenge makes it visible to the peer.
    let (mut send, mut recv) = conn.open_bi().await?;

    let mut chal = [0u8; 17];
    chal[..16].copy_from_slice(&challenge.nonce);
    chal[16] = challenge.difficulty;
    send.write_all(&chal).await?;

    let request = recv.read_to_end(40).await?;
    let token = match check_request(&challenge, &request) {
        Ok(t) => t,
        Err(_) => {
            let _ = send.write_all(b"NO").await;
            let _ = send.finish();
            return Err("proof of work rejected".into());
        }
    };

    if is_known(&token) {
        send.write_all(b"OK").await?;
        send.finish()?;
        conn.closed().await;
        Ok(token)
    } else {
        let _ = send.write_all(b"NO").await;
        let _ = send.finish();
        Err("unknown routing token".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use quinn::Connection;

    async fn present_token(conn: &Connection, token: &RoutingToken) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(&token.0).await.expect("write token");
        send.finish().expect("finish");
        recv.read_to_end(64).await.unwrap_or_default()
    }

    #[tokio::test]
    async fn edge_resolves_known_token() {
        let known = RoutingToken([7u8; 32]);
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let known_task = known.clone();
        let server_task = tokio::spawn(async move {
            resolve_rendezvous(&server, move |t| *t == known_task)
                .await
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let ack = present_token(&conn, &known).await;
        assert_eq!(ack, b"OK");
        conn.close(0u32.into(), b"done");
        let resolved = server_task.await.expect("join").expect("resolved");
        assert_eq!(resolved, known);
    }

    #[tokio::test]
    async fn edge_rejects_unknown_token() {
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_rendezvous(&server, |_| false)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let ack = present_token(&conn, &RoutingToken([9u8; 32])).await;
        assert_ne!(ack, b"OK", "unknown token must not be accepted");
        let _ = server_task.await;
    }

    // --- P4.2b: PoW-gated rendezvous over QUIC ---

    async fn present_gated(conn: &quinn::Connection, req: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept bi");
        let mut chal = [0u8; 17];
        recv.read_exact(&mut chal).await.expect("read challenge");
        send.write_all(req).await.expect("write request");
        send.finish().expect("finish");
        recv.read_to_end(64).await.unwrap_or_default()
    }

    fn challenge_from(chal: &[u8; 17]) -> Challenge {
        Challenge {
            nonce: chal[..16].try_into().unwrap(),
            difficulty: chal[16],
        }
    }

    #[tokio::test]
    async fn pow_gated_accepts_valid_solution() {
        use ct_common::pow::build_request;

        let known = RoutingToken([7u8; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 10,
        };
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let (known_task, chal_task) = (known.clone(), challenge.clone());
        let server_task = tokio::spawn(async move {
            resolve_rendezvous_gated(&server, chal_task, move |t| *t == known_task)
                .await
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        // Read the challenge, solve it, present solution+token.
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut chal = [0u8; 17];
        recv.read_exact(&mut chal).await.unwrap();
        let req = build_request(&challenge_from(&chal), &known).unwrap();
        send.write_all(&req).await.unwrap();
        send.finish().unwrap();
        let ack = recv.read_to_end(64).await.unwrap();
        assert_eq!(ack, b"OK");
        let _ = challenge;
        conn.close(0u32.into(), b"done");

        let resolved = server_task.await.expect("join").expect("resolved");
        assert_eq!(resolved, known);
    }

    #[tokio::test]
    async fn pow_gated_rejects_bad_pow() {
        let known = RoutingToken([7u8; 32]);
        // High difficulty; the client sends solution 0 without solving.
        let challenge = Challenge {
            nonce: [0x22; 16],
            difficulty: 24,
        };
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            resolve_rendezvous_gated(&server, challenge, move |_| true)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let mut bad = Vec::new();
        bad.extend_from_slice(&0u64.to_le_bytes()); // unsolved
        bad.extend_from_slice(&known.0);
        let ack = present_gated(&conn, &bad).await;
        assert_ne!(ack, b"OK", "invalid proof of work must be rejected");
        let _ = server_task.await;
    }
}

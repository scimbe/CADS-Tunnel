//! Client-side PoW-gated rendezvous (M5.3a).
//!
//! The counterpart to the Edge's `resolve_rendezvous_gated`: read the Edge's
//! challenge, solve the proof of work, present `solution | token`, and await OK.

use crate::transport::build_request_blocking;
use ct_common::pow::Challenge;
use ct_common::RoutingToken;
use quinn::Connection;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Perform PoW-gated rendezvous for `token` on `conn`. Returns `Ok(())` when the
/// Edge accepts the token.
pub async fn client_rendezvous(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let mut chal = [0u8; 17];
    recv.read_exact(&mut chal).await?;
    let challenge = Challenge {
        nonce: chal[..16].try_into().unwrap(),
        difficulty: chal[16],
    };
    let req = build_request_blocking(&challenge, token).await;
    send.write_all(&req).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected rendezvous".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{client_exchange, dial_edge};

    /// M15.5 — the full v1 money→tunnel path: the routing token that establishes
    /// the tunnel is issued through the *paid* control-plane flow (open account →
    /// top-up → credit-gated issuance), and a zero-balance account is denied a
    /// token (so it gets no tunnel). Ties M15 (accounts/payment/billing) to the
    /// real Noise tunnel (edge relay + agent bridge + origin).
    #[tokio::test]
    async fn billing_issued_token_establishes_a_tunnel() {
        use crate::transport::client_tunnel_noise;
        use ct_agent::serve::serve_noise_bridge;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_control_plane::client::ControlPlaneClient;
        use ct_control_plane::enrollment::Enrollment;
        use ct_control_plane::http::{control_plane_router, BillingState};
        use ct_control_plane::registry::TunnelRegistry;
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // --- Billing service: buy the tunnel token through the paid flow. ---
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let bill = Arc::new(Mutex::new(BillingState::default()));
        let cp_app = control_plane_router(enr, reg, bill);
        let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cp_addr = cp_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(cp_listener, cp_app).await.unwrap() });
        let cp = ControlPlaneClient::new(format!("http://{cp_addr}"));

        // A zero-balance account is denied a token → it could never tunnel.
        let broke = cp.open_account().await.unwrap();
        assert!(
            cp.buy_token(&broke, 1).await.is_err(),
            "zero-balance account is denied a token"
        );

        // A funded account tops up and buys the routing token we will tunnel with.
        let account = cp.open_account().await.unwrap();
        let payment = cp.create_payment_intent(&account, 5).await.unwrap();
        cp.confirm_payment(&payment).await.unwrap();
        let token = cp.buy_token(&account, 1).await.unwrap();

        // --- Establish the real Noise tunnel using that paid token. ---
        let challenge = Challenge {
            nonce: [0x55; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Real TCP echo Origin — sees only plaintext.
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = origin_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register the paid token, then serve the relayed Noise stream.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut ra_send, mut ra_recv) = agent_conn.open_bi().await.unwrap();
        ra_send.write_all(b"A").await.unwrap();
        ra_send.write_all(&token.0).await.unwrap();
        ra_send.finish().unwrap();
        assert_eq!(ra_recv.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            let (mut s, mut r) = agent_conn.accept_bi().await.unwrap();
            serve_noise_bridge(&mut s, &mut r, origin_addr, &origin_priv)
                .await
                .unwrap();
            s.finish().unwrap();
            agent_conn.closed().await;
        });

        // Client: Noise-tunnel through the edge to the origin using the paid token.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let resp = client_tunnel_noise(&conn, &token, &cap, &client_kp.private, b"paid-payload")
            .await
            .expect("client noise tunnel");
        assert_eq!(
            resp, b"paid-payload",
            "a billing-issued token establishes a working Noise tunnel end to end"
        );
        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
        let _ = origin.await;
    }

    #[tokio::test]
    async fn client_tunnels_data_to_agent_through_edge() {
        use crate::transport::client_tunnel;
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([4u8; 32]);
        let challenge = Challenge {
            nonce: [0x33; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // Edge: serve the Agent (register) then the Client (rendezvous+route+relay).
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await; // hold the client conn until it closes
            Ok::<(), String>(())
        });

        // Agent: register ('A' | token), then echo the relayed stream.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut ra_send, mut ra_recv) = agent_conn.open_bi().await.unwrap();
        ra_send.write_all(b"A").await.unwrap();
        ra_send.write_all(&token.0).await.unwrap();
        ra_send.finish().unwrap();
        assert_eq!(ra_recv.read_to_end(8).await.unwrap(), b"OK");
        let agent_task = tokio::spawn(async move {
            let (mut s, mut r) = agent_conn.accept_bi().await.unwrap();
            let data = r.read_to_end(1024).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.finish().unwrap();
            agent_conn.closed().await;
        });

        // Client: tunnel data through the edge to the agent.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let resp = client_tunnel(&conn, &token, b"payload")
            .await
            .expect("client tunnel");
        assert_eq!(
            resp, b"payload",
            "client data reaches the agent and echoes back through the edge"
        );
        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
    }

    #[tokio::test]
    async fn client_noise_tunnels_through_edge_to_origin() {
        // Full Noise E2E path: Client --(Noise ciphertext)--> real Edge relay
        // --> Agent serve_noise_bridge --> real TCP echo Origin (plaintext) and
        // back. The Edge never holds a Noise key; it only relays frames.
        use crate::transport::client_tunnel_noise;
        use ct_agent::serve::serve_noise_bridge;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let token = RoutingToken([9u8; 32]);
        let challenge = Challenge {
            nonce: [0x55; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Real TCP echo Origin — sees only plaintext.
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = origin_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge: serve the Agent (register) then the Client (rendezvous+route+relay).
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register, then serve the relayed stream as the Noise responder.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut ra_send, mut ra_recv) = agent_conn.open_bi().await.unwrap();
        ra_send.write_all(b"A").await.unwrap();
        ra_send.write_all(&token.0).await.unwrap();
        ra_send.finish().unwrap();
        assert_eq!(ra_recv.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            let (mut s, mut r) = agent_conn.accept_bi().await.unwrap();
            serve_noise_bridge(&mut s, &mut r, origin_addr, &origin_priv)
                .await
                .unwrap();
            s.finish().unwrap();
            agent_conn.closed().await;
        });

        // Client: Noise-tunnel through the edge to the origin.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let resp = client_tunnel_noise(&conn, &token, &cap, &client_kp.private, b"secret-payload")
            .await
            .expect("client noise tunnel");
        assert_eq!(
            resp, b"secret-payload",
            "encrypted payload round-trips through edge relay + agent bridge to origin"
        );
        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
        let _ = origin.await;
    }

    #[tokio::test]
    async fn client_streams_bidirectionally_through_edge() {
        // Full streaming path: Client app <-> noise_pump <-> Edge relay <->
        // agent serve_noise_stream <-> real streaming TCP echo Origin. A 150 KB
        // (multi-frame) payload travels both ways through the real Edge.
        use crate::transport::client_tunnel_stream;
        use ct_agent::serve::serve_noise_stream;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let token = RoutingToken([0x9A; 32]);
        let challenge = Challenge {
            nonce: [0x66; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Streaming TCP echo Origin.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge: serve the Agent (register) then the Client (rendezvous+route+relay).
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register, then stream the relayed connection to the Origin.
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            let (s, r) = agent_conn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(s, r, origin_addr, &[origin_priv], std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new())).await;
            agent_conn.closed().await;
        });

        // Client: stream a 150 KB payload through the tunnel and read the echo.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let expected: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
        let (mut ar, mut aw) = tokio::io::split(app_remote);
        let payload = expected.clone();
        let writer = async move {
            aw.write_all(&payload).await.unwrap();
            aw.shutdown().await.unwrap();
        };
        let reader = async move {
            let mut got = Vec::new();
            ar.read_to_end(&mut got).await.unwrap();
            got
        };
        let (cres, _, got) = tokio::join!(
            client_tunnel_stream(
                &conn,
                &token,
                &cap,
                &client_kp.private,
                app_local,
                crate::transport::DEFAULT_STREAM_SETUP_DEADLINE,
            ),
            writer,
            reader,
        );
        cres.expect("client stream ok");
        assert_eq!(got, expected, "150 KB streams both ways through the real Edge");

        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn https_website_through_the_tunnel_with_client_side_cert_validation() {
        // #22 HW1: a real HTTPS website is the private Origin — TLS terminates AT
        // the Origin, not the Edge. A client reaches it through the tunnel, runs
        // the TLS handshake end-to-end (over the Noise stream), validates the
        // Origin's cert CLIENT-SIDE, and reads a genuine HTTP 200 page. Because
        // the client trusts ONLY the Origin's self-signed cert, a successful
        // handshake proves the cert was validated at the client (the Edge, being
        // provider-blind, never terminated TLS). The tunnel payload the Edge
        // relays is TLS-over-Noise ciphertext (edge-sees-only-ciphertext is
        // separately proven by relay::tests::noise_e2e_through_relay_edge_sees_only_ciphertext).
        use crate::transport::client_tunnel_stream;
        use ct_agent::serve::serve_noise_stream;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
        };
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let token = RoutingToken([0x2C; 32]);
        let challenge = Challenge { nonce: [0x77; 16], difficulty: 8 };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // A real HTTPS Origin on loopback: self-signed cert (SAN "localhost"),
        // TLS terminates here, serves a tiny static page.
        let (listener, acceptor, origin_cert) =
            build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
                .await
                .expect("https origin");
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.expect("origin TLS handshake");
            let mut buf = [0u8; 1024];
            let n = tls.read(&mut buf).await.unwrap();
            assert!(buf[..n].starts_with(b"GET "), "origin got an HTTP request over TLS");
            let body = "hello, secured";
            let resp = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            tls.write_all(resp.as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register, then stream the relayed connection to the HTTPS Origin
        // (raw bytes — the agent is provider-blind, it never sees TLS plaintext).
        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep.connect(addr, "localhost").expect("cfg").await.expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            let (s, r) = agent_conn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(
                s,
                r,
                origin_addr,
                &[origin_priv],
                Arc::new(ct_common::metrics::TunnelMetrics::new()),
            )
            .await;
            agent_conn.closed().await;
        });

        // Client: open the tunnel stream, then run a TLS client over it that
        // trusts ONLY the Origin's cert, and GET the page.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let (app_local, app_remote) = tokio::io::duplex(64 * 1024);
        let origin_cert_c = origin_cert.clone();
        let tls_client = async move {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(origin_cert_c).unwrap();
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let sni = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            // A successful handshake here IS the client-side cert validation.
            let mut tls = connector
                .connect(sni, app_remote)
                .await
                .expect("client validates the origin's cert and completes TLS through the tunnel");
            tls.write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
            let mut page = Vec::new();
            tls.read_to_end(&mut page).await.unwrap();
            String::from_utf8_lossy(&page).into_owned()
        };

        let (cres, page) = tokio::join!(
            client_tunnel_stream(
                &conn,
                &token,
                &cap,
                &client_kp.private,
                app_local,
                crate::transport::DEFAULT_STREAM_SETUP_DEADLINE,
            ),
            tls_client,
        );
        cres.expect("client tunnel stream ok");
        assert!(page.contains("200 OK"), "HTTPS 200 through the tunnel: {page}");
        assert!(page.contains("hello, secured"), "the real page body arrived: {page}");

        conn.close(0u32.into(), b"done");
        agent_task.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn forward_mode_bridges_a_local_tcp_connection_through_the_tunnel() {
        // #22 HW2a: client_forward accepts a plain local TCP connection and
        // bridges it through the tunnel to the Origin — the enabler that lets
        // real TCP/TLS apps (curl, browsers) ride the mesh via a local port.
        use crate::transport::client_forward;
        use ct_agent::serve::serve_noise_stream;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let token = RoutingToken([0x3F; 32]);
        let challenge = Challenge { nonce: [0x88; 16], difficulty: 8 };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // TCP echo Origin.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        let agent_ep = build_client_endpoint(cert.clone()).expect("agent ep");
        let agent_conn = agent_ep.connect(addr, "localhost").expect("cfg").await.expect("agent conn");
        let (mut rs, mut rr) = agent_conn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let origin_priv = origin_kp.private;
        let agent_task = tokio::spawn(async move {
            let (s, r) = agent_conn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(
                s,
                r,
                origin_addr,
                &[origin_priv],
                Arc::new(ct_common::metrics::TunnelMetrics::new()),
            )
            .await;
            agent_conn.closed().await;
        });

        // Forward proxy: bind a local port and bridge it through the tunnel.
        let fwd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_addr = fwd_listener.local_addr().unwrap();
        let fwd = tokio::spawn(client_forward(
            fwd_listener,
            addr,
            cert,
            token.clone(),
            cap,
            client_kp.private,
            crate::transport::DEFAULT_STREAM_SETUP_DEADLINE,
        ));

        // A plain local TCP client rides the forward port.
        let mut c = TcpStream::connect(fwd_addr).await.unwrap();
        c.write_all(b"through-the-forward").await.unwrap();
        c.shutdown().await.unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        assert_eq!(
            got, b"through-the-forward",
            "a local TCP connection round-trips through the tunnel via the forward proxy"
        );

        fwd.abort();
        agent_task.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn client_udp_tunnels_datagrams_through_edge() {
        // Full UDP path: local UDP app <-> client_tunnel_udp <-> Edge relay <->
        // agent serve_noise_udp <-> real UDP echo Origin. Datagram boundaries
        // are preserved (one datagram = one Noise frame).
        use crate::transport::udp_selftest;
        use ct_agent::serve::serve_noise_udp;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::sync::Arc;
        use tokio::net::UdpSocket;

        let token = RoutingToken([0xAB; 32]);
        let challenge = Challenge {
            nonce: [0x77; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // UDP echo Origin.
        let origin_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_sock.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            while let Ok((n, peer)) = origin_sock.recv_from(&mut b).await {
                let _ = origin_sock.send_to(&b[..n], peer).await;
            }
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge.
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let ac = server.accept().await.unwrap().await.unwrap();
            serve_connection(&ac, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            let cc = server.accept().await.unwrap().await.unwrap();
            serve_connection(&cc, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            cc.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register, serve the relayed stream as a UDP bridge.
        let aep = build_client_endpoint(cert.clone()).expect("agent ep");
        let aconn = aep.connect(addr, "localhost").expect("cfg").await.expect("agent conn");
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let opriv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let (s, r) = aconn.accept_bi().await.unwrap();
            let _ = serve_noise_udp(s, r, origin_addr, &[opriv]).await;
            aconn.closed().await;
        });

        let conn = dial_edge(addr, cert).await.expect("client dial");

        // udp_selftest sends one datagram through the tunnel and returns the echo.
        let echo = udp_selftest(&conn, &token, &cap, &client_kp.private, b"a-udp-datagram")
            .await
            .expect("udp selftest");
        assert_eq!(echo, b"a-udp-datagram", "UDP datagram round-trips with boundary preserved");

        conn.close(0u32.into(), b"done");
        agent.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn client_queries_advertised_direct_endpoint() {
        // M11.4b-ii: an Agent advertises its direct-path listener ('D'); a Client
        // queries the Edge ('P') and receives that (addr, cert).
        use crate::transport::query_direct_endpoint;
        use ct_agent::transport::{advertise_direct_listener, build_direct_listener_at};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::build_server_endpoint_with_cert;
        use quinn::Connection;
        use std::net::Ipv4Addr;
        use std::sync::Arc;

        let token = RoutingToken([0x5C; 32]);
        let challenge = Challenge {
            nonce: [0x22; 16],
            difficulty: 8,
        };
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // The values the Agent advertises.
        let adv_addr: std::net::SocketAddr = "10.5.0.4:40001".parse().unwrap();
        let (_ep, adv_cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");

        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&agent_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            agent_conn.closed().await;
            let client_conn = server.accept().await.unwrap().await.unwrap();
            serve_connection(&client_conn, &state_e, &chal_e)
                .await
                .map_err(|e| e.to_string())?;
            client_conn.closed().await;
            Ok::<(), String>(())
        });

        // Agent advertises its direct-path listener ('D').
        let aconn = dial_edge(addr, cert.clone()).await.expect("agent dial");
        advertise_direct_listener(&aconn, &token, adv_addr, &adv_cert)
            .await
            .expect("advertise");
        aconn.close(0u32.into(), b"done");

        // Client queries the advertised endpoint ('P').
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let ep = query_direct_endpoint(&conn, &token)
            .await
            .expect("direct-endpoint query");
        let (got_addr, got_cert) = ep.expect("endpoint advertised");
        assert_eq!(got_addr, adv_addr, "advertised address returned");
        assert_eq!(got_cert, adv_cert, "advertised cert returned");

        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn client_tunnels_directly_to_agent() {
        // M11.3c: the Client connects straight to the Agent's direct-path
        // listener (no Edge, no PoW) and tunnels over Noise to the Origin.
        use crate::transport::{client_direct_connect, client_tunnel_direct};
        use ct_agent::serve::serve_noise_stream;
        use ct_agent::transport::build_direct_listener_at;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use std::net::Ipv4Addr;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming TCP echo Origin.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = l.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        // Agent direct listener: accept one direct connection, serve it as the
        // Noise responder straight to the Origin.
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let laddr = listener.local_addr().expect("laddr");
        let opriv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap().await.unwrap();
            let (s, r) = conn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(s, r, origin_addr, &[opriv], std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new())).await;
            conn.closed().await;
        });

        // Client: connect directly (bypassing the Edge) and tunnel.
        let conn = client_direct_connect(laddr, cert, Duration::from_secs(3))
            .await
            .expect("direct connect");
        let resp = client_tunnel_direct(&conn, &cap, &client_kp.private, b"direct-payload")
            .await
            .expect("direct tunnel");
        assert_eq!(resp, b"direct-payload", "direct P2P tunnel bypasses the Edge");

        conn.close(0u32.into(), b"done");
        agent.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn p2p_falls_back_to_relay_when_direct_fails() {
        // M11.4: with an unreachable direct candidate, the orchestrator degrades
        // to the Edge relay and still delivers the payload.
        use crate::transport::client_tunnel_p2p_or_relay;
        use ct_agent::serve::serve_noise_stream;
        use ct_agent::transport::build_direct_listener_at;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
        use quinn::Connection;
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let token = RoutingToken([0x7F; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();

        // Streaming echo Origin.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = l.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: addr.to_string(),
        };

        // Edge relay: serve agent (register) then client (rendezvous+relay).
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let ac = server.accept().await.unwrap().await.unwrap();
            serve_connection(&ac, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            let cc = server.accept().await.unwrap().await.unwrap();
            serve_connection(&cc, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            cc.closed().await;
            Ok::<(), String>(())
        });

        // Agent registers and serves the relayed stream.
        let aep = build_client_endpoint(cert.clone()).expect("agent ep");
        let aconn = aep.connect(addr, "localhost").expect("cfg").await.expect("agent conn");
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let opriv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let (s, r) = aconn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(s, r, origin_addr, &[opriv], std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new())).await;
            aconn.closed().await;
        });

        // An unreachable direct candidate (free UDP port, nothing listening) + a
        // throwaway cert; the direct attempt will time out.
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let (_ep, throwaway_cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");

        // Orchestrator: direct fails → relay delivers.
        let conn = dial_edge(addr, cert).await.expect("client dial");
        let (used_direct, resp) = client_tunnel_p2p_or_relay(
            &conn,
            &token,
            &cap,
            &client_kp.private,
            b"fallback-payload",
            Some((dead_addr, throwaway_cert)),
            Duration::from_millis(400),
        )
        .await
        .expect("p2p-or-relay");
        assert!(!used_direct, "unreachable direct candidate → fell back to relay");
        assert_eq!(resp, b"fallback-payload", "relay delivered the payload");

        conn.close(0u32.into(), b"done");
        agent.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn client_auto_uses_direct_path_when_advertised() {
        // M11.4b-iv: full auto P2P flow — the Agent advertises its direct
        // listener; the Client discovers it via the Edge ('P') and connects
        // straight to the Agent (used_direct=true), bypassing the relay.
        use crate::transport::client_tunnel_auto;
        use ct_agent::config::OriginProto;
        use ct_agent::serve::serve_direct;
        use ct_agent::transport::{advertise_direct_listener, build_direct_listener_at};
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::serve_connection;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::build_server_endpoint_with_cert;
        use quinn::Connection;
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let token = RoutingToken([0xD1; 32]);
        let challenge = Challenge {
            nonce: [0x33; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming echo Origin.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = l.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        // Agent direct listener + serve_direct loop.
        let (listener, agent_cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let laddr = listener.local_addr().expect("laddr");
        let opriv = origin_kp.private;
        let direct_srv =
            tokio::spawn(async move { let _ = serve_direct(listener, origin_addr, std::sync::Arc::new(vec![opriv]), OriginProto::Tcp, std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new())).await; });

        // Edge: serve the Agent's 'D' advertise, then the Client's 'P' query.
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let state_e = state.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            let ac = server.accept().await.unwrap().await.unwrap();
            serve_connection(&ac, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            ac.closed().await;
            let cc = server.accept().await.unwrap().await.unwrap();
            serve_connection(&cc, &state_e, &chal_e).await.map_err(|e| e.to_string())?;
            cc.closed().await;
            Ok::<(), String>(())
        });

        // Agent advertises its listener to the Edge.
        let adv = dial_edge(addr, cert.clone()).await.expect("agent dial");
        advertise_direct_listener(&adv, &token, laddr, &agent_cert)
            .await
            .expect("advertise");
        adv.close(0u32.into(), b"done");

        // Client auto: discover + direct tunnel.
        let cconn = dial_edge(addr, cert).await.expect("client dial");
        let (used_direct, resp) = client_tunnel_auto(
            &cconn,
            &token,
            &cap,
            &client_kp.private,
            b"auto-payload",
            Duration::from_secs(3),
        )
        .await
        .expect("auto tunnel");
        assert!(used_direct, "auto discovered + used the direct P2P path");
        assert_eq!(resp, b"auto-payload", "direct tunnel delivered the payload");

        cconn.close(0u32.into(), b"done");
        direct_srv.abort();
        let _ = edge.await;
        origin.abort();
    }

    #[tokio::test]
    async fn client_noise_tunnels_over_tcp_fallback() {
        // M12.2c: the Client's UDP is blocked, so it tunnels over TLS-TCP; the
        // Edge relays it to the QUIC Agent, Noise E2E to the Origin.
        use crate::transport::client_tunnel_noise_tcp;
        use ct_agent::serve::serve_noise_stream;
        use ct_common::noise::generate_static_keypair;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::serve::{register_agent, serve_tcp_connection};
        use ct_edge::state::EdgeState;
        use ct_edge::transport::{
            build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at,
            tcp_tls_connect,
        };
        use quinn::Connection;
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let token = RoutingToken([0x77; 32]);
        let challenge = Challenge {
            nonce: [0x55; 16],
            difficulty: 8,
        };
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming echo Origin.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = l.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, qcert) = build_server_endpoint_with_cert().expect("quic edge");
        let qaddr = server.local_addr().unwrap();
        let (tcp_listener, acceptor, tcert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("tcp edge");
        let taddr = tcp_listener.local_addr().unwrap();

        // QUIC edge: register the Agent.
        let state_q = state.clone();
        let quic_edge = tokio::spawn(async move {
            let ac = server.accept().await.unwrap().await.unwrap();
            register_agent(&ac, &state_q).await.map_err(|e| e.to_string())?;
            ac.closed().await;
            Ok::<(), String>(())
        });

        // Agent: register (QUIC), serve the relayed stream as Noise responder.
        let aep = build_client_endpoint(qcert).expect("agent ep");
        let aconn = aep.connect(qaddr, "localhost").unwrap().await.unwrap();
        let (mut rs, mut rr) = aconn.open_bi().await.unwrap();
        rs.write_all(b"A").await.unwrap();
        rs.write_all(&token.0).await.unwrap();
        rs.finish().unwrap();
        assert_eq!(rr.read_to_end(8).await.unwrap(), b"OK");
        let opriv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let (s, r) = aconn.accept_bi().await.unwrap();
            let _ = serve_noise_stream(s, r, origin_addr, &[opriv], std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new())).await;
            aconn.closed().await;
        });

        // TLS-TCP edge: serve the fallback client.
        let state_t = state.clone();
        let chal_t = challenge.clone();
        let tcp_edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let _ = serve_tcp_connection(tls, &state_t, &chal_t).await;
        });

        // Client over TLS-TCP: Noise tunnel to the Origin.
        let client = tcp_tls_connect(taddr, tcert).await.expect("tcp connect");
        let resp = client_tunnel_noise_tcp(client, &token, &cap, &client_kp.private, b"tcp-noise")
            .await
            .expect("tcp noise tunnel");
        assert_eq!(resp, b"tcp-noise", "Noise E2E round-trips over the TCP fallback");

        agent.abort();
        quic_edge.abort();
        tcp_edge.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn client_tcp_tls_connects_and_echoes() {
        // M12.3b: the Client's own TLS-TCP connector reaches the Edge's fallback
        // listener and a byte stream round-trips.
        use crate::transport::tcp_tls_connect;
        use ct_edge::transport::build_tcp_tls_listener_at;
        use std::net::Ipv4Addr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (listener, acceptor, cert) =
            build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into()).await.expect("listener");
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let mut client = tcp_tls_connect(addr, cert).await.expect("connect");
        client.write_all(b"client-tcp").await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"client-tcp", "client TLS-TCP connector round-trips");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn client_exchanges_data_over_stream() {
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let edge = tokio::spawn(async move {
            ct_edge::transport::accept_and_echo_one(&server)
                .await
                .map_err(|e| e.to_string())
        });

        let conn = dial_edge(addr, cert).await.expect("dial");
        let response = client_exchange(&conn, b"hello-origin")
            .await
            .expect("exchange");
        assert_eq!(response, b"hello-origin", "data round-trips over the tunnel stream");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn client_completes_pow_gated_rendezvous() {
        let token = RoutingToken([7u8; 32]);
        let challenge = Challenge {
            nonce: [0x11; 16],
            difficulty: 10,
        };
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let token_e = token.clone();
        let chal_e = challenge.clone();
        let edge = tokio::spawn(async move {
            ct_edge::rendezvous::resolve_rendezvous_gated(&server, chal_e, move |t| *t == token_e)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_edge(addr, cert).await.expect("dial");
        client_rendezvous(&conn, &token)
            .await
            .expect("client completes rendezvous");
        conn.close(0u32.into(), b"done");
        edge.await.unwrap().expect("edge resolved");
    }

    #[tokio::test]
    async fn load_cert_reads_written_der() {
        use crate::transport::load_cert;
        let (_endpoint, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-client-cert-{}.der", std::process::id()));
        std::fs::write(&path, cert.as_ref()).unwrap();
        assert_eq!(load_cert(&path).unwrap(), cert);
        let _ = std::fs::remove_file(&path);
    }
}

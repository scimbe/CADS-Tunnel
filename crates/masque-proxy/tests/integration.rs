//! End-to-end proof this crate actually does what ADR-0024 M2 asks for: a real
//! `masque_proxy::run` instance, fronting a real UDP socket standing in for "the
//! edge's own QUIC listener", driven by a real h2 client speaking Extended CONNECT
//! (RFC 9220) + RFC 9297/9298 capsule-framed datagrams -- the same protocol layer
//! ct-agent's spike-masque-h2/ (M1) proved feasible, now exercised against the actual
//! production proxy rather than a throwaway client+server pair.

use bytes::Bytes;
use h2::ext::Protocol;
use http::{Method, Request};
use masque_proxy::{capsule, Config};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Binds a UDP socket that echoes every datagram it receives back to its sender --
/// stands in for "the edge's QUIC listener" (this proxy's single hard-restricted
/// target) without needing a real QUIC endpoint in this test.
async fn spawn_udp_echo_target() -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_527];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { break };
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn a_udp_datagram_round_trips_through_the_real_proxy_to_the_configured_target() {
    let target = spawn_udp_echo_target().await;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
    };
    // `run()` binds its own listener; grab the real (OS-assigned) address by binding
    // ourselves first and handing it the same address run() will then re-bind to
    // would race -- instead, bind here and pass the bound listener's address through
    // a fixed loopback port 0, then poll until the proxy is actually accepting.
    let listen_probe = std::net::TcpListener::bind(config.listen).unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe); // release the port; run() rebinds it -- see the retry loop below for the inherent race this accepts

    let mut config = config;
    config.listen = proxy_addr;
    tokio::spawn(masque_proxy::run(config));

    // The proxy needs a moment to actually bind after the probe above released the
    // port -- bounded retry rather than a fixed sleep, matching this codebase's own
    // "don't guess a delay" convention.
    let client_io = 'connect: {
        for _ in 0..50 {
            if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                break 'connect io;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("masque-proxy never started accepting on {proxy_addr}");
    };

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(send_request.is_extended_connect_protocol_enabled());

    let path = format!("/.well-known/masque/udp/{}/{}/", target.ip(), target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, mut client_send) = send_request.send_request(request, false).unwrap();

    let udp_payload = b"a datagram tunneled to the configured target and back";
    let framed = capsule::encode_datagram(&capsule::udp_datagram_payload::encode(udp_payload));
    client_send.send_data(Bytes::from(framed), false).unwrap();

    let response = response_fut.await.unwrap();
    assert_eq!(response.status(), 200, "the proxy accepted the CONNECT-UDP request for its configured target");

    let mut body = response.into_body();
    let mut buf = Vec::new();
    let echoed = loop {
        let chunk = body.data().await.unwrap().unwrap();
        body.flow_control().release_capacity(chunk.len()).unwrap();
        buf.extend_from_slice(&chunk);
        if let Ok(Some((cap_type, value, _))) = capsule::decode(&buf) {
            assert_eq!(cap_type, 0x00);
            break capsule::udp_datagram_payload::decode(value).unwrap().to_vec();
        }
    };

    assert_eq!(
        echoed, udp_payload,
        "ADR-0024 M2 PROVEN: a datagram sent through a real masque-proxy instance reached the real UDP \
         target (echoed back by it) and the echo made it back through the proxy to the client, byte-for-byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_any_target_other_than_the_configured_one_is_refused() {
    // The security-critical property (#559, ADR-0024 Decision 5): this proxy is not
    // a general relay. A request naming a DIFFERENT host/port than the one configured
    // target must be refused, not silently proxied somewhere else.
    let target = spawn_udp_echo_target().await;
    let attacker_chosen_target: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap(); // not `target`

    let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listen_probe.local_addr().unwrap();
    drop(listen_probe);

    let config = Config {
        listen: proxy_addr,
        target,
        max_concurrent_tunnels: 4,
        idle_timeout: Duration::from_secs(5),
    };
    tokio::spawn(masque_proxy::run(config));

    let client_io = 'connect: {
        for _ in 0..50 {
            if let Ok(io) = tokio::net::TcpStream::connect(proxy_addr).await {
                break 'connect io;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("masque-proxy never started accepting on {proxy_addr}");
    };

    let (send_request, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);

    let mut send_request = send_request.ready().await.unwrap();
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let path = format!("/.well-known/masque/udp/{}/{}/", attacker_chosen_target.ip(), attacker_chosen_target.port());
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{proxy_addr}{path}"))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, _client_send) = send_request.send_request(request, true).unwrap();

    // A refused stream surfaces as an h2-level error to the response future (RST_STREAM),
    // never a 200 -- either outcome proves the request did NOT succeed as a tunnel.
    match response_fut.await {
        Ok(response) => panic!(
            "a request for an unconfigured target must never succeed -- got status {} instead of a refusal",
            response.status()
        ),
        Err(_) => {} // expected: the stream was reset
    }
}

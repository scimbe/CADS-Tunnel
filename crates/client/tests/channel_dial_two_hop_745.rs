//! #745 end-to-end: `ct_common::channel_dial::dial_and_call` against the REAL edge pairers.
//!
//! `crates/common` cannot dev-depend on `ct-edge` (a cycle), but ct-client already does, so
//! this is where the bridge dialer meets the edge's own `broker_channel_rendezvous`
//! (`:4435` shape) and `broker_channel_relay` (`:4436` shape) -- the exact completers the live
//! broker loops use (`finish_rendezvous_pair` / `finish_relay_pair`). The acceptor is a
//! second in-process QUIC client that does what a relay-only `ct-agent channel --serve` does:
//! rendezvous join, relay join, `accept_bi()` the edge-opened session stream, `a2a_respond`,
//! then `noise_pump` into a `serve_request_loop` duplex (the real serve shape) to answer one
//! JSON-RPC `tools/call`.
//!
//! Hermetic: loopback UDP only, self-signed certs from `ct_edge::transport`.

use std::sync::Arc;
use std::time::Duration;

use ct_common::a2a::{a2a_respond, serve_request_loop};
use ct_common::noise::noise_pump;
use ct_common::channel::{
    member_noise_attest_bytes, ChannelGrant, ChannelId, ChannelJoinRequest, Direction, Rights, SignedChannelGrant,
    CHANNEL_ENDPOINT_RELAY_ONLY,
};
use ct_edge::channel_broker::{broker_channel_relay, broker_channel_rendezvous};
use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
use ed25519_dalek::{Signer, SigningKey};

const OP_SEED: [u8; 32] = [5u8; 32];
const CHANNEL: [u8; 32] = [0x45u8; 32];
/// The edge's notion of "now" for grant checks; the grants below expire at 1_000.
const NOW: u64 = 500;
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// A member row as the control-plane registry would hand it to the edge's `authorize`
/// callback: holder, attested Noise key, attestation.
type MemberRow = ([u8; 32], [u8; 32], [u8; 64]);

fn operator_pubkey() -> [u8; 32] {
    SigningKey::from_bytes(&OP_SEED).verifying_key().to_bytes()
}

fn grant(holder: &SigningKey, direction: Direction) -> SignedChannelGrant {
    let g = ChannelGrant {
        channel: ChannelId(CHANNEL),
        holder: holder.verifying_key().to_bytes(),
        direction,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let signature = SigningKey::from_bytes(&OP_SEED).sign(&g.signing_bytes()).to_bytes();
    SignedChannelGrant { grant: g, signature }
}

fn member_row(holder: &SigningKey, noise_public: &[u8; 32]) -> MemberRow {
    let holder_pub = holder.verifying_key().to_bytes();
    let attest = holder.sign(&member_noise_attest_bytes(&ChannelId(CHANNEL), &holder_pub, noise_public)).to_bytes();
    (holder_pub, *noise_public, attest)
}

/// The edge's `authorize` callback shape, backed by a two-row registry.
fn authorize_for(
    table: Arc<Vec<MemberRow>>,
) -> impl Fn(ChannelId, [u8; 32]) -> std::future::Ready<Option<([u8; 32], Option<[u8; 32]>, Option<[u8; 64]>)>> {
    let op = operator_pubkey();
    move |channel, holder| {
        let row = (channel.0 == CHANNEL)
            .then(|| table.iter().find(|r| r.0 == holder).map(|r| (op, Some(r.1), Some(r.2))))
            .flatten();
        std::future::ready(row)
    }
}

/// The acceptor's client side of one QUIC admission, as ct-agent presents it: length-framed
/// join, possession signature, FIN, then the EOF-terminated ack (same shape as the edge's own
/// `present_join` test helper).
async fn present_join(conn: &quinn::Connection, req_bytes: &[u8], holder: &SigningKey) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
    send.write_all(&(req_bytes.len() as u16).to_be_bytes()).await.expect("write length");
    send.write_all(req_bytes).await.expect("write request");
    let mut challenge = [0u8; 32];
    if recv.read_exact(&mut challenge).await.is_ok() {
        let sig = holder.sign(&challenge).to_bytes();
        let _ = send.write_all(&sig).await;
    }
    let _ = send.finish();
    recv.read_to_end(512).await.unwrap_or_default()
}

#[tokio::test]
async fn dial_and_call_completes_one_tools_call_through_the_real_edge_rendezvous_and_relay_745() {
    let bridge_holder = SigningKey::from_bytes(&[0xa1u8; 32]);
    let bridge_noise = ct_common::noise::generate_static_keypair();
    let agent_holder = SigningKey::from_bytes(&[0xb2u8; 32]);
    let agent_noise = ct_common::noise::generate_static_keypair();
    let table = Arc::new(vec![
        member_row(&bridge_holder, &bridge_noise.public),
        member_row(&agent_holder, &agent_noise.public),
    ]);

    // Two real edge endpoints: the rendezvous port and the relay port.
    let (rendezvous_server, rendezvous_cert) = build_server_endpoint_with_cert().expect("rendezvous server");
    let (relay_server, relay_cert) = build_server_endpoint_with_cert().expect("relay server");
    let rendezvous_addr = rendezvous_server.local_addr().expect("addr");
    let relay_addr = relay_server.local_addr().expect("addr");
    let rendezvous_task = {
        let table = table.clone();
        tokio::spawn(async move { broker_channel_rendezvous(&rendezvous_server, NOW, authorize_for(table)).await })
    };
    let relay_task = {
        let table = table.clone();
        tokio::spawn(async move { broker_channel_relay(&relay_server, NOW, authorize_for(table)).await })
    };

    // The relay-only acceptor (what `ct-agent channel --serve` with CT_CHANNEL_RELAY_ONLY=1 does).
    let bridge_holder_hex: String = bridge_holder.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let agent_holder_pub = agent_holder.verifying_key().to_bytes();
    let expect_bridge_hex = bridge_holder_hex.clone();
    let acceptor = tokio::spawn(async move {
        let req = ChannelJoinRequest {
            grant: grant(&agent_holder, Direction::Accept),
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        }
        .encode();

        // Hop 1: rendezvous, ack-and-close.
        let rendezvous_client = build_client_endpoint(rendezvous_cert).expect("client");
        let rendezvous_conn = rendezvous_client.connect(rendezvous_addr, "localhost").expect("cfg").await.expect("conn");
        let ack1 = tokio::time::timeout(STEP_TIMEOUT, present_join(&rendezvous_conn, &req, &agent_holder))
            .await
            .expect("rendezvous ack in time");
        let ack1 = String::from_utf8_lossy(&ack1).into_owned();
        assert!(ack1.starts_with("OK relay-only "), "acceptor's rendezvous ack names the relay-only bridge: {ack1:?}");
        drop(rendezvous_conn);

        // Hop 2: relay admission, then accept the edge-opened session stream.
        let relay_client = build_client_endpoint(relay_cert).expect("client");
        let relay_conn = relay_client.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
        let ack2 = tokio::time::timeout(STEP_TIMEOUT, present_join(&relay_conn, &req, &agent_holder))
            .await
            .expect("relay ack in time");
        let ack2 = String::from_utf8_lossy(&ack2).into_owned();
        assert!(ack2.starts_with("OK relay-only "), "acceptor's relay ack: {ack2:?}");
        assert!(ack2.contains(&expect_bridge_hex), "the relay paired the acceptor with the BRIDGE holder: {ack2:?}");

        let (mut send, mut recv) = tokio::time::timeout(STEP_TIMEOUT, relay_conn.accept_bi())
            .await
            .expect("the edge opens the session stream toward the acceptor once msg1 arrives")
            .expect("accept_bi");
        let session = tokio::time::timeout(STEP_TIMEOUT, a2a_respond(&mut send, &mut recv, &agent_noise.private))
            .await
            .expect("handshake in time")
            .expect("Noise_IK responder");
        // From here on the acceptor is the PRODUCTION shape (ct-agent `serve_local` +
        // `noise_pump`): the pump writes each decrypted record into a duplex whose far end
        // is ct-common's own `serve_request_loop`, which reads APP-LAYER u16 frames and
        // answers through `write_message`. An acceptor that decrypted with `a2a_recv` and
        // parsed the bytes directly accepted a bare, unframed request that the real one
        // stalls on forever -- the post-#749 "pairs, then times out at exactly 20 s" bug.
        let (session_side, serve_side) = tokio::io::duplex(1 << 16);
        let serve = tokio::spawn(async move {
            let (mut sr, mut sw) = tokio::io::split(serve_side);
            serve_request_loop(&mut sw, &mut sr, |request: Vec<u8>| async move {
                let request: serde_json::Value = serde_json::from_slice(&request).expect("JSON-RPC request");
                assert_eq!(request["method"], "tools/call");
                assert_eq!(request["params"]["name"], "echo");
                let reply = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"].clone(),
                    "result": { "echo": request["params"]["arguments"].clone() },
                });
                serde_json::to_vec(&reply).unwrap()
            })
            .await
        });
        tokio::time::timeout(STEP_TIMEOUT, noise_pump(session, tokio::io::join(recv, send), session_side))
            .await
            .expect("the one-call session ends in time")
            .expect("noise_pump");
        let _ = serve.await;
        // The bridge hangs up after its one reply; wait for that (bounded) so the splice
        // ends from the initiator side, as it does live.
        let _ = tokio::time::timeout(STEP_TIMEOUT, relay_conn.closed()).await;
        (ack1, ack2)
    });

    // Under test: the bridge dialer, two hops, one call.
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        ct_common::channel_dial::dial_and_call(
            rendezvous_addr,
            relay_addr,
            grant(&bridge_holder, Direction::Initiate),
            &bridge_holder,
            &bridge_noise.private,
            "echo",
            serde_json::json!({ "hello": "world" }),
        ),
    )
    .await
    .expect("the dial completes well within its budgets on loopback");
    assert_eq!(
        result,
        Ok(serde_json::json!({ "echo": { "hello": "world" } })),
        "the tools/call reply came back through the real rendezvous + relay"
    );

    let (ack1, ack2) = tokio::time::timeout(STEP_TIMEOUT, acceptor).await.expect("acceptor done").expect("acceptor ok");
    assert!(ack1.contains(&bridge_holder_hex), "the rendezvous ack carried the bridge's attested triple: {ack1:?}");
    assert!(ack2.ends_with(" sp=1"), "loopback pair is tagged same-public-IP: {ack2:?}");

    // The real completers' own verdicts: the rendezvous pairing names the bridge as the
    // initiator; the relay's `broker_channel_relay` returns once the splice ends (the
    // initiator hung up), and its pairing must agree.
    let rendezvous_pairing = tokio::time::timeout(STEP_TIMEOUT, rendezvous_task)
        .await
        .expect("rendezvous completer returns once both members closed")
        .expect("join")
        .expect("rendezvous pairing");
    assert_eq!(rendezvous_pairing.initiator_holder, bridge_holder.verifying_key().to_bytes());
    assert_eq!(rendezvous_pairing.acceptor_holder, agent_holder_pub);
    let relay_outcome = tokio::time::timeout(STEP_TIMEOUT, relay_task).await.expect("relay completer returns").expect("join");
    match relay_outcome {
        Ok(pairing) => assert_eq!(pairing.initiator_holder, bridge_holder.verifying_key().to_bytes()),
        // The splice ends when the bridge drops its relay connection after the reply; the
        // edge may report that teardown as an error AFTER both acks -- either way the pairing
        // happened (both acks above prove it), so only a pre-ack failure is a bug.
        Err(e) => assert!(
            e.to_string().contains("after both sides acked"),
            "the relay must have paired and acked both sides before the initiator hung up: {e}"
        ),
    }
}

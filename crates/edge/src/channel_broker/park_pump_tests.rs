use super::*;

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test(start_paused = true)]
async fn park_pump_ticks_nuls_on_schedule_while_client_writes_without_reading_027() {
    // (p3-a): AUF-20261005-019 decouples the two directions -- a client that writes
    // into the parked leg but never reads its own ticks must not perturb the keepalive
    // schedule on the other direction: still exactly one NUL per PARK_KEEPALIVE_INTERVAL,
    // first tick one full interval after parking.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, real) = tokio::io::duplex(4096);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (_lv, dead) = ParkLiveness::monitored();
    let mut parked_end = spawn_park_keepalive_pump(boxed, true, dead);
    let (mut client_r, mut client_w) = tokio::io::split(client_end);

    // Client writes continuously (auf direction) without ever draining its own ticks;
    // the duplex's bounded buffer naturally throttles it once nobody drains the far side.
    let _writer = tokio::spawn(async move {
        loop {
            if client_w.write_all(b"x").await.is_err() {
                break;
            }
        }
    });

    let mut nul = [0u8; 1];
    for i in 0..3u32 {
        tokio::time::advance(PARK_KEEPALIVE_INTERVAL).await;
        client_r.read_exact(&mut nul).await.expect("keepalive byte");
        assert_eq!(
            nul[0], 0,
            "keepalive tick {i} stays a lone NUL even while the client writes"
        );
    }

    // The client's writes still reach the parked side undisturbed.
    let mut got = [0u8; 3];
    parked_end
        .read_exact(&mut got)
        .await
        .expect("client payload still relays");
    assert_eq!(&got[..], b"xxx");
}

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test(start_paused = true)]
async fn park_pump_ack_chunk_arrives_with_no_nul_inside_or_trailing_027() {
    // (p3-b): once the first splice->client chunk starts, `parked` flips to false
    // before the write begins -- the chunk's bytes must be byte-exact with no NUL
    // woven in or appended, even though the ack itself contains no zero bytes.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, real) = tokio::io::duplex(4096);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (_lv, dead) = ParkLiveness::monitored();
    let mut parked_end = spawn_park_keepalive_pump(boxed, true, dead);
    let (mut client_r, _client_w) = tokio::io::split(client_end);

    // Two parked intervals pass first (two NULs), then the ack chunk lands.
    let mut nul = [0u8; 1];
    for _ in 0..2u32 {
        tokio::time::advance(PARK_KEEPALIVE_INTERVAL).await;
        client_r.read_exact(&mut nul).await.expect("keepalive byte");
        assert_eq!(nul[0], 0);
    }
    let ack = b"OK 203.0.113.5:9999";
    parked_end.write_all(ack).await.expect("ack");
    parked_end.flush().await.expect("flush");
    let mut got = vec![0u8; ack.len()];
    client_r
        .read_exact(&mut got)
        .await
        .expect("ack relayed whole");
    assert_eq!(&got[..], ack, "no NUL woven inside the chunk");

    // Nothing trails the chunk: no byte (NUL or otherwise) shows up afterwards.
    let trailing = tokio::time::timeout(PARK_KEEPALIVE_INTERVAL * 3, async {
        let mut b = [0u8; 1];
        client_r.read_exact(&mut b).await.map(|_| b[0])
    })
    .await;
    assert!(
        trailing.is_err(),
        "no byte trails the ack, got {trailing:?}"
    );
}

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test]
async fn park_pump_dead_flag_reflects_eof_only_on_a_still_parked_keepalive_leg_027() {
    // (p3-c): #499 slice B's corpse semantics, exercised directly against the pump --
    // a clean client EOF is death ONLY while a keepalive-negotiated leg is still parked;
    // everywhere else (no keepalive, or already past the first ack chunk) it is a
    // tolerated legacy half-close and the dead flag must stay clear.
    use tokio::io::AsyncWriteExt;

    // (1) keepalive=true, parked, client EOF -> dead.
    {
        let (mut client_end, real) = tokio::io::duplex(4096);
        let boxed: BoxedChannelStream = Box::pin(real);
        let (lv, dead) = ParkLiveness::monitored();
        let _parked_end = spawn_park_keepalive_pump(boxed, true, dead);
        client_end.shutdown().await.expect("client half-close");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            lv.is_dead(),
            "KA-negotiated EOF while parked must flag death"
        );
    }

    // (2) keepalive=false, parked, client EOF -> tolerated, not dead.
    {
        let (mut client_end, real) = tokio::io::duplex(4096);
        let boxed: BoxedChannelStream = Box::pin(real);
        let (lv, dead) = ParkLiveness::monitored();
        let _parked_end = spawn_park_keepalive_pump(boxed, false, dead);
        client_end.shutdown().await.expect("client half-close");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !lv.is_dead(),
            "a legacy half-close on a plain leg must not flag death"
        );
    }

    // (3) keepalive=true, EOF AFTER the first ack chunk (no longer parked) -> not dead.
    {
        let (mut client_end, real) = tokio::io::duplex(4096);
        let boxed: BoxedChannelStream = Box::pin(real);
        let (lv, dead) = ParkLiveness::monitored();
        let mut parked_end = spawn_park_keepalive_pump(boxed, true, dead);
        parked_end.write_all(b"OK").await.expect("ack");
        parked_end.flush().await.expect("flush");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        client_end
            .shutdown()
            .await
            .expect("client half-close after the ack");
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !lv.is_dead(),
            "EOF after the first chunk must not flag death"
        );
    }
}

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test]
async fn park_pump_still_delivers_a_full_chunk_to_a_half_closed_plain_client_027() {
    // (p3-d): AUF-20261005-019's HalfClosed tolerance (#499 slice B) keeps (ab) running
    // alone after a plain client's half-close -- the outbound chunk (ack/EX) must still
    // reach the client byte-exact.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, real) = tokio::io::duplex(4096);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (_lv, dead) = ParkLiveness::monitored();
    let mut parked_end = spawn_park_keepalive_pump(boxed, false, dead);
    let (mut client_r, mut client_w) = tokio::io::split(client_end);

    client_w
        .shutdown()
        .await
        .expect("client half-closes its write side");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    let chunk = b"OK 203.0.113.5:9999";
    parked_end
        .write_all(chunk)
        .await
        .expect("chunk still writes");
    parked_end.flush().await.expect("flush");
    let mut got = vec![0u8; chunk.len()];
    client_r
        .read_exact(&mut got)
        .await
        .expect("half-closed client still receives the full chunk");
    assert_eq!(&got[..], chunk);
}

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test]
async fn park_pump_teardown_on_drop_closes_the_real_connection_to_the_client_027() {
    // (p3-e): dropping the duplex end the pairer holds (the parked side) must close
    // the real connection -- (ab) sees far_r EOF, breaks, and shuts real_w down, so the
    // client observes a clean EOF instead of a silently hung connection.
    use tokio::io::AsyncReadExt;
    let (mut client_end, real) = tokio::io::duplex(4096);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (_lv, dead) = ParkLiveness::monitored();
    let parked_end = spawn_park_keepalive_pump(boxed, false, dead);
    drop(parked_end);

    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_end.read_to_end(&mut buf),
    )
    .await
    .expect("teardown must complete")
    .expect("read to EOF");
    assert!(buf.is_empty(), "no stray bytes on teardown, got {buf:?}");
}

// trace: REQ-0006, AUF-20261005-019, AUF-20261005-023, AUF-20261005-027
//
// (f1): woertliche Kopie von park_pump_relays_32mib_each_way_with_concurrent_read_write_auf019
// in channel_broker.rs -- einzig die beiden Client-Duplexe sind 256 KiB statt 4096 Bytes.
// Befund (gemessen auf 67ff320, vor dem Umbau): mit duplex(4096) liest die Pumpe nie ein
// volles 16-KiB-Stueck, der innere Duplex laeuft nicht voll, und der Test bleibt gruen ohne
// die Feldform zu messen -- 30/30 mehrfaedig und 5/5 einfaedig rot mit duplex(256*1024),
// jeweils "beide Richtungen muessen binnen 20s ankommen: Elapsed(())".
#[tokio::test]
async fn park_pump_relays_32mib_each_way_with_256k_client_duplex_auf027() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const LEN: usize = 32 * 1024 * 1024;
    let (client_a, real_a) = tokio::io::duplex(256 * 1024);
    let (client_b, real_b) = tokio::io::duplex(256 * 1024);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), false, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), false, dead_b);
    let _splice =
        tokio::spawn(async move { crate::relay::relay_streams(leg_a, leg_b, "auf027_f1").await });
    let (mut a_r, mut a_w) = tokio::io::split(client_a);
    let (mut b_r, mut b_w) = tokio::io::split(client_b);

    // Je Client: Schreib- und Lesehaelfte gemeinsam gejoint, nie erst schreiben und dann lesen.
    let client_a_task = tokio::spawn(async move {
        let write = async {
            a_w.write_all(&vec![0xa5u8; LEN]).await.expect("a write");
            a_w.flush().await.expect("a flush");
        };
        let read = async {
            let mut got = vec![0u8; LEN];
            a_r.read_exact(&mut got).await.expect("a read");
            got
        };
        let (_, got) = tokio::join!(write, read);
        got
    });
    let client_b_task = tokio::spawn(async move {
        let write = async {
            b_w.write_all(&vec![0xb5u8; LEN]).await.expect("b write");
            b_w.flush().await.expect("b flush");
        };
        let read = async {
            let mut got = vec![0u8; LEN];
            b_r.read_exact(&mut got).await.expect("b read");
            got
        };
        let (_, got) = tokio::join!(write, read);
        got
    });

    let (got_a, got_b) = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let got_a = client_a_task.await.expect("a task");
        let got_b = client_b_task.await.expect("b task");
        (got_a, got_b)
    })
    .await
    .expect("beide Richtungen muessen binnen 20s ankommen");

    assert!(
        got_a.iter().all(|&x| x == 0xb5),
        "a muss b's Muster empfangen"
    );
    assert!(
        got_b.iter().all(|&x| x == 0xa5),
        "b muss a's Muster empfangen"
    );
}

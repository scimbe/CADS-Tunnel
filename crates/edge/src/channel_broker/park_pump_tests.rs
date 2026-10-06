// trace: REQ-0006, AUF-20261006-002
use super::*;

// AUF-20261006-002 (c): event-driven replacement for a fixed "yield 8 times then check
// dead.load()" -- returns immediately once dead flips true; otherwise waits until the
// flag has been observed stable (unchanged) for a short real-time window, bounded overall
// by the 2s timeout so a genuinely stuck case cannot hang the test.
async fn wait_for_dead_flag_settle(lv: &ParkLiveness) {
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut seen = lv.is_dead();
        let mut stable_since = std::time::Instant::now();
        loop {
            if seen {
                return;
            }
            tokio::task::yield_now().await;
            let now = lv.is_dead();
            if now != seen {
                seen = now;
                stable_since = std::time::Instant::now();
                continue;
            }
            if stable_since.elapsed() >= std::time::Duration::from_millis(20) {
                return;
            }
        }
    })
    .await;
}

// AUF-20261006-002 (c): event-driven replacement for a fixed sleep(200ms) "Stau sicher
// aufgebaut" guess -- waits until a writer-reported byte counter has stopped increasing
// for 250ms (the backpressure has genuinely built up), bounded overall by a 2s timeout.
async fn wait_for_write_stall(progress: &std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::Ordering;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut last = progress.load(Ordering::Relaxed);
        let mut stable_for = std::time::Duration::ZERO;
        let step = std::time::Duration::from_millis(10);
        while stable_for < std::time::Duration::from_millis(250) {
            tokio::time::sleep(step).await;
            let now = progress.load(Ordering::Relaxed);
            if now == last {
                stable_for += step;
            } else {
                last = now;
                stable_for = std::time::Duration::ZERO;
            }
        }
    })
    .await
    .expect("writer must stall within 2s");
}

// Art: BEWEIS (haengt real auf a0267e8 -- siehe PR-Text)
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

// Art: ERHALT (gruen auch auf a0267e8)
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

// Art: ERHALT (gruen auch auf a0267e8)
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
        wait_for_dead_flag_settle(&lv).await;
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
        wait_for_dead_flag_settle(&lv).await;
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
        wait_for_dead_flag_settle(&lv).await;
        client_end
            .shutdown()
            .await
            .expect("client half-close after the ack");
        wait_for_dead_flag_settle(&lv).await;
        assert!(
            !lv.is_dead(),
            "EOF after the first chunk must not flag death"
        );
    }
}

// Art: ERHALT (gruen auch auf a0267e8)
// trace: REQ-0006, AUF-20261005-019, AUF-20261005-027
#[tokio::test]
async fn park_pump_still_delivers_a_full_chunk_to_a_half_closed_plain_client_027() {
    // (p3-d): AUF-20261005-019's HalfClosed tolerance (#499 slice B) keeps (ab) running
    // alone after a plain client's half-close -- the outbound chunk (ack/EX) must still
    // reach the client byte-exact.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, real) = tokio::io::duplex(4096);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (lv, dead) = ParkLiveness::monitored();
    let mut parked_end = spawn_park_keepalive_pump(boxed, false, dead);
    let (mut client_r, mut client_w) = tokio::io::split(client_end);

    client_w
        .shutdown()
        .await
        .expect("client half-closes its write side");
    wait_for_dead_flag_settle(&lv).await;

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

// Art: ERHALT (gruen auch auf a0267e8)
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

// Art: BEWEIS
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

    // AUF-20261006-002 (b): Laengenpruefung vor all(), sonst waere ein leeres got_a/got_b
    // (durch all() auf leerem Iterator vacuous-wahr) unsichtbar -- hier trivial erfuellt,
    // weil read_exact die vorab auf LEN allozierten Vektoren nie verkuerzt, aber explizit
    // verlangt (AUF-20261006-002 (b)).
    assert_eq!(
        got_a.len(),
        LEN,
        "a's read_exact muss exakt LEN Bytes liefern"
    );
    assert_eq!(
        got_b.len(),
        LEN,
        "b's read_exact muss exakt LEN Bytes liefern"
    );
    assert!(
        got_a.iter().all(|&x| x == 0xb5),
        "a muss b's Muster empfangen"
    );
    assert!(
        got_b.iter().all(|&x| x == 0xa5),
        "b muss a's Muster empfangen"
    );
}

// Art: ERHALT (gruen auch auf a0267e8)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027
//
// (f2) Arm 1, Abbau des Gegenbeins (INC-20261005-203): Client A wird GANZ fallengelassen
// (beide Haelften); Client B muss binnen 3s EOF sehen (read liefert Ok(0)), statt das Bein
// ESTABLISHED mit ungelesener rx_queue zu halten.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_after_peer_close_auf027() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(4096);
    let (mut client_b, real_b) = tokio::io::duplex(4096);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice =
        tokio::spawn(
            async move { crate::relay::relay_streams(leg_a, leg_b, "auf027_f2_arm1").await },
        );

    // Beide Clients tauschen zuerst je einen kleinen Chunk aus (parked -> false auf beiden Seiten).
    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    client_b.read_exact(&mut buf).await.expect("b read");
    client_b.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    drop(client_a);

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client_b.read(&mut byte))
        .await
        .expect("b muss binnen 3s EOF sehen, statt das Bein offen zu halten")
        .expect("read");
    assert_eq!(n, 0, "b muss EOF (Ok(0)) sehen, nachdem a geschlossen hat");
}

// Art: ERHALT (gruen auch auf a0267e8)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027
//
// (f2) Arm 2, Abbau des Gegenbeins: vor dem Schliessen staut B's Schreiben (ab)_A, weil A
// nicht mehr liest (wie in (p2)); danach schliesst A ganz. B muss trotz des gestauten
// Gegenzweigs binnen 3s EOF sehen -- die Kopplung aus (p2) darf den Abbau nicht blockieren.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_after_peer_close_with_stalled_down_leg_auf027() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(4096);
    let (client_b, real_b) = tokio::io::duplex(4096);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice =
        tokio::spawn(
            async move { crate::relay::relay_streams(leg_a, leg_b, "auf027_f2_arm2").await },
        );
    let (mut b_r, mut b_w) = tokio::io::split(client_b);

    // Beide Clients tauschen zuerst je einen kleinen Chunk aus (parked -> false auf beiden Seiten).
    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    b_r.read_exact(&mut buf).await.expect("b read");
    b_w.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    // b -> a staut, weil a ab jetzt nicht mehr liest; die Aufgabe wird nicht abgewartet.
    // AUF-20261006-002 (c): der Schreiber meldet seinen Fortschritt ueber einen AtomicUsize
    // in kleinen Schritten, statt in einem einzigen write_all zu verschwinden, damit der
    // Test auf einen beobachtbaren Stau wartet statt auf eine feste Zeitspanne zu hoffen.
    let progress = Arc::new(AtomicUsize::new(0));
    let progress_w = progress.clone();
    let _stuck = tokio::spawn(async move {
        let payload = vec![0xb5u8; 1 << 20];
        let mut written = 0usize;
        while written < payload.len() {
            let end = (written + 4096).min(payload.len());
            if b_w.write_all(&payload[written..end]).await.is_err() {
                break;
            }
            written = end;
            progress_w.store(written, Ordering::Relaxed);
        }
    });
    wait_for_write_stall(&progress).await;

    drop(client_a);

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), b_r.read(&mut byte))
        .await
        .expect("b muss trotz gestautem Gegenzweig binnen 3s EOF sehen")
        .expect("read");
    assert_eq!(n, 0, "b muss EOF (Ok(0)) sehen, nachdem a geschlossen hat");
}

// Art: ERHALT (gruen auch auf a0267e8)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027
//
// (f2) Arm 3 (core's "Nein-Fall 1"): A schreibt so viel, dass (auf)_A im far_w.write_all
// steht, weil B nichts abnimmt; dann schliesst A ganz. B muss danach, sobald es die
// gestauten Bytes liest, binnen 3s nach dem letzten Byte EOF sehen.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_when_up_leg_is_blocked_in_write_auf027() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(4096);
    let (client_b, real_b) = tokio::io::duplex(4096);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice =
        tokio::spawn(
            async move { crate::relay::relay_streams(leg_a, leg_b, "auf027_f2_arm3").await },
        );
    let (mut b_r, mut b_w) = tokio::io::split(client_b);

    // Beide Clients tauschen zuerst je einen kleinen Chunk aus (parked -> false auf beiden Seiten).
    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    b_r.read_exact(&mut buf).await.expect("b read");
    b_w.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    // a -> b staut, weil b ab jetzt nicht mehr liest, bis (auf)_A in far_w.write_all steht.
    // AUF-20261006-002 (c): wie in Arm 2, Fortschritt ueber AtomicUsize statt fester Sleep-Zeit.
    let progress = Arc::new(AtomicUsize::new(0));
    let progress_w = progress.clone();
    let writer = tokio::spawn(async move {
        let payload = vec![0xa5u8; 1 << 20];
        let mut written = 0usize;
        while written < payload.len() {
            let end = (written + 4096).min(payload.len());
            if client_a.write_all(&payload[written..end]).await.is_err() {
                break;
            }
            written = end;
            progress_w.store(written, Ordering::Relaxed);
        }
    });
    wait_for_write_stall(&progress).await;

    // A schliesst ganz, waehrend (auf)_A im Schreiben steht.
    writer.abort();

    // B liest die gestauten Bytes und muss binnen 3s nach dem letzten Byte EOF sehen.
    let mut got = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), b_r.read_to_end(&mut got))
        .await
        .expect("b muss binnen 3s nach dem letzten Byte EOF sehen")
        .expect("read to EOF");
    // AUF-20261006-002 (b): all() ist fuer ein leeres got vacuous wahr -- die Laengenpruefung
    // muss zuerst scheitern, wenn b in Wahrheit nichts empfangen hat.
    assert!(
        !got.is_empty(),
        "b muss die gestauten Bytes tatsaechlich empfangen, nicht nur ein leeres EOF"
    );
    assert!(
        got.len() >= 4096,
        "b muss mindestens einen vollen Puffer der gestauten Bytes empfangen, got {} bytes",
        got.len()
    );
    assert!(
        got.iter().all(|&x| x == 0xa5),
        "die gestauten Bytes muessen a's Muster tragen"
    );
}

// Art: ERHALT (gruen auch auf a0267e8 -- kein Test belegt den Abbau des Gegenbeins gegen den alten Code)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027, AUF-20261006-002
//
// (a) Feldform-Variante von (f2) Arm 1 mit 256-KiB-Client-Duplexen auf beiden Seiten statt
// 4096 Byte (AUF-20261006-002), um auszuschliessen, dass der kleine Testpuffer den Abbau
// zufaellig begruenstigt.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_after_peer_close_256k_auf002() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(256 * 1024);
    let (mut client_b, real_b) = tokio::io::duplex(256 * 1024);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice = tokio::spawn(async move {
        crate::relay::relay_streams(leg_a, leg_b, "auf002_f2_arm1_256k").await
    });

    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    client_b.read_exact(&mut buf).await.expect("b read");
    client_b.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    drop(client_a);

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client_b.read(&mut byte))
        .await
        .expect("b muss binnen 3s EOF sehen, statt das Bein offen zu halten")
        .expect("read");
    assert_eq!(n, 0, "b muss EOF (Ok(0)) sehen, nachdem a geschlossen hat");
}

// Art: ERHALT (gruen auch auf a0267e8 -- kein Test belegt den Abbau des Gegenbeins gegen den alten Code)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027, AUF-20261006-002
//
// (a) Feldform-Variante von (f2) Arm 2 mit 256-KiB-Client-Duplexen auf beiden Seiten.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_after_peer_close_with_stalled_down_leg_256k_auf002() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(256 * 1024);
    let (client_b, real_b) = tokio::io::duplex(256 * 1024);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice = tokio::spawn(async move {
        crate::relay::relay_streams(leg_a, leg_b, "auf002_f2_arm2_256k").await
    });
    let (mut b_r, mut b_w) = tokio::io::split(client_b);

    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    b_r.read_exact(&mut buf).await.expect("b read");
    b_w.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    // Groesser als die 256-KiB-Duplexe, damit der Stau trotz des groesseren Puffers entsteht.
    let progress = Arc::new(AtomicUsize::new(0));
    let progress_w = progress.clone();
    let _stuck = tokio::spawn(async move {
        let payload = vec![0xb5u8; 4 << 20];
        let mut written = 0usize;
        while written < payload.len() {
            let end = (written + 4096).min(payload.len());
            if b_w.write_all(&payload[written..end]).await.is_err() {
                break;
            }
            written = end;
            progress_w.store(written, Ordering::Relaxed);
        }
    });
    wait_for_write_stall(&progress).await;

    drop(client_a);

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), b_r.read(&mut byte))
        .await
        .expect("b muss trotz gestautem Gegenzweig binnen 3s EOF sehen")
        .expect("read");
    assert_eq!(n, 0, "b muss EOF (Ok(0)) sehen, nachdem a geschlossen hat");
}

// Art: ERHALT (gruen auch auf a0267e8 -- kein Test belegt den Abbau des Gegenbeins gegen den alten Code)
// trace: REQ-0006, AUF-20261005-023, AUF-20261005-027, AUF-20261006-002
//
// (a) Feldform-Variante von (f2) Arm 3 mit 256-KiB-Client-Duplexen auf beiden Seiten.
#[tokio::test]
async fn park_pump_far_leg_sees_eof_when_up_leg_is_blocked_in_write_256k_auf002() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(256 * 1024);
    let (client_b, real_b) = tokio::io::duplex(256 * 1024);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), true, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), true, dead_b);
    let _splice = tokio::spawn(async move {
        crate::relay::relay_streams(leg_a, leg_b, "auf002_f2_arm3_256k").await
    });
    let (mut b_r, mut b_w) = tokio::io::split(client_b);

    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    b_r.read_exact(&mut buf).await.expect("b read");
    b_w.write_all(b"b2a1").await.expect("b write");
    client_a.read_exact(&mut buf).await.expect("a read");

    let progress = Arc::new(AtomicUsize::new(0));
    let progress_w = progress.clone();
    let writer = tokio::spawn(async move {
        let payload = vec![0xa5u8; 4 << 20];
        let mut written = 0usize;
        while written < payload.len() {
            let end = (written + 4096).min(payload.len());
            if client_a.write_all(&payload[written..end]).await.is_err() {
                break;
            }
            written = end;
            progress_w.store(written, Ordering::Relaxed);
        }
    });
    wait_for_write_stall(&progress).await;

    writer.abort();

    let mut got = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), b_r.read_to_end(&mut got))
        .await
        .expect("b muss binnen 3s nach dem letzten Byte EOF sehen")
        .expect("read to EOF");
    assert!(
        !got.is_empty(),
        "b muss die gestauten Bytes tatsaechlich empfangen, nicht nur ein leeres EOF"
    );
    assert!(
        got.len() >= 4096,
        "b muss mindestens einen vollen Puffer der gestauten Bytes empfangen, got {} bytes",
        got.len()
    );
    assert!(
        got.iter().all(|&x| x == 0xa5),
        "die gestauten Bytes muessen a's Muster tragen"
    );
}

// Art: BEWEIS (haengt real auf a0267e8/da990b0 -- siehe PR-Text)
// trace: REQ-0006, AUF-20261006-002
//
// (e) Nicht-KA-Bein, voller Client-Close (INC-20261005-203): beide Beine ohne Keepalive.
// Auf dem Stand vor dieser Korrektur schliesst (auf) bei Ok(0)+keepalive==false nur sich
// selbst (HalfClosed) ohne far_w zu schliessen; die aeussere Schleife wartet dann nur noch
// auf splice_to_client (far_r-EOF), das nie kommt, obwohl der Client ganz (beide Haelften)
// geschlossen hat -- b sieht nie EOF und die Pumpe lebt weiter.
#[tokio::test]
async fn park_pump_plain_leg_propagates_client_close_to_far_side_auf002() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client_a, real_a) = tokio::io::duplex(4096);
    let (mut client_b, real_b) = tokio::io::duplex(4096);
    let (_la, dead_a) = ParkLiveness::monitored();
    let (_lb, dead_b) = ParkLiveness::monitored();
    let leg_a = spawn_park_keepalive_pump(Box::pin(real_a), false, dead_a);
    let leg_b = spawn_park_keepalive_pump(Box::pin(real_b), false, dead_b);
    let _splice = tokio::spawn(async move {
        crate::relay::relay_streams(leg_a, leg_b, "auf002_plain_full_close").await
    });

    client_a.write_all(b"a2b1").await.expect("a write");
    let mut buf = [0u8; 4];
    client_b.read_exact(&mut buf).await.expect("b read");

    drop(client_a);

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), client_b.read(&mut byte))
        .await
        .expect("b muss binnen 3s EOF sehen, statt dass die Pumpe weiterlebt")
        .expect("read");
    assert_eq!(n, 0, "b muss EOF (Ok(0)) sehen, nachdem a ganz geschlossen hat");
}

// Art: BEWEIS
// trace: REQ-0006, AUF-20261006-002
//
// (e) Nicht-KA-Bein, Halbschluss: der Client schliesst nur die Schreibhaelfte (shutdown);
// die Gegenseite (direkt am zurueckgegebenen Pumpen-Ende, wie in den p3/f1-ERHALT-Tests)
// muss binnen 3s EOF sehen UND danach noch 64 KiB an den Client liefern koennen, die der
// Client vollstaendig liest -- sichert, dass das Schliessen von far_w im (auf)-Zweig nur
// die Client->Gegenseite-Richtung trifft und (ab) (der Ruecklauf) unveraendert weiterlaeuft.
#[tokio::test]
async fn park_pump_plain_leg_propagates_half_close_and_still_delivers_auf002() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client_end, real) = tokio::io::duplex(128 * 1024);
    let boxed: BoxedChannelStream = Box::pin(real);
    let (_lv, dead) = ParkLiveness::monitored();
    let mut parked_end = spawn_park_keepalive_pump(boxed, false, dead);
    let (mut client_r, mut client_w) = tokio::io::split(client_end);

    client_w
        .shutdown()
        .await
        .expect("client half-closes its write side");

    let mut byte = [0u8; 1];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), parked_end.read(&mut byte))
        .await
        .expect("Gegenseite muss binnen 3s EOF sehen, nachdem der Client die Schreibhaelfte geschlossen hat")
        .expect("read");
    assert_eq!(
        n, 0,
        "Gegenseite muss EOF (Ok(0)) sehen, nachdem der Client die Schreibhaelfte geschlossen hat"
    );

    let payload = vec![0xc3u8; 64 * 1024];
    parked_end.write_all(&payload).await.expect("Gegenseite write");
    parked_end.flush().await.expect("Gegenseite flush");

    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(std::time::Duration::from_secs(3), client_r.read_exact(&mut got))
        .await
        .expect("Client muss binnen 3s die vollen 64 KiB empfangen")
        .expect("read");
    assert_eq!(got, payload, "Client muss die vollen 64 KiB unveraendert empfangen");
}

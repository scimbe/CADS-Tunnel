//! #31 FD3 — the client's transport fallback ladder. Restrictive client networks
//! (HAW field evidence: `:8090`/`:4433`/UDP all time out) allow only outbound TCP
//! :443, so a client must try a sequence of `(transport, port)` rungs and remember
//! which one worked *per network* — not just today's two-rung QUIC:4433 →
//! TLS-TCP:4433. This module (FD3-a) is the pure ordering + per-network cache; the
//! live socket dialing is injected (FD3-b), so the ladder logic is fully testable
//! without real sockets or timeouts.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;

/// One rung of the fallback ladder: a transport over a port on the edge host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rung {
    /// QUIC (UDP) on the given port.
    Quic(u16),
    /// TLS-over-TCP on the given port.
    TlsTcp(u16),
}

/// The unified front-door port (FD2) — a fixed, restrictive-network-friendly
/// fallback that every deployment exposes, independent of the edge's own port.
pub const FRONT_DOOR_PORT: u16 = 443;

/// The default ladder for an edge on `edge_port`:
/// `QUIC:<edge_port> → TLS-TCP:<edge_port> → QUIC:443 → TLS-TCP:443`.
/// Ordered most-direct/fastest first (QUIC on the edge's own port, taken from the
/// capability's `edge_addr` — #74), most restrictive-network-friendly last
/// (TLS-TCP on :443, the one port such networks reliably allow). The `:443` rungs
/// reach the unified front door (FD2). When the edge already runs on :443 the
/// front-door rungs coincide and are not duplicated.
pub fn default_ladder(edge_port: u16) -> Vec<Rung> {
    let mut rungs = vec![Rung::Quic(edge_port), Rung::TlsTcp(edge_port)];
    for r in [Rung::Quic(FRONT_DOOR_PORT), Rung::TlsTcp(FRONT_DOOR_PORT)] {
        if !rungs.contains(&r) {
            rungs.push(r);
        }
    }
    rungs
}

/// Remembers the last rung that worked, keyed by an opaque network signature, so a
/// re-connect on the same restrictive network skips straight to the rung that
/// succeeded before instead of re-paying a timeout on every blocked rung first.
#[derive(Default, Clone)]
pub struct LadderCache {
    by_network: HashMap<String, Rung>,
}

impl LadderCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The rung last known to work on `network`, if any.
    pub fn remembered(&self, network: &str) -> Option<Rung> {
        self.by_network.get(network).copied()
    }

    /// Record `rung` as the working rung for `network`.
    pub fn remember(&mut self, network: &str, rung: Rung) {
        self.by_network.insert(network.to_string(), rung);
    }
}

/// The order to attempt rungs for `network`: the cached-good rung first (when it
/// is still part of `ladder`), then the rest of `ladder` in its natural order,
/// with the cached rung not repeated. A stale cached rung (no longer in `ladder`)
/// is ignored, and an empty cache yields `ladder` unchanged.
pub fn attempt_order(cache: &LadderCache, network: &str, ladder: &[Rung]) -> Vec<Rung> {
    let mut order: Vec<Rung> = Vec::with_capacity(ladder.len());
    if let Some(cached) = cache.remembered(network) {
        if ladder.contains(&cached) {
            order.push(cached);
        }
    }
    for r in ladder {
        if Some(*r) != order.first().copied() {
            order.push(*r);
        }
    }
    order
}

/// RFC 8305-style "Happy Eyeballs" stagger between starting successive rungs
/// (#367): the rung at position `i` in [`attempt_order`]'s output starts
/// `STAGGER_DELAY * i` after the race begins, so a fast-responding early rung
/// still wins well before a later one even starts, but a blocked/slow early
/// rung no longer blocks later rungs from starting concurrently -- unlike the
/// old fully-serial "await one at a time" walk, the worst case (every rung
/// blocked) is now bounded by the slowest rung's own timeout plus its
/// stagger offset, not the SUM of every rung's own timeout.
const STAGGER_DELAY: Duration = Duration::from_millis(250);

/// Race every rung in [`attempt_order`] concurrently via the injected async
/// `dial`, returning the first rung that connects together with its
/// connection, and recording that rung in `cache` for `network`. `dial`
/// yields `None` for an unreachable rung (a timeout/refusal in the live
/// path). Returns `None` only when every rung fails.
///
/// #367: this used to await each rung one at a time, so a client on a
/// restrictive network paid the SUM of every blocked rung's own timeout
/// before reaching the one that works. Now every rung starts concurrently
/// (staggered — see [`STAGGER_DELAY`]), so the worst case is bounded by the
/// slowest rung's own timeout plus its stagger offset instead. The
/// cache-preferred rung (`attempt_order` already puts it first, unchanged)
/// gets stagger offset zero -- a real, genuine head start, not merely "tried
/// first" the way the old serial walk gave it.
///
/// `dial(rung)` is called eagerly here to build each rung's future, but
/// nothing it does actually runs until that future is first polled -- which
/// the `sleep` inside each entry defers until its own stagger offset elapses
/// -- so a later rung's real dial (its socket connect / QUIC handshake)
/// genuinely doesn't start early just because its future object exists.
///
/// Real cancellation, not merely "stopped awaiting": the first rung to
/// actually connect wins, and every future still pending in the race when
/// this function returns -- including a rung's dial mid-flight, or one still
/// waiting out its own stagger delay and never even touching a socket -- is
/// dropped along with the race itself. That is real, standard Rust async
/// cancellation: neither `dial_edge` nor `tcp_tls_connect` (the two real
/// per-rung dialers in `transport.rs`) registers anything that needs an
/// explicit close — each owns its socket/QUIC endpoint locally and Drop
/// cleans it up, so a dropped in-flight dial leaks nothing.
pub async fn connect_via_ladder<T, F, Fut>(
    cache: &mut LadderCache,
    network: &str,
    ladder: &[Rung],
    mut dial: F,
) -> Option<(Rung, T)>
where
    F: FnMut(Rung) -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let mut races: FuturesUnordered<_> = attempt_order(cache, network, ladder)
        .into_iter()
        .enumerate()
        .map(|(i, rung)| {
            let attempt = dial(rung);
            let offset = STAGGER_DELAY * i as u32;
            async move {
                if !offset.is_zero() {
                    tokio::time::sleep(offset).await;
                }
                (rung, attempt.await)
            }
        })
        .collect();

    while let Some((rung, result)) = races.next().await {
        if let Some(conn) = result {
            cache.remember(network, rung);
            return Some((rung, conn));
        }
    }
    None
}

/// The ladder to attempt, honoring `CT_CLIENT_FORCE_TCP` (#31 FD3-c): when TCP is
/// forced (the UDP-blocked smoke, or a known QUIC-hostile network) keep only the
/// TLS-TCP rungs, so the client doesn't burn a timeout on every QUIC rung first.
pub fn filtered_ladder(force_tcp: bool, edge_port: u16) -> Vec<Rung> {
    let full = default_ladder(edge_port);
    if force_tcp {
        full.into_iter()
            .filter(|r| matches!(r, Rung::TlsTcp(_)))
            .collect()
    } else {
        full
    }
}

/// The cache key for the current network (#31 FD3-c). Prefers an explicit
/// `CT_CLIENT_NET_SIG` (operators/tests pin it); else a best-effort key from the
/// default egress interface's IPv4 /24 (stable per LAN, distinct across networks);
/// else `"default"`. It only needs to be stable-per-network and distinct-across —
/// it is a local cache key and never leaves the host.
pub fn network_signature() -> String {
    network_signature_from(
        std::env::var("CT_CLIENT_NET_SIG").ok(),
        local_egress_ip(),
    )
}

/// Pure core of [`network_signature`] (testable): explicit override wins, else the
/// egress IP is reduced to a stable per-network key.
fn network_signature_from(override_env: Option<String>, egress: Option<std::net::IpAddr>) -> String {
    if let Some(s) = override_env
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return s;
    }
    match egress {
        Some(std::net::IpAddr::V4(ip)) => {
            let o = ip.octets();
            format!("v4:{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Some(std::net::IpAddr::V6(ip)) => format!("v6:{ip}"),
        None => "default".to_string(),
    }
}

/// Best-effort local egress IP: "connect" a UDP socket to an unrouted public
/// address (no packet is sent — it only makes the OS pick the default-route source
/// interface) and read the socket's local address. `None` when there is no route.
fn local_egress_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): never a real host, so nothing is
    // contacted; connect() only fixes the source interface via the routing table.
    sock.connect(("192.0.2.1", 9)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    #[test]
    fn filtered_ladder_keeps_only_tcp_when_forced() {
        assert_eq!(filtered_ladder(false, 4433), default_ladder(4433));
        assert_eq!(
            filtered_ladder(true, 4433),
            vec![Rung::TlsTcp(4433), Rung::TlsTcp(443)],
            "force-TCP drops the QUIC rungs"
        );
        // #74: the forced-TCP ladder also honors a non-4433 edge port.
        assert_eq!(
            filtered_ladder(true, 4434),
            vec![Rung::TlsTcp(4434), Rung::TlsTcp(443)],
            "force-TCP keeps the capability's edge port, then the :443 front door"
        );
    }

    #[test]
    fn default_ladder_honors_the_capability_edge_port() {
        // #74 regression: an edge on a non-4433 port (e.g. the #15 self-host stack
        // on :4434) must be the PRIMARY rungs — the ladder previously hardcoded
        // :4433 and dropped the real port, making such edges unreachable by clients.
        assert_eq!(
            default_ladder(4434),
            vec![
                Rung::Quic(4434),
                Rung::TlsTcp(4434),
                Rung::Quic(443),
                Rung::TlsTcp(443),
            ],
            "the edge's own port leads; :443 front door follows as the fallback"
        );
        // An edge already on :443 must not duplicate the front-door rungs.
        assert_eq!(
            default_ladder(443),
            vec![Rung::Quic(443), Rung::TlsTcp(443)],
            "edge on :443 coincides with the front door — no duplicate rungs"
        );
    }

    #[test]
    fn network_signature_prefers_override_then_reduces_egress_ip() {
        let v4 = Some(IpAddr::V4(Ipv4Addr::new(141, 22, 33, 44)));
        // Explicit override wins verbatim.
        assert_eq!(network_signature_from(Some("pinned-net".into()), v4), "pinned-net");
        // A blank override is ignored -> fall through to the egress key.
        assert_eq!(network_signature_from(Some("  ".into()), v4), "v4:141.22.33.0/24");
        // IPv4 is reduced to its /24; IPv6 kept whole; no route -> "default".
        assert_eq!(network_signature_from(None, v4), "v4:141.22.33.0/24");
        assert_eq!(
            network_signature_from(None, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            "v6:::1"
        );
        assert_eq!(network_signature_from(None, None), "default");
    }

    #[test]
    fn default_ladder_is_direct_first_restrictive_last() {
        assert_eq!(
            default_ladder(4433),
            vec![
                Rung::Quic(4433),
                Rung::TlsTcp(4433),
                Rung::Quic(443),
                Rung::TlsTcp(443),
            ]
        );
    }

    #[test]
    fn attempt_order_puts_the_cached_rung_first_without_duplicating() {
        let ladder = default_ladder(4433);
        let mut cache = LadderCache::new();

        // Empty cache -> the ladder unchanged.
        assert_eq!(attempt_order(&cache, "net-a", &ladder), ladder);

        // A remembered rung is tried first, and appears exactly once.
        cache.remember("net-a", Rung::TlsTcp(443));
        assert_eq!(
            attempt_order(&cache, "net-a", &ladder),
            vec![
                Rung::TlsTcp(443),
                Rung::Quic(4433),
                Rung::TlsTcp(4433),
                Rung::Quic(443),
            ]
        );

        // A different network is unaffected by net-a's cache.
        assert_eq!(attempt_order(&cache, "net-b", &ladder), ladder);

        // A stale cached rung (not in this ladder) is ignored.
        cache.remember("net-c", Rung::TlsTcp(8443));
        assert_eq!(attempt_order(&cache, "net-c", &ladder), ladder);
    }

    // #367: paused clock so the real 250ms-per-position stagger in
    // connect_via_ladder resolves at virtual-time speed, not real wall-clock
    // time -- same pattern/rationale as ct-edge's #111 and ct-common's #269
    // paused-clock tests.
    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_picks_first_reachable_and_caches_it() {
        let ladder = default_ladder(4433);
        let mut cache = LadderCache::new();
        let tried: Arc<Mutex<Vec<Rung>>> = Arc::new(Mutex::new(Vec::new()));

        // Only TLS-TCP:443 is reachable (a :443-only restrictive network). The
        // ladder must walk past the three blocked rungs and land there.
        let tried1 = Arc::clone(&tried);
        let got = connect_via_ladder(&mut cache, "haw", &ladder, |rung| {
            let tried = Arc::clone(&tried1);
            async move {
                tried.lock().unwrap().push(rung);
                (rung == Rung::TlsTcp(443)).then_some("conn")
            }
        })
        .await;
        assert_eq!(got, Some((Rung::TlsTcp(443), "conn")));
        assert_eq!(
            *tried.lock().unwrap(),
            ladder,
            "all rungs attempted in order until the reachable one"
        );
        assert_eq!(cache.remembered("haw"), Some(Rung::TlsTcp(443)), "working rung cached");

        // Re-connect on the same network: the cached rung is tried FIRST, so the
        // blocked rungs are not re-attempted.
        tried.lock().unwrap().clear();
        let tried2 = Arc::clone(&tried);
        let got2 = connect_via_ladder(&mut cache, "haw", &ladder, |rung| {
            let tried = Arc::clone(&tried2);
            async move {
                tried.lock().unwrap().push(rung);
                (rung == Rung::TlsTcp(443)).then_some("conn")
            }
        })
        .await;
        assert_eq!(got2, Some((Rung::TlsTcp(443), "conn")));
        assert_eq!(
            tried.lock().unwrap().first().copied(),
            Some(Rung::TlsTcp(443)),
            "cached rung attempted first on re-connect"
        );
        assert_eq!(tried.lock().unwrap().len(), 1, "no blocked rung re-attempted");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_returns_none_when_every_rung_fails() {
        let ladder = default_ladder(4433);
        let mut cache = LadderCache::new();
        let got: Option<(Rung, &str)> =
            connect_via_ladder(&mut cache, "dead", &ladder, |_rung| async { None }).await;
        assert_eq!(got, None);
        assert_eq!(cache.remembered("dead"), None, "nothing cached when all fail");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_races_concurrently_a_fast_later_rung_beats_a_slow_earlier_one_367() {
        // #367: a fast rung ordered SECOND must still win well before a slow/blocked
        // rung ordered FIRST finishes its own (much longer) timeout -- proving real
        // concurrent racing, not just serial-with-extra-steps. Rung::Quic(1) never
        // resolves within the test's own patience (2s); Rung::TlsTcp(2), staggered
        // 250ms behind it, resolves 50ms after it starts (t=300ms).
        let ladder = vec![Rung::Quic(1), Rung::TlsTcp(2)];
        let mut cache = LadderCache::new();

        let start = tokio::time::Instant::now();
        let got = connect_via_ladder(&mut cache, "race-net", &ladder, |rung| async move {
            match rung {
                Rung::Quic(1) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    None
                }
                Rung::TlsTcp(2) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Some("fast")
                }
                _ => unreachable!(),
            }
        })
        .await;
        let elapsed = start.elapsed();

        assert_eq!(got, Some((Rung::TlsTcp(2), "fast")), "the fast rung wins despite being second");
        assert!(
            elapsed < Duration::from_millis(500),
            "must not wait anywhere near the slow rung's own 2s timeout, elapsed {elapsed:?}"
        );
        assert_eq!(cache.remembered("race-net"), Some(Rung::TlsTcp(2)), "the real winner is cached");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_racing_still_gives_the_cached_rung_a_real_head_start_367() {
        // #367: A and B are BOTH immediately reachable (0-latency dials) -- with no
        // cache, A (first in the raw ladder) would win by simply being polled first.
        // But B is the cache-remembered rung for this network, so attempt_order puts
        // it at position 0 (offset zero) and pushes A back to position 1 (a real
        // 250ms stagger behind it) -- B must still win, proving cache preference
        // survives the move from serial to concurrent racing, not just in
        // attempt_order's own (unit-tested, unchanged) ordering logic.
        let ladder = vec![Rung::Quic(10), Rung::TlsTcp(20)];
        let mut cache = LadderCache::new();
        cache.remember("cached-net", Rung::TlsTcp(20));

        let got = connect_via_ladder(&mut cache, "cached-net", &ladder, |rung| async move {
            Some(match rung {
                Rung::Quic(10) => "A",
                Rung::TlsTcp(20) => "B",
                _ => unreachable!(),
            })
        })
        .await;

        assert_eq!(got, Some((Rung::TlsTcp(20), "B")), "the cache-preferred rung wins its real head start");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_genuinely_cancels_losers_not_just_stops_awaiting_them_367() {
        // #367: three rungs -- one already mid-dial when the race is won (must be
        // cancelled before its own long completion), one that hasn't even started
        // yet (its stagger delay hasn't elapsed -- must never touch its own dial
        // body at all), and the real winner. Each tracks "started" (incremented the
        // instant its OWN dial body -- after any stagger -- begins) and "completed"
        // (incremented only if it runs to its own natural end) independently, so a
        // nonzero started/zero completed is real, observable proof of cancellation,
        // not merely "the test didn't wait for it."
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mid_flight_started = Arc::new(AtomicUsize::new(0));
        let mid_flight_completed = Arc::new(AtomicUsize::new(0));
        let never_started_started = Arc::new(AtomicUsize::new(0));

        let ladder = vec![Rung::Quic(1), Rung::TlsTcp(2), Rung::Quic(3)];
        let mut cache = LadderCache::new();

        let (mfs, mfc, nss) = (
            Arc::clone(&mid_flight_started),
            Arc::clone(&mid_flight_completed),
            Arc::clone(&never_started_started),
        );
        let got = connect_via_ladder(&mut cache, "cancel-net", &ladder, move |rung| {
            let (mfs, mfc, nss) = (Arc::clone(&mfs), Arc::clone(&mfc), Arc::clone(&nss));
            async move {
                match rung {
                    // Position 0 (offset 0): starts immediately, would take 5s to
                    // finish -- must be cancelled long before then.
                    Rung::Quic(1) => {
                        mfs.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        mfc.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                    // Position 1 (offset 250ms): the real winner, done at t=300ms.
                    Rung::TlsTcp(2) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Some("winner")
                    }
                    // Position 2 (offset 500ms): the race is already won at t=300ms,
                    // well before this rung's own 500ms stagger elapses -- its dial
                    // body must never run at all.
                    Rung::Quic(3) => {
                        nss.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                    _ => unreachable!(),
                }
            }
        })
        .await;

        assert_eq!(got, Some((Rung::TlsTcp(2), "winner")));
        assert_eq!(mid_flight_started.load(Ordering::SeqCst), 1, "the mid-flight loser did start");
        assert_eq!(
            mid_flight_completed.load(Ordering::SeqCst),
            0,
            "the mid-flight loser's own 5s sleep must never have been allowed to elapse -- real cancellation"
        );
        assert_eq!(
            never_started_started.load(Ordering::SeqCst),
            0,
            "a rung whose stagger delay hadn't elapsed yet must never touch its own dial body"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_via_ladder_all_fail_waits_the_slowest_stagger_plus_timeout_not_the_sum_367() {
        // #367: two rungs, both eventually fail, each with its own 100ms dial delay.
        // Under the OLD fully-serial walk this would need rung0's 100ms + rung1's
        // 100ms one after the other; concurrently (250ms stagger between starts) the
        // real bound is rung1's own offset+duration (250 + 100 = 350ms), since rung0
        // finishes (at 100ms) well before rung1 even starts.
        let ladder = vec![Rung::Quic(1), Rung::TlsTcp(2)];
        let mut cache = LadderCache::new();

        let start = tokio::time::Instant::now();
        let got: Option<(Rung, &str)> = connect_via_ladder(&mut cache, "all-fail-net", &ladder, |_rung| async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            None
        })
        .await;
        let elapsed = start.elapsed();

        assert_eq!(got, None, "every rung genuinely failed");
        assert_eq!(cache.remembered("all-fail-net"), None, "nothing cached when all fail");
        assert!(
            elapsed >= Duration::from_millis(350),
            "must wait out the real slowest rung's own offset+timeout, elapsed {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(600),
            "must NOT wait the serial sum (would be ~450ms+ with old behavior plus real overhead), elapsed {elapsed:?}"
        );
    }
}

//! #517 V3 — direct-serving decision logic (traffic offload, slice 1).
//!
//! A Grün-tier tunnel whose agent is reachable on an open port (a service
//! provider with a forwarded port -- the common hosted-service case) can serve
//! browsers DIRECTLY instead of relaying every byte through the central edge.
//! The mechanism is DNS: the control plane publishes an `HTTPS`/`A` record
//! pointing at the agent's own endpoint (low TTL), and browsers pick the direct
//! path on their own. The tunnel stays registered at the edge the whole time, so
//! a failing direct path always falls back to the relay -- the operator's
//! standing invariant ("the old service is always preserved").
//!
//! This module is the RISK-FREE core: the pure state machine that turns a stream
//! of external reachability probes into "publish the direct record" / "withdraw
//! it" decisions, with hysteresis so a single flaky probe never flaps a live
//! route. It touches no DNS, no DB, and no network -- those are wired in later
//! slices around this tested nucleus (same staging discipline #495-U used).

/// How many CONSECUTIVE failed probes withdraw a currently-advertised direct
/// record. Two (not one) so a single dropped probe -- packet loss, a momentary
/// GC pause on the agent -- never yanks a working direct route; two in a row is
/// a real outage, not noise. Paired with the probe interval this bounds the
/// withdraw latency: at a 30s interval, worst case ~60s to fall back via DNS
/// (browsers with the record cached fall back to the still-live relay
/// immediately on a failed direct connection -- DNS is the slow, belt-and-
/// suspenders layer, not the fast one).
pub const WITHDRAW_AFTER_FAILURES: u32 = 2;

/// The advertisement state a tunnel's direct record is in, as the control plane
/// tracks it. Kept minimal on purpose -- the probe timestamps and the endpoint
/// itself live in storage; this is only what the decision function needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectServingState {
    /// Whether a direct DNS record is currently published for this tunnel.
    pub advertised: bool,
    /// Consecutive failed probes since the last success (0 while healthy).
    pub consecutive_failures: u32,
}

impl DirectServingState {
    /// The initial state before any probe: not advertised, no failures.
    pub fn initial() -> Self {
        Self { advertised: false, consecutive_failures: 0 }
    }
}

/// What the control plane should DO to DNS after folding one probe result into
/// the state -- the only three actions, so a caller can't forget one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectServingAction {
    /// Publish the direct record now (was not advertised, agent is reachable).
    Publish,
    /// Withdraw the direct record now (was advertised, reachability lost per the
    /// hysteresis rule) -- browsers fall back to the always-registered relay.
    Withdraw,
    /// Nothing to change (already in the right state for this probe outcome).
    Hold,
}

/// Fold one external reachability probe (`reachable`) into `state`, returning the
/// new state and the DNS action to take. Pure and total -- the caller supplies
/// the probe result (from an out-of-band external check, never the agent's own
/// self-report) and this decides, with [`WITHDRAW_AFTER_FAILURES`] hysteresis:
///
/// - reachable + not advertised  -> Publish (first good probe brings the record up)
/// - reachable + advertised      -> Hold, failure streak reset
/// - unreachable + advertised    -> Hold until the streak reaches the threshold, then Withdraw
/// - unreachable + not advertised -> Hold (nothing published to pull)
///
/// A `Publish` is deliberately IMMEDIATE on the first success (no "up" hysteresis):
/// advertising a reachable direct path early is safe -- a browser that then can't
/// reach it falls back to the live relay at once, and the next failed probe pair
/// withdraws the record. The asymmetry (slow to withdraw, fast to publish) is the
/// right one: the cost of a spuriously-withdrawn record is lost offload; the cost
/// of a spuriously-published one is bounded by the relay fallback.
pub fn fold_probe(state: DirectServingState, reachable: bool) -> (DirectServingState, DirectServingAction) {
    if reachable {
        let next = DirectServingState { advertised: true, consecutive_failures: 0 };
        let action = if state.advertised { DirectServingAction::Hold } else { DirectServingAction::Publish };
        (next, action)
    } else {
        let failures = state.consecutive_failures.saturating_add(1);
        if state.advertised && failures >= WITHDRAW_AFTER_FAILURES {
            (DirectServingState { advertised: false, consecutive_failures: failures }, DirectServingAction::Withdraw)
        } else {
            // Still advertised but not yet at the threshold, or never advertised:
            // carry the growing failure streak, change nothing in DNS.
            (DirectServingState { advertised: state.advertised, consecutive_failures: failures }, DirectServingAction::Hold)
        }
    }
}

/// #517 V3 slice 3: how long an external reachability probe waits for a TCP
/// connect before calling the endpoint unreachable. Short -- a healthy direct
/// endpoint accepts a SYN in well under a second even across regions; a longer
/// wait just delays a withdraw that the browser-side relay fallback already
/// covers.
pub const PROBE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// #517 V3 slice 3: probe `endpoint` (an `ip:port`) for reachability by opening a
/// TCP connection from HERE (the control plane), never trusting the agent's own
/// self-report -- an agent behind a NAT that thinks it's reachable but isn't must
/// probe as unreachable, or the CP would publish a black-hole direct record. Any
/// connect error or timeout is `false`; a completed TCP handshake is `true`. This
/// only proves the port ACCEPTS from the internet, which is exactly the property
/// the direct DNS record promises a browser.
pub async fn probe_reachable(endpoint: &str) -> bool {
    let addr = match endpoint.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => return false, // a malformed endpoint can never be reachable
    };
    matches!(
        tokio::time::timeout(PROBE_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// #517 V3 slice 3: one probe sweep. For every direct-serving-enabled tunnel,
/// probe its endpoint, fold the result through the hysteresis machine, and persist
/// the new state -- returning the (tunnel_id, hostname, action) list so the caller
/// (slice 4) knows which DNS records to publish/withdraw. Slice 3 stops at the
/// decision + persistence; it does NOT touch DNS yet, so it is safe to run in
/// production behind its env gate with no live-routing effect. `now` is injected
/// for deterministic tests. Best-effort per tunnel -- a probe or a DB write for
/// one tunnel never aborts the sweep for the rest.
pub async fn sweep_probes(
    tunnels: &crate::storage::SqliteTunnelStore,
    now: u64,
) -> Vec<(String, String, DirectServingAction)> {
    let candidates = match tunnels.direct_serving_candidates() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ct-cp: direct-serving: candidate list failed: {e}");
            return Vec::new();
        }
    };
    let mut actions = Vec::new();
    for (tunnel_id, hostname, endpoint, state) in candidates {
        let reachable = probe_reachable(&endpoint).await;
        let (next, action) = fold_probe(state, reachable);
        if let Err(e) = tunnels.record_direct_probe(&tunnel_id, next, now) {
            eprintln!("ct-cp: direct-serving: persisting probe for {tunnel_id} failed: {e}");
            continue;
        }
        if action != DirectServingAction::Hold {
            actions.push((tunnel_id, hostname, action));
        }
    }
    actions
}

/// #517 V3 slice 3: run [`sweep_probes`] forever on `tick`. Opt-in at the call
/// site via `CT_CP_DIRECT_PROBE` (this function has no gate -- the caller decides
/// whether to spawn it, matching acme_broker's convention). Slice 4 will consume
/// the returned actions to drive DNS; for now they are logged so the probe loop is
/// observable before it ever touches a live record.
pub async fn run_probe_loop(tunnels: std::sync::Arc<crate::storage::SqliteTunnelStore>, tick: std::time::Duration) -> ! {
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for (tunnel_id, hostname, action) in sweep_probes(&tunnels, now).await {
            eprintln!("ct-cp: direct-serving: {action:?} for {hostname} (tunnel {tunnel_id}) — DNS wiring pending (slice 4)");
        }
        tokio::time::sleep(tick).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sweep_probes_folds_reachability_into_actions_and_persists() {
        use crate::storage::{CreateTunnelOutcome, SqliteTunnelStore};
        let store = SqliteTunnelStore::open_in_memory().unwrap();
        let t = match store.create_if_under_owned_limit("s", "svc", Some("svc.example"), 1).unwrap() {
            CreateTunnelOutcome::Created(t) => t,
            other => panic!("{other:?}"),
        };
        // A live listener as the direct endpoint.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        store.set_direct_serving("s", &t.id, true, Some(&addr.to_string())).unwrap();

        // First sweep: reachable -> Publish, and the advertised state persists.
        let actions = sweep_probes(&store, 1_000).await;
        assert_eq!(actions, vec![(t.id.clone(), "svc.example".to_string(), DirectServingAction::Publish)]);
        assert_eq!(store.direct_serving("s", &t.id).unwrap(), Some((true, Some(addr.to_string()), true)));
        // Second sweep still reachable -> Hold (no action emitted).
        assert!(sweep_probes(&store, 1_030).await.is_empty(), "a steady reachable endpoint emits no action");

        // Endpoint dies: two sweeps to withdraw (hysteresis).
        drop(listener);
        assert!(sweep_probes(&store, 1_060).await.is_empty(), "first failure holds");
        let actions = sweep_probes(&store, 1_090).await;
        assert_eq!(actions, vec![(t.id.clone(), "svc.example".to_string(), DirectServingAction::Withdraw)]);
        assert_eq!(store.direct_serving("s", &t.id).unwrap().unwrap().2, false, "no longer advertised");
    }

    #[tokio::test]
    async fn probe_reachable_true_for_a_live_listener_false_for_a_dead_port() {
        // A live listener accepts -> reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(probe_reachable(&addr.to_string()).await, "an accepting port probes reachable");
        // Its port after close -> connection refused -> unreachable.
        drop(listener);
        assert!(!probe_reachable(&addr.to_string()).await, "a dead port probes unreachable");
        // A malformed endpoint is never reachable (and never panics).
        assert!(!probe_reachable("not-an-addr").await);
        assert!(!probe_reachable("").await);
    }

    #[test]
    fn first_reachable_probe_publishes_then_holds() {
        let s = DirectServingState::initial();
        let (s, a) = fold_probe(s, true);
        assert_eq!(a, DirectServingAction::Publish);
        assert_eq!(s, DirectServingState { advertised: true, consecutive_failures: 0 });
        // A second success changes nothing.
        let (s, a) = fold_probe(s, true);
        assert_eq!(a, DirectServingAction::Hold);
        assert!(s.advertised);
    }

    #[test]
    fn a_single_failure_does_not_withdraw_a_live_record() {
        let (s, _) = fold_probe(DirectServingState::initial(), true); // advertised
        let (s, a) = fold_probe(s, false);
        assert_eq!(a, DirectServingAction::Hold, "one flaky probe must not pull a working route");
        assert_eq!(s, DirectServingState { advertised: true, consecutive_failures: 1 });
    }

    #[test]
    fn two_consecutive_failures_withdraw() {
        let (s, _) = fold_probe(DirectServingState::initial(), true);
        let (s, _) = fold_probe(s, false); // failure 1: Hold
        let (s, a) = fold_probe(s, false); // failure 2: Withdraw
        assert_eq!(a, DirectServingAction::Withdraw);
        assert!(!s.advertised);
    }

    #[test]
    fn a_success_between_failures_resets_the_streak() {
        let (s, _) = fold_probe(DirectServingState::initial(), true);
        let (s, _) = fold_probe(s, false); // failure 1
        let (s, a) = fold_probe(s, true); // recovered before the threshold
        assert_eq!(a, DirectServingAction::Hold);
        assert_eq!(s.consecutive_failures, 0, "the streak resets, so the next single failure can't withdraw");
        let (_, a) = fold_probe(s, false);
        assert_eq!(a, DirectServingAction::Hold, "one failure after a reset is still just Hold");
    }

    #[test]
    fn failures_while_never_advertised_never_produce_a_withdraw() {
        let mut s = DirectServingState::initial();
        for _ in 0..5 {
            let (ns, a) = fold_probe(s, false);
            assert_eq!(a, DirectServingAction::Hold, "nothing published, nothing to withdraw");
            s = ns;
        }
        assert!(!s.advertised);
    }

    #[test]
    fn re_publishes_after_a_withdraw_when_reachability_returns() {
        let (s, _) = fold_probe(DirectServingState::initial(), true);
        let (s, _) = fold_probe(s, false);
        let (s, a) = fold_probe(s, false);
        assert_eq!(a, DirectServingAction::Withdraw);
        // Agent comes back: the very next good probe re-publishes.
        let (s, a) = fold_probe(s, true);
        assert_eq!(a, DirectServingAction::Publish);
        assert!(s.advertised);
    }
}

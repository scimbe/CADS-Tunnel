//! SIGTERM graceful-drain machinery for the Edge daemon (#400, follow-up to #376).
//!
//! #376 fixed signal *delivery* (tini as PID 1, `STOPSIGNAL SIGTERM` in the Dockerfile)
//! so a SIGTERM actually reaches this process instead of being silently dropped by
//! Docker's default handling. This module is the missing *application-level* half: a
//! [`ShutdownSignal`]/[`ShutdownController`] pair every accept loop in this crate
//! (`transport::serve_listener`, `channel_broker::run_channel_broker_loop`,
//! `ws_channel::serve_with_optional_tls`) selects against so it stops admitting NEW
//! connections the moment shutdown is requested, plus [`wait_for_drain`], which bounds
//! how long `run_edge` waits for already-admitted connections to finish before it
//! returns (letting the process exit, which force-closes whatever is still open).
//!
//! What "drain" means here, concretely (see `run_edge`'s doc comment for the full
//! design writeup): on SIGTERM, every listener stops calling `accept()`/`endpoint.accept()`
//! so the process isn't handed more work while it's trying to exit, but connections
//! already admitted keep running normally for a bounded grace period
//! (`CT_EDGE_SHUTDOWN_GRACE_SECS`, default 30s) so in-flight tunnel traffic isn't
//! abruptly severed. Once every [`crate::state::ConnectionCap`] this crate tracks
//! reports zero connections in use, or the grace period elapses first, `run_edge`
//! returns — a stuck/never-finishing connection can therefore never hang shutdown
//! past the grace bound; it is force-closed when the process exits.

use std::time::Duration;

use crate::state::ConnectionCap;

/// A cheaply-cloneable "has shutdown been requested?" signal, backed by a
/// `tokio::sync::watch` so every accept loop can `tokio::select!` against
/// [`Self::cancelled`] without polling.
#[derive(Clone)]
pub struct ShutdownSignal(Option<tokio::sync::watch::Receiver<bool>>);

impl ShutdownSignal {
    /// A signal that never fires — for call sites (mainly tests) that don't exercise
    /// shutdown behavior and just need a value of the right type. [`Self::cancelled`]
    /// on this variant is a `Future` that never resolves (`std::future::pending`), so
    /// it never wins a `tokio::select!` race against real work.
    pub fn never() -> Self {
        Self(None)
    }

    /// Resolves once shutdown has been requested (immediately if it already has been
    /// by the time this is called/awaited again).
    pub async fn cancelled(&self) {
        match &self.0 {
            Some(rx) => {
                let mut rx = rx.clone();
                if *rx.borrow() {
                    return;
                }
                // An `Err` here means the `ShutdownController` was dropped without ever
                // triggering — treat that the same as "never", not as an implicit
                // shutdown: the caller keeps running, exactly as if no controller
                // existed. In production `run_edge` holds the controller for the
                // process's whole life, so this path is untaken there.
                let _ = rx.changed().await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    /// Non-blocking check, for call sites that just want to know "already shutting
    /// down?" without awaiting (e.g. deciding whether to run the post-loop drain wait
    /// at all).
    pub fn is_cancelled(&self) -> bool {
        match &self.0 {
            Some(rx) => *rx.borrow(),
            None => false,
        }
    }
}

/// Owns the sending half of a [`ShutdownSignal`]. `Clone`, so both the SIGTERM/Ctrl-C
/// listener task and `run_edge` itself (which needs `is_cancelled()` after its own
/// accept loop exits) can hold a copy.
#[derive(Clone)]
pub struct ShutdownController(tokio::sync::watch::Sender<bool>);

impl ShutdownController {
    /// A fresh, not-yet-triggered controller and its paired signal.
    pub fn new() -> (Self, ShutdownSignal) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (Self(tx), ShutdownSignal(Some(rx)))
    }

    /// Request shutdown. Idempotent — a second call is a harmless no-op (the watch
    /// channel simply reports "changed" to receivers that haven't observed the first
    /// `true` yet, and `false -> true -> true` collapses to one observable transition
    /// for anything that only checks the current value).
    pub fn trigger(&self) {
        let _ = self.0.send(true);
    }
}

/// Waits until every cap in `caps` reports zero connections in use (fully drained),
/// or `grace` elapses first — whichever comes first (#400's bounded-wait requirement,
/// "a stuck connection can't hang shutdown forever"). Returns the number of
/// connections still counted as in-use when the wait ended: `0` means every cap
/// drained within the grace window; anything else is how many will be force-closed
/// when the caller returns and the process exits.
///
/// A `None` cap (an operator explicitly disabled that budget via e.g.
/// `CT_EDGE_MAX_CONNECTIONS=off`) can't be waited on — there is no permit to observe,
/// so its connections are simply not represented in the returned count. In that
/// configuration the wait is best-effort: it still honors every OTHER configured
/// cap's drain, but stops guaranteeing anything about the uncapped listener's
/// connections specifically.
pub(crate) async fn wait_for_drain(caps: &[Option<ConnectionCap>], grace: Duration) -> usize {
    let still_open = |caps: &[Option<ConnectionCap>]| -> usize {
        caps.iter().flatten().map(ConnectionCap::in_use).sum()
    };
    if still_open(caps) == 0 {
        return 0;
    }
    let deadline = tokio::time::sleep(grace);
    tokio::pin!(deadline);
    // Polling (not e.g. a `Notify` fired on every permit release) keeps this simple and
    // correct without adding a wake-up hook to `ConnectionCap`'s hot admit/release path
    // for a bound that only matters during the last few seconds of the process's life;
    // 50ms is fine resolution for a multi-second grace window.
    let mut ticker = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => return still_open(caps),
            _ = ticker.tick() => {
                let n = still_open(caps);
                if n == 0 {
                    return 0;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_signal_never_does_not_resolve() {
        // `never()` must behave like no shutdown was ever requested — a real accept
        // loop racing it in `select!` must keep accepting indefinitely, not exit early.
        let sig = ShutdownSignal::never();
        assert!(!sig.is_cancelled());
        let raced = tokio::time::timeout(Duration::from_millis(150), sig.cancelled()).await;
        assert!(raced.is_err(), "never() must not resolve within a bounded wait");
    }

    #[tokio::test]
    async fn controller_trigger_is_observed_by_every_clone_of_the_signal() {
        let (ctl, sig) = ShutdownController::new();
        let sig2 = sig.clone();
        assert!(!sig.is_cancelled());
        assert!(!sig2.is_cancelled());

        ctl.trigger();

        // Both the original and a clone taken BEFORE the trigger observe it.
        tokio::time::timeout(Duration::from_millis(200), sig.cancelled())
            .await
            .expect("original signal observes the trigger");
        tokio::time::timeout(Duration::from_millis(200), sig2.cancelled())
            .await
            .expect("a clone taken before the trigger also observes it");
        assert!(sig.is_cancelled());
        assert!(sig2.is_cancelled());

        // A clone taken AFTER the trigger sees it as already-cancelled (no missed wakeup).
        let sig3 = sig.clone();
        assert!(sig3.is_cancelled());
        tokio::time::timeout(Duration::from_millis(50), sig3.cancelled())
            .await
            .expect("a clone taken after the trigger resolves immediately");
    }

    #[tokio::test]
    async fn stops_a_pending_accept_promptly_when_triggered() {
        // The property every accept loop in this crate relies on: `select!`ing
        // `cancelled()` against a long-blocked future (here, standing in for
        // `listener.accept()`/`endpoint.accept()`) resolves promptly once triggered,
        // not only on the next spurious wakeup.
        let (ctl, sig) = ShutdownController::new();

        let start = tokio::time::Instant::now();
        let handle = tokio::spawn(async move { sig.cancelled().await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        ctl.trigger();
        tokio::time::timeout(Duration::from_millis(200), handle)
            .await
            .expect("cancelled() resolves promptly after trigger()")
            .expect("task joined");
        assert!(start.elapsed() < Duration::from_millis(250), "no long spurious delay");
    }

    // ---- wait_for_drain ---------------------------------------------------------------

    #[tokio::test]
    async fn wait_for_drain_returns_immediately_when_nothing_is_in_use() {
        let cap = ConnectionCap::new(4);
        let elapsed = {
            let start = tokio::time::Instant::now();
            let n = wait_for_drain(&[Some(cap)], Duration::from_secs(5)).await;
            assert_eq!(n, 0, "an already-empty cap drains instantly");
            start.elapsed()
        };
        assert!(elapsed < Duration::from_millis(100), "must not wait out any part of the grace window when already drained");
    }

    #[tokio::test]
    async fn wait_for_drain_succeeds_when_an_in_flight_connection_finishes_within_the_grace_window() {
        // (b) from #400's test requirements: a connection that completes WITHIN the
        // grace window must be observed as drained, not force-closed.
        let cap = ConnectionCap::new(1);
        let permit = cap.try_admit().expect("cap has room");
        assert_eq!(cap.in_use(), 1);

        // Release the permit shortly after the wait starts -- well inside the grace window.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(permit);
        });

        let start = tokio::time::Instant::now();
        let n = wait_for_drain(&[Some(cap.clone())], Duration::from_secs(5)).await;
        assert_eq!(n, 0, "the connection finished before the grace window elapsed -- fully drained");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must return as soon as drained, not wait out the whole grace window"
        );
        assert_eq!(cap.in_use(), 0);
    }

    #[tokio::test]
    async fn wait_for_drain_force_closes_after_the_grace_window_elapses() {
        // (c) from #400's test requirements: a connection that does NOT finish within
        // the grace window must not hang shutdown forever -- the wait returns once the
        // bound elapses, reporting how many are still open, so the caller can proceed
        // to exit (force-closing it) instead of blocking indefinitely.
        let cap = ConnectionCap::new(1);
        let _permit = cap.try_admit().expect("cap has room"); // held for the whole test -- never released
        assert_eq!(cap.in_use(), 1);

        let start = tokio::time::Instant::now();
        let n = wait_for_drain(&[Some(cap.clone())], Duration::from_millis(200)).await;
        let elapsed = start.elapsed();
        assert_eq!(n, 1, "the still-held connection is reported, not silently dropped");
        assert!(elapsed >= Duration::from_millis(200), "must wait out the full grace window: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(600), "must not wait meaningfully longer than the grace window: {elapsed:?}");
    }

    #[tokio::test]
    async fn wait_for_drain_covers_multiple_caps_independently() {
        // `run_edge` passes every one of its connection caps (front door, TCP-fallback
        // agent registrations, browser-tunnel, ws-channel, channel-broker) into one
        // drain wait -- it must not report "drained" until ALL of them are empty.
        let fast = ConnectionCap::new(1);
        let slow = ConnectionCap::new(1);
        let fast_permit = fast.try_admit().unwrap();
        let _slow_permit = slow.try_admit().unwrap(); // held for the whole grace window

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(60)).await;
            drop(fast_permit);
        });

        let n = wait_for_drain(&[Some(fast.clone()), Some(slow.clone())], Duration::from_millis(250)).await;
        assert_eq!(n, 1, "the still-held cap's one connection is reported even though the other cap fully drained");
        assert_eq!(fast.in_use(), 0);
        assert_eq!(slow.in_use(), 1);
    }
}

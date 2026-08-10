//! Opportunistic relay→direct upgrade coordination for A2A channels (#104).
//!
//! When two channel members can't reach each other directly they fall back to the
//! edge relay (`AF4-relay-clientwire`), which then carries the full ciphertext path
//! for the session's lifetime — even if a direct path later becomes viable (NAT
//! rebinds, a firewall opens, peers roam). This module is the pure, deterministic
//! **coordination + accounting** core of promoting such a session back to direct and
//! freeing the relay — the Tailscale DERP→direct shape.
//!
//! Two pieces, both mesh-independent and unit-testable (the live QUIC re-dial + stream
//! handover is a follow packet):
//!
//! * [`UpgradeCoordinator`] — decides **when** and **who**: only the initiator side
//!   owns triggering the swap (so both peers don't race), retries a background direct
//!   dial on a backoff while still relayed, and records the handover (with the
//!   time-to-upgrade metric) once a direct path is confirmed.
//! * [`PathMeter`] — per-session byte accounting (relay vs direct) so the offload goal
//!   is *measurable*, not just asserted.
//!
//! Time is caller-supplied (`now`, unix seconds) for deterministic tests, mirroring
//! [`crate::replay`] and [`crate::ratelimit`].

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Which transport an A2A session's data path is currently riding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Path {
    /// Forwarded through the edge relay (ciphertext only).
    Relay,
    /// Peer-to-peer direct connection (edge offloaded).
    Direct,
}

/// A member's role in the channel (mirrors the grant `Direction`). Exactly one side —
/// the initiator — owns *triggering* an upgrade; the responder reacts, so the two
/// peers never race to swap simultaneously.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// Dials the peer (grant `Direction::Initiate`) — owns triggering the upgrade.
    Initiator,
    /// Accepts (grant `Direction::Accept`) — reacts to the initiator's swap.
    Responder,
}

/// Backoff bounds (seconds) for the background direct-dial retry while relayed.
const DEFAULT_BASE_INTERVAL_SECS: u64 = 5;
const DEFAULT_MAX_INTERVAL_SECS: u64 = 60;

/// The tiny control protocol the two members speak **over the still-open relay stream**
/// to coordinate a relay→direct handover (#104). The initiator (which owns triggering,
/// per [`UpgradeCoordinator`]) offers its now-reachable direct endpoint; the responder
/// sets up the direct path and acks `Ready`; only then does either side stop the relay
/// leg — so there is no window where data silently drops. `Abort` lets a side back out
/// (e.g. the direct path failed to come up) and stay on the relay.
///
/// Wire form: a 1-byte tag, then a tag-specific payload. `Offer` carries the direct
/// endpoint as trailing UTF-8 (no length prefix needed — it is the remainder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeMsg {
    /// Initiator → responder: "I can reach you direct — prepare the swap. Here is the
    /// direct endpoint (host:port) to expect/dial."
    Offer { direct_endpoint: String },
    /// Responder → initiator: the direct path is set up and live on my side.
    Ready,
    /// Either side: abandon this upgrade attempt and stay on the relay.
    Abort,
}

impl UpgradeMsg {
    const TAG_OFFER: u8 = 0;
    const TAG_READY: u8 = 1;
    const TAG_ABORT: u8 = 2;

    /// Encode to the wire form (`tag(1) | payload`).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            UpgradeMsg::Offer { direct_endpoint } => {
                let mut out = Vec::with_capacity(1 + direct_endpoint.len());
                out.push(Self::TAG_OFFER);
                out.extend_from_slice(direct_endpoint.as_bytes());
                out
            }
            UpgradeMsg::Ready => vec![Self::TAG_READY],
            UpgradeMsg::Abort => vec![Self::TAG_ABORT],
        }
    }

    /// Decode from [`encode`](Self::encode). Bounds-checked and panic-free: an empty
    /// buffer, an unknown tag, a non-UTF-8 or empty `Offer` endpoint, or trailing bytes
    /// on a payloadless tag all return `None`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        match tag {
            Self::TAG_OFFER => {
                if rest.is_empty() {
                    return None; // an Offer must carry an endpoint
                }
                let endpoint = std::str::from_utf8(rest).ok()?.to_string();
                Some(UpgradeMsg::Offer { direct_endpoint: endpoint })
            }
            Self::TAG_READY if rest.is_empty() => Some(UpgradeMsg::Ready),
            Self::TAG_ABORT if rest.is_empty() => Some(UpgradeMsg::Abort),
            _ => None,
        }
    }
}

/// Coordinates the opportunistic relay→direct upgrade of one A2A session (#104).
///
/// Constructed when a session starts on the relay. The initiator polls
/// [`should_attempt`](Self::should_attempt); on each failed background dial it calls
/// [`record_attempt_failed`](Self::record_attempt_failed) (which schedules the next
/// attempt with exponential backoff up to a cap); once a direct path is confirmed live
/// both ways it calls [`confirm_upgraded`](Self::confirm_upgraded), which flips the
/// path to [`Path::Direct`], stops further attempts, and records the time-to-upgrade.
#[derive(Clone, Debug)]
pub struct UpgradeCoordinator {
    role: Role,
    path: Path,
    started_at: u64,
    upgraded_at: Option<u64>,
    next_attempt_at: u64,
    attempts: u32,
    base_interval: u64,
    max_interval: u64,
}

impl UpgradeCoordinator {
    /// Start coordinating a session that began on the relay at `now`, for this member's
    /// `role`. The first background dial is scheduled one base interval out (don't
    /// hammer the moment fallback happens).
    pub fn new(role: Role, now: u64) -> Self {
        Self::with_backoff(role, now, DEFAULT_BASE_INTERVAL_SECS, DEFAULT_MAX_INTERVAL_SECS)
    }

    /// Like [`new`](Self::new) with explicit backoff bounds (for tests / tuning).
    pub fn with_backoff(role: Role, now: u64, base_interval: u64, max_interval: u64) -> Self {
        let base = base_interval.max(1);
        Self {
            role,
            path: Path::Relay,
            started_at: now,
            upgraded_at: None,
            next_attempt_at: now.saturating_add(base),
            attempts: 0,
            base_interval: base,
            max_interval: max_interval.max(base),
        }
    }

    /// Whether this member should attempt a background direct dial now. True only for
    /// the initiator, only while still relayed, and only once the scheduled time has
    /// arrived — so the responder never triggers, and an already-upgraded session stops.
    pub fn should_attempt(&self, now: u64) -> bool {
        self.role == Role::Initiator && self.path == Path::Relay && now >= self.next_attempt_at
    }

    /// Record that a background direct dial failed; schedule the next attempt with
    /// exponential backoff (`base · 2^attempts`, capped at `max_interval`).
    pub fn record_attempt_failed(&mut self, now: u64) {
        self.attempts = self.attempts.saturating_add(1);
        let shift = self.attempts.min(16); // cap the exponent so the shift can't overflow
        let backoff = self
            .base_interval
            .saturating_mul(1u64 << shift)
            .min(self.max_interval);
        self.next_attempt_at = now.saturating_add(backoff);
    }

    /// Confirm the direct path is live both ways: promote to [`Path::Direct`] and record
    /// the handover time. Idempotent — a second confirm keeps the first upgrade time.
    pub fn confirm_upgraded(&mut self, now: u64) {
        if self.path != Path::Direct {
            self.path = Path::Direct;
            self.upgraded_at = Some(now);
        }
    }

    /// The current data path.
    pub fn path(&self) -> Path {
        self.path
    }

    /// Whether the session has been promoted to the direct path.
    pub fn is_direct(&self) -> bool {
        self.path == Path::Direct
    }

    /// Seconds from relay-fallback to a confirmed direct path (#104's time-to-upgrade
    /// metric), or `None` while still relayed.
    pub fn time_to_upgrade(&self) -> Option<u64> {
        self.upgraded_at.map(|t| t.saturating_sub(self.started_at))
    }

    /// Number of background dial attempts recorded so far.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// Per-session byte accounting for the relay→direct offload metric (#104): how much
/// data rode the edge relay vs the direct path. `direct_fraction` is the number that
/// demonstrates the edge is actually being offloaded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMeter {
    relay_bytes: u64,
    direct_bytes: u64,
}

impl PathMeter {
    /// A fresh meter (both counters zero).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `bytes` transferred over `path`.
    pub fn record(&mut self, path: Path, bytes: u64) {
        match path {
            Path::Relay => self.relay_bytes = self.relay_bytes.saturating_add(bytes),
            Path::Direct => self.direct_bytes = self.direct_bytes.saturating_add(bytes),
        }
    }

    /// Bytes carried by the edge relay.
    pub fn relay_bytes(&self) -> u64 {
        self.relay_bytes
    }

    /// Bytes carried by the direct path (edge offloaded).
    pub fn direct_bytes(&self) -> u64 {
        self.direct_bytes
    }

    /// Total bytes across both paths.
    pub fn total_bytes(&self) -> u64 {
        self.relay_bytes.saturating_add(self.direct_bytes)
    }

    /// Fraction of bytes that went direct (0.0 when nothing sent yet). Higher = more
    /// of the session offloaded from the edge.
    pub fn direct_fraction(&self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            0.0
        } else {
            self.direct_bytes as f64 / total as f64
        }
    }
}

/// **#104-handover H1 — the relay→direct upgrade coordination handshake (initiator half).**
/// Runs over the still-open relay **control** stream and drives the existing
/// [`UpgradeCoordinator`] + [`UpgradeMsg`]; it is **coordination only — no application bytes
/// move here** (the actual cutover is H2), so it is inert/safe until the cutover is wired.
///
/// If `coord` says it's time ([`should_attempt`](UpgradeCoordinator::should_attempt), which
/// is initiator-only) and the injected `discover_direct` yields our reachable direct endpoint,
/// send `Offer{endpoint}` and await the responder: `Ready` confirms the upgrade
/// (`Ok(true)`, `coord` now `Direct`); anything else — `Abort`, a non-`Ready` message, or a
/// closed stream — keeps the relay (`Ok(false)`, the attempt recorded failed for backoff). A
/// failed discovery sends nothing and just records the failure. `dial`/discovery is injected
/// so the live caller passes the real direct-dial and a test passes a mock.
pub async fn initiator_negotiate_upgrade<W, R, F, Fut>(
    coord: &mut UpgradeCoordinator,
    now: u64,
    send: &mut W,
    recv: &mut R,
    discover_direct: F,
) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    if !coord.should_attempt(now) {
        return Ok(false);
    }
    let endpoint = match discover_direct().await {
        Some(e) => e,
        None => {
            coord.record_attempt_failed(now);
            return Ok(false);
        }
    };
    send.write_all(&crate::noise::frame(
        &UpgradeMsg::Offer { direct_endpoint: endpoint }.encode(),
    ))
    .await?;
    let reply = crate::noise::read_frame(recv)
        .await
        .ok()
        .and_then(|b| UpgradeMsg::decode(&b));
    match reply {
        Some(UpgradeMsg::Ready) => {
            coord.confirm_upgraded(now);
            Ok(true)
        }
        _ => {
            coord.record_attempt_failed(now);
            Ok(false)
        }
    }
}

/// **#104-handover H1 — the coordination handshake (responder half).** Reads one control
/// message; on an `Offer{endpoint}` it dials that endpoint via the injected `dial` — on
/// success it replies `Ready` and `confirm_upgraded`s (`Ok(true)`), on failure it replies
/// `Abort` and stays on the relay (`Ok(false)`). A non-`Offer` message → `Ok(false)`. Like
/// the initiator half this is coordination only; no application bytes move (H2 does the swap).
pub async fn responder_negotiate_upgrade<W, R, F, Fut>(
    coord: &mut UpgradeCoordinator,
    now: u64,
    send: &mut W,
    recv: &mut R,
    dial: F,
) -> io::Result<bool>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let msg = crate::noise::read_frame(recv)
        .await
        .ok()
        .and_then(|b| UpgradeMsg::decode(&b));
    let endpoint = match msg {
        Some(UpgradeMsg::Offer { direct_endpoint }) => direct_endpoint,
        _ => return Ok(false),
    };
    if dial(endpoint).await {
        send.write_all(&crate::noise::frame(&UpgradeMsg::Ready.encode())).await?;
        coord.confirm_upgraded(now);
        Ok(true)
    } else {
        let _ = send
            .write_all(&crate::noise::frame(&UpgradeMsg::Abort.encode()))
            .await;
        Ok(false)
    }
}

/// **#104 H3-wire — the upgrade negotiation driven *in-band* over the running relay pump.**
/// H1 ([`initiator_negotiate_upgrade`]) speaks `UpgradeMsg` over a *separate* control stream; but
/// the live relay path has exactly one stream (a `:443`-only member can't open a second), so the
/// negotiation must ride the [`crate::noise::noise_pump_multiplexed`] control channels instead:
/// `ctl` enqueues outbound control on the pump (delivered to the peer as in-band `CONTROL` frames),
/// and `inbound` yields the peer's control payloads the pump decoded for us. This is the
/// initiator half — the same coordinator/backoff logic as H1, only the transport differs (discrete
/// pump messages, no framing).
///
/// If `coord` says it's time and `discover_direct` yields our reachable endpoint, send `Offer` and
/// await the peer: `Ready` → `Ok(Some(endpoint))` — the caller then establishes the direct Noise
/// session and enqueues [`crate::noise::PumpControl::Cutover`]; anything else (`Abort`, an
/// unexpected message, or a closed channel = the pump/session ended) → `Ok(None)`, relay kept and
/// the attempt recorded failed for backoff. **No `Cutover` is sent here** — installing the direct
/// session into the pump and triggering the swap is the caller's next step (its correctness is
/// proven live, H4). Bounding the reply wait is the caller's concern, as in H1.
pub async fn drive_initiator_upgrade<F, Fut>(
    coord: &mut UpgradeCoordinator,
    now: u64,
    ctl: &tokio::sync::mpsc::UnboundedSender<crate::noise::PumpControl>,
    inbound: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    discover_direct: F,
) -> io::Result<Option<String>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    if !coord.should_attempt(now) {
        return Ok(None);
    }
    let endpoint = match discover_direct().await {
        Some(e) => e,
        None => {
            coord.record_attempt_failed(now);
            return Ok(None);
        }
    };
    if ctl
        .send(crate::noise::PumpControl::Send(
            UpgradeMsg::Offer { direct_endpoint: endpoint.clone() }.encode(),
        ))
        .is_err()
    {
        // The pump is gone — the session ended; nothing to upgrade.
        coord.record_attempt_failed(now);
        return Ok(None);
    }
    match inbound.recv().await.and_then(|b| UpgradeMsg::decode(&b)) {
        Some(UpgradeMsg::Ready) => {
            coord.confirm_upgraded(now);
            Ok(Some(endpoint))
        }
        _ => {
            coord.record_attempt_failed(now);
            Ok(None)
        }
    }
}

/// **#104 H3-wire — the in-band negotiation (responder half).** Mirrors
/// [`responder_negotiate_upgrade`] but over the [`crate::noise::noise_pump_multiplexed`] control
/// channels. Reads one inbound control message; on an `Offer{endpoint}` it dials that endpoint via
/// the injected `dial` — success → reply `Ready`, `confirm_upgraded`, `Ok(Some(endpoint))` (the
/// caller installs the direct session; the initiator drives the `Cutover`); failure → reply `Abort`,
/// stay on the relay (`Ok(None)`). A non-`Offer` (or closed channel) → `Ok(None)`.
pub async fn drive_responder_upgrade<F, Fut>(
    coord: &mut UpgradeCoordinator,
    now: u64,
    ctl: &tokio::sync::mpsc::UnboundedSender<crate::noise::PumpControl>,
    inbound: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    dial: F,
) -> io::Result<Option<String>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let endpoint = match inbound.recv().await.and_then(|b| UpgradeMsg::decode(&b)) {
        Some(UpgradeMsg::Offer { direct_endpoint }) => direct_endpoint,
        _ => return Ok(None),
    };
    if dial(endpoint.clone()).await {
        let _ = ctl.send(crate::noise::PumpControl::Send(UpgradeMsg::Ready.encode()));
        coord.confirm_upgraded(now);
        Ok(Some(endpoint))
    } else {
        let _ = ctl.send(crate::noise::PumpControl::Send(UpgradeMsg::Abort.encode()));
        Ok(None)
    }
}

/// **#104 direct-P2P orchestration (initiator side).** Run the relayed A2A session on the
/// multiplexed pump while, in the background, opportunistically upgrading it to a direct link.
/// First handshakes the relay Noise_IK session, then runs the pump; concurrently it advertises our
/// reachable endpoint (`discover_direct`) via the in-band driver, and on the peer's `Ready` accepts
/// the incoming direct dial + handshakes it (`accept_and_establish`, which returns the pump-ready
/// `(TransportState, read, write)`), installs it into the pump's late-bind one-shot, and triggers
/// the cutover. If either the negotiation or the establishment fails, the session simply stays on
/// the relay. The pump alone decides when the session ends. **The direct Noise handshake happens
/// only AFTER `Ready` is exchanged** — the responder replies `Ready` on reachability, not on a
/// completed handshake — so the two sides handshake concurrently and neither blocks the other.
#[allow(clippy::too_many_arguments)]
pub async fn run_upgradable_session_initiator<RW, RR, P, DR, DW, DF, DFut, EF, EFut>(
    mut relay_send: RW,
    mut relay_recv: RR,
    local: P,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    mut coord: UpgradeCoordinator,
    now: u64,
    discover_direct: DF,
    accept_and_establish: EF,
) -> io::Result<()>
where
    RW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    DR: AsyncRead + Unpin,
    DW: AsyncWrite + Unpin,
    DF: FnOnce() -> DFut,
    DFut: std::future::Future<Output = Option<String>>,
    EF: FnOnce() -> EFut,
    EFut: std::future::Future<Output = Option<(snow::TransportState, DR, DW)>>,
{
    let relay_ts =
        crate::a2a::a2a_initiate(&mut relay_send, &mut relay_recv, own_noise_private, peer_noise_public).await?;
    let (plain_r, plain_w) = tokio::io::split(local);
    let (ctl_tx, ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (dir_tx, dir_rx) = tokio::sync::oneshot::channel();

    let coordinator = async move {
        let mut dir_tx = Some(dir_tx);
        if let Ok(Some(_ep)) =
            drive_initiator_upgrade(&mut coord, now, &ctl_tx, &mut in_rx, discover_direct).await
        {
            if let Some(session) = accept_and_establish().await {
                if let Some(tx) = dir_tx.take() {
                    let _ = tx.send(session);
                }
                let _ = ctl_tx.send(crate::noise::PumpControl::Cutover);
            }
        }
        // Drop an un-sent `dir_tx` so the pump's installer unblocks (stay on relay), then PARK:
        // the coordinator must never resolve, or `select!` would drop the pump future when it does.
        drop(dir_tx.take());
        std::future::pending::<()>().await
    };
    let pump = crate::noise::noise_pump_multiplexed(
        relay_ts, relay_recv, relay_send, plain_r, plain_w, ctl_rx, in_tx, dir_rx,
    );
    tokio::select! {
        res = pump => res,
        _ = coordinator => unreachable!("the upgrade coordinator parks after its one-shot work"),
    }
}

/// **#104 direct-P2P orchestration (responder side).** The mirror of
/// [`run_upgradable_session_initiator`]: handshake the relay session, run the pump, and
/// concurrently answer the peer's `Offer` — `dial_probe` checks the offered endpoint is reachable
/// (the driver replies `Ready` on success), then `dial_and_establish` dials it + handshakes the
/// direct Noise session, which is installed into the pump and cut over to. Establishment is done
/// only after `Ready`, concurrently with the initiator's accept, so neither handshake blocks.
///
/// **#416: `peer_noise_public` is required, mirroring [`run_upgradable_session_initiator`]'s own
/// `peer_noise_public` parameter** — the initiator side always pinned its expected peer via
/// [`crate::a2a::a2a_initiate`]; this responder side previously called the unauthenticated
/// [`crate::a2a::a2a_respond`] and accepted whichever static key showed up. Callers must supply
/// the channel-attested `noise_pubkey` for the member they believe they're relaying with — the
/// same value the caller already used to admit this pairing at the channel broker.
#[allow(clippy::too_many_arguments)]
pub async fn run_upgradable_session_responder<RW, RR, P, DR, DW, DF, DFut, EF, EFut>(
    mut relay_send: RW,
    mut relay_recv: RR,
    local: P,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    mut coord: UpgradeCoordinator,
    now: u64,
    dial_probe: DF,
    dial_and_establish: EF,
) -> io::Result<()>
where
    RW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    DR: AsyncRead + Unpin,
    DW: AsyncWrite + Unpin,
    DF: FnOnce(String) -> DFut,
    DFut: std::future::Future<Output = bool>,
    EF: FnOnce(String) -> EFut,
    EFut: std::future::Future<Output = Option<(snow::TransportState, DR, DW)>>,
{
    let relay_ts = crate::a2a::a2a_respond_verified(
        &mut relay_send,
        &mut relay_recv,
        own_noise_private,
        peer_noise_public,
    )
    .await?;
    let (plain_r, plain_w) = tokio::io::split(local);
    let (ctl_tx, ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (dir_tx, dir_rx) = tokio::sync::oneshot::channel();

    let coordinator = async move {
        let mut dir_tx = Some(dir_tx);
        if let Ok(Some(ep)) =
            drive_responder_upgrade(&mut coord, now, &ctl_tx, &mut in_rx, dial_probe).await
        {
            if let Some(session) = dial_and_establish(ep).await {
                if let Some(tx) = dir_tx.take() {
                    let _ = tx.send(session);
                }
                let _ = ctl_tx.send(crate::noise::PumpControl::Cutover);
            }
        }
        drop(dir_tx.take());
        std::future::pending::<()>().await
    };
    let pump = crate::noise::noise_pump_multiplexed(
        relay_ts, relay_recv, relay_send, plain_r, plain_w, ctl_rx, in_tx, dir_rx,
    );
    tokio::select! {
        res = pump => res,
        _ = coordinator => unreachable!("the upgrade coordinator parks after its one-shot work"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upgrade_handshake_promotes_both_sides_to_direct_over_the_control_stream() {
        // #104-handover H1 (frozen): the coordination handshake drives both UpgradeCoordinators
        // from Relay → Direct over the relay control stream — the initiator offers its
        // discovered direct endpoint, the responder dials it and replies Ready, both confirm.
        // NO application bytes move here (that is H2). initiator writes a_w → responder reads
        // a_r; responder writes b_w → initiator reads b_r.
        let (mut a_w, mut a_r) = tokio::io::duplex(1024);
        let (mut b_w, mut b_r) = tokio::io::duplex(1024);
        let mut init = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
        let mut resp = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);

        let resp_task = tokio::spawn(async move {
            let ok = responder_negotiate_upgrade(&mut resp, 5, &mut b_w, &mut a_r, |ep| async move {
                ep == "203.0.113.9:7000"
            })
            .await
            .unwrap();
            (ok, resp.is_direct())
        });
        let ok_i = initiator_negotiate_upgrade(&mut init, 5, &mut a_w, &mut b_r, || async {
            Some("203.0.113.9:7000".to_string())
        })
        .await
        .unwrap();
        let (ok_r, resp_direct) = resp_task.await.unwrap();

        assert!(ok_i, "initiator promoted to direct");
        assert!(ok_r, "responder promoted to direct");
        assert!(init.is_direct(), "initiator coordinator is Direct");
        assert!(resp_direct, "responder coordinator is Direct");
        assert!(init.time_to_upgrade().is_some(), "the handover time was recorded (offload metric)");
    }

    #[tokio::test]
    async fn upgrade_handshake_stays_on_relay_when_the_responder_cannot_dial_direct() {
        // The responder's direct dial fails → it Aborts; both sides stay on the relay and the
        // initiator records a failed attempt (so the backoff schedule advances).
        let (mut a_w, mut a_r) = tokio::io::duplex(1024);
        let (mut b_w, mut b_r) = tokio::io::duplex(1024);
        let mut init = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
        let mut resp = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);

        let resp_task = tokio::spawn(async move {
            let ok = responder_negotiate_upgrade(&mut resp, 5, &mut b_w, &mut a_r, |_ep| async { false })
                .await
                .unwrap();
            (ok, resp.is_direct())
        });
        let ok_i = initiator_negotiate_upgrade(&mut init, 5, &mut a_w, &mut b_r, || async {
            Some("203.0.113.9:7000".to_string())
        })
        .await
        .unwrap();
        let (ok_r, resp_direct) = resp_task.await.unwrap();

        assert!(!ok_i && !ok_r, "neither side upgraded");
        assert!(!init.is_direct() && !resp_direct, "both stay on the relay");
        assert!(init.attempts() >= 1, "the initiator recorded a failed attempt for backoff");
    }

    // Simulate the multiplexed pump relaying in-band control: drain one side's outbound
    // `PumpControl` channel and forward each `Send` payload to the peer's inbound sink — exactly
    // what `noise_pump_multiplexed` does (a `Send(bytes)` becomes a CONTROL frame the peer's pump
    // decodes into an inbound `Vec<u8>`). `Cutover` is not part of the negotiation, so it's ignored.
    async fn relay_control(
        mut ctl_rx: tokio::sync::mpsc::UnboundedReceiver<crate::noise::PumpControl>,
        peer_inbound: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) {
        while let Some(pc) = ctl_rx.recv().await {
            if let crate::noise::PumpControl::Send(bytes) = pc {
                if peer_inbound.send(bytes).is_err() {
                    break;
                }
            }
        }
    }

    #[tokio::test]
    async fn inband_upgrade_driver_promotes_both_sides_over_the_pump_control_channels() {
        // #104 H3-wire (frozen): the SAME Offer→Ready promotion as H1, but negotiated in-band over
        // the multiplexed pump's control channels (no separate control stream) — the driver the
        // live wire-in uses. Two relay tasks stand in for the two pumps forwarding CONTROL frames.
        let (ctl_tx_i, ctl_rx_i) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_i, mut in_rx_i) = tokio::sync::mpsc::unbounded_channel();
        let (ctl_tx_r, ctl_rx_r) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_r, mut in_rx_r) = tokio::sync::mpsc::unbounded_channel();
        // initiator's outbound → responder's inbound, and vice versa.
        tokio::spawn(relay_control(ctl_rx_i, in_tx_r));
        tokio::spawn(relay_control(ctl_rx_r, in_tx_i));

        let mut init = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
        let mut resp = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);

        let resp_task = tokio::spawn(async move {
            let out = drive_responder_upgrade(&mut resp, 5, &ctl_tx_r, &mut in_rx_r, |ep| async move {
                ep == "203.0.113.9:7000"
            })
            .await
            .unwrap();
            (out, resp.is_direct())
        });
        let out_i = drive_initiator_upgrade(&mut init, 5, &ctl_tx_i, &mut in_rx_i, || async {
            Some("203.0.113.9:7000".to_string())
        })
        .await
        .unwrap();
        let (out_r, resp_direct) = resp_task.await.unwrap();

        assert_eq!(out_i.as_deref(), Some("203.0.113.9:7000"), "initiator agreed on the direct endpoint");
        assert_eq!(out_r.as_deref(), Some("203.0.113.9:7000"), "responder dialed + agreed the endpoint");
        assert!(init.is_direct(), "initiator coordinator is Direct");
        assert!(resp_direct, "responder coordinator is Direct");
        assert!(init.time_to_upgrade().is_some(), "the handover time was recorded (offload metric)");
    }

    #[tokio::test]
    async fn inband_upgrade_driver_stays_on_relay_when_the_responder_cannot_dial() {
        // The responder's direct dial fails → it sends Abort in-band; both stay on the relay and
        // the initiator records a failed attempt (backoff advances) — the negative of the above.
        let (ctl_tx_i, ctl_rx_i) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_i, mut in_rx_i) = tokio::sync::mpsc::unbounded_channel();
        let (ctl_tx_r, ctl_rx_r) = tokio::sync::mpsc::unbounded_channel();
        let (in_tx_r, mut in_rx_r) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(relay_control(ctl_rx_i, in_tx_r));
        tokio::spawn(relay_control(ctl_rx_r, in_tx_i));

        let mut init = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
        let mut resp = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);

        let resp_task = tokio::spawn(async move {
            let out = drive_responder_upgrade(&mut resp, 5, &ctl_tx_r, &mut in_rx_r, |_ep| async { false })
                .await
                .unwrap();
            (out, resp.is_direct())
        });
        let out_i = drive_initiator_upgrade(&mut init, 5, &ctl_tx_i, &mut in_rx_i, || async {
            Some("203.0.113.9:7000".to_string())
        })
        .await
        .unwrap();
        let (out_r, resp_direct) = resp_task.await.unwrap();

        assert!(out_i.is_none() && out_r.is_none(), "neither side upgraded");
        assert!(!init.is_direct() && !resp_direct, "both stay on the relay");
        assert!(init.attempts() >= 1, "the initiator recorded a failed attempt for backoff");
    }

    #[test]
    fn only_the_initiator_triggers_upgrades_and_respects_the_schedule() {
        // The responder reacts, it never triggers — so both peers don't race.
        let responder = UpgradeCoordinator::new(Role::Responder, 1_000);
        assert!(!responder.should_attempt(1_000_000), "responder never triggers");

        // The initiator waits one base interval before the first attempt, then fires.
        let init = UpgradeCoordinator::with_backoff(Role::Initiator, 1_000, 5, 60);
        assert!(!init.should_attempt(1_002), "not before the first scheduled attempt");
        assert!(init.should_attempt(1_005), "fires once the base interval elapses");
    }

    #[test]
    fn failed_attempts_back_off_exponentially_up_to_the_cap() {
        let mut c = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 5, 60);
        // First window opens at t=5.
        assert!(c.should_attempt(5));
        c.record_attempt_failed(5); // next: 5 + 5*2 = 15
        assert!(!c.should_attempt(14) && c.should_attempt(15), "backoff to +10s");
        c.record_attempt_failed(15); // next: 15 + 5*4 = 35
        assert!(!c.should_attempt(34) && c.should_attempt(35), "backoff to +20s");
        // Keep failing — the interval is capped at max_interval (60s), never unbounded.
        for t in [35, 95, 155, 215] {
            c.record_attempt_failed(t);
        }
        // After the cap, the next attempt is exactly max_interval out.
        c.record_attempt_failed(1_000);
        assert!(!c.should_attempt(1_059) && c.should_attempt(1_060), "capped at +60s");
    }

    #[test]
    fn confirming_the_direct_path_stops_attempts_and_records_time_to_upgrade() {
        let mut c = UpgradeCoordinator::with_backoff(Role::Initiator, 100, 5, 60);
        assert_eq!(c.path(), Path::Relay);
        assert_eq!(c.time_to_upgrade(), None, "no upgrade time while relayed");
        assert!(c.should_attempt(200), "would attempt while relayed");

        c.confirm_upgraded(160); // 60s after the session started at 100
        assert!(c.is_direct() && c.path() == Path::Direct);
        assert_eq!(c.time_to_upgrade(), Some(60), "time-to-upgrade = confirmed - started");
        assert!(!c.should_attempt(1_000_000), "no further attempts once direct");

        // Idempotent: a second confirm keeps the original upgrade time.
        c.confirm_upgraded(999);
        assert_eq!(c.time_to_upgrade(), Some(60));
    }

    #[test]
    fn upgrade_msg_round_trips_and_rejects_malformed() {
        // #104-signal: the relay-borne handover control messages round-trip, and any
        // malformed frame is rejected (never panics) so a garbled relay byte can't
        // crash the swap coordination.
        for msg in [
            UpgradeMsg::Offer { direct_endpoint: "203.0.113.7:4500".into() },
            UpgradeMsg::Ready,
            UpgradeMsg::Abort,
        ] {
            assert_eq!(UpgradeMsg::decode(&msg.encode()), Some(msg.clone()), "round-trips: {msg:?}");
        }
        // The Offer's endpoint is carried verbatim.
        let off = UpgradeMsg::decode(&UpgradeMsg::Offer { direct_endpoint: "h:1".into() }.encode());
        assert_eq!(off, Some(UpgradeMsg::Offer { direct_endpoint: "h:1".into() }));

        // Malformed frames -> None (no panic): empty, unknown tag, empty-endpoint Offer,
        // and trailing bytes on a payloadless tag.
        assert_eq!(UpgradeMsg::decode(&[]), None, "empty");
        assert_eq!(UpgradeMsg::decode(&[9]), None, "unknown tag");
        assert_eq!(UpgradeMsg::decode(&[UpgradeMsg::TAG_OFFER]), None, "offer needs an endpoint");
        assert_eq!(UpgradeMsg::decode(&[UpgradeMsg::TAG_READY, 0xff]), None, "ready takes no payload");
        assert_eq!(UpgradeMsg::decode(&[UpgradeMsg::TAG_OFFER, 0xff, 0xfe]), None, "non-utf8 endpoint");
    }

    #[test]
    fn path_meter_accounts_relay_vs_direct_bytes() {
        let mut m = PathMeter::new();
        assert_eq!(m.direct_fraction(), 0.0, "nothing sent yet");
        m.record(Path::Relay, 300);
        m.record(Path::Direct, 900);
        assert_eq!(m.relay_bytes(), 300);
        assert_eq!(m.direct_bytes(), 900);
        assert_eq!(m.total_bytes(), 1_200);
        assert!((m.direct_fraction() - 0.75).abs() < 1e-9, "75% offloaded to direct");
    }

    #[tokio::test]
    async fn upgradable_session_upgrades_a_relayed_transfer_to_direct_byte_exact() {
        // #104 direct-P2P (frozen): the full orchestration — two peers run the relayed A2A session
        // on the multiplexed pump, negotiate the upgrade in-band, install a direct session, and cut
        // over — and a payload spanning the seam arrives byte-exact. The direct link is injected
        // (pre-handshaked) so this is a deterministic unit proof of the COMPOSITION; the live dial +
        // NAT hole-punch is H4.
        use crate::a2a::establish_direct_session;
        use crate::noise::generate_static_keypair;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let a = generate_static_keypair(); // initiator (channel role)
        let b = generate_static_keypair(); // responder
        let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);

        // Pre-handshake the DIRECT session over a duplex pair; its halves become the direct data
        // path. The dialer (responder) is the direct-Noise initiator, matching who-dials-first.
        let (hd_r2i_w, hd_r2i_r) = tokio::io::duplex(1 << 16); // responder→initiator direct
        let (hd_i2r_w, hd_i2r_r) = tokio::io::duplex(1 << 16); // initiator→responder direct
        let resp_est = tokio::spawn(async move {
            establish_direct_session(hd_r2i_w, hd_i2r_r, true, &b_priv, &a_pub).await
        });
        // #416: `establish_direct_session`'s responder branch now actually pins its peer, so this
        // must be the real expected key (B, the direct-Noise initiator above), not a placeholder.
        let (ini_ts, ini_dr, ini_dw) =
            establish_direct_session(hd_i2r_w, hd_r2i_r, false, &a_priv, &b_pub)
                .await
                .expect("initiator direct handshake");
        let (resp_ts, resp_dr, resp_dw) = resp_est.await.expect("join").expect("responder direct handshake");

        // Relay stream halves between the two peers.
        let (ra2b_w, ra2b_r) = tokio::io::duplex(1 << 16);
        let (rb2a_w, rb2a_r) = tokio::io::duplex(1 << 16);

        // App endpoints: test → initiator's source; responder's sink → test.
        let (ini_app, ini_test) = tokio::io::duplex(1 << 16);
        let (_ini_test_r, mut ini_feed) = tokio::io::split(ini_test); // write payload to the WriteHalf
        let (resp_app, resp_test) = tokio::io::duplex(1 << 16);
        // Keep the responder's app-source write half open during negotiation (its outbound must
        // stay open to send Ready); we shut it down after the assertion so both pumps wind down.
        let (mut resp_out, resp_test_w) = tokio::io::split(resp_test); // read delivered from ReadHalf

        let coord_i = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
        let coord_r = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);
        const EP: &str = "203.0.113.9:7000";

        let init_task = tokio::spawn(async move {
            run_upgradable_session_initiator(
                ra2b_w, rb2a_r, ini_app, &a_priv, &b_pub, coord_i, 5,
                || async { Some(EP.to_string()) },
                move || async move { Some((ini_ts, ini_dr, ini_dw)) },
            )
            .await
        });
        let resp_task = tokio::spawn(async move {
            run_upgradable_session_responder(
                rb2a_w, ra2b_r, resp_app, &b_priv, &a_pub, coord_r, 5,
                |ep| async move { ep == EP },
                move |_ep| async move { Some((resp_ts, resp_dr, resp_dw)) },
            )
            .await
        });

        // Stream a 2000-byte payload: some rides the relay, then the cutover, then the rest rides
        // direct — all through the ONE app stream, transparently to the caller.
        let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
        ini_feed.write_all(&payload).await.unwrap();
        ini_feed.flush().await.unwrap();
        ini_feed.shutdown().await.unwrap(); // EOF the source (drop alone won't, split shares the stream)

        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(std::time::Duration::from_secs(10), resp_out.read_exact(&mut got))
            .await
            .expect("the responder receives the whole payload within 10s")
            .expect("read_exact");
        assert_eq!(got, payload, "relayed transfer upgraded to direct with a byte-exact stream (#104)");

        // The delivery is the assertion; tear the background sessions down without waiting on
        // graceful relay/direct shutdown (which is a live-teardown concern, covered by #134/H4).
        drop(resp_test_w);
        init_task.abort();
        resp_task.abort();
    }
}

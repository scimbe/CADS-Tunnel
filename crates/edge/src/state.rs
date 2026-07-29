//! Edge routing state (M5.1b).
//!
//! Maps a Routing Token to the Agent tunnel handle that serves it, so the Edge
//! can route a resolved Client rendezvous to the right Agent connection. Generic
//! over the handle type (`quinn::Connection` in the daemon) to stay
//! unit-testable. `is_known` plugs straight into `resolve_rendezvous_gated`.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ct_common::metrics::Counter;
use ct_common::ratelimit::RateLimiter;
use ct_common::RoutingToken;
use ct_common::sync::MutexExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use std::sync::Arc;

/// A concurrency cap for the edge accept loop (#86 SEC86b, ADR-0018's connection-
/// flood half): at most `max` connections are handled at once. [`try_admit`] hands
/// out an owned permit that the caller holds for the connection's lifetime; when the
/// cap is reached it returns `None` and the caller sheds the connection (quinn
/// `Incoming::ignore`), so a flood can't exhaust memory / file descriptors before the
/// PoW gate even runs. Load-shedding (not queueing) keeps a rejected connection cheap.
///
/// [`try_admit`]: ConnectionCap::try_admit
#[derive(Clone)]
pub struct ConnectionCap {
    sem: Arc<Semaphore>,
}

impl ConnectionCap {
    /// A cap admitting at most `max` concurrent connections.
    pub fn new(max: usize) -> Self {
        Self {
            sem: Arc::new(Semaphore::new(max)),
        }
    }

    /// Try to admit one connection: `Some(permit)` when below the cap (hold it for
    /// the connection's lifetime), `None` when full (shed the connection). Never
    /// blocks.
    pub fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.sem).try_acquire_owned().ok()
    }

    /// Currently free slots (for tests / metrics).
    pub fn available(&self) -> usize {
        self.sem.available_permits()
    }
}

/// A boxed bidirectional byte stream — the concrete handoff type for a
/// TCP-fallback agent rendezvous (issue #3 / P1.2c-3), where a single stream
/// cannot be cloned/multiplexed like a QUIC connection.
pub trait DuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DuplexStream for T {}
pub type BoxedStream = Box<dyn DuplexStream>;

/// Thread-safe registry of live Agent tunnels keyed by Routing Token, plus each
/// Agent's Edge-observed peer candidate (its reflexive address) for P2P
/// rendezvous (M11.1).
pub struct EdgeState<H> {
    /// Live Agent tunnels per token. **Multiple** Agents may register the same
    /// token for redundancy/failover (#8); each is tagged with a monotonic
    /// registration id so exactly one can be evicted when its connection drops.
    agents: Mutex<HashMap<RoutingToken, Vec<(u64, H)>>>,
    /// Source of monotonic registration ids.
    next_reg: AtomicU64,
    candidates: Mutex<HashMap<RoutingToken, SocketAddr>>,
    /// Agent-advertised direct-path listener: (address, cert DER) a Client can
    /// connect to directly, bypassing the Edge relay (M11.4b).
    direct: Mutex<HashMap<RoutingToken, (SocketAddr, Vec<u8>)>>,
    /// Parked TCP-fallback agents (issue #3 / P1.2c-3): a `token` maps to a
    /// sender the Client handler uses to hand its stream to the waiting agent.
    /// Unlike QUIC agents these are single-use (one client per registration).
    tcp_agents: Mutex<HashMap<RoutingToken, oneshot::Sender<BoxedStream>>>,
    /// Browser Plane (#23): public hostname -> routing token, so an SNI-routed
    /// TLS connection can be mapped to a tunnel without the Client protocol.
    /// Hostnames are stored lowercased. The payload stays blind (TLS ciphertext
    /// is passed through); only the SNI hostname is visible to the Edge.
    hosts: Mutex<HashMap<String, RoutingToken>>,
    /// Revoked routing tokens (#27 RB3): a token here is torn down and refuses
    /// re-registration, so a customer's "revoke" actually stops the tunnel even
    /// though the agent keeps reconnecting.
    revoked: Mutex<HashSet<RoutingToken>>,
    /// Shared admin secret authenticating the control plane's `'R'` revoke op
    /// (#27 RB3). `None` = revocation disabled (no `CT_EDGE_ADMIN_TOKEN`).
    admin_token: Mutex<Option<[u8; 32]>>,
    /// Hostname-ownership authorization (#23 BP4b). `None` = not required (legacy
    /// binds allowed, subject to BP4a takeover-safety). `Some(map)` = required:
    /// a hostname may only be bound by the token the control plane authorized for
    /// it — so an anonymous `'H'` bind on a public `:443` can't claim a name.
    host_auth: Mutex<Option<HashMap<String, RoutingToken>>>,
    /// Rot/Gelb/Grün certificate tier (#233): hostnames currently in the
    /// **Gelb** tier — live via the shared front-door wildcard certificate,
    /// not yet on their own agent-held one. Absence here (the default for
    /// every hostname on a fresh boot) means ordinary SNI-passthrough
    /// (`serve_sni_passthrough`), exactly today's behavior — a host only
    /// ever gets TLS-terminated at the edge with the wildcard cert when the
    /// control plane has explicitly pushed it here via
    /// `POST /admin/authorize-host/:token/:host?tier=gelb`.
    gelb_hosts: Mutex<HashSet<String>>,
    /// Per-token fixed-window rendezvous rate limit (#86, ADR-0018). `None` = off
    /// (no cap). `Some(limiter)` caps how many rendezvous a single routing token may
    /// drive per window — the second half of the layered rendezvous-flood defense
    /// (PoW raises per-attempt cost; this caps per-token volume even for a solver).
    rendezvous_limiter: Mutex<Option<RateLimiter>>,
    /// Cumulative data-plane counters for observability (#10 O2).
    registrations: Counter,
    relays: Counter,
    relay_bytes: Counter,
    failovers: Counter,
}

impl<H: Clone> EdgeState<H> {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
            next_reg: AtomicU64::new(1),
            candidates: Mutex::new(HashMap::new()),
            direct: Mutex::new(HashMap::new()),
            tcp_agents: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            admin_token: Mutex::new(None),
            host_auth: Mutex::new(None),
            gelb_hosts: Mutex::new(HashSet::new()),
            rendezvous_limiter: Mutex::new(None),
            registrations: Counter::default(),
            relays: Counter::default(),
            relay_bytes: Counter::default(),
            failovers: Counter::default(),
        }
    }

    /// Bind a public hostname to a routing token (Browser Plane, #23), **unless**
    /// the hostname is already bound to a *different* token — a takeover-safe bind
    /// (#23 BP4a). Rebinding the same token (an agent reconnecting) is idempotent
    /// and succeeds. Returns `true` when the binding is in place, `false` when a
    /// conflicting bind was refused (the existing route is left untouched). The
    /// hostname is lowercased so SNI lookups are case-insensitive.
    pub fn register_host(&self, host: &str, token: RoutingToken) -> bool {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return false; // reject malformed hostnames (#23 BP4b-d)
        };
        let mut hosts = self.hosts.lock_safe();
        match hosts.get(&key) {
            Some(existing) if *existing != token => false,
            _ => {
                hosts.insert(key, token);
                true
            }
        }
    }

    /// Remove every hostname bound to `token` — called when its last agent drops
    /// or it is revoked, so no stale host->token route lingers (#23 BP4a).
    fn clear_hosts_for(&self, token: &RoutingToken) {
        self.hosts.lock_safe().retain(|_, v| v != token);
    }

    /// Every currently-authorized (hostname, token) pair, or `None` if
    /// authorization was never required on this edge (host_auth still `None`).
    /// Read-only — the operator-facing admin dump this deployment's own current
    /// state can be backfilled from before touching a control-plane registry
    /// that has no other way to learn what this edge already knows (#153: a
    /// live edge holds authorizations the control plane never persisted itself
    /// for hostnames bound via the loopback admin API directly).
    pub fn dump_host_auth(&self) -> Option<Vec<(String, RoutingToken)>> {
        self.host_auth
            .lock_safe()
            .as_ref()
            .map(|m| m.iter().map(|(h, t)| (h.clone(), t.clone())).collect())
    }

    /// Require hostname-ownership authorization (#23 BP4b): once enabled, an
    /// `'H'` bind is refused unless the control plane has authorized that
    /// (hostname, token) pair. Enabled at startup for a reachable `:443`.
    pub fn require_host_auth(&self) {
        let mut ha = self.host_auth.lock_safe();
        if ha.is_none() {
            *ha = Some(HashMap::new());
        }
    }

    /// Authorize `host` to be bound by `token` (#23 BP4b) — the control plane
    /// pushes this when a customer sets a hostname on a tunnel they own. Also
    /// enables authorization if it was not already required.
    pub fn authorize_host(&self, host: &str, token: RoutingToken) {
        if let Some(key) = ct_common::normalize_hostname(host) {
            self.host_auth
                .lock_safe()
                .get_or_insert_with(HashMap::new)
                .insert(key, token);
        }
    }

    /// Whether binding `host` to `token` is permitted (#23 BP4b): always true
    /// when authorization is not required; otherwise only for the authorized
    /// (hostname, token) pair.
    pub fn host_bind_allowed(&self, host: &str, token: &RoutingToken) -> bool {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return false; // a malformed hostname is never bindable (#23 BP4b-d)
        };
        match self.host_auth.lock_safe().as_ref() {
            None => true,
            Some(map) => map.get(&key) == Some(token),
        }
    }

    /// Enable the per-token rendezvous rate limit (#86, ADR-0018): at most
    /// `max_per_window` rendezvous per routing token per window. Off until called.
    pub fn set_rendezvous_limit(&self, max_per_window: u32) {
        *self.rendezvous_limiter.lock_safe() = Some(RateLimiter::new(max_per_window));
    }

    /// Whether `token` may drive another rendezvous in `window` (#86): always true
    /// when the limit is off; otherwise consults the fixed-window counter. `window`
    /// is a caller-supplied window index (e.g. `unix_secs / window_secs`), so this
    /// stays deterministic and unit-testable.
    pub fn rendezvous_allowed(&self, token: &RoutingToken, window: u64) -> bool {
        match self.rendezvous_limiter.lock_safe().as_mut() {
            None => true,
            Some(rl) => rl.allow(token, window),
        }
    }

    /// Resolve a public hostname (from the TLS SNI) to its routing token.
    pub fn route_host(&self, host: &str) -> Option<RoutingToken> {
        let key = ct_common::normalize_hostname(host)?;
        self.hosts.lock_safe().get(&key).cloned()
    }

    /// Set whether `host` is currently in the **Gelb** certificate tier
    /// (#233) — the control plane calls this (via the admin API) every time
    /// a hostname's tier changes, in both directions: `true` when it enters
    /// Gelb (live via the shared wildcard cert), `false` once it reaches
    /// Grün (its own cert exists; revert to ordinary passthrough so the
    /// browser sees the origin's own certificate again). A malformed
    /// hostname is silently a no-op, same as [`Self::register_host`].
    pub fn set_cert_tier(&self, host: &str, gelb: bool) {
        let Some(key) = ct_common::normalize_hostname(host) else {
            return;
        };
        let mut gelb_hosts = self.gelb_hosts.lock_safe();
        if gelb {
            gelb_hosts.insert(key);
        } else {
            gelb_hosts.remove(&key);
        }
    }

    /// Whether `host` is currently in the Gelb tier — `false` for any
    /// hostname never explicitly marked so (a fresh boot, or one the control
    /// plane has never pushed a tier for), which is exactly what preserves
    /// today's ordinary SNI-passthrough behavior for every hostname this
    /// feature doesn't touch.
    pub fn is_gelb(&self, host: &str) -> bool {
        match ct_common::normalize_hostname(host) {
            Some(key) => self.gelb_hosts.lock_safe().contains(&key),
            None => false,
        }
    }

    /// Note a completed relay of `bytes` total bytes (both directions), and a
    /// failover to a non-primary agent, for observability (#10 O2).
    pub fn note_relay(&self, bytes: u64) {
        self.relays.inc();
        self.relay_bytes.add(bytes);
    }
    pub fn note_failover(&self) {
        self.failovers.inc();
    }
    /// Cumulative counter snapshots for the metrics endpoint (#10 O2).
    pub fn registrations_total(&self) -> u64 {
        self.registrations.get()
    }
    pub fn relays_total(&self) -> u64 {
        self.relays.get()
    }
    pub fn relay_bytes_total(&self) -> u64 {
        self.relay_bytes.get()
    }
    pub fn failovers_total(&self) -> u64 {
        self.failovers.get()
    }

    /// Park a TCP-fallback agent for `token`: returns a receiver that resolves to
    /// a Client's stream once one rendezvouses for this token (single-tunnel).
    /// The agent then relays its own stream to the received one.
    pub fn park_tcp_agent(&self, token: RoutingToken) -> oneshot::Receiver<BoxedStream> {
        let (tx, rx) = oneshot::channel();
        self.tcp_agents.lock_safe().insert(token, tx);
        rx
    }

    /// Hand a Client's `stream` to a parked TCP-fallback agent for `token`.
    /// Returns the stream back as `Err` if no TCP agent is waiting (so the caller
    /// can fall through to the QUIC route), consuming the registration on success.
    pub fn deliver_to_tcp_agent(
        &self,
        token: &RoutingToken,
        stream: BoxedStream,
    ) -> Result<(), BoxedStream> {
        let tx = self.tcp_agents.lock_safe().remove(token);
        match tx {
            Some(tx) => tx.send(stream),
            None => Err(stream),
        }
    }

    /// Whether a TCP-fallback agent is currently parked for `token`.
    pub fn has_tcp_agent(&self, token: &RoutingToken) -> bool {
        self.tcp_agents.lock_safe().contains_key(token)
    }

    /// Record the Agent's advertised direct-path listener for `token` (M11.4b):
    /// the address and cert DER a Client uses to connect directly.
    pub fn advertise_direct(&self, token: RoutingToken, addr: SocketAddr, cert: Vec<u8>) {
        self.direct.lock_safe().insert(token, (addr, cert));
    }

    /// The Agent's advertised direct-path `(addr, cert)` for `token`, if any.
    pub fn direct_endpoint(&self, token: &RoutingToken) -> Option<(SocketAddr, Vec<u8>)> {
        self.direct.lock_safe().get(token).cloned()
    }

    /// Register an Agent tunnel serving `token`, returning a **registration id**.
    /// Multiple Agents may register the same token for redundancy/failover (#8);
    /// the id lets exactly this registration be evicted (via
    /// [`remove_registration`](Self::remove_registration)) when its connection
    /// drops, without disturbing the other Agents serving the token.
    pub fn register(&self, token: RoutingToken, handle: H) -> u64 {
        let id = self.next_reg.fetch_add(1, Ordering::Relaxed);
        self.agents
            .lock_safe()
            .entry(token)
            .or_default()
            .push((id, handle));
        self.registrations.inc();
        id
    }

    /// Register the Agent tunnel and record its Edge-observed peer candidate —
    /// the reflexive address a Client will hole-punch toward (M11.1). Returns the
    /// registration id (see [`register`](Self::register)).
    pub fn register_with_candidate(
        &self,
        token: RoutingToken,
        handle: H,
        candidate: SocketAddr,
    ) -> u64 {
        self.candidates.lock_safe().insert(token.clone(), candidate);
        self.register(token, handle)
    }

    /// The Agent's Edge-observed peer candidate for `token`, if recorded.
    pub fn candidate(&self, token: &RoutingToken) -> Option<SocketAddr> {
        self.candidates.lock_safe().get(token).copied()
    }

    /// Route `token` to a live Agent tunnel handle, if any. Returns the **most
    /// recently registered** Agent, so a reconnecting Agent is preferred over its
    /// own dying registration and, with redundant Agents (#8), the newest serves
    /// (the next takes over on its drop).
    pub fn route(&self, token: &RoutingToken) -> Option<H> {
        self.agents
            .lock_safe()
            .get(token)
            .and_then(|v| v.last().map(|(_, h)| h.clone()))
    }

    /// All live Agent handles for `token`, **most-recently-registered first** —
    /// the failover order for the relay: try the newest, fall back to older ones
    /// if its `open_bi()` fails (#8 R2, covers the dead-but-not-yet-evicted race).
    pub fn routes(&self, token: &RoutingToken) -> Vec<H> {
        self.agents.lock_safe().get(token).map_or_else(Vec::new, |v| {
            v.iter().rev().map(|(_, h)| h.clone()).collect()
        })
    }

    /// Number of redundant Agent registrations currently serving `token` (#8).
    pub fn registration_count(&self, token: &RoutingToken) -> usize {
        self.agents.lock_safe().get(token).map_or(0, Vec::len)
    }

    /// Distinct routing tokens with at least one live Agent — the number of
    /// tunnels the Edge is currently serving (observability gauge, #10).
    pub fn active_tunnels(&self) -> usize {
        self.agents.lock_safe().values().filter(|v| !v.is_empty()).count()
    }

    /// Total live Agent registrations across all tokens — redundant Agents (#8)
    /// counted separately (observability gauge, #10).
    pub fn total_registrations(&self) -> usize {
        self.agents.lock_safe().values().map(Vec::len).sum()
    }

    /// Evict exactly the registration `id` for `token` — an Agent whose
    /// connection dropped — leaving any other redundant Agents in place (#8).
    /// The token's candidate/direct entries are cleared only when the **last**
    /// Agent for the token is gone.
    pub fn remove_registration(&self, token: &RoutingToken, id: u64) {
        let mut agents = self.agents.lock_safe();
        if let Some(v) = agents.get_mut(token) {
            v.retain(|(rid, _)| *rid != id);
            if v.is_empty() {
                agents.remove(token);
                drop(agents);
                self.candidates.lock_safe().remove(token);
                self.direct.lock_safe().remove(token);
                // The tunnel is gone — drop its hostname routes too (#23 BP4a).
                self.clear_hosts_for(token);
            }
        }
    }

    /// Remove **all** Agent tunnels (and candidate + direct + tcp) for `token` —
    /// a full teardown, regardless of how many redundant Agents serve it.
    pub fn remove(&self, token: &RoutingToken) {
        self.agents.lock_safe().remove(token);
        self.candidates.lock_safe().remove(token);
        self.direct.lock_safe().remove(token);
        self.tcp_agents.lock_safe().remove(token);
        self.clear_hosts_for(token);
    }

    /// Revoke `token` (#27 RB3): tear down its live registrations and any hostname
    /// mappings, and mark it so a reconnecting Agent cannot re-register it. This
    /// is what makes a customer's "revoke" actually stop the tunnel — without the
    /// revoked set, the Agent's reconnect loop would simply register again.
    pub fn revoke_token(&self, token: &RoutingToken) {
        self.revoked.lock_safe().insert(token.clone());
        self.remove(token); // also clears the token's hostname routes (#23 BP4a)
    }

    /// Whether `token` has been revoked (#27 RB3).
    pub fn is_revoked(&self, token: &RoutingToken) -> bool {
        self.revoked.lock_safe().contains(token)
    }

    /// Configure the shared admin secret that authenticates the `'R'` revoke op
    /// (#27 RB3). Set from `CT_EDGE_ADMIN_TOKEN` at startup.
    pub fn set_admin_token(&self, token: [u8; 32]) {
        *self.admin_token.lock_safe() = Some(token);
    }

    /// Constant-time check that `auth` matches the configured admin secret.
    /// Always `false` when no admin token is configured (revocation disabled).
    pub fn admin_revoke_ok(&self, auth: &[u8; 32]) -> bool {
        match self.admin_token.lock_safe().as_ref() {
            Some(expected) => {
                auth.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
            }
            None => false,
        }
    }

    /// Register an Agent tunnel unless its token has been revoked (#27 RB3).
    /// Returns the registration id, or `None` if the token is revoked — the
    /// registration path the serve loop uses so a revoked token stays down even
    /// as its Agent keeps reconnecting.
    pub fn register_unless_revoked(&self, token: RoutingToken, handle: H) -> Option<u64> {
        if self.is_revoked(&token) {
            return None;
        }
        Some(self.register(token, handle))
    }

    /// Whether `token` currently has at least one live Agent tunnel.
    pub fn is_known(&self, token: &RoutingToken) -> bool {
        self.agents
            .lock_safe()
            .get(token)
            .is_some_and(|v| !v.is_empty())
    }
}

impl<H: Clone> Default for EdgeState<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn connection_cap_admits_up_to_max_then_sheds_and_recovers_on_release() {
        // #95/#119: the load-shedding cap admits at most `max` concurrent connections
        // (each admitted connection holds its permit for its lifetime). Over the cap
        // `try_admit` returns `None` so the accept loop sheds cheaply, and dropping a
        // permit (a connection closed) frees a slot for the next admission. This is the
        // mechanism every edge accept loop — QUIC, the TCP fallback, and the `:443` front
        // door (#119) — relies on to bound a pre-auth connection flood.
        let cap = ConnectionCap::new(2);
        assert_eq!(cap.available(), 2);
        let p1 = cap.try_admit().expect("1st admitted");
        let _p2 = cap.try_admit().expect("2nd admitted");
        assert_eq!(cap.available(), 0, "at the cap");
        assert!(cap.try_admit().is_none(), "over the cap -> shed");
        drop(p1); // a connection closed, releasing its slot
        assert_eq!(cap.available(), 1);
        let _p3 = cap.try_admit().expect("a freed slot admits the next");
        assert!(cap.try_admit().is_none(), "full again after re-admitting");
    }

    #[test]
    fn register_then_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        assert_eq!(state.route(&token(1)), Some(42));
        assert!(state.is_known(&token(1)));
    }

    #[test]
    fn rendezvous_rate_limit_off_by_default_then_caps_per_token_per_window() {
        let state: EdgeState<u32> = EdgeState::new();
        // Off by default: any number of rendezvous is allowed.
        for _ in 0..100 {
            assert!(state.rendezvous_allowed(&token(1), 0), "no cap until enabled (#86)");
        }
        // Enable a cap of 2 per window.
        state.set_rendezvous_limit(2);
        assert!(state.rendezvous_allowed(&token(1), 0), "1st allowed");
        assert!(state.rendezvous_allowed(&token(1), 0), "2nd allowed");
        assert!(!state.rendezvous_allowed(&token(1), 0), "3rd in the window rejected");
        // A different token has its own budget.
        assert!(state.rendezvous_allowed(&token(2), 0), "per-token budget is independent");
        // A new window resets the budget.
        assert!(state.rendezvous_allowed(&token(1), 1), "next window resets the cap");
    }

    #[test]
    fn host_bind_authorization_gates_binds_when_required() {
        // #23 BP4b: with authorization required, only the CP-authorized (host,
        // token) pair may bind; unauthorized host or wrong token is refused.
        let state = EdgeState::<u32>::new();
        // Legacy (not required): any bind allowed.
        assert!(state.host_bind_allowed("x.test", &token(1)));

        state.require_host_auth();
        assert!(!state.host_bind_allowed("x.test", &token(1)), "nothing allowed until authorized");

        state.authorize_host("X.Test", token(1)); // case-insensitive
        assert!(state.host_bind_allowed("x.test", &token(1)), "authorized pair allowed");
        assert!(!state.host_bind_allowed("x.test", &token(2)), "wrong token refused");
        assert!(!state.host_bind_allowed("y.test", &token(1)), "unauthorized host refused");
    }

    #[test]
    fn dump_host_auth_reflects_current_authorizations_or_none_if_never_required() {
        let state = EdgeState::<u32>::new();
        assert_eq!(state.dump_host_auth(), None, "authorization never required -> None, not empty");

        state.require_host_auth();
        assert_eq!(state.dump_host_auth(), Some(vec![]), "required but nothing authorized yet -> empty");

        state.authorize_host("a.test", token(1));
        state.authorize_host("b.test", token(2));
        let mut dump = state.dump_host_auth().unwrap();
        dump.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(dump, vec![("a.test".to_string(), token(1)), ("b.test".to_string(), token(2))]);
    }

    #[test]
    fn host_normalization_collapses_trailing_dot_and_rejects_junk() {
        // #23 BP4b-d: bind/lookup normalize identically; malformed hosts refused.
        let state = EdgeState::<u32>::new();
        assert!(state.register_host("App.Example.", token(7)));
        assert_eq!(state.route_host("app.example"), Some(token(7)));
        assert_eq!(state.route_host("app.example."), Some(token(7)), "trailing dot collapses");
        assert!(!state.register_host("bad host", token(8)), "malformed hostname refused at bind");
        assert_eq!(state.route_host("bad host"), None);
    }

    #[test]
    fn cert_tier_defaults_to_not_gelb_and_is_toggleable_both_ways() {
        // #233: a fresh boot (or any hostname the control plane never pushed a
        // tier for) must default to false -- that's what keeps every existing,
        // already-gruen hostname on ordinary passthrough with zero config.
        let state = EdgeState::<u32>::new();
        assert!(!state.is_gelb("app.example"), "never marked -> not gelb, the safe default");

        state.set_cert_tier("App.Example.", true);
        assert!(state.is_gelb("app.example"), "normalized the same way register_host/route_host do");

        // Gelb -> Grün: the control plane reverts the tier once the hostname's
        // own real cert exists, and passthrough must resume.
        state.set_cert_tier("app.example", false);
        assert!(!state.is_gelb("app.example"));

        // A malformed hostname is a silent no-op, same as register_host.
        state.set_cert_tier("bad host", true);
        assert!(!state.is_gelb("bad host"));
    }

    #[test]
    fn host_binding_is_takeover_safe_and_cleared_on_agent_drop() {
        // #23 BP4a: first bind wins; a conflicting bind can't steal the route;
        // the binding is cleared when the tunnel's last agent drops.
        let state = EdgeState::new();
        let (t1, t2) = (token(1), token(2));
        let id = state.register(t1.clone(), 5u32);

        // First bind wins; rebinding the SAME token (reconnect) is idempotent-OK.
        assert!(state.register_host("app.example", t1.clone()));
        assert!(state.register_host("app.example", t1.clone()), "same-token rebind ok");
        assert_eq!(state.route_host("app.example"), Some(t1.clone()));

        // A conflicting bind to a DIFFERENT token is refused; route untouched.
        assert!(!state.register_host("app.example", t2.clone()), "takeover refused");
        assert_eq!(state.route_host("app.example"), Some(t1.clone()), "original route intact");

        // When the tunnel's last agent drops, the stale host route is cleared.
        state.remove_registration(&t1, id);
        assert_eq!(state.route_host("app.example"), None, "host route cleared on drop");

        // ...so the hostname is now free for a different tunnel to claim.
        assert!(state.register_host("app.example", t2.clone()));
        assert_eq!(state.route_host("app.example"), Some(t2));
    }

    #[test]
    fn admin_revoke_ok_requires_the_configured_secret() {
        // #27 RB3: the 'R' revoke op authenticates against CT_EDGE_ADMIN_TOKEN.
        let state = EdgeState::<u32>::new();
        let secret = [0x11u8; 32];
        // Unconfigured -> revocation disabled, every auth rejected.
        assert!(!state.admin_revoke_ok(&secret));
        state.set_admin_token(secret);
        assert!(state.admin_revoke_ok(&secret), "correct secret accepted");
        let mut wrong = secret;
        wrong[31] ^= 1;
        assert!(!state.admin_revoke_ok(&wrong), "wrong secret rejected");
    }

    #[test]
    fn revoke_token_drops_registration_and_blocks_reregistration() {
        // #27 RB3: revoke tears down the live tunnel and refuses re-registration,
        // so a reconnecting agent can't defeat a customer's "revoke".
        let state = EdgeState::new();
        let t = token(9);
        state.register_host("app.example", t.clone());
        state.register(t.clone(), 1u32);
        assert_eq!(state.active_tunnels(), 1);

        state.revoke_token(&t);
        assert_eq!(state.active_tunnels(), 0, "revoke drops the live registration");
        assert!(state.is_revoked(&t));
        assert_eq!(state.route_host("app.example"), None, "hostname mapping cleared");

        // A reconnecting agent cannot re-register the revoked token.
        assert!(state.register_unless_revoked(t.clone(), 2u32).is_none());
        assert_eq!(state.active_tunnels(), 0, "still no tunnel after a blocked re-register");

        // A different (unrevoked) token registers normally.
        assert!(state.register_unless_revoked(token(10), 3u32).is_some());
        assert_eq!(state.active_tunnels(), 1);
    }

    #[test]
    fn route_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.route(&token(9)), None);
        assert!(!state.is_known(&token(9)));
    }

    #[test]
    fn redundant_agents_fail_over_on_registration_drop() {
        // #8 R1: two Agents register the same token; routing prefers the most
        // recent, and evicting one registration fails over to the other without
        // disturbing it — the whole point of Agent redundancy.
        let state: EdgeState<u32> = EdgeState::new();
        let t = token(1);
        let a = state.register(t.clone(), 10); // Agent A
        let b = state.register(t.clone(), 20); // Agent B (more recent)
        assert_eq!(state.registration_count(&t), 2, "both agents registered");
        assert_eq!(state.route(&t), Some(20), "most-recent agent serves");

        // Agent B's connection drops → evict just B → fail over to A.
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10), "failover to the surviving agent");
        assert_eq!(state.registration_count(&t), 1);
        assert!(state.is_known(&t), "tunnel still up on one agent");

        // Evicting an already-gone id is a no-op (idempotent).
        state.remove_registration(&t, b);
        assert_eq!(state.route(&t), Some(10));

        // Last agent drops → tunnel is gone and its metadata is cleaned up.
        state.remove_registration(&t, a);
        assert_eq!(state.route(&t), None, "no agents left");
        assert!(!state.is_known(&t));
        assert_eq!(state.registration_count(&t), 0);
    }

    #[test]
    fn remove_drops_route() {
        let state = EdgeState::new();
        state.register(token(1), 42u32);
        state.remove(&token(1));
        assert_eq!(state.route(&token(1)), None);
        assert!(!state.is_known(&token(1)));
    }

    #[test]
    fn register_with_candidate_records_and_routes() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "203.0.113.7:51820".parse().unwrap();
        state.register_with_candidate(token(2), 7u32, cand);
        assert_eq!(state.route(&token(2)), Some(7), "handle routable");
        assert_eq!(state.candidate(&token(2)), Some(cand), "candidate recorded");
    }

    #[test]
    fn candidate_unknown_is_none() {
        let state: EdgeState<u32> = EdgeState::new();
        assert_eq!(state.candidate(&token(9)), None);
    }

    #[test]
    fn remove_drops_candidate() {
        let state = EdgeState::new();
        let cand: std::net::SocketAddr = "198.51.100.4:4433".parse().unwrap();
        state.register_with_candidate(token(3), 1u32, cand);
        state.remove(&token(3));
        assert_eq!(state.candidate(&token(3)), None);
    }

    #[test]
    fn advertise_and_look_up_direct_endpoint() {
        let state: EdgeState<u32> = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(4), addr, vec![1, 2, 3, 4]);
        assert_eq!(state.direct_endpoint(&token(4)), Some((addr, vec![1, 2, 3, 4])));
        assert_eq!(state.direct_endpoint(&token(5)), None, "unknown → None");
    }

    #[test]
    fn remove_drops_direct_endpoint() {
        let state = EdgeState::new();
        let addr: std::net::SocketAddr = "203.0.113.9:5000".parse().unwrap();
        state.advertise_direct(token(6), addr, vec![9, 9]);
        state.register(token(6), 1u32);
        state.remove(&token(6));
        assert_eq!(state.direct_endpoint(&token(6)), None);
    }

    #[tokio::test]
    async fn tcp_agent_park_then_deliver_hands_over_the_stream() {
        // issue #3 / P1.2c-3: a parked TCP agent receives the Client's stream.
        let state: EdgeState<u32> = EdgeState::new();
        let rx = state.park_tcp_agent(token(7));
        assert!(state.has_tcp_agent(&token(7)));
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(7), client).is_ok(),
            "delivery to a parked agent succeeds"
        );
        assert!(rx.await.is_ok(), "the agent receives the client stream");
        assert!(!state.has_tcp_agent(&token(7)), "registration consumed (single-use)");
    }

    #[tokio::test]
    async fn deliver_without_parked_tcp_agent_returns_the_stream() {
        let state: EdgeState<u32> = EdgeState::new();
        let client: BoxedStream = Box::new(tokio::io::duplex(16).0);
        assert!(
            state.deliver_to_tcp_agent(&token(8), client).is_err(),
            "no parked agent → stream handed back so the caller can fall through"
        );
    }

    #[tokio::test]
    async fn remove_drops_parked_tcp_agent() {
        let state: EdgeState<u32> = EdgeState::new();
        let _rx = state.park_tcp_agent(token(9));
        state.remove(&token(9));
        assert!(!state.has_tcp_agent(&token(9)));
    }

    #[test]
    fn connection_cap_admits_up_to_max_then_sheds_until_a_permit_frees() {
        // #86 SEC86b: the accept-loop cap admits at most `max` concurrent
        // connections and sheds the rest; dropping a held permit frees a slot.
        let cap = ConnectionCap::new(2);
        assert_eq!(cap.available(), 2);

        let a = cap.try_admit().expect("1st admitted");
        let b = cap.try_admit().expect("2nd admitted");
        assert_eq!(cap.available(), 0, "both slots taken");
        assert!(cap.try_admit().is_none(), "over the cap -> shed");

        // Releasing one held permit frees exactly one slot.
        drop(a);
        assert_eq!(cap.available(), 1);
        let c = cap.try_admit().expect("slot freed -> admits again");
        assert!(cap.try_admit().is_none(), "back at the cap");

        drop(b);
        drop(c);
        assert_eq!(cap.available(), 2, "all permits returned");
    }

    #[test]
    fn connection_cap_clones_share_one_global_budget() {
        // #86 SEC86c: the QUIC and TCP accept loops hold CLONES of one
        // ConnectionCap, so the cap must be global — a permit taken through one
        // handle is unavailable through the other (not a per-loop budget).
        let cap = ConnectionCap::new(1);
        let clone = cap.clone();
        let p = cap.try_admit().expect("global slot admitted via one handle");
        assert!(clone.try_admit().is_none(), "the clone sees the shared budget exhausted");
        drop(p);
        assert!(clone.try_admit().is_some(), "releasing frees the slot for the clone too");
    }
}

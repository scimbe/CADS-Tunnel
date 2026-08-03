//! Agent Fabric — channel addressing and trust-chain grants (ADR-0020, #72).
//!
//! A **Channel** is an opaque agent-to-agent rendezvous point one agent operates
//! and others join; it is addressed by a [`ChannelId`] (no hostname, operator-blind
//! — the same shape as a `RoutingToken`). A **[`ChannelGrant`]** is the trust-chain
//! primitive: a *scoped, directional, expiring* authorization minted by a channel
//! operator for a member — deliberately unlike a flat bearer token where possession
//! equals full access. This module holds the claims, the wire form, and stateless
//! verification; the operator's signing key lives with the operator, mirroring the
//! issuer model of [`crate::credential`]. Time is caller-supplied so it stays
//! deterministic and wall-clock-free.
//!
//! AF2a lands only these primitives (types + sign/verify + wire). The rendezvous
//! transport, the control-plane channel/invitation registry, and connect-time
//! enforcement of the `holder` binding come in later sub-packets (AF2b/AF3/AF4).

use crate::preimage::Preimage;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Unix timestamp in whole seconds, supplied by the caller.
pub type UnixSeconds = u64;

/// Opaque channel address in the Agent Fabric — like a `RoutingToken`, it reveals
/// no hostname to the operator and decouples "who I want to reach" from any network
/// address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ChannelId(#[serde(with = "card_hex::b32")] pub [u8; 32]);

/// The domain separating a derived per-link channel id from every other hashed object.
const LINK_CHANNEL_DOMAIN: &[u8] = b"ct-link-channel-v1";

/// Derive the deterministic [`ChannelId`] for the A2A link between two members
/// (`holder_a`, `holder_b`) under channel operator `operator_pubkey` (#107-nway). A
/// topology's overlay links (from `min_latency_overlay`/`plan_network_overlay`) each map
/// to a channel the controller mints per-link grants for — and because the id is
/// **derived**, both endpoints compute the *same* `ChannelId` locally from their holder
/// keys with no coordination round-trip.
///
/// It is a domain-separated SHA-256 over `domain || operator_pubkey || min(a,b) ||
/// max(a,b)`, so it is:
/// - **canonical / order-independent** — the two members derive the same id regardless of
///   which they call `a` (the pair is sorted before hashing);
/// - **operator-bound** — binding `operator_pubkey` means two different operators can't
///   collide onto the same channel id for the same holder pair (cross-operator isolation);
/// - **collision-resistant** — distinct holder pairs (or operators) yield distinct ids.
///
/// This is a channel *address* only (like a `RoutingToken`); it authorizes nothing on its
/// own — membership still flows from the operator-signed [`SignedChannelGrant`] the
/// controller issues for this channel to each holder.
pub fn channel_id_for_link(
    operator_pubkey: &[u8; 32],
    holder_a: &[u8; 32],
    holder_b: &[u8; 32],
) -> ChannelId {
    use sha2::{Digest, Sha256};
    // Canonical order so both endpoints hash the same (lo, hi) regardless of their roles.
    let (lo, hi) = if holder_a <= holder_b {
        (holder_a, holder_b)
    } else {
        (holder_b, holder_a)
    };
    let mut h = Sha256::new();
    h.update(LINK_CHANNEL_DOMAIN);
    h.update(operator_pubkey);
    h.update(lo);
    h.update(hi);
    ChannelId(h.finalize().into())
}

/// The domain separating a derived per-pipeline-role channel id from every other hashed object.
const PIPELINE_ROLE_CHANNEL_DOMAIN: &[u8] = b"ct-pipeline-role-channel-v1";

/// Derive the deterministic [`ChannelId`] for a workflow pipeline's role (#214 follow-up: generic
/// pipeline provisioning). Unlike [`channel_id_for_link`] — bound to a *specific pair* of holders,
/// so the two endpoints must already know each other's public key before they can agree on an id
/// — this id is derived from information a pipeline publisher makes public via
/// `POST /registry/pipelines` (the operator's key, the pipeline's id, the role tag): any bridge
/// that needs a role's output and any agent that can serve it independently compute the *same*
/// `ChannelId` with **no coordination round-trip** — no GitHub-comment pubkey relay, no
/// operator-mediated pairwise derivation. Both are then free to self-join via the existing
/// `POST /me/channels/:channel/members` self-service API using their own OIDC bearer token, so a
/// brand-new pipeline never requires touching core: it just needs a `pipeline_id` and its roles'
/// tags, both of which the publisher already declares.
///
/// A domain-separated SHA-256 over `domain || operator_pubkey || len(pipeline_id) || pipeline_id
/// || len(role) || role`, built via [`Preimage`] so the two variable-length fields are
/// length-prefixed and cannot collide (`pipeline_id="ab", role="c"` and `pipeline_id="a",
/// role="bc"` hash to different ids, unlike naive concatenation).
///
/// This is a channel *address* only, like [`channel_id_for_link`]; it authorizes nothing on its
/// own — membership is still governed by `/me/channels` ownership plus the operator-signed
/// [`SignedChannelGrant`]/attested Noise key each member presents.
pub fn channel_id_for_pipeline_role(operator_pubkey: &[u8; 32], pipeline_id: &str, role: &str) -> ChannelId {
    use sha2::{Digest, Sha256};
    let preimage = Preimage::new(PIPELINE_ROLE_CHANNEL_DOMAIN)
        .fixed(operator_pubkey)
        .var_bytes(pipeline_id.as_bytes())
        .var_bytes(role.as_bytes())
        .finish();
    let mut h = Sha256::new();
    h.update(&preimage);
    ChannelId(h.finalize().into())
}

/// The set of channels an operator's declared overlay **authorizes** (#107-enforce /
/// #102-broker-enforce): given the overlay as its holder-pair links, the `ChannelId`s those
/// links derive via [`channel_id_for_link`]. This is the *enforcement* counterpart to grant
/// *minting* (`compile_overlay_grants`) — the inverse question: not "mint the grants for these
/// links" but "which channels does this overlay sanction at all". The admission gate consults it
/// to refuse any channel the declared topology does not describe. Pure + canonical (identical
/// derivation to `channel_id_for_link`), so the controller that authored the overlay and the gate
/// that enforces it agree with no round-trip. Duplicate/reversed links collapse (set semantics).
pub fn authorized_channels(
    operator_pubkey: &[u8; 32],
    links: &[([u8; 32], [u8; 32])],
) -> std::collections::HashSet<ChannelId> {
    links
        .iter()
        .map(|(a, b)| channel_id_for_link(operator_pubkey, a, b))
        .collect()
}

/// Whether an operator's declared overlay authorizes `channel` — true iff some declared link
/// `(a, b)` derives exactly it (#107-enforce / #102-broker-enforce). The predicate the
/// broker-enforce admission gate calls so a member is admissible to a channel only when the
/// declared topology actually contains the link that names it; an edge removed from the overlay
/// stops authorizing its channel with no per-channel bookkeeping. Canonical order-independent, so
/// `(a, b)` and `(b, a)` authorize the same channel.
pub fn overlay_authorizes_channel(
    operator_pubkey: &[u8; 32],
    links: &[([u8; 32], [u8; 32])],
    channel: &ChannelId,
) -> bool {
    links
        .iter()
        .any(|(a, b)| &channel_id_for_link(operator_pubkey, a, b) == channel)
}

/// The direction a grant authorizes on its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// May open connections to the channel (dial out).
    Initiate,
    /// May accept connections on the channel (the operator/host side).
    Accept,
    /// Both directions.
    Both,
}

impl Direction {
    fn as_byte(self) -> u8 {
        match self {
            Direction::Initiate => 1,
            Direction::Accept => 2,
            Direction::Both => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Direction::Initiate),
            2 => Some(Direction::Accept),
            3 => Some(Direction::Both),
            _ => None,
        }
    }
    /// Stable label used in the canonical signing bytes.
    fn label(self) -> &'static str {
        match self {
            Direction::Initiate => "initiate",
            Direction::Accept => "accept",
            Direction::Both => "both",
        }
    }
    /// Whether this direction permits `want` (Both permits either).
    pub fn permits(self, want: Direction) -> bool {
        self == Direction::Both || self == want
    }
}

/// The data-exchange rights a grant confers on its channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rights {
    /// Read-only.
    Read,
    /// Write-only.
    Write,
    /// Read and write.
    ReadWrite,
}

impl Rights {
    fn as_byte(self) -> u8 {
        match self {
            Rights::Read => 1,
            Rights::Write => 2,
            Rights::ReadWrite => 3,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Rights::Read),
            2 => Some(Rights::Write),
            3 => Some(Rights::ReadWrite),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Rights::Read => "r",
            Rights::Write => "w",
            Rights::ReadWrite => "rw",
        }
    }
    /// Whether these rights include reading.
    pub fn can_read(self) -> bool {
        matches!(self, Rights::Read | Rights::ReadWrite)
    }
    /// Whether these rights include writing.
    pub fn can_write(self) -> bool {
        matches!(self, Rights::Write | Rights::ReadWrite)
    }
}

/// The claims of a channel grant: which channel, bound to which holder, in which
/// direction, with which rights, whether re-delegable, until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelGrant {
    /// The channel this grant is for.
    pub channel: ChannelId,
    /// The member's identity (their static public key) the grant is bound to — a
    /// stolen grant is useless without the matching private key (connect-time
    /// possession proof lands in a later sub-packet).
    pub holder: [u8; 32],
    /// Which direction(s) the holder may use on the channel.
    pub direction: Direction,
    /// The data-exchange rights conferred.
    pub rights: Rights,
    /// Whether the holder may re-delegate (extend the trust chain). A flat bearer
    /// token has no such control; here re-delegation is explicit.
    pub delegable: bool,
    /// Expiry (unix seconds); the grant is invalid at and after this instant.
    pub expires_at: UnixSeconds,
}

impl ChannelGrant {
    /// Canonical bytes covered by the operator signature. Human-auditable and
    /// stable: any change to a field changes these bytes, so a tampered grant
    /// fails verification.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "ct-grant:v1|{}|{}|{}|{}|{}|{}",
            hex32(&self.channel.0),
            hex32(&self.holder),
            self.direction.label(),
            self.rights.label(),
            self.delegable as u8,
            self.expires_at,
        )
        .into_bytes()
    }
}

/// A channel grant together with the operator's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChannelGrant {
    pub grant: ChannelGrant,
    pub signature: [u8; 64],
}

/// Why grant verification or decoding failed.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    BadSignature,
    Expired,
    BadKey,
    /// The wire bytes were not a well-formed grant.
    Malformed,
    /// A previously-accepted grant was presented again before its expiry
    /// (#88 SEC88b) — rejected by the replay cache in [`verify_fresh`].
    Replayed,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::BadSignature => write!(f, "channel grant signature invalid"),
            GrantError::Expired => write!(f, "channel grant expired"),
            GrantError::BadKey => write!(f, "operator public key invalid"),
            GrantError::Malformed => write!(f, "channel grant bytes malformed"),
            GrantError::Replayed => write!(f, "channel grant replayed"),
        }
    }
}

impl std::error::Error for GrantError {}

impl SignedChannelGrant {
    /// The exact byte length of [`SignedChannelGrant::encode`]'s output — all
    /// fields are fixed-size, so a grant occupies a fixed prefix on the wire.
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 1 + 1 + 1 + 8; // 139

    /// Encode to a fixed-layout binary wire form (all fields are fixed size):
    /// `signature(64) | channel(32) | holder(32) | direction(1) | rights(1) | delegable(1) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let g = &self.grant;
        let mut out = Vec::with_capacity(64 + 32 + 32 + 1 + 1 + 1 + 8);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&g.channel.0);
        out.extend_from_slice(&g.holder);
        out.push(g.direction.as_byte());
        out.push(g.rights.as_byte());
        out.push(g.delegable as u8);
        out.extend_from_slice(&g.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedChannelGrant::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut holder = [0u8; 32];
        holder.copy_from_slice(take(&mut cur, 32)?);
        let direction = Direction::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let rights = Rights::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let delegable = match take(&mut cur, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(GrantError::Malformed),
        };
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(SignedChannelGrant {
            grant: ChannelGrant {
                channel: ChannelId(channel),
                holder,
                direction,
                rights,
                delegable,
                expires_at,
            },
            signature,
        })
    }
}

/// The reserved advertised endpoint of a **relay-only** member (#121): a NAT-only host
/// with no globally-routable address that participates purely via the edge relay (plus the
/// #106 `:443` fallback) instead of a direct dial. A member sets `endpoint` to this literal
/// instead of a `host:port` to declare it is not dialable. It is deliberately **not** a
/// parseable [`std::net::SocketAddr`], so [`ChannelJoinRequest::is_relay_only`] is
/// unambiguous and it can never collide with a real endpoint: the edge admits it as an
/// explicit non-dialable marker *without* weakening its private/loopback endpoint filter
/// (#94), and a peer that is paired with such a member skips the wasted direct dial and
/// goes straight to the relay.
pub const CHANNEL_ENDPOINT_RELAY_ONLY: &str = "relay-only";

/// What an agent presents to the edge to join/operate a channel: its signed
/// [`ChannelGrant`] plus the direct endpoint it advertises for the peer to reach it
/// (host:port — the edge brokers the two advertised endpoints, ADR-0015), or the
/// [`CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel for a member that can only be reached via
/// the relay (#121). The channel and holder are inside the grant, so they are not
/// repeated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelJoinRequest {
    pub grant: SignedChannelGrant,
    pub endpoint: String,
}

impl ChannelJoinRequest {
    /// Whether this join advertises the [`CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel (#121)
    /// rather than a dialable address — a NAT-only member that participates via relay only.
    pub fn is_relay_only(&self) -> bool {
        self.endpoint == CHANNEL_ENDPOINT_RELAY_ONLY
    }

    /// Wire form: the fixed-length grant, then the advertised endpoint as the tail
    /// (`grant(WIRE_LEN) | endpoint(utf8, rest)`). No length prefix is needed — the
    /// grant is fixed-size, so the endpoint is unambiguously the remainder.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.grant.encode();
        out.extend_from_slice(self.endpoint.as_bytes());
        out
    }

    /// Decode from [`ChannelJoinRequest::encode`]. Requires a full grant prefix and
    /// a non-empty, valid-UTF-8 endpoint.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        if bytes.len() <= SignedChannelGrant::WIRE_LEN {
            return Err(GrantError::Malformed);
        }
        let (grant_bytes, endpoint_bytes) = bytes.split_at(SignedChannelGrant::WIRE_LEN);
        let grant = SignedChannelGrant::decode(grant_bytes)?;
        let endpoint = std::str::from_utf8(endpoint_bytes)
            .map_err(|_| GrantError::Malformed)?
            .to_string();
        if endpoint.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(ChannelJoinRequest { grant, endpoint })
    }
}

/// Whether `addr` is a **global-unicast** socket address — a real, publicly-routable
/// host a peer can dial (#121). The single source of truth for "is this reachable from
/// the outside": it rejects loopback, unspecified, and multicast, plus every private /
/// internal range a NAT hides behind — RFC1918, link-local (`169.254/16`, `fe80::/10`),
/// shared/CGNAT (`100.64/10`), and IPv6 unique-local (`fc00::/7`). Only a global-unicast
/// address returns `true`. `ct_edge`'s `safe_endpoint` admission filter is defined in
/// terms of this helper, so the reachability classifier and the edge's SSRF filter agree
/// by construction on exactly which addresses count as externally reachable.
pub fn is_global_unicast(addr: std::net::SocketAddr) -> bool {
    use std::net::IpAddr;
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => is_global_unicast_v4(v4),
        IpAddr::V6(v6) => {
            // #267: an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`)
            // IPv6 address embeds a real IPv4 address that neither the `is_loopback`/
            // `is_unspecified` check above nor the segment-mask checks below can see --
            // `::ffff:127.0.0.1` and `::ffff:169.254.169.254` (cloud metadata) both
            // classified as global-unicast before this fix, bypassing the SSRF filter
            // `ct_edge::safe_endpoint` and the #104/#137 upgrade guard are both defined
            // in terms of this function. Re-run the IPv4 classification on the embedded
            // address before falling through to the native-IPv6 range checks.
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_global_unicast_v4(v4);
            }
            let s0 = v6.segments()[0];
            if (s0 & 0xfe00) == 0xfc00 {
                return false; // unique-local fc00::/7
            }
            if (s0 & 0xffc0) == 0xfe80 {
                return false; // link-local fe80::/10
            }
            true
        }
    }
}

/// The IPv4 half of [`is_global_unicast`]'s classification, factored out so the same
/// RFC1918/link-local/CGNAT logic applies uniformly whether the address arrived as a
/// native `Ipv4Addr` or was unwrapped from an IPv4-mapped/IPv4-compatible `Ipv6Addr`
/// (#267). Callers are expected to have already ruled out loopback/unspecified/
/// multicast on the original address; `Ipv4Addr`'s own checks are included here too so
/// this stays correct as a standalone helper regardless.
fn is_global_unicast_v4(v4: std::net::Ipv4Addr) -> bool {
    if v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() {
        return false;
    }
    // RFC1918 private + link-local (169.254/16) + shared/CGNAT (100.64/10).
    if v4.is_private() || v4.is_link_local() {
        return false;
    }
    let o = v4.octets();
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        return false; // 100.64.0.0/10
    }
    true
}

/// #276 (LAN-local fast path, piece 1's safety gate): whether a peer-offered **local**
/// (private-range) direct-connect `candidate` is safe for THIS host to dial, given this
/// host's OWN enumerated local address `local`.
///
/// A local candidate is never edge-observed the way [`is_global_unicast`]'s reflexive
/// addresses are — it is just a string the offering peer chose to send — so accepting it
/// outright would reopen exactly the SSRF shape `#137` closed, one hop later: a malicious
/// peer could offer e.g. `192.168.1.1:80` (a LAN admin panel) or `169.254.169.254:80`
/// (cloud instance metadata) and have an unwitting responder dial it.
///
/// **This is deliberately NOT gated by "the two members' public reflexive addresses
/// match" alone.** Matching public IPs proves the two peers are co-located on the same
/// *external* network; it says nothing about which of the offering peer's *claimed*
/// private addresses are safe for the responder to reach into — a same-public-IP peer
/// (e.g. sharing a coworking-space NAT) is not thereby authorized to direct the responder
/// at arbitrary hosts on the responder's own LAN. A public-IP match is a legitimate cheap
/// *pre-filter* (skip even trying when the peers clearly aren't co-located), but it must
/// never be the sole gate before dialing.
///
/// The actual safety property enforced here: `candidate` must fall within the **same
/// local subnet** as `local` — i.e. it must look like it is genuinely on the responder's
/// own LAN, independent of anything the peer claims. A bare [`std::net::IpAddr`] carries
/// no netmask, so this is a conservative heuristic prefix match (IPv4 `/24`, IPv6 `/64` —
/// matching the same bucketing convention `ct-client`'s `local_egress_ip` classifier
/// already uses for its own local-network heuristic), not an authoritative subnet lookup;
/// a `candidate` outside a private/link-local/ULA range is rejected outright regardless of
/// prefix (global-unicast candidates go through [`is_global_unicast`] instead, never
/// through this path).
pub fn same_local_subnet(local: std::net::IpAddr, candidate: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (local, candidate) {
        (IpAddr::V4(l), IpAddr::V4(c)) => {
            if !(c.is_private() || c.is_link_local()) {
                return false;
            }
            l.octets()[..3] == c.octets()[..3]
        }
        (IpAddr::V6(l), IpAddr::V6(c)) => {
            let c_seg0 = c.segments()[0];
            let c_is_ula_or_link_local = (c_seg0 & 0xfe00) == 0xfc00 || (c_seg0 & 0xffc0) == 0xfe80;
            if !c_is_ula_or_link_local {
                return false;
            }
            l.segments()[..4] == c.segments()[..4]
        }
        _ => false, // mixed address families never match
    }
}

/// How a channel member can be reached, classified from what it **advertised** and the
/// **reflexive** (post-NAT) source address the edge observed on its already-authenticated
/// join connection (#121 Phase B1 — the AutoNAT analog). This is the input the later
/// hole-punch (B2) punches toward and the superpeer election (Phase C) classifies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// The advertised address is global-unicast **and** equals the reflexive address:
    /// the member is directly reachable with no NAT rewrite (a public host).
    Public,
    /// The member is behind a NAT (it advertised a private/loopback address or the
    /// relay-only sentinel), but its reflexive address is global-unicast — so it is
    /// punchable at that reflexive address.
    Nat { reflexive: std::net::SocketAddr },
    /// No usable reflexive: the edge-observed source is itself private/loopback, so the
    /// member is behind symmetric / CGNAT double-NAT and is reachable only via the relay.
    RelayOnly,
}

/// Classify a member's reachability from its `advertised` endpoint string and the
/// `reflexive` address the edge observed on its authenticated join (#121 Phase B1).
/// Pure — no I/O. See [`Reachability`]:
/// - a non-global-unicast reflexive → [`Reachability::RelayOnly`] (symmetric/CGNAT);
/// - a global-unicast reflexive that the member also advertised verbatim →
///   [`Reachability::Public`] (no NAT rewrite);
/// - otherwise (private/loopback or relay-only advertised, but a global-unicast
///   reflexive) → [`Reachability::Nat`], punchable at the reflexive address.
pub fn reachability_class(advertised: &str, reflexive: std::net::SocketAddr) -> Reachability {
    // The edge saw a private/loopback source: symmetric/CGNAT double-NAT — relay only,
    // there is no reflexive address a peer could punch toward.
    if !is_global_unicast(reflexive) {
        return Reachability::RelayOnly;
    }
    // The reflexive is globally routable. If the member advertised that exact global
    // address it is a directly-reachable public host; otherwise it is NAT'd but punchable
    // at the reflexive (a private/loopback or relay-only advertised address never parses
    // to a global-unicast match, so it always falls through to `Nat`).
    if advertised
        .parse::<std::net::SocketAddr>()
        .ok()
        .filter(|a| is_global_unicast(*a))
        == Some(reflexive)
    {
        return Reachability::Public;
    }
    Reachability::Nat { reflexive }
}

/// The #104 / #121 Phase B2 **direct-upgrade trigger** (`#121-symmetric-fallback`): given
/// both members' #121-B1 [`Reachability`] classifications, decide whether attempting a
/// direct hole-punch is worthwhile or whether the pair should stay relayed. A punch needs
/// **both** sides to have a stable, punchable reflexive — a [`Reachability::RelayOnly`]
/// member (symmetric / CGNAT double-NAT: no consistent reflexive mapping) can't be punched
/// toward, so any pair that includes one stays on the relay. `Public`/`Nat` on both sides →
/// attempt the upgrade. Pure. The relay leg is end-to-end regardless, so a `false` here is
/// never a failure — just "don't bother punching, the relay is the answer".
pub fn should_attempt_direct_upgrade(own: Reachability, peer: Reachability) -> bool {
    // Punchable iff the edge saw a usable reflexive (Public or Nat); RelayOnly has none.
    let punchable = |r: Reachability| !matches!(r, Reachability::RelayOnly);
    punchable(own) && punchable(peer)
}

/// A channel member's identity paired with its edge-observed reachability — the input
/// row to Phase C superpeer election (#121). `holder` is the member's ed25519 holder
/// pubkey (the same key family that signs grants/staples); `reachability` is its
/// #121-B1 classification ([`reachability_class`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberReachability {
    pub holder: [u8; 32],
    pub reachability: Reachability,
}

/// Elect up to `count` superpeers from a channel's members (#121 Phase C) — self-organizing
/// and coordinator-free: every member computes the **same** result from the same membership
/// view, so no central authority assigns the role (the central is a replaceable bootstrap,
/// never in the data path). Policy (maintainer-decided — *any member is eligible*, subject to
/// two gates):
///  1. the member must be [`Reachability::Public`] — a superpeer runs the Circuit-Relay v2
///     server other members dial, so a NAT'd / relay-only member cannot serve inbound circuits
///     (the election *classifies on* the B1 [`Reachability`]);
///  2. it must not be in the operator's `veto` set — operator-veto is the only override, and the
///     operator holds the signing key locally (#117 / invariant #6), never the central.
///
/// Winners are chosen deterministically by ascending holder pubkey — a stable, view-independent
/// tie-break every member agrees on without a coordinator. Returns fewer than `count` (possibly
/// empty) when too few members are eligible; an **empty** result is the *fail-static* signal —
/// no superpeer, so the existing grant-gated broker / `:443` relay stays the fallback (absence
/// degrades to the prior relay path, never fail-closed).
pub fn elect_superpeers(
    members: &[MemberReachability],
    veto: &[[u8; 32]],
    count: usize,
) -> Vec<[u8; 32]> {
    let mut eligible: Vec<[u8; 32]> = members
        .iter()
        .filter(|m| m.reachability == Reachability::Public)
        .map(|m| m.holder)
        .filter(|h| !veto.contains(h))
        .collect();
    eligible.sort_unstable();
    eligible.dedup();
    eligible.truncate(count);
    eligible
}

/// Verify a signed grant against the channel `operator_pubkey` at time `now`.
/// Confirms the operator signature over the claims and that the grant has not
/// expired. Does NOT check holder possession — that is a connect-time proof in a
/// later sub-packet; this establishes the grant is authentic and current.
pub fn verify(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelGrant,
    now: UnixSeconds,
) -> Result<(), GrantError> {
    let vk = VerifyingKey::from_bytes(operator_pubkey).map_err(|_| GrantError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.grant.signing_bytes(), &sig)
        .map_err(|_| GrantError::BadSignature)?;
    if now >= signed.grant.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(())
}

/// Like [`verify`], but additionally rejects a **replay** (#88 SEC88b). A captured
/// grant is otherwise valid until `expires_at` *any number of times*; `cache` records
/// the grant's 64-byte signature (unique per grant — a replay carries the identical
/// bytes) until that expiry, so the first presentation of an authentic, unexpired
/// grant succeeds and any later presentation of the same signature fails with
/// [`GrantError::Replayed`]. Call this at the single admission point (the broker) that
/// owns `cache`; the cache evicts on expiry so it stays bounded. Signature/expiry are
/// checked first, so an invalid or expired grant never populates the cache. This is
/// orthogonal to holder-possession (#81) and membership/revocation — all three gate
/// admission together.
pub fn verify_fresh(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelGrant,
    now: UnixSeconds,
    cache: &mut crate::replay::ReplayCache,
) -> Result<(), GrantError> {
    verify(operator_pubkey, signed, now)?;
    if !cache.check_and_record(&signed.signature, signed.grant.expires_at, now) {
        return Err(GrantError::Replayed);
    }
    Ok(())
}

/// Verify a holder's **proof of possession** (#81 gap 1): `signature` must be the
/// holder's ed25519 signature over the edge-issued `challenge`. This closes "stolen
/// grant = bearer token" — presenting a valid [`SignedChannelGrant`] is not enough;
/// the presenter must also prove it holds the private key matching the grant's
/// `holder` public key by signing a fresh, single-use challenge the edge picks. The
/// caller pairs this with the grant/membership checks at the admission gate. Returns
/// `false` on a non-key `holder`, a bad signature, or a challenge mismatch.
pub fn verify_holder_possession(holder: &[u8; 32], challenge: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(holder) {
        Ok(vk) => vk.verify(challenge, &Signature::from_bytes(signature)).is_ok(),
        Err(_) => false,
    }
}

/// The domain-separated message an **operator** signs to prove it holds the secret for
/// `operator_pubkey` when binding that key to topology `topology_id` (#107-enforce ii-a). Because
/// `operator_pubkey` is *public*, topology ownership alone must not be enough to bind it: without
/// this proof-of-possession, anyone could bind a **victim's** operator key to their own topology
/// and — once enforcement consults the binding — mint admission to the victim's channels
/// (`channel_id_for_link` is operator-bound, so the derived channels would be the victim's real
/// ones). The operator signs this with its operator `SigningKey`; the control plane verifies with
/// [`verify_topology_operator_binding`] before storing the binding. The length-prefixed
/// `topology_id` keeps the preimage injective (no id/key boundary ambiguity).
pub fn topology_operator_binding_bytes(topology_id: &str, operator_pubkey: &[u8; 32]) -> Vec<u8> {
    // #184: DOMAIN ‖ topology_id.len()(u64 LE) ‖ topology_id ‖ operator_pubkey — byte-identical.
    // NOTE: this field is length-prefixed with a u64 (not Preimage::var_bytes's u32), so it is written
    // as an explicit `.u64(len).fixed(bytes)` to preserve the exact wire bytes — changing the prefix
    // width would break every existing topology-operator binding signature.
    Preimage::new(b"ct-topology-operator-v1")
        .u64(topology_id.len() as u64)
        .fixed(topology_id.as_bytes())
        .fixed(operator_pubkey)
        .finish()
}

/// Verify an operator's **proof of possession** for binding `operator_pubkey` to `topology_id`
/// (#107-enforce ii-a): `signature` must be `operator_pubkey`'s ed25519 signature over
/// [`topology_operator_binding_bytes`]. Returns `false` on a non-key operator, a wrong
/// `(topology_id, operator_pubkey)` binding, or a bad signature — closing the admission bypass
/// where a public operator key could otherwise be bound to an attacker-controlled topology.
pub fn verify_topology_operator_binding(
    topology_id: &str,
    operator_pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(operator_pubkey) {
        Ok(vk) => vk
            .verify(
                &topology_operator_binding_bytes(topology_id, operator_pubkey),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The domain-separated message a member signs with its **holder** key to attest that
/// it authorized `noise_pubkey` as its Noise static key on `channel` (#72 AF4-keydist /
/// #101). Binding the Noise key to `(channel, holder)` means a DB-controlling operator
/// can't substitute a key to MITM the A2A direct path — a substituted key carries no
/// valid holder signature. The agent signs this with its holder `SigningKey`; peers
/// verify with [`verify_member_noise_attestation`] before pinning the key.
pub fn member_noise_attest_bytes(
    channel: &ChannelId,
    holder: &[u8; 32],
    noise_pubkey: &[u8; 32],
) -> Vec<u8> {
    // #184: DOMAIN ‖ channel ‖ holder ‖ noise_pubkey — byte-identical (literal domain kept verbatim).
    Preimage::new(b"ct-a2a-noise-attest-v1")
        .fixed(&channel.0)
        .fixed(holder)
        .fixed(noise_pubkey)
        .finish()
}

/// Verify a member Noise-key attestation (#101): `signature` must be `holder`'s
/// ed25519 signature over [`member_noise_attest_bytes`]. Returns `false` on a bad key,
/// a wrong `(channel, holder, noise_pubkey)` binding, or a bad signature — so an
/// un-attested or operator-substituted Noise key is rejected before an initiator pins
/// it for the direct-path `Noise_IK` handshake.
pub fn verify_member_noise_attestation(
    channel: &ChannelId,
    holder: &[u8; 32],
    noise_pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(holder) {
        Ok(vk) => vk
            .verify(
                &member_noise_attest_bytes(channel, holder, noise_pubkey),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The domain separating a membership-staple preimage from every other signed object.
const MEMBERSHIP_STAPLE_DOMAIN: &[u8] = b"ct-membership-staple-v1";

/// A soft-state **membership staple** (E-fail-static, invariant #7): the operator's
/// short-lived, signed assertion that `holder` is *currently* a member of `channel`,
/// valid only until `expires_at`. Unlike a [`SignedChannelGrant`] — a long-lived
/// capability — a staple is refreshed continuously (gossiped) while central is reachable
/// and **cached locally**, so if central goes away existing channels keep admitting their
/// known members until the cached staple's TTL lapses: **fail-static, never fail-closed.**
/// Because it expires, revocation needs no central round-trip either — stop refreshing a
/// revoked member and its cached staple dies within one TTL (invariant #7: revocation
/// latency = staple TTL; proposed default 1h staple / 15m gossip refresh).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipStaple {
    pub channel: ChannelId,
    pub holder: [u8; 32],
    /// When the operator minted this staple.
    pub stapled_at: UnixSeconds,
    /// When it lapses (`stapled_at + staple_ttl`). After this the staple is dead; a reader
    /// must fall back to a fresher staple or refuse — this bounds the fail-static window.
    pub expires_at: UnixSeconds,
    /// The operator's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl MembershipStaple {
    /// The domain-separated preimage the operator signs: `domain || channel || holder ||
    /// stapled_at || expires_at`. Binding **every** field means a staple can't be replayed
    /// onto another `(channel, holder)` and its TTL can't be extended without re-signing.
    pub fn signing_bytes(
        channel: &ChannelId,
        holder: &[u8; 32],
        stapled_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ channel ‖ holder ‖ stapled_at(LE) ‖ expires_at(LE) — byte-identical.
        Preimage::new(MEMBERSHIP_STAPLE_DOMAIN)
            .fixed(&channel.0)
            .fixed(holder)
            .u64(stapled_at)
            .u64(expires_at)
            .finish()
    }

    /// Whether this staple is authentic **and** still fresh at `now`: the operator
    /// signature verifies for its exact `(channel, holder, stapled_at, expires_at)` binding
    /// and `now < expires_at`. A forged staple (wrong operator key), any tampered field, or
    /// a lapsed staple all return `false` — the single gate fail-static admission consults.
    pub fn is_valid(&self, operator_pubkey: &[u8; 32], now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(operator_pubkey) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.holder,
                        self.stapled_at,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The exact byte length of [`encode`](Self::encode)'s output — every field is
    /// fixed-size, so a staple occupies a fixed 144-byte record on the wire (the unit the
    /// gossip transport ships/refreshes).
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 8 + 8; // 144

    /// Encode to a fixed-layout binary wire form (all fields fixed size):
    /// `signature(64) | channel(32) | holder(32) | stapled_at(u64 LE) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.channel.0);
        out.extend_from_slice(&self.holder);
        out.extend_from_slice(&self.stapled_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`encode`](Self::encode)'s wire form. Rejects a truncated or
    /// over-long buffer as [`GrantError::Malformed`] (a partial staple is never
    /// half-trusted). Decoding does NOT authenticate — the caller still gates on
    /// [`is_valid`](Self::is_valid); a well-formed record can still be forged or lapsed.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut holder = [0u8; 32];
        holder.copy_from_slice(take(&mut cur, 32)?);
        let stapled_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(MembershipStaple {
            channel: ChannelId(channel),
            holder,
            stapled_at,
            expires_at,
            signature,
        })
    }
}

/// A channel's **staple admission policy** (#121 E-fail-static, option A — *staple-optional*,
/// maintainer decision 2026-07-20). A channel opts into TTL-bounded revocation; those that
/// don't are unaffected. Consumed by [`StapleCache::admits_under_policy`], always *after* the
/// operator-grant check — enabling staples can only *add* a freshness requirement, never
/// weaken the existing grant-based admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChannelAdmissionPolicy {
    /// Grant-only admission — today's behaviour and the default: a valid operator-signed
    /// grant is sufficient. Channels that don't opt into staples use this.
    #[default]
    Open,
    /// The member must also present a fresh cached [`MembershipStaple`], so revocation
    /// propagates within the staple TTL (invariant #7).
    RequireStaple,
}

/// A soft-state cache of the freshest [`MembershipStaple`] per `(channel, holder)` — the
/// local memory that lets a node keep admitting known members while central is unreachable
/// (E-fail-static). Gossip/refresh feeds [`refresh`](Self::refresh); admission consults
/// [`is_member`](Self::is_member). Keeping only the **latest-expiring** staple means a
/// stale/out-of-order gossip can never SHORTEN a member's validity, and a revoked member
/// simply stops being refreshed so its entry lapses within one TTL (invariant #7).
#[derive(Debug, Default)]
pub struct StapleCache {
    fresh: std::collections::HashMap<([u8; 32], [u8; 32]), MembershipStaple>,
}

impl StapleCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a staple (from gossip or a direct refresh). It is verified against
    /// `operator_pubkey` at `now` **first** — an invalid or already-lapsed staple is
    /// ignored, never cached. The entry with the later `expires_at` wins, so out-of-order
    /// gossip can't regress validity. Returns whether the cache now holds this (or an
    /// already-fresher) staple for the pair.
    pub fn refresh(
        &mut self,
        operator_pubkey: &[u8; 32],
        staple: MembershipStaple,
        now: UnixSeconds,
    ) -> bool {
        if !staple.is_valid(operator_pubkey, now) {
            return false;
        }
        let key = (staple.channel.0, staple.holder);
        match self.fresh.get(&key) {
            // An existing staple that lasts at least as long already dominates — keep it.
            Some(existing) if existing.expires_at >= staple.expires_at => true,
            _ => {
                self.fresh.insert(key, staple);
                true
            }
        }
    }

    /// Fail-static admission input: is `holder` a currently-stapled member of `channel` at
    /// `now`? True iff a cached staple for the pair still verifies against `operator_pubkey`
    /// and has not lapsed — with **no central round-trip**, which is the whole point:
    /// existing channels survive a central outage until the TTL. A lapsed entry returns
    /// `false` and is evicted, so a revoked (no-longer-refreshed) member is gone within one
    /// TTL (invariant #7).
    pub fn is_member(
        &mut self,
        operator_pubkey: &[u8; 32],
        channel: &ChannelId,
        holder: &[u8; 32],
        now: UnixSeconds,
    ) -> bool {
        let key = (channel.0, *holder);
        match self.fresh.get(&key) {
            Some(s) if s.is_valid(operator_pubkey, now) => true,
            Some(_) => {
                self.fresh.remove(&key); // lapsed — drop it so the map stays bounded
                false
            }
            None => false,
        }
    }

    /// Compose the channel's **staple admission policy** on top of an already grant-verified
    /// member (#121 E-fail-static, option A — *staple-optional*, maintainer decision
    /// 2026-07-20). The caller has already verified the operator-signed grant (and possession)
    /// exactly as today; this adds the staple requirement **only when the channel opted in**:
    /// - [`ChannelAdmissionPolicy::Open`] → always `true`: grant-only admission, byte-for-byte
    ///   today's behaviour and the default, so nothing changes for channels that don't opt in;
    /// - [`ChannelAdmissionPolicy::RequireStaple`] → `true` iff a fresh, unexpired,
    ///   operator-signed staple is cached for `(channel, holder)` (delegates to
    ///   [`is_member`](Self::is_member)), so revocation propagates within the staple TTL
    ///   (invariant #7).
    ///
    /// This is the single tested chokepoint the edge broker consults *after* its grant check,
    /// so enabling staples on a channel can never *weaken* admission (a valid grant is still
    /// required) — it can only add the freshness requirement.
    pub fn admits_under_policy(
        &mut self,
        policy: ChannelAdmissionPolicy,
        operator_pubkey: &[u8; 32],
        channel: &ChannelId,
        holder: &[u8; 32],
        now: UnixSeconds,
    ) -> bool {
        match policy {
            ChannelAdmissionPolicy::Open => true,
            ChannelAdmissionPolicy::RequireStaple => {
                self.is_member(operator_pubkey, channel, holder, now)
            }
        }
    }
}

/// The domain separating a billing-commitment preimage from every other signed object.
const BILLING_COMMITMENT_DOMAIN: &[u8] = b"ct-billing-commitment-v1";

/// An **optional, agent-verifiable A2A billing coupling** for a channel (#132). It does **not**
/// move funds — settlement stays external (the classic tunnel-token billing lives in
/// `ct-control-plane::billing`; multi-hop path-transit *receipts* are a #121 follow) — it is
/// the cryptographic commitment a member can **require and verify at channel setup**: the
/// committing (paying) `holder` commits, for `channel`, to the off-band billing `terms_hash`,
/// payable to `payee`, up to `max_amount` (opaque units), until `expires_at`, signed with its
/// ed25519 **holder** key (the same key family as grants/attestations). The peer verifies it
/// against that holder pubkey before proceeding. **Opt-in**: a channel that doesn't require
/// billing never uses it — exactly like [`ChannelAdmissionPolicy`], so the core tunnel stays
/// payment-free and this can never *weaken* admission (it only adds a requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingCommitment {
    pub channel: ChannelId,
    /// The committing (paying) member — the signature is checked against this holder pubkey.
    pub holder: [u8; 32],
    /// The settlement payee identity (opaque; a settlement pubkey/handle the external layer resolves).
    pub payee: [u8; 32],
    /// Hash of the off-band billing terms (price/unit, currency, metering rule …) — the terms
    /// themselves stay out-of-band; only their hash is committed on the wire.
    pub terms_hash: [u8; 32],
    /// The upper bound (opaque units) the payer commits to for this channel/session.
    pub max_amount: u64,
    pub expires_at: UnixSeconds,
    /// The holder's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl BillingCommitment {
    /// Domain-separated preimage: `domain ‖ channel ‖ holder ‖ payee ‖ terms_hash ‖
    /// max_amount(LE) ‖ expires_at(LE)`. Binding every field means the commitment can't be
    /// replayed onto another channel/payee nor have its amount/terms/TTL altered without
    /// re-signing.
    pub fn signing_bytes(
        channel: &ChannelId,
        holder: &[u8; 32],
        payee: &[u8; 32],
        terms_hash: &[u8; 32],
        max_amount: u64,
        expires_at: UnixSeconds,
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ channel ‖ holder ‖ payee ‖ terms_hash ‖ max_amount(LE) ‖ expires_at(LE) — byte-identical.
        Preimage::new(BILLING_COMMITMENT_DOMAIN)
            .fixed(&channel.0)
            .fixed(holder)
            .fixed(payee)
            .fixed(terms_hash)
            .u64(max_amount)
            .u64(expires_at)
            .finish()
    }

    /// Whether this commitment is authentic AND still current at `now`: the holder signature
    /// verifies for its exact `(channel, holder, payee, terms_hash, max_amount, expires_at)`
    /// binding and `now < expires_at`. A forged/tampered/expired commitment returns `false`.
    pub fn is_valid(&self, now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(&self.holder) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.holder,
                        &self.payee,
                        &self.terms_hash,
                        self.max_amount,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The **requiring agent's setup gate**: does this commitment authentically cover what the
    /// requirer demands — signed + unexpired ([`is_valid`](Self::is_valid)), for the expected
    /// `required_payee` and `required_terms_hash`, with a `max_amount` of at least `min_amount`?
    /// A channel that requires billing calls this at setup; `false` refuses the tunnel.
    pub fn satisfies(
        &self,
        now: UnixSeconds,
        required_payee: &[u8; 32],
        required_terms_hash: &[u8; 32],
        min_amount: u64,
    ) -> bool {
        self.is_valid(now)
            && &self.payee == required_payee
            && &self.terms_hash == required_terms_hash
            && self.max_amount >= min_amount
    }
}

/// A per-channel **billing requirement** consulted at channel setup (#132 BC2). Opt-in and
/// default-off, exactly like [`ChannelAdmissionPolicy`]: it can only *add* a requirement, never
/// weaken admission, so the core tunnel stays payment-free. A channel that requires billing pins
/// the demanded `payee`, off-band `terms_hash`, and `min_amount`; the joining member must present a
/// [`BillingCommitment`] that [`satisfies`](BillingCommitment::satisfies) them, or setup is refused.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BillingPolicy {
    /// No billing coupling required (default) — grant-only, payment-free setup.
    #[default]
    None,
    /// The joining member must present a `BillingCommitment` satisfying these demands at setup.
    Require {
        payee: [u8; 32],
        terms_hash: [u8; 32],
        min_amount: u64,
    },
}

impl BillingPolicy {
    /// The **setup gate**: does `commitment` satisfy this policy at `now`? [`None`](Self::None) →
    /// always admits (opt-in, like [`ChannelAdmissionPolicy::Open`]). [`Require`](Self::Require) →
    /// admits iff a commitment is present and [`satisfies`](BillingCommitment::satisfies) the
    /// demanded payee/terms with at least the demanded amount. Missing/expired/forged/mismatched →
    /// refused. Moves no funds — it is purely the setup-time verification of the opt-in coupling.
    pub fn admits(&self, commitment: Option<&BillingCommitment>, now: UnixSeconds) -> bool {
        match self {
            BillingPolicy::None => true,
            BillingPolicy::Require { payee, terms_hash, min_amount } => {
                commitment.is_some_and(|c| c.satisfies(now, payee, terms_hash, *min_amount))
            }
        }
    }
}

/// The domain separating a settle-receipt preimage from every other signed object.
const SETTLE_RECEIPT_DOMAIN: &[u8] = b"ct-settle-receipt-v1";

/// A rolling digest over an A2A transfer's application byte stream (#132 SR1 — the `settle` step of
/// `quote → approve → settle`). Both peers fold the SAME plaintext bytes through it as they pump; at
/// close the **receiver** signs its finalized digest into a [`SettleReceipt`] and the sender/
/// verifier compares against its own — so "delivered" is *witnessed by the receiver*, never merely
/// asserted by the send side. sha2 is already a dependency; folding one hash update per pumped chunk
/// costs no extra round-trips.
#[derive(Clone)]
pub struct TransferDigest {
    hasher: sha2::Sha256,
    bytes: u64,
}

impl Default for TransferDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferDigest {
    pub fn new() -> Self {
        use sha2::Digest;
        Self { hasher: sha2::Sha256::new(), bytes: 0 }
    }

    /// Fold the next chunk of delivered application plaintext into the digest.
    pub fn update(&mut self, chunk: &[u8]) {
        use sha2::Digest;
        self.hasher.update(chunk);
        self.bytes += chunk.len() as u64;
    }

    /// Application bytes folded so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The digest of the stream folded so far (clones the hasher — does not consume it).
    pub fn digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.hasher.clone().finalize());
        out
    }
}

/// A **receiver-attested transfer receipt** for an A2A session (#132 SR1 — the `settle` step). The
/// **receiver** signs, with its ed25519 holder key, a digest over the application bytes it actually
/// received ([`TransferDigest`]), bound to the `channel`, the approve-time billing `terms_hash`
/// (from the [`BillingCommitment`]), and a per-session `session_nonce` — so the receipt cannot be
/// replayed onto another session, channel, or terms. It moves **no funds**: external settlement
/// consumes it; the tunnel only PRODUCES the verifiable proof-of-delivery. The sender/verifier
/// checks it against its OWN [`TransferDigest`], so the receiver can neither under-report nor forge
/// what was delivered — this is what defeats *ambient send-side trust*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettleReceipt {
    pub channel: ChannelId,
    /// The attesting (delivered-to) member; the signature is checked against this holder pubkey.
    pub receiver: [u8; 32],
    /// The approve-time billing terms this delivery settles against (ties the receipt to the coupling).
    pub terms_hash: [u8; 32],
    /// Per-session binding (a fresh nonce agreed at setup) — prevents cross-session/channel replay.
    pub session_nonce: [u8; 32],
    /// Application bytes the receiver attests it received.
    pub bytes_delivered: u64,
    /// Digest over those delivered bytes ([`TransferDigest::digest`]).
    pub transfer_digest: [u8; 32],
    /// The receiver's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    pub signature: [u8; 64],
}

impl SettleReceipt {
    /// Domain-separated preimage: `domain ‖ channel ‖ receiver ‖ terms_hash ‖ session_nonce ‖
    /// bytes_delivered(LE) ‖ transfer_digest`. Binding every field means a receipt can't be
    /// replayed onto another channel/session/terms nor have its byte count or digest altered
    /// without re-signing (which only the receiver's holder key can do).
    pub fn signing_bytes(
        channel: &ChannelId,
        receiver: &[u8; 32],
        terms_hash: &[u8; 32],
        session_nonce: &[u8; 32],
        bytes_delivered: u64,
        transfer_digest: &[u8; 32],
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ channel ‖ receiver ‖ terms_hash ‖ session_nonce ‖ bytes_delivered(LE) ‖ transfer_digest — byte-identical.
        Preimage::new(SETTLE_RECEIPT_DOMAIN)
            .fixed(&channel.0)
            .fixed(receiver)
            .fixed(terms_hash)
            .fixed(session_nonce)
            .u64(bytes_delivered)
            .fixed(transfer_digest)
            .finish()
    }

    /// Whether the receipt is authentic: the receiver signature verifies for its exact binding. A
    /// forged/tampered receipt returns `false`.
    pub fn is_valid(&self) -> bool {
        match VerifyingKey::from_bytes(&self.receiver) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.channel,
                        &self.receiver,
                        &self.terms_hash,
                        &self.session_nonce,
                        self.bytes_delivered,
                        &self.transfer_digest,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// The **sender/verifier's settle gate**: the receipt is authentic AND attests delivery of what
    /// we actually sent — signed by the **`expected_receiver`** (the peer we delivered to), for the
    /// same `channel`, the expected `terms_hash` and `session_nonce`, at least `min_bytes`, and a
    /// `transfer_digest` byte-equal to our own [`TransferDigest::digest`]. A truncated, tampered, or
    /// forged delivery claim → `false`.
    ///
    /// **Binding `expected_receiver` is load-bearing (#138):** [`is_valid`](Self::is_valid) only
    /// checks the signature against the receipt's *self-declared* `receiver`, so without pinning the
    /// receiver a malicious **sender** — which also knows the `transfer_digest` (both Noise_IK peers
    /// fold the same plaintext) — could self-sign a receipt with `receiver` = its own key and pass.
    /// Pinning the receiver we actually delivered to is exactly what makes "only a receipt the
    /// RECEIVER signed passes — no send-side assertion can" true; the caller supplies the peer's
    /// channel-attested holder key as `expected_receiver`.
    pub fn confirms_delivery(
        &self,
        expected_channel: &ChannelId,
        expected_receiver: &[u8; 32],
        expected_terms_hash: &[u8; 32],
        expected_session_nonce: &[u8; 32],
        min_bytes: u64,
        sender_digest: &[u8; 32],
    ) -> bool {
        self.is_valid()
            && &self.receiver == expected_receiver
            && &self.channel == expected_channel
            && &self.terms_hash == expected_terms_hash
            && &self.session_nonce == expected_session_nonce
            && self.bytes_delivered >= min_bytes
            && &self.transfer_digest == sender_digest
    }
}

/// The domain separating an agent-card preimage from every other signed object.
const AGENT_CARD_DOMAIN: &[u8] = b"ct-agent-card-v1";

/// An **affinity-group (cell) identifier** (#135 L1): a self-organized, task-scoped group of agents
/// (e.g. #133's source/sink/central triangle). Opaque 32 bytes, same shape as [`ChannelId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CellId(#[serde(with = "card_hex::b32")] pub [u8; 32]);

/// A capability an agent advertises it can be asked to perform (#135 L1, A2A `AgentCard`-shaped):
/// a stable `id`, a human `description`, and `examples` of use. Self-asserted advertisement — a
/// reader learns *what the holder claims to offer*, and negotiates/authorizes the actual invocation
/// separately (an `AgentCard` signature proves the holder issued the claim, never that it works).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Skill {
    pub id: String,
    pub description: String,
    pub examples: Vec<String>,
}

/// Hex (de)serialization for the fixed-size byte fields of an [`AgentCard`] and its
/// [`ChannelId`]/[`CellId`] members, so the card's serde form is a human-readable JSON
/// **profile** (`"7a3f…"` strings) rather than raw number arrays. The signed content is
/// unchanged — [`AgentCard::signing_bytes`] remains the canonical binary preimage; JSON is
/// only a transport/display encoding, and [`AgentCard::is_valid`] re-checks the signature
/// after any round-trip (#135 L1 — the JSON profile agent onboarding / #133 dogfood reads).
mod card_hex {
    fn to_hex(b: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
    fn from_hex(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
            .collect()
    }
    pub mod b32 {
        use serde::{Deserialize, Deserializer, Serializer};
        pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&super::to_hex(b))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
            let v = super::from_hex(&String::deserialize(d)?)
                .ok_or_else(|| serde::de::Error::custom("invalid hex"))?;
            v.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        }
    }
    pub mod b64 {
        use serde::{Deserialize, Deserializer, Serializer};
        pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_str(&super::to_hex(b))
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            let v = super::from_hex(&String::deserialize(d)?)
                .ok_or_else(|| serde::de::Error::custom("invalid hex"))?;
            let a: [u8; 64] = v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
            Ok(a)
        }
    }
}

/// A **holder-signed, discoverable agent identity document** (#135 Layer 1) — an A2A `AgentCard`
/// built on the ed25519 **holder** key this codebase already uses for channel membership. It says
/// *who an agent is and what it offers*: its `role_tags`, `skills`, the `cells` it claims to sit in,
/// and the `channels` it is reachable via — so a new participant can be discovered from a shared
/// registry/vault instead of central hand-crafting each channel (the friction #133 onboarding paid).
///
/// **Self-assertion boundary (converged on #135):** every advertised field — `role_tags`, `skills`,
/// and especially **`cells`** — is *self-asserted and unverified*. The signature proves only that the
/// holder **issued** these claims, never that anyone **ratified** them (no one "admits" the holder to
/// a cell here; that check, when it exists, lives at use-time against whatever backs the cell — a
/// future governance layer). `cells` is empty/forward-looking until that layer lands. A reader trusts
/// the *holder-issued* fact, then authorizes any actual action separately — the same discipline as
/// [`BillingCommitment`]/[`SettleReceipt`], never the DHT/`PeerId` (invariant #1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentCard {
    /// The agent's ed25519 holder public key — the signature is checked against this, and it is the
    /// same key family that authorizes the agent's channel membership + attests its Noise key.
    #[serde(with = "card_hex::b32")]
    pub holder_pubkey: [u8; 32],
    pub role_tags: Vec<String>,
    pub skills: Vec<Skill>,
    /// Cells the holder *claims* membership in — self-asserted/unverified (see the type doc).
    pub cells: Vec<CellId>,
    /// Channels the holder advertises it is reachable via.
    pub channels: Vec<ChannelId>,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    /// The holder's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    #[serde(with = "card_hex::b64")]
    pub signature: [u8; 64],
}

impl AgentCard {
    /// Domain-separated, **canonical** preimage: `domain ‖ holder ‖ ⟨role_tags⟩ ‖ ⟨skills⟩ ‖
    /// ⟨cells⟩ ‖ ⟨channels⟩ ‖ issued_at(LE) ‖ expires_at(LE)`, where every variable-length field is
    /// length-prefixed (`count`/byte-`len` as u32 LE) so the encoding is injective — no two distinct
    /// card contents share a preimage, and no field can be re-partitioned to forge an equivalent
    /// signature. Fixed-wire binary (the codebase precedent), not JSON canonicalization.
    pub fn signing_bytes(
        holder_pubkey: &[u8; 32],
        role_tags: &[String],
        skills: &[Skill],
        cells: &[CellId],
        channels: &[ChannelId],
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ holder ‖ ⟨role_tags⟩ ‖ ⟨skills⟩ ‖ ⟨cells⟩ ‖ ⟨channels⟩ ‖ issued_at ‖ expires_at,
        // each sequence a u32-LE count then its elements, each string u32-LE-length-prefixed
        // (var_bytes) — byte-identical to the prior put_str form.
        let mut p = Preimage::new(AGENT_CARD_DOMAIN)
            .fixed(holder_pubkey)
            .u32(role_tags.len() as u32);
        for t in role_tags {
            p = p.var_bytes(t.as_bytes());
        }
        p = p.u32(skills.len() as u32);
        for s in skills {
            p = p
                .var_bytes(s.id.as_bytes())
                .var_bytes(s.description.as_bytes())
                .u32(s.examples.len() as u32);
            for e in &s.examples {
                p = p.var_bytes(e.as_bytes());
            }
        }
        p = p.u32(cells.len() as u32);
        for c in cells {
            p = p.fixed(&c.0);
        }
        p = p.u32(channels.len() as u32);
        for ch in channels {
            p = p.fixed(&ch.0);
        }
        p.u64(issued_at).u64(expires_at).finish()
    }

    /// Whether this card is authentic AND still current at `now`: the holder signature verifies for
    /// its exact contents and `now < expires_at`. A forged/tampered/expired card returns `false`.
    /// This authenticates the *holder-issued claims* only — never that a self-asserted `cell`
    /// membership or `skill` is ratified/working (see the struct doc).
    pub fn is_valid(&self, now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(&self.holder_pubkey) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.holder_pubkey,
                        &self.role_tags,
                        &self.skills,
                        &self.cells,
                        &self.channels,
                        self.issued_at,
                        self.expires_at,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Construct and **sign** a card from a holder `SigningKey` and the claims to advertise
    /// (#144 ①-wiring construct-and-sign). This is the production analogue of what was, until
    /// now, only a test helper: it derives `holder_pubkey` from the key, signs the canonical
    /// [`signing_bytes`](Self::signing_bytes) preimage, and returns a card for which
    /// [`is_valid`](Self::is_valid) holds at any `now < expires_at`. Callers (an
    /// `onboard --mode browser` / `ct-agent channel agent-card` hook) load the holder key, pass
    /// the role/skill/cell/channel claims, and hand the result to
    /// `ct_agent::well_known::write_agent_card_for_origin` — closing the emit chain without
    /// anyone hand-rolling ed25519. The `holder_pubkey` is always the signing key's own public
    /// key, so a caller cannot mint a card claiming a key it does not hold.
    pub fn sign_new(
        signing_key: &ed25519_dalek::SigningKey,
        role_tags: Vec<String>,
        skills: Vec<Skill>,
        cells: Vec<CellId>,
        channels: Vec<ChannelId>,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> AgentCard {
        use ed25519_dalek::Signer;
        let holder_pubkey = signing_key.verifying_key().to_bytes();
        let signature = signing_key
            .sign(&Self::signing_bytes(
                &holder_pubkey,
                &role_tags,
                &skills,
                &cells,
                &channels,
                issued_at,
                expires_at,
            ))
            .to_bytes();
        AgentCard {
            holder_pubkey,
            role_tags,
            skills,
            cells,
            channels,
            issued_at,
            expires_at,
            signature,
        }
    }
}

/// The domain separating a [`CapacityOffer`] preimage from every other signed object.
const CAPACITY_OFFER_DOMAIN: &[u8] = b"ct-capacity-offer-v1";

/// The kind of idle LLM capacity an agent offers (#147 requirement 1 — both must coexist): proxying
/// calls through the agent's own remaining **cloud API quota**, or dispatching inference jobs onto its
/// idle **local hardware**. They have genuinely different mechanisms + consumption-proof needs
/// (a provider response signature vs. attesting a local model actually ran), so a marketplace primitive
/// must distinguish them from the start; that proof scheme is a later phase, not decided here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CapacityKind {
    CloudApiQuota,
    LocalHardware,
}

impl CapacityKind {
    /// The one byte that represents this kind in the signing preimage (stable across serde renames).
    fn tag(self) -> u8 {
        match self {
            CapacityKind::CloudApiQuota => 0,
            CapacityKind::LocalHardware => 1,
        }
    }

    /// Inverse of [`tag`](Self::tag): reconstruct the kind from its wire byte (for binary decoding),
    /// or `None` for an unknown tag.
    fn from_tag(tag: u8) -> Option<CapacityKind> {
        match tag {
            0 => Some(CapacityKind::CloudApiQuota),
            1 => Some(CapacityKind::LocalHardware),
            _ => None,
        }
    }
}

/// A **declared service task-type** a [`CapacityOffer`] serves (#149-A.1 — schema-typed service
/// catalog; maintainer decision 2026-07-24: **opt-in convention**). Declaring a closed set of task
/// types instead of a free-form chat passthrough is the biggest structural abuse mitigation: a
/// schema-typed task is far harder to jailbreak into "ignore your task, act as an unrestricted
/// assistant" than an open completion endpoint, and it narrows what data can flow through the channel.
/// An offer with an **empty** `services` list is undeclared/generic (the opt-out — a generic offer
/// stays valid); a provider that opts in advertises exactly the task types it serves (and registers
/// one MCP tool per service — that tool-per-service wiring is the follow slice).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ServiceType {
    /// Generate code to a specification.
    CodeGeneration,
    /// Review code/config for security issues.
    SecurityReview,
    /// Check content against a safety policy.
    SafetyCheck,
    /// General text completion — the closest to a raw chat endpoint, so declaring it is explicit.
    TextGeneration,
    /// An open-ended, pipeline-designer-declared service that doesn't fit the four fixed variants
    /// above (#382 follow-up: generalizing `RequiredRole`/`convene()` beyond flappy/cookbook's
    /// closed catalog for non-demo workflow pipelines — e.g. `"StaticAnalysis"`,
    /// `"AndroidInstrumentedTest"`, `"CodeReview"`). Free-form, but matching is still an EXACT
    /// string match between a [`crate::pipeline::RequiredRole::service`] and an offering agent's
    /// [`CapacityOffer::services`] entry — same discipline every fixed variant already requires,
    /// just without a core-crate code change per new pipeline-stage type. This is intentionally
    /// still opt-in/schema-typed (the string names a task-TYPE, not a free-form instruction) —
    /// #149-A.1's own abuse-mitigation rationale for a closed catalog applies just as much to an
    /// open one: an agent still exposes exactly `service/<slug>` per declared entry, never a
    /// generic completion proxy.
    Custom(String),
}

impl ServiceType {
    /// The one byte representing this service KIND in the signing preimage (stable across serde
    /// renames) -- for [`ServiceType::Custom`], this alone is NOT injective (every custom name
    /// shares tag `4`); [`CapacityOffer::signing_bytes`] additionally length-prefixes the name
    /// itself right after this byte for that variant, restoring injectivity. The four fixed
    /// variants are byte-identical to before this existed -- no signature computed against them
    /// changes.
    fn tag(&self) -> u8 {
        match self {
            ServiceType::CodeGeneration => 0,
            ServiceType::SecurityReview => 1,
            ServiceType::SafetyCheck => 2,
            ServiceType::TextGeneration => 3,
            ServiceType::Custom(_) => 4,
        }
    }
}

/// A **holder-signed advertisement of idle LLM capacity** (#147 L1 — the discovery/advertisement layer
/// of the idle-capacity marketplace). The design-neutral foundation: it says *what an agent offers and
/// its floor terms* so a buyer can discover + bid, WITHOUT deciding the contentious later phases —
/// the consumption-proof scheme (#147 req 2), the escrow/minimum-spend resolution (#147 req 4 tension),
/// or the dedicated settlement chain (#147 req 3, referenced here only as an opaque `currency_id`).
///
/// Same cryptographic discipline as [`AgentCard`]/[`BillingCommitment`]: a domain-separated, injective
/// (length-prefixed) preimage signed by the agent's ed25519 **holder** key. The signature proves the
/// holder *issued* the offer — never that capacity was delivered or consumed (that is exactly what the
/// later proof phase must establish). `min_price` is the **buyer's guaranteed-minimum floor** (#147 req
/// 4), not a seller reserve; how it interacts with unproven consumption is the open tension, out of
/// scope for this primitive.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapacityOffer {
    /// The offering agent's ed25519 holder public key — the signature is checked against this.
    #[serde(with = "card_hex::b32")]
    pub holder_pubkey: [u8; 32],
    /// Which kind of capacity (cloud API quota vs. local hardware).
    pub kind: CapacityKind,
    /// The model ids this capacity can serve (e.g. `claude-opus-4-8`, a local model tag).
    pub models: Vec<String>,
    /// Units offered (tokens for cloud quota, job-units for local hardware — unit semantics per `kind`).
    pub units_available: u64,
    /// The buyer's guaranteed-minimum spend floor for winning this capacity (#147 req 4), in
    /// `currency_id`'s smallest unit. NOT a seller reserve.
    pub min_price: u64,
    /// Opaque id of the dedicated LLM-token settlement currency/chain (#147 req 3) — this primitive
    /// does not implement or validate the chain, only names which one settles this offer.
    pub currency_id: String,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    /// #149-A.1 opt-in service catalog: the closed task-types this offer serves, or **empty** for an
    /// undeclared/generic offer (the opt-out). Covered by the signature, so the advertised catalog is
    /// tamper-evident.
    #[serde(default)]
    pub services: Vec<ServiceType>,
    /// The holder's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    #[serde(with = "card_hex::b64")]
    pub signature: [u8; 64],
}

impl CapacityOffer {
    /// Domain-separated, **canonical injective** preimage: `domain ‖ holder ‖ kind(u8) ‖ ⟨models⟩ ‖
    /// units_available(LE) ‖ min_price(LE) ‖ ⟨currency_id⟩ ‖ issued_at(LE) ‖ expires_at(LE) ‖
    /// ⟨services⟩`, every variable-length field length-prefixed (u32 LE count/byte-len) so no two
    /// distinct offers share a preimage. `services` (#149-A.1) is appended as `count(u32 LE) ‖
    /// ⟨tag(u8) ‖ (Custom only: var_bytes(name))⟩` per entry — the four fixed variants are
    /// byte-identical to before [`ServiceType::Custom`] existed (a lone tag byte, nothing after);
    /// `Custom`'s tag byte (4) is shared by every custom name, so its own name is length-prefixed
    /// right after to restore injectivity (two different custom names can never share a preimage,
    /// same guarantee this whole preimage already gives every other field, #382 follow-up).
    #[allow(clippy::too_many_arguments)]
    pub fn signing_bytes(
        holder_pubkey: &[u8; 32],
        kind: CapacityKind,
        models: &[String],
        units_available: u64,
        min_price: u64,
        currency_id: &str,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        services: &[ServiceType],
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ holder ‖ kind.tag ‖ ⟨models⟩ ‖ units ‖ min_price ‖ currency ‖ issued ‖ expires
        // ‖ ⟨service tags⟩ — byte-identical to the prior put_str form (u32-LE counts, var_bytes strings).
        let mut p = Preimage::new(CAPACITY_OFFER_DOMAIN)
            .fixed(holder_pubkey)
            .tag(kind.tag())
            .u32(models.len() as u32);
        for model in models {
            p = p.var_bytes(model.as_bytes());
        }
        p = p
            .u64(units_available)
            .u64(min_price)
            .var_bytes(currency_id.as_bytes())
            .u64(issued_at)
            .u64(expires_at)
            .u32(services.len() as u32);
        for service in services {
            p = p.tag(service.tag());
            if let ServiceType::Custom(name) = service {
                p = p.var_bytes(name.as_bytes());
            }
        }
        p.finish()
    }

    /// Whether this offer is authentic AND still current at `now`: the holder signature verifies for its
    /// exact contents and `now < expires_at`. A forged/tampered/expired offer returns `false`. Proves
    /// only that the holder *issued* the offer — never that the capacity exists or was delivered.
    pub fn is_valid(&self, now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(&self.holder_pubkey) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.holder_pubkey,
                        self.kind,
                        &self.models,
                        self.units_available,
                        self.min_price,
                        &self.currency_id,
                        self.issued_at,
                        self.expires_at,
                        &self.services,
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Construct + sign an offer with **no** declared service catalog (`services` empty — a generic
    /// offer). Equivalent to [`sign_new_with_services`](Self::sign_new_with_services) with an empty list.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        signing_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        models: Vec<String>,
        units_available: u64,
        min_price: u64,
        currency_id: String,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> CapacityOffer {
        Self::sign_new_with_services(
            signing_key,
            kind,
            models,
            units_available,
            min_price,
            currency_id,
            issued_at,
            expires_at,
            Vec::new(),
        )
    }

    /// Construct + sign an offer that **declares a service catalog** (#149-A.1): `services` is the
    /// closed set of task-types the offer serves (empty = generic). It rides the holder-signed preimage,
    /// so the advertised catalog is tamper-evident. Derives `holder_pubkey` from the key, so a caller
    /// cannot advertise capacity under a key it does not hold.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new_with_services(
        signing_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        models: Vec<String>,
        units_available: u64,
        min_price: u64,
        currency_id: String,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        services: Vec<ServiceType>,
    ) -> CapacityOffer {
        use ed25519_dalek::Signer;
        let holder_pubkey = signing_key.verifying_key().to_bytes();
        let signature = signing_key
            .sign(&Self::signing_bytes(
                &holder_pubkey,
                kind,
                &models,
                units_available,
                min_price,
                &currency_id,
                issued_at,
                expires_at,
                &services,
            ))
            .to_bytes();
        CapacityOffer {
            holder_pubkey,
            kind,
            models,
            units_available,
            min_price,
            currency_id,
            issued_at,
            expires_at,
            services,
            signature,
        }
    }
}

const USAGE_RECEIPT_DOMAIN: &[u8] = b"ct-usage-receipt-v1";

/// A **co-signed attestation that a specific amount of capacity was consumed** (#147 L3 — the
/// consumption-proof layer). Maintainer decision 2026-07-23: the scheme is *co-signed usage
/// receipts*, chosen as the **highest-correctness-enforcement** option — BOTH parties sign the
/// **same** token count over the **same** preimage, so neither can unilaterally claim consumption:
/// a provider cannot over-bill (the consumer never signed that number) and a consumer cannot
/// under-report (the provider never signed the smaller one). A one-sided receipt is simply not a
/// proof. This is the settlement trigger the auction escrow (#147 L2) releases on and the
/// settlement chain (#147 L4) turns into a finalized transfer.
///
/// Same domain-separated, injective (length-prefixed) preimage discipline as [`CapacityOffer`],
/// but with **two** signatures over the identical bytes: `provider_sig` (the capacity holder) and
/// `consumer_sig` (the buyer). [`is_valid`](Self::is_valid) requires BOTH to verify. It is per
/// [`CapacityKind`] — a cloud-API response vs a local-inference result are different mechanisms, so
/// `units_consumed`'s semantics follow `kind` exactly as in `CapacityOffer`. `match_ref` binds the
/// receipt to the auction match/offer it settles, so a receipt can't be replayed against a different
/// match. A receipt attests a *past* event, so it has no expiry (a proof of consumption doesn't lapse).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageReceipt {
    /// The capacity holder (provider)'s ed25519 public key — `provider_sig` is checked against this.
    #[serde(with = "card_hex::b32")]
    pub provider: [u8; 32],
    /// The buyer (consumer)'s ed25519 public key — `consumer_sig` is checked against this.
    #[serde(with = "card_hex::b32")]
    pub consumer: [u8; 32],
    /// Which capacity kind was consumed (cloud API quota vs local hardware).
    pub kind: CapacityKind,
    /// The model id served (e.g. `claude-opus-4-8`, a local model tag).
    pub model: String,
    /// Units both parties attest were consumed (semantics per `kind`, as in [`CapacityOffer`]).
    pub units_consumed: u64,
    /// Opaque 32-byte id binding the receipt to the auction match/offer it settles (e.g. a hash of
    /// the winning bid) — prevents replaying one consumption proof against a different match.
    #[serde(with = "card_hex::b32")]
    pub match_ref: [u8; 32],
    pub issued_at: UnixSeconds,
    /// #149-A.4 forensic audit: SHA-256 of the served **request** content, or all-zeros for "not
    /// recorded". The hash — never the content — rides the receipt, so a provider can later prove
    /// exactly what was asked without the marketplace ever transmitting or retaining the plaintext.
    /// Because it's in the co-signed preimage, neither party can alter the recorded request after the
    /// fact without invalidating the other's signature.
    #[serde(with = "card_hex::b32")]
    pub request_hash: [u8; 32],
    /// #149-A.4 forensic audit: SHA-256 of the returned **response** content (all-zeros = not
    /// recorded), co-signed exactly like `request_hash`.
    #[serde(with = "card_hex::b32")]
    pub response_hash: [u8; 32],
    /// The provider's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    #[serde(with = "card_hex::b64")]
    pub provider_sig: [u8; 64],
    /// The consumer's ed25519 signature over the **same** [`signing_bytes`](Self::signing_bytes).
    #[serde(with = "card_hex::b64")]
    pub consumer_sig: [u8; 64],
}

impl UsageReceipt {
    /// Domain-separated, **canonical injective** preimage both parties sign: `domain ‖ provider ‖
    /// consumer ‖ kind(u8) ‖ ⟨model⟩ ‖ units_consumed(LE) ‖ match_ref ‖ issued_at(LE) ‖ request_hash ‖
    /// response_hash`, the variable-length `model` length-prefixed (u32 LE) so no two distinct
    /// receipts share a preimage. The two fixed-size audit hashes are appended (#149-A.4) so both
    /// parties co-sign the forensic record, not just the consumption terms.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_bytes(
        provider: &[u8; 32],
        consumer: &[u8; 32],
        kind: CapacityKind,
        model: &str,
        units_consumed: u64,
        match_ref: &[u8; 32],
        issued_at: UnixSeconds,
        request_hash: &[u8; 32],
        response_hash: &[u8; 32],
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ provider ‖ consumer ‖ kind.tag ‖ model ‖ units ‖ match_ref ‖ issued ‖
        // request_hash ‖ response_hash — byte-identical (model is u32-LE-length-prefixed via var_bytes).
        Preimage::new(USAGE_RECEIPT_DOMAIN)
            .fixed(provider)
            .fixed(consumer)
            .tag(kind.tag())
            .var_bytes(model.as_bytes())
            .u64(units_consumed)
            .fixed(match_ref)
            .u64(issued_at)
            .fixed(request_hash)
            .fixed(response_hash)
            .finish()
    }

    /// Whether this is an authentic co-signed proof: **both** the provider signature (against
    /// `provider`) and the consumer signature (against `consumer`) verify for the receipt's exact
    /// contents. A receipt with either signature forged, or that one party never signed, returns
    /// `false` — that is the whole point: consumption is proven only by mutual agreement.
    pub fn is_valid(&self) -> bool {
        let bytes = Self::signing_bytes(
            &self.provider,
            &self.consumer,
            self.kind,
            &self.model,
            self.units_consumed,
            &self.match_ref,
            self.issued_at,
            &self.request_hash,
            &self.response_hash,
        );
        let ok = |pk: &[u8; 32], sig: &[u8; 64]| match VerifyingKey::from_bytes(pk) {
            Ok(vk) => vk.verify(&bytes, &Signature::from_bytes(sig)).is_ok(),
            Err(_) => false,
        };
        ok(&self.provider, &self.provider_sig) && ok(&self.consumer, &self.consumer_sig)
    }

    /// Construct a fully co-signed receipt **without** forensic hashes (both audit fields all-zeros =
    /// "not recorded") — the plain consumption proof. Equivalent to
    /// [`co_sign_audited`](Self::co_sign_audited) with zero hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn co_sign(
        provider_key: &ed25519_dalek::SigningKey,
        consumer_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        model: String,
        units_consumed: u64,
        match_ref: [u8; 32],
        issued_at: UnixSeconds,
    ) -> UsageReceipt {
        Self::co_sign_audited(
            provider_key,
            consumer_key,
            kind,
            model,
            units_consumed,
            match_ref,
            issued_at,
            [0u8; 32],
            [0u8; 32],
        )
    }

    /// Construct a fully co-signed receipt that also binds a forensic **audit trail** (#149-A.4):
    /// `request_hash`/`response_hash` are SHA-256 of the served request/response content (all-zeros for
    /// "not recorded"). They ride the co-signed preimage, so both parties attest the exact hashes — a
    /// provider can later prove *what* was requested/returned if abuse is reported, and neither side can
    /// alter that record without invalidating the other's signature, all without the marketplace ever
    /// transmitting or retaining the plaintext content. The production flow is asymmetric (provider
    /// pre-signs, consumer counter-signs the identical bytes); deriving both pubkeys from the keys means
    /// neither party can be attributed a signature it did not make.
    #[allow(clippy::too_many_arguments)]
    pub fn co_sign_audited(
        provider_key: &ed25519_dalek::SigningKey,
        consumer_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        model: String,
        units_consumed: u64,
        match_ref: [u8; 32],
        issued_at: UnixSeconds,
        request_hash: [u8; 32],
        response_hash: [u8; 32],
    ) -> UsageReceipt {
        use ed25519_dalek::Signer;
        let provider = provider_key.verifying_key().to_bytes();
        let consumer = consumer_key.verifying_key().to_bytes();
        let bytes = Self::signing_bytes(
            &provider,
            &consumer,
            kind,
            &model,
            units_consumed,
            &match_ref,
            issued_at,
            &request_hash,
            &response_hash,
        );
        UsageReceipt {
            provider,
            consumer,
            kind,
            model,
            units_consumed,
            match_ref,
            issued_at,
            request_hash,
            response_hash,
            provider_sig: provider_key.sign(&bytes).to_bytes(),
            consumer_sig: consumer_key.sign(&bytes).to_bytes(),
        }
    }

    /// Canonical binary wire form (#147-L2 on-chain escrow — the release-proof payload a settlement
    /// block commits when escrow is folded on-chain): `provider(32) ‖ consumer(32) ‖ kind(1) ‖
    /// model_len(u32 LE) ‖ model ‖ units_consumed(8) ‖ match_ref(32) ‖ issued_at(8) ‖ request_hash(32)
    /// ‖ response_hash(32) ‖ provider_sig(64) ‖ consumer_sig(64)`. Variable-length only in `model`
    /// (length-prefixed), so it round-trips losslessly. Both signatures are carried, so a decoded
    /// receipt re-verifies with [`is_valid`](Self::is_valid) — never trusted on decode alone.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 1 + 4 + self.model.len() + 8 + 32 + 8 + 32 + 32 + 64 + 64);
        out.extend_from_slice(&self.provider);
        out.extend_from_slice(&self.consumer);
        out.push(self.kind.tag());
        out.extend_from_slice(&(self.model.len() as u32).to_le_bytes());
        out.extend_from_slice(self.model.as_bytes());
        out.extend_from_slice(&self.units_consumed.to_le_bytes());
        out.extend_from_slice(&self.match_ref);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.request_hash);
        out.extend_from_slice(&self.response_hash);
        out.extend_from_slice(&self.provider_sig);
        out.extend_from_slice(&self.consumer_sig);
        out
    }

    /// Decode from [`encode`](Self::encode). `None` on truncation, a bad `kind` tag, non-UTF-8 `model`,
    /// or any trailing bytes. Structural only — call [`is_valid`](Self::is_valid) to authenticate.
    pub fn decode(b: &[u8]) -> Option<UsageReceipt> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            if cur.len() < n {
                return None;
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Some(head)
        }
        let mut cur = b;
        let provider: [u8; 32] = take(&mut cur, 32)?.try_into().ok()?;
        let consumer: [u8; 32] = take(&mut cur, 32)?.try_into().ok()?;
        let kind = CapacityKind::from_tag(take(&mut cur, 1)?[0])?;
        let model_len = u32::from_le_bytes(take(&mut cur, 4)?.try_into().ok()?) as usize;
        // `take` bounds `model_len` against the actual remaining bytes, so a bogus length can't
        // over-allocate — it just fails the read.
        let model = String::from_utf8(take(&mut cur, model_len)?.to_vec()).ok()?;
        let units_consumed = u64::from_le_bytes(take(&mut cur, 8)?.try_into().ok()?);
        let match_ref: [u8; 32] = take(&mut cur, 32)?.try_into().ok()?;
        let issued_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().ok()?);
        let request_hash: [u8; 32] = take(&mut cur, 32)?.try_into().ok()?;
        let response_hash: [u8; 32] = take(&mut cur, 32)?.try_into().ok()?;
        let provider_sig: [u8; 64] = take(&mut cur, 64)?.try_into().ok()?;
        let consumer_sig: [u8; 64] = take(&mut cur, 64)?.try_into().ok()?;
        if !cur.is_empty() {
            return None; // trailing bytes → malformed
        }
        Some(UsageReceipt {
            provider,
            consumer,
            kind,
            model,
            units_consumed,
            match_ref,
            issued_at,
            request_hash,
            response_hash,
            provider_sig,
            consumer_sig,
        })
    }
}

const PROPOSAL_ACCEPTANCE_DOMAIN: &[u8] = b"ct-proposal-acceptance-v1";

/// An accepter's decision on a `propose` (#163): the narrow design/coordination verbs sink scoped —
/// accept, reject, or counter. Kept a small closed set (not free text) so the decision is one byte in
/// the co-signed preimage; the co-signed record shape is signature-ready to grow into a governance
/// primitive later (a richer decision set) without a wire-format rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalDecision {
    Accept,
    Reject,
    Counter,
}

impl ProposalDecision {
    /// The one byte that represents this decision in the signing preimage (stable across serde renames).
    fn tag(self) -> u8 {
        match self {
            ProposalDecision::Accept => 0,
            ProposalDecision::Reject => 1,
            ProposalDecision::Counter => 2,
        }
    }
}

/// A **non-repudiable, attributable record of an accepter's decision on a proposal** (#163 `propose`).
///
/// The collaboration analog of [`UsageReceipt`]: where a bare `{accepted: bool}` is an unattributable
/// claim (nobody could later prove *who* accepted *what*), this is the accepter's holder signature over
/// a domain-separated preimage that binds all four facts of the decision — the accepter, the authenticated
/// proposer, the exact proposal (by SHA-256), and the deadline it was decided under. Only the accepter
/// signs (it is the accepter's decision that must be provable); the proposer receives it live over the
/// already-authenticated channel, and the proposer's identity is *inside* the co-signed preimage so the
/// record can't be replayed as if a different agent had proposed.
///
/// `proposal_hash` is `SHA-256(proposal)` — the hash, never the text, rides the record, so the decision
/// is bound to the exact proposal without the record having to carry (or re-transmit) its full content.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedAcceptance {
    /// The accepter (the deciding agent)'s ed25519 holder public key — `accepter_sig` is checked against this.
    #[serde(with = "card_hex::b32")]
    pub accepter: [u8; 32],
    /// The proposer's channel-authenticated holder public key, bound into the signature so the decision
    /// is attributable to a specific proposer (not replayable against another).
    #[serde(with = "card_hex::b32")]
    pub proposer: [u8; 32],
    /// The decision the accepter reached.
    pub decision: ProposalDecision,
    /// SHA-256 of the proposal text this decision is about — binds the record to the exact proposal.
    #[serde(with = "card_hex::b32")]
    pub proposal_hash: [u8; 32],
    /// The deadline (unix seconds) the proposal asked to be decided by, co-signed so it can't be altered.
    pub requires_response_by: UnixSeconds,
    /// The accepter's ed25519 signature over [`signing_bytes`](Self::signing_bytes).
    #[serde(with = "card_hex::b64")]
    pub accepter_sig: [u8; 64],
}

impl SignedAcceptance {
    /// Domain-separated, canonical injective preimage the accepter signs: `domain ‖ accepter ‖ proposer ‖
    /// decision(u8) ‖ proposal_hash ‖ requires_response_by(LE)`. All fields fixed-size, so no length
    /// prefixing is needed for injectivity.
    pub fn signing_bytes(
        accepter: &[u8; 32],
        proposer: &[u8; 32],
        decision: ProposalDecision,
        proposal_hash: &[u8; 32],
        requires_response_by: UnixSeconds,
    ) -> Vec<u8> {
        Preimage::new(PROPOSAL_ACCEPTANCE_DOMAIN)
            .fixed(accepter)
            .fixed(proposer)
            .tag(decision.tag())
            .fixed(proposal_hash)
            .u64(requires_response_by)
            .finish()
    }

    /// SHA-256 of a proposal's text — what [`proposal_hash`](Self::proposal_hash) records.
    pub fn hash_proposal(proposal: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(proposal.as_bytes());
        h.finalize().into()
    }

    /// The accepter signs its decision on `proposal` from `proposer`, producing the attributable record.
    pub fn sign_new(
        accepter_key: &ed25519_dalek::SigningKey,
        proposer: [u8; 32],
        decision: ProposalDecision,
        proposal: &str,
        requires_response_by: UnixSeconds,
    ) -> SignedAcceptance {
        use ed25519_dalek::Signer;
        let accepter = accepter_key.verifying_key().to_bytes();
        let proposal_hash = Self::hash_proposal(proposal);
        let bytes =
            Self::signing_bytes(&accepter, &proposer, decision, &proposal_hash, requires_response_by);
        let accepter_sig = accepter_key.sign(&bytes).to_bytes();
        SignedAcceptance { accepter, proposer, decision, proposal_hash, requires_response_by, accepter_sig }
    }

    /// Whether the accepter's signature authentically covers this record's exact contents. A record with
    /// a forged signature, or one the named accepter never signed, returns `false`.
    pub fn is_valid(&self) -> bool {
        let bytes = Self::signing_bytes(
            &self.accepter,
            &self.proposer,
            self.decision,
            &self.proposal_hash,
            self.requires_response_by,
        );
        match VerifyingKey::from_bytes(&self.accepter) {
            Ok(vk) => vk.verify(&bytes, &Signature::from_bytes(&self.accepter_sig)).is_ok(),
            Err(_) => false,
        }
    }

    /// Verify this record is an authentic decision **by `accepter`** on **exactly `proposal`** from
    /// **`proposer`**: the signature verifies *and* the record's bound identities and proposal hash match
    /// the ones the caller expects. This is what a verifier (or an audit) checks — a valid signature over
    /// a *different* proposal or a swapped proposer is rejected.
    pub fn verify_for(&self, proposer: &[u8; 32], proposal: &str) -> bool {
        self.is_valid()
            && &self.proposer == proposer
            && self.proposal_hash == Self::hash_proposal(proposal)
    }
}

const CAPACITY_BID_DOMAIN: &[u8] = b"ct-capacity-bid-v1";
const CAPACITY_MATCH_DOMAIN: &[u8] = b"ct-capacity-match-v1";

/// A **buyer's signed bid for idle capacity** (#147-L2 — the demand side of the auction). Where a
/// [`CapacityOffer`] is the seller's advertisement (the ask), a `CapacityBid` is a consumer's
/// commitment to pay up to `total_price` for `units` of `model` capacity of `kind`, valid until
/// `expires_at`. Same domain-separated injective (length-prefixed) preimage discipline as
/// `CapacityOffer`, signed by the consumer's ed25519 key so a bid can't be forged under another's key.
/// `total_price` is the whole-bid amount the buyer commits (and, on a match, escrows via a
/// [`crate::settlement::Hold`]) — it must meet the seller's `min_price` floor for the bid to clear.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapacityBid {
    /// The bidding consumer's ed25519 public key — the signature is checked against this.
    #[serde(with = "card_hex::b32")]
    pub bidder: [u8; 32],
    pub kind: CapacityKind,
    /// The single model id the buyer wants served (must be one the offer lists).
    pub model: String,
    /// Units wanted (semantics per `kind`, as in [`CapacityOffer`]).
    pub units: u64,
    /// The whole-bid amount the buyer commits to pay for `units` (must be >= the offer's `min_price`).
    pub total_price: u64,
    pub issued_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    /// #149-A.5 acceptable-use acknowledgment: SHA-256 of the provider's stated use-restriction terms
    /// this consumer accepts, or all-zeros for "no acknowledgment". It rides the bidder-signed preimage,
    /// so the bid **is** a signed record that this consumer accepted terms identified by exactly this
    /// hash — a liability-allocation artifact (doesn't *prevent* misuse, but makes acceptance provable
    /// and non-repudiable). A provider that requires acceptance checks `terms_ack` against its own
    /// terms hash; whether it's mandatory is the proposal's open enforcement question, so this is the
    /// opt-in capability, not an enforced gate.
    #[serde(with = "card_hex::b32")]
    pub terms_ack: [u8; 32],
    /// #149-A.1 requested service: the closed task-type this bid is for, or `None` for an unspecified
    /// (generic) request. In the bidder-signed preimage, so the requested service is attested. When
    /// `Some`, [`match_offer`] only clears the bid against an offer whose catalog declares that service.
    #[serde(default)]
    pub service: Option<ServiceType>,
    #[serde(with = "card_hex::b64")]
    pub signature: [u8; 64],
}

impl CapacityBid {
    /// Domain-separated, canonical injective preimage: `domain ‖ bidder ‖ kind(u8) ‖ ⟨model⟩ ‖
    /// units(LE) ‖ total_price(LE) ‖ issued_at(LE) ‖ expires_at(LE) ‖ terms_ack ‖ service`, `model`
    /// length-prefixed. `terms_ack` (#149-A.5) and `service` (#149-A.1, `0` = none, else `1 ‖ tag`,
    /// with a [`ServiceType::Custom`] name length-prefixed right after its tag byte — same
    /// injectivity fix as [`CapacityOffer::signing_bytes`], #382 follow-up) are appended so both
    /// are covered by the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_bytes(
        bidder: &[u8; 32],
        kind: CapacityKind,
        model: &str,
        units: u64,
        total_price: u64,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        terms_ack: &[u8; 32],
        service: Option<ServiceType>,
    ) -> Vec<u8> {
        // #184: DOMAIN ‖ bidder ‖ kind.tag ‖ model ‖ units ‖ total_price ‖ issued ‖ expires ‖ terms_ack
        // ‖ optional service (present: 0x01 ‖ tag ; absent: 0x00) — byte-identical to the prior form.
        let p = Preimage::new(CAPACITY_BID_DOMAIN)
            .fixed(bidder)
            .tag(kind.tag())
            .var_bytes(model.as_bytes())
            .u64(units)
            .u64(total_price)
            .u64(issued_at)
            .u64(expires_at)
            .fixed(terms_ack);
        match &service {
            Some(s) => {
                let p = p.tag(1).tag(s.tag());
                match s {
                    ServiceType::Custom(name) => p.var_bytes(name.as_bytes()).finish(),
                    _ => p.finish(),
                }
            }
            None => p.tag(0).finish(),
        }
    }

    /// Whether the bid is authentic and still current at `now` (signature verifies, `now < expires_at`).
    pub fn is_valid(&self, now: UnixSeconds) -> bool {
        if now >= self.expires_at {
            return false;
        }
        match VerifyingKey::from_bytes(&self.bidder) {
            Ok(vk) => vk
                .verify(
                    &Self::signing_bytes(
                        &self.bidder,
                        self.kind,
                        &self.model,
                        self.units,
                        self.total_price,
                        self.issued_at,
                        self.expires_at,
                        &self.terms_ack,
                        self.service.clone(),
                    ),
                    &Signature::from_bytes(&self.signature),
                )
                .is_ok(),
            Err(_) => false,
        }
    }

    /// Construct + sign a bid with no acknowledgment and no specified service (`terms_ack` all-zeros,
    /// `service` `None`). Equivalent to [`sign_new_full`](Self::sign_new_full) with those defaults.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        signing_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        model: String,
        units: u64,
        total_price: u64,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> CapacityBid {
        Self::sign_new_full(signing_key, kind, model, units, total_price, issued_at, expires_at, [0u8; 32], None)
    }

    /// Construct + sign a bid that **acknowledges the provider's use-restriction terms** (#149-A.5) with
    /// no specified service. Equivalent to [`sign_new_full`](Self::sign_new_full) with `service = None`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new_with_terms(
        signing_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        model: String,
        units: u64,
        total_price: u64,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        terms_ack: [u8; 32],
    ) -> CapacityBid {
        Self::sign_new_full(signing_key, kind, model, units, total_price, issued_at, expires_at, terms_ack, None)
    }

    /// Construct + sign a bid with a `terms_ack` **and** a requested `service` (#149-A.1/A.5). Both ride
    /// the bidder-signed preimage. Derives `bidder` from the key so neither the acknowledgment nor the
    /// requested service can be attributed to a key the caller doesn't hold.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new_full(
        signing_key: &ed25519_dalek::SigningKey,
        kind: CapacityKind,
        model: String,
        units: u64,
        total_price: u64,
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        terms_ack: [u8; 32],
        service: Option<ServiceType>,
    ) -> CapacityBid {
        use ed25519_dalek::Signer;
        let bidder = signing_key.verifying_key().to_bytes();
        let signature = signing_key
            .sign(&Self::signing_bytes(
                &bidder, kind, &model, units, total_price, issued_at, expires_at, &terms_ack, service.clone(),
            ))
            .to_bytes();
        CapacityBid { bidder, kind, model, units, total_price, issued_at, expires_at, terms_ack, service, signature }
    }
}

/// A **cleared match** between a seller's [`CapacityOffer`] and a buyer's [`CapacityBid`] (#147-L2).
/// Produced by [`match_offer`], it names both parties and the agreed terms, and carries a
/// **deterministic** `match_ref` — both sides compute the identical value from the same offer+bid, so
/// it uniquely binds the downstream escrow [`crate::settlement::Hold`] and the [`UsageReceipt`] to
/// *this* match (no cross-match replay). A `CapacityMatch` is a derived fact, not a signed object: its
/// authority comes from the offer and bid it was computed from (both signed, both re-checkable).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapacityMatch {
    /// The provider (= the offer's `holder_pubkey`).
    #[serde(with = "card_hex::b32")]
    pub provider: [u8; 32],
    /// The consumer (= the bid's `bidder`).
    #[serde(with = "card_hex::b32")]
    pub consumer: [u8; 32],
    pub kind: CapacityKind,
    pub model: String,
    pub units: u64,
    /// The clearing amount the consumer escrows for the provider (= the bid's `total_price`).
    pub total_price: u64,
    /// Deterministic id binding the escrow hold + usage receipt to this match.
    #[serde(with = "card_hex::b32")]
    pub match_ref: [u8; 32],
}

/// The deterministic `match_ref` for a cleared match — `sha256(domain ‖ provider ‖ consumer ‖
/// kind(u8) ‖ ⟨model⟩ ‖ units(LE) ‖ total_price(LE) ‖ bid_issued_at(LE) ‖ offer_issued_at(LE))`.
/// Both parties compute the same value; including both timestamps makes distinct auctions for the
/// same terms distinct matches.
fn compute_match_ref(
    provider: &[u8; 32],
    consumer: &[u8; 32],
    kind: CapacityKind,
    model: &str,
    units: u64,
    total_price: u64,
    bid_issued_at: UnixSeconds,
    offer_issued_at: UnixSeconds,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CAPACITY_MATCH_DOMAIN);
    h.update(provider);
    h.update(consumer);
    h.update([kind.tag()]);
    h.update((model.len() as u32).to_le_bytes());
    h.update(model.as_bytes());
    h.update(units.to_le_bytes());
    h.update(total_price.to_le_bytes());
    h.update(bid_issued_at.to_le_bytes());
    h.update(offer_issued_at.to_le_bytes());
    h.finalize().into()
}

/// **Clear a bid against an offer** (#147-L2 matching). Returns a [`CapacityMatch`] iff the two are
/// compatible at `now`, else `None`. Both must be authentic and unexpired (`is_valid`); the `kind`s
/// must agree; the offer must list the bid's `model`; the offer must have enough `units_available`;
/// and the bid's `total_price` must meet the offer's `min_price` **floor** (the buyer clears at or
/// above the seller's minimum). The clearing amount is the bid's `total_price` — what the consumer
/// then escrows via a [`crate::settlement::Hold`] keyed by the match's `match_ref`.
pub fn match_offer(offer: &CapacityOffer, bid: &CapacityBid, now: UnixSeconds) -> Option<CapacityMatch> {
    if !offer.is_valid(now) || !bid.is_valid(now) {
        return None;
    }
    if offer.kind != bid.kind {
        return None;
    }
    if !offer.models.iter().any(|m| m == &bid.model) {
        return None;
    }
    // #149-A.1: a service-specific bid only clears against an offer whose declared catalog serves that
    // service. A bid with no service (`None`) is unconstrained (matches as before); a service-specific
    // bid against a generic (undeclared) or non-matching offer does NOT clear — the schema-typed
    // catalog is enforced at match time, not merely advertised.
    if let Some(service) = &bid.service {
        if !offer.services.contains(service) {
            return None;
        }
    }
    if offer.units_available < bid.units {
        return None;
    }
    if bid.total_price < offer.min_price {
        return None;
    }
    let match_ref = compute_match_ref(
        &offer.holder_pubkey,
        &bid.bidder,
        bid.kind,
        &bid.model,
        bid.units,
        bid.total_price,
        bid.issued_at,
        offer.issued_at,
    );
    Some(CapacityMatch {
        provider: offer.holder_pubkey,
        consumer: bid.bidder,
        kind: bid.kind,
        model: bid.model.clone(),
        units: bid.units,
        total_price: bid.total_price,
        match_ref,
    })
}

/// **Cumulative per-offer capacity accounting** (#158): [`match_offer`] is a stateless *preview* — it
/// checks `offer.units_available >= bid.units` but has no memory of units already committed to prior
/// matches, so on its own the same 1000-unit offer could clear unlimited full-capacity bids
/// (overselling). This is the authoritative running tally the *caller* keeps at commit time (where the
/// escrow/match bookkeeping lives): after a preview clears, [`commit`](Self::commit) atomically checks
/// remaining capacity and reserves the units, so an offer can never be booked beyond `units_available`.
/// Keyed by the offer's signature, which uniquely identifies it.
#[derive(Debug, Default)]
pub struct OfferCommitments {
    committed: std::collections::BTreeMap<[u8; 64], u64>,
}

impl OfferCommitments {
    pub fn new() -> Self {
        Self::default()
    }

    /// Units already committed against `offer`.
    pub fn committed(&self, offer: &CapacityOffer) -> u64 {
        self.committed.get(&offer.signature).copied().unwrap_or(0)
    }

    /// Units still available on `offer` (`units_available - committed`, saturating).
    pub fn remaining(&self, offer: &CapacityOffer) -> u64 {
        offer.units_available.saturating_sub(self.committed(offer))
    }

    /// **Reserve `units` against `offer`**, returning `true` (and recording them) iff the cumulative
    /// total would not exceed `offer.units_available`, else `false` with no change. This is the check
    /// that prevents double-booking: the Nth bid fails once prior matches have consumed the capacity.
    /// `checked_add` so a huge `units` can't wrap the tally.
    pub fn commit(&mut self, offer: &CapacityOffer, units: u64) -> bool {
        let already = self.committed(offer);
        match already.checked_add(units) {
            Some(total) if total <= offer.units_available => {
                self.committed.insert(offer.signature, total);
                true
            }
            _ => false,
        }
    }
}

/// A **cross-user channel invitation** (#72 AF3): the operator invites a specific
/// *invitee identity* (another user's agent) to join a channel, **without yet knowing**
/// the member (holder) key that agent will use. The invitee's agent redeems it — proving
/// it holds the invitee identity key and choosing a holder key (see
/// [`invitation_redeem_bytes`]) — after which the operator/CP issues the real per-holder
/// [`SignedChannelGrant`]. Distinct from *sharing*: an invitation crosses users and is
/// meant to be redeemed **once** into a scoped membership. The invitation object itself is
/// stateless (a signed token with a static redemption proof), so single-use is **not**
/// self-enforcing — the redeeming CP MUST record consumption (keyed by the operator
/// signature) and reject a replay, exactly as `verify_fresh`/`ReplayCache` do for grants
/// (#88 SEC88b). Without that, a **revoked** member could replay the identical redemption
/// to restore membership until expiry (#108). Same claim shape as [`ChannelGrant`], but
/// bound to the invitee's *identity* key rather than a member key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelInvitation {
    /// The channel the invitee is invited to.
    pub channel: ChannelId,
    /// The invited user's agent **identity** public key — the invitee proves possession
    /// of the matching private key at redemption, so only the intended user can accept.
    pub invitee_identity: [u8; 32],
    /// The direction(s) the resulting membership will confer.
    pub direction: Direction,
    /// The data-exchange rights the resulting membership will confer.
    pub rights: Rights,
    /// Whether the resulting membership may re-delegate.
    pub delegable: bool,
    /// Expiry (unix seconds); the invitation is invalid at and after this instant.
    pub expires_at: UnixSeconds,
}

impl ChannelInvitation {
    /// Canonical bytes the operator signs — domain-separated from a grant so an
    /// invitation can never be mistaken for (or replayed as) a grant.
    pub fn signing_bytes(&self) -> Vec<u8> {
        format!(
            "ct-chan-invite:v1|{}|{}|{}|{}|{}|{}",
            hex32(&self.channel.0),
            hex32(&self.invitee_identity),
            self.direction.label(),
            self.rights.label(),
            self.delegable as u8,
            self.expires_at,
        )
        .into_bytes()
    }
}

/// A channel invitation together with the operator's signature over its claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedChannelInvitation {
    pub invitation: ChannelInvitation,
    pub signature: [u8; 64],
}

impl SignedChannelInvitation {
    /// Fixed wire length — every field is fixed-size (mirrors [`SignedChannelGrant`]).
    pub const WIRE_LEN: usize = 64 + 32 + 32 + 1 + 1 + 1 + 8; // 139

    /// Encode to a fixed-layout binary wire form:
    /// `signature(64) | channel(32) | invitee_identity(32) | direction(1) | rights(1) | delegable(1) | expires_at(u64 LE)`.
    pub fn encode(&self) -> Vec<u8> {
        let i = &self.invitation;
        let mut out = Vec::with_capacity(Self::WIRE_LEN);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&i.channel.0);
        out.extend_from_slice(&i.invitee_identity);
        out.push(i.direction.as_byte());
        out.push(i.rights.as_byte());
        out.push(i.delegable as u8);
        out.extend_from_slice(&i.expires_at.to_le_bytes());
        out
    }

    /// Decode from [`SignedChannelInvitation::encode`]'s wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], GrantError> {
            if cur.len() < n {
                return Err(GrantError::Malformed);
            }
            let (head, tail) = cur.split_at(n);
            *cur = tail;
            Ok(head)
        }
        let mut cur = bytes;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(take(&mut cur, 64)?);
        let mut channel = [0u8; 32];
        channel.copy_from_slice(take(&mut cur, 32)?);
        let mut invitee_identity = [0u8; 32];
        invitee_identity.copy_from_slice(take(&mut cur, 32)?);
        let direction = Direction::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let rights = Rights::from_byte(take(&mut cur, 1)?[0]).ok_or(GrantError::Malformed)?;
        let delegable = match take(&mut cur, 1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(GrantError::Malformed),
        };
        let expires_at = u64::from_le_bytes(take(&mut cur, 8)?.try_into().unwrap());
        if !cur.is_empty() {
            return Err(GrantError::Malformed);
        }
        Ok(SignedChannelInvitation {
            invitation: ChannelInvitation {
                channel: ChannelId(channel),
                invitee_identity,
                direction,
                rights,
                delegable,
                expires_at,
            },
            signature,
        })
    }
}

/// Verify a signed invitation against the channel `operator_pubkey` at time `now`
/// (mirrors [`verify`]): confirms the operator signature over the claims and that the
/// invitation has not expired. Does NOT check the invitee's acceptance — that is the
/// redemption proof ([`verify_invitation_redemption`]); this establishes the invitation
/// is authentic and current.
pub fn verify_invitation(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelInvitation,
    now: UnixSeconds,
) -> Result<(), GrantError> {
    let vk = VerifyingKey::from_bytes(operator_pubkey).map_err(|_| GrantError::BadKey)?;
    let sig = Signature::from_bytes(&signed.signature);
    vk.verify(&signed.invitation.signing_bytes(), &sig)
        .map_err(|_| GrantError::BadSignature)?;
    if now >= signed.invitation.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(())
}

/// The domain-separated message the invitee signs with its **identity** key to redeem an
/// invitation (#72 AF3), binding the member `holder` key it will use on the channel.
/// Signing this proves two things at once: the intended invitee (only it holds the
/// identity private key) accepted, and it chose `holder` — so the operator/CP can then
/// issue a [`SignedChannelGrant`] for `holder` knowing the right user asked for it. The
/// binding to `(channel, invitee_identity, holder)` stops a captured invitation from
/// being redeemed to a different key or channel.
pub fn invitation_redeem_bytes(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 32 + 32);
    m.extend_from_slice(b"ct-chan-invite-redeem-v1");
    m.extend_from_slice(&channel.0);
    m.extend_from_slice(invitee_identity);
    m.extend_from_slice(holder);
    m
}

/// Verify an invitation redemption (#72 AF3): `signature` must be `invitee_identity`'s
/// ed25519 signature over [`invitation_redeem_bytes`]. Returns `false` on a bad key, a
/// wrong `(channel, invitee_identity, holder)` binding, or a bad signature — so only the
/// intended invitee can accept, and only into the holder key it actually chose.
pub fn verify_invitation_redemption(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(invitee_identity) {
        Ok(vk) => vk
            .verify(
                &invitation_redeem_bytes(channel, invitee_identity, holder),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The domain-separated message the invitee signs to redeem an invitation **against a
/// fresh, single-use CP challenge** (#108 defense-in-depth): like
/// [`invitation_redeem_bytes`] but also binding the `challenge` nonce the CP issued for
/// this redemption. Because the nonce is fresh and consumed at the CP, a captured
/// redemption signature is non-replayable **independent of** the single-use invitation
/// consumption — belt-and-braces over the [`redeem_invitation`] path. Domain `v2` keeps
/// it distinct from the static `v1` bytes so one can never be presented as the other.
pub fn invitation_redeem_challenge_bytes(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    challenge: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(27 + 32 + 32 + 32 + 32);
    m.extend_from_slice(b"ct-chan-invite-redeem-v2-chal");
    m.extend_from_slice(&channel.0);
    m.extend_from_slice(invitee_identity);
    m.extend_from_slice(holder);
    m.extend_from_slice(challenge);
    m
}

/// Verify a challenge-bound invitation redemption (#108): `signature` must be
/// `invitee_identity`'s ed25519 signature over [`invitation_redeem_challenge_bytes`].
/// Returns `false` on a bad key, a wrong `(channel, invitee_identity, holder, challenge)`
/// binding, or a bad signature — so a redemption signed for one fresh challenge can't be
/// replayed against another.
pub fn verify_invitation_redemption_challenge(
    channel: &ChannelId,
    invitee_identity: &[u8; 32],
    holder: &[u8; 32],
    challenge: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(invitee_identity) {
        Ok(vk) => vk
            .verify(
                &invitation_redeem_challenge_bytes(channel, invitee_identity, holder, challenge),
                &Signature::from_bytes(signature),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// Verify a cross-user invitation **redemption end-to-end** (#72 AF3) and, on success,
/// return the membership claims the invitee earned. This is the two-proof gate the CP
/// runs when an invitee's agent presents a redemption:
///
/// 1. the operator invitation is authentic + current ([`verify_invitation`]), and
/// 2. the intended invitee accepted and bound `holder` ([`verify_invitation_redemption`]).
///
/// On success it returns the invitation's channel/direction/rights/delegable/expiry now
/// bound to the invitee's chosen `holder` — exactly the [`ChannelGrant`] claims the CP
/// records as membership. **No operator private key is needed at redeem time**: the
/// operator authority already rides in the signed invitation, so a provider-blind CP can
/// admit the member from the two public-key proofs alone. Errors mirror
/// [`verify`]: `BadKey`/`BadSignature`/`Expired` (a failed redemption proof surfaces as
/// `BadSignature`).
///
/// This is **pure verification** — like [`verify`] vs [`verify_fresh`], it does NOT
/// enforce single-use. The caller MUST record consumption of the invitation (by its
/// operator signature) and reject a replay, or a revoked member can replay this to
/// restore membership until expiry (#108). The live redeem endpoint does so via
/// `SqliteChannelStore::consume_invitation`.
pub fn redeem_invitation(
    operator_pubkey: &[u8; 32],
    signed: &SignedChannelInvitation,
    redeem_signature: &[u8; 64],
    holder: &[u8; 32],
    now: UnixSeconds,
) -> Result<ChannelGrant, GrantError> {
    verify_invitation(operator_pubkey, signed, now)?;
    let inv = &signed.invitation;
    if !verify_invitation_redemption(&inv.channel, &inv.invitee_identity, holder, redeem_signature) {
        return Err(GrantError::BadSignature);
    }
    Ok(ChannelGrant {
        channel: inv.channel,
        holder: *holder,
        direction: inv.direction,
        rights: inv.rights,
        delegable: inv.delegable,
        expires_at: inv.expires_at,
    })
}

/// Lowercase-hex a 32-byte value for the canonical signing bytes. Writes a static
/// nibble table directly into the pre-sized `String` — **byte-identical** output to
/// the old `format!("{:02x}")` loop (so the signature preimage is unchanged), but
/// without the ~64 throwaway `format!` allocations per call. `signing_bytes` calls
/// this twice on every grant/invitation verify, which is the per-connection A2A
/// admission gate (#114 #5).
fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// #252: every hand-built golden-vector `expected` below starts with a domain tag; since
    /// `Preimage::new` now length-prefixes it (`u32-LE len || domain`), this is the one place that
    /// prefix is spelled out, so a golden vector reads as domain‖fields exactly like before.
    fn dom(d: &[u8]) -> Vec<u8> {
        let mut v = (d.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(d);
        v
    }

    #[test]
    fn signing_bytes_golden_vectors_are_byte_identical_after_the_preimage_refactor_184() {
        // #184 slice 2 (frozen): pin the EXACT preimage bytes for each channel primitive migrated to
        // the Preimage builder, so the refactor cannot drift a single byte (a drift silently breaks
        // every signature over that object type — staples → admission, commitments/receipts →
        // settlement, noise-attest → direct-path key pinning, topology-binding → overlay admission).
        // `expected` is the canonical layout built by hand, identical to the prior hand-rolled encoders.
        let ch = ChannelId([0x11; 32]);
        let a = [0x22u8; 32];
        let b = [0x33u8; 32];
        let c = [0x44u8; 32];
        let d = [0x55u8; 32];

        // MembershipStaple: DOMAIN ‖ channel ‖ holder ‖ stapled_at(LE) ‖ expires_at(LE)
        let mut e = Vec::new();
        e.extend_from_slice(&dom(MEMBERSHIP_STAPLE_DOMAIN));
        e.extend_from_slice(&ch.0);
        e.extend_from_slice(&a);
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(MembershipStaple::signing_bytes(&ch, &a, 7, 9), e, "MembershipStaple preimage drifted");

        // BillingCommitment: DOMAIN ‖ channel ‖ holder ‖ payee ‖ terms_hash ‖ max_amount(LE) ‖ expires_at(LE)
        let mut e = Vec::new();
        e.extend_from_slice(&dom(BILLING_COMMITMENT_DOMAIN));
        e.extend_from_slice(&ch.0);
        e.extend_from_slice(&a);
        e.extend_from_slice(&b);
        e.extend_from_slice(&c);
        e.extend_from_slice(&100u64.to_le_bytes());
        e.extend_from_slice(&200u64.to_le_bytes());
        assert_eq!(BillingCommitment::signing_bytes(&ch, &a, &b, &c, 100, 200), e, "BillingCommitment preimage drifted");

        // SettleReceipt: DOMAIN ‖ channel ‖ receiver ‖ terms_hash ‖ session_nonce ‖ bytes_delivered(LE) ‖ transfer_digest
        let mut e = Vec::new();
        e.extend_from_slice(&dom(SETTLE_RECEIPT_DOMAIN));
        e.extend_from_slice(&ch.0);
        e.extend_from_slice(&a);
        e.extend_from_slice(&b);
        e.extend_from_slice(&c);
        e.extend_from_slice(&4096u64.to_le_bytes());
        e.extend_from_slice(&d);
        assert_eq!(SettleReceipt::signing_bytes(&ch, &a, &b, &c, 4096, &d), e, "SettleReceipt preimage drifted");

        // member_noise_attest_bytes: DOMAIN ‖ channel ‖ holder ‖ noise_pubkey
        let mut e = Vec::new();
        e.extend_from_slice(&dom(b"ct-a2a-noise-attest-v1"));
        e.extend_from_slice(&ch.0);
        e.extend_from_slice(&a);
        e.extend_from_slice(&b);
        assert_eq!(member_noise_attest_bytes(&ch, &a, &b), e, "member_noise_attest preimage drifted");

        // topology_operator_binding_bytes: DOMAIN ‖ len(u64 LE) ‖ topology_id ‖ operator_pubkey
        let topo = "my-topology-α"; // multibyte: len is BYTE length, not char count
        let mut e = Vec::new();
        e.extend_from_slice(&dom(b"ct-topology-operator-v1"));
        e.extend_from_slice(&(topo.len() as u64).to_le_bytes());
        e.extend_from_slice(topo.as_bytes());
        e.extend_from_slice(&a);
        assert_eq!(topology_operator_binding_bytes(topo, &a), e, "topology_operator_binding preimage drifted");
    }

    #[test]
    fn signing_bytes_golden_vectors_variable_length_are_byte_identical_184_slice3() {
        // #184 slice 3 (frozen): the VARIABLE-length preimages — where the length-prefix variants
        // lived — pinned byte-for-byte, with MULTIBYTE strings + multi-element sequences so the u32
        // length prefixes are exercised as BYTE lengths, not char counts. A drift here silently breaks
        // every card/offer/bid/receipt signature.
        fn put_str(m: &mut Vec<u8>, s: &str) {
            m.extend_from_slice(&(s.len() as u32).to_le_bytes());
            m.extend_from_slice(s.as_bytes());
        }
        let h = [0x11u8; 32];

        // AgentCard: DOMAIN ‖ holder ‖ ⟨role_tags⟩ ‖ ⟨skills⟩ ‖ ⟨cells⟩ ‖ ⟨channels⟩ ‖ issued ‖ expires
        let roles = vec!["α".to_string(), "b".to_string()]; // α = 2 UTF-8 bytes
        let skills = vec![Skill {
            id: "s1".to_string(),
            description: "δ".to_string(),
            examples: vec!["e1".to_string(), "é".to_string()],
        }];
        let cells = vec![CellId([0x22; 32])];
        let chans = vec![ChannelId([0x33; 32])];
        let mut e = Vec::new();
        e.extend_from_slice(&dom(AGENT_CARD_DOMAIN));
        e.extend_from_slice(&h);
        e.extend_from_slice(&2u32.to_le_bytes());
        put_str(&mut e, "α");
        put_str(&mut e, "b");
        e.extend_from_slice(&1u32.to_le_bytes());
        put_str(&mut e, "s1");
        put_str(&mut e, "δ");
        e.extend_from_slice(&2u32.to_le_bytes());
        put_str(&mut e, "e1");
        put_str(&mut e, "é");
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&cells[0].0);
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&chans[0].0);
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(AgentCard::signing_bytes(&h, &roles, &skills, &cells, &chans, 7, 9), e, "AgentCard preimage drifted");

        // CapacityOffer: DOMAIN ‖ holder ‖ kind.tag ‖ ⟨models⟩ ‖ units ‖ min ‖ currency ‖ issued ‖ expires ‖ ⟨svc tags⟩
        let models = vec!["m1".to_string(), "µ".to_string()];
        let svcs = vec![ServiceType::CodeGeneration, ServiceType::SafetyCheck];
        let mut e = Vec::new();
        e.extend_from_slice(&dom(CAPACITY_OFFER_DOMAIN));
        e.extend_from_slice(&h);
        e.push(CapacityKind::CloudApiQuota.tag());
        e.extend_from_slice(&2u32.to_le_bytes());
        put_str(&mut e, "m1");
        put_str(&mut e, "µ");
        e.extend_from_slice(&100u64.to_le_bytes());
        e.extend_from_slice(&50u64.to_le_bytes());
        put_str(&mut e, "€");
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        e.extend_from_slice(&2u32.to_le_bytes());
        e.push(ServiceType::CodeGeneration.tag());
        e.push(ServiceType::SafetyCheck.tag());
        assert_eq!(
            CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &models, 100, 50, "€", 7, 9, &svcs),
            e, "CapacityOffer preimage drifted"
        );

        // UsageReceipt: DOMAIN ‖ provider ‖ consumer ‖ kind.tag ‖ model ‖ units ‖ match_ref ‖ issued ‖ req ‖ resp
        let (p, c, mref, rq, rs) = ([0x22u8; 32], [0x33u8; 32], [0x44u8; 32], [0x55u8; 32], [0x66u8; 32]);
        let mut e = Vec::new();
        e.extend_from_slice(&dom(USAGE_RECEIPT_DOMAIN));
        e.extend_from_slice(&p);
        e.extend_from_slice(&c);
        e.push(CapacityKind::LocalHardware.tag());
        put_str(&mut e, "m");
        e.extend_from_slice(&10u64.to_le_bytes());
        e.extend_from_slice(&mref);
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&rq);
        e.extend_from_slice(&rs);
        assert_eq!(
            UsageReceipt::signing_bytes(&p, &c, CapacityKind::LocalHardware, "m", 10, &mref, 7, &rq, &rs),
            e, "UsageReceipt preimage drifted"
        );

        // CapacityBid: DOMAIN ‖ bidder ‖ kind.tag ‖ model ‖ units ‖ total ‖ issued ‖ expires ‖ terms_ack ‖ optional service
        let ta = [0x77u8; 32];
        // Some(service) → 0x01 ‖ tag
        let mut e = Vec::new();
        e.extend_from_slice(&dom(CAPACITY_BID_DOMAIN));
        e.extend_from_slice(&h);
        e.push(CapacityKind::CloudApiQuota.tag());
        put_str(&mut e, "m");
        e.extend_from_slice(&5u64.to_le_bytes());
        e.extend_from_slice(&500u64.to_le_bytes());
        e.extend_from_slice(&7u64.to_le_bytes());
        e.extend_from_slice(&9u64.to_le_bytes());
        e.extend_from_slice(&ta);
        e.push(1);
        e.push(ServiceType::TextGeneration.tag());
        assert_eq!(
            CapacityBid::signing_bytes(&h, CapacityKind::CloudApiQuota, "m", 5, 500, 7, 9, &ta, Some(ServiceType::TextGeneration)),
            e, "CapacityBid (Some service) preimage drifted"
        );
        // None → 0x00 (truncate the last two bytes, append 0)
        let mut e_none = e[..e.len() - 2].to_vec();
        e_none.push(0);
        assert_eq!(
            CapacityBid::signing_bytes(&h, CapacityKind::CloudApiQuota, "m", 5, 500, 7, 9, &ta, None),
            e_none, "CapacityBid (None service) preimage drifted"
        );
    }

    #[test]
    fn service_type_custom_preimage_stays_injective_and_the_four_fixed_variants_are_unchanged() {
        // #382 follow-up: ServiceType gained Custom(String). Two things must both hold or the
        // signing preimage's own "canonical injective" guarantee (the doc comment on every
        // signing_bytes fn in this file) is broken:
        // 1. The four PRE-EXISTING variants' encoding is byte-identical to before Custom existed
        //    (a lone tag byte, nothing appended) -- no already-issued signature's verification
        //    changes.
        // 2. Two DIFFERENT Custom names never share a preimage (tag 4 alone is NOT injective --
        //    the name itself must be length-prefixed right after it), the same guarantee every
        //    other variable-length field in this preimage already has.
        let h = [0x9au8; 32];

        // (1) Fixed variants: exactly one byte per service, unchanged.
        let fixed = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[ServiceType::CodeGeneration]);
        assert_eq!(fixed.last(), Some(&0u8), "CodeGeneration's tag byte, nothing appended after it");
        let empty = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[]);
        assert_eq!(fixed.len(), empty.len() + 1, "a fixed variant appends EXACTLY one byte (its tag) to the services section");

        // (2) Custom: two DIFFERENT names must never collide, even though both share tag 4.
        let custom_a = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[ServiceType::Custom("StaticAnalysis".into())]);
        let custom_b = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[ServiceType::Custom("AndroidInstrumentedTest".into())]);
        assert_ne!(custom_a, custom_b, "two different Custom service names must not share a preimage");
        assert!(custom_a.len() > empty.len() + 1, "a Custom variant appends its tag AND its length-prefixed name, more than a fixed variant's single byte");

        // Boundary case: "ab"+"c" must not collide with "a"+"bc" for two Custom names in
        // sequence -- the classic var-length-concatenation collision this whole preimage
        // discipline exists to prevent, now exercised for the new variable-length variant too.
        let boundary_1 = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[ServiceType::Custom("ab".into()), ServiceType::Custom("c".into())]);
        let boundary_2 = CapacityOffer::signing_bytes(&h, CapacityKind::CloudApiQuota, &[], 1, 1, "c", 0, 10, &[ServiceType::Custom("a".into()), ServiceType::Custom("bc".into())]);
        assert_ne!(boundary_1, boundary_2, "Custom names are length-prefixed, not just concatenated");

        // A real signature over a Custom-service offer verifies correctly end to end.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x5eu8; 32]);
        let offer = CapacityOffer::sign_new_with_services(
            &sk, CapacityKind::CloudApiQuota, vec!["m".into()], 5, 10, "c".into(), 0, 1000,
            vec![ServiceType::Custom("StaticAnalysis".into())],
        );
        assert!(offer.is_valid(50), "a real Custom-service offer signs and verifies correctly");
        let mut tampered = offer.clone();
        tampered.services = vec![ServiceType::Custom("SomethingElse".into())];
        assert!(!tampered.is_valid(50), "swapping the Custom name after signing invalidates the signature");
    }

    #[test]
    fn channel_id_for_pipeline_role_is_deterministic_and_collision_resistant() {
        // #214 follow-up: bridge + server must derive the SAME id with no round-trip, and
        // distinct (operator, pipeline_id, role) triples must derive DIFFERENT ids — including
        // the classic variable-length-field collision a naive concatenation would allow.
        let op_a = [0x11u8; 32];
        let op_b = [0x22u8; 32];

        let id1 = channel_id_for_pipeline_role(&op_a, "flappy-demo", "physics");
        let id1_again = channel_id_for_pipeline_role(&op_a, "flappy-demo", "physics");
        assert_eq!(id1, id1_again, "deterministic: same inputs -> same id every time");

        let id_other_role = channel_id_for_pipeline_role(&op_a, "flappy-demo", "art");
        assert_ne!(id1, id_other_role, "distinct role -> distinct channel");

        let id_other_pipeline = channel_id_for_pipeline_role(&op_a, "cookbook-demo", "physics");
        assert_ne!(id1, id_other_pipeline, "distinct pipeline_id -> distinct channel");

        let id_other_operator = channel_id_for_pipeline_role(&op_b, "flappy-demo", "physics");
        assert_ne!(id1, id_other_operator, "distinct operator -> distinct channel (cross-operator isolation)");

        // Injectivity at the pipeline_id/role boundary: "ab"+"c" must not collide with "a"+"bc".
        let boundary_1 = channel_id_for_pipeline_role(&op_a, "ab", "c");
        let boundary_2 = channel_id_for_pipeline_role(&op_a, "a", "bc");
        assert_ne!(boundary_1, boundary_2, "var-length fields must be length-prefixed, not just concatenated");
    }

    #[test]
    fn channel_id_for_pipeline_role_golden_vector_is_frozen() {
        // Pin the exact preimage bytes (DOMAIN ‖ operator ‖ len(pipeline_id) ‖ pipeline_id ‖
        // len(role) ‖ role) so a future refactor cannot silently change every published pipeline's
        // channel ids.
        use sha2::{Digest, Sha256};
        let op = [0x11u8; 32];
        let mut e = Vec::new();
        e.extend_from_slice(&dom(PIPELINE_ROLE_CHANNEL_DOMAIN));
        e.extend_from_slice(&op);
        e.extend_from_slice(&11u32.to_le_bytes());
        e.extend_from_slice(b"flappy-demo");
        e.extend_from_slice(&7u32.to_le_bytes());
        e.extend_from_slice(b"physics");
        let expected = ChannelId(Sha256::digest(&e).into());
        assert_eq!(channel_id_for_pipeline_role(&op, "flappy-demo", "physics"), expected);
    }

    #[test]
    fn signed_acceptance_preimage_is_frozen_and_binds_proposal_and_proposer_163() {
        // #163 (frozen): pin the EXACT SignedAcceptance preimage — DOMAIN ‖ accepter ‖ proposer ‖
        // decision(u8) ‖ proposal_hash(32) ‖ requires_response_by(LE) — so the co-signed collaboration
        // record can't drift a byte (a drift would silently break every acceptance signature). All
        // fields are fixed-size; the proposal is bound by its SHA-256, so the record binds the exact
        // proposal without carrying its text.
        use sha2::{Digest, Sha256};
        let accepter = [0x11u8; 32];
        let proposer = [0x22u8; 32];
        let proposal = "let's use topology X";
        let mut hh = Sha256::new();
        hh.update(proposal.as_bytes());
        let proposal_hash: [u8; 32] = hh.finalize().into();
        assert_eq!(SignedAcceptance::hash_proposal(proposal), proposal_hash, "hash_proposal = SHA-256(text)");

        let mut e = Vec::new();
        e.extend_from_slice(&dom(PROPOSAL_ACCEPTANCE_DOMAIN));
        e.extend_from_slice(&accepter);
        e.extend_from_slice(&proposer);
        e.push(ProposalDecision::Counter.tag()); // 2
        e.extend_from_slice(&proposal_hash);
        e.extend_from_slice(&5_000u64.to_le_bytes());
        assert_eq!(
            SignedAcceptance::signing_bytes(&accepter, &proposer, ProposalDecision::Counter, &proposal_hash, 5_000),
            e, "SignedAcceptance preimage drifted"
        );

        // End-to-end: a signed record verifies only for the exact (proposer, proposal) pair.
        let key = SigningKey::from_bytes(&[0x11u8; 32]);
        let rec = SignedAcceptance::sign_new(&key, proposer, ProposalDecision::Accept, proposal, 5_000);
        assert!(rec.is_valid(), "the accepter signature verifies");
        assert!(rec.verify_for(&proposer, proposal), "verifies for the bound proposer + exact proposal");
        assert!(!rec.verify_for(&proposer, "tampered proposal"), "a different proposal is rejected");
        assert!(!rec.verify_for(&[0x99u8; 32], proposal), "a swapped proposer is rejected");
        // The three decision tags are distinct + stable.
        assert_eq!(
            (ProposalDecision::Accept.tag(), ProposalDecision::Reject.tag(), ProposalDecision::Counter.tag()),
            (0, 1, 2), "decision tags are stable"
        );
    }

    #[test]
    fn hex32_is_byte_identical_to_the_format_loop() {
        // #114 #5 (frozen): the table-driven hex32 must produce EXACTLY the lowercase
        // hex the old `format!("{:02x}")` loop did — the signing preimage must not
        // change (a different preimage would invalidate every existing grant/invite
        // signature). Check fixed vectors + an arbitrary pattern against the reference.
        let reference = |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };

        let zero = [0x00u8; 32];
        let max = [0xffu8; 32];
        let mut pat = [0u8; 32];
        for (i, p) in pat.iter_mut().enumerate() {
            *p = (i as u8).wrapping_mul(37).wrapping_add(0x0a); // spans low/high nibbles
        }

        assert_eq!(hex32(&zero), "00".repeat(32));
        assert_eq!(hex32(&max), "ff".repeat(32));
        for v in [&zero, &max, &pat] {
            assert_eq!(hex32(v), reference(v), "table hex must equal the format! loop byte-for-byte");
            assert_eq!(hex32(v).len(), 64, "always 64 lowercase hex chars");
        }
    }

    /// Sign a grant with a deterministic operator key (no rng needed in tests).
    fn signed_grant(
        direction: Direction,
        rights: Rights,
        delegable: bool,
        expires_at: UnixSeconds,
    ) -> ([u8; 32], SignedChannelGrant) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let grant = ChannelGrant {
            channel: ChannelId([0xabu8; 32]),
            holder: [0xcdu8; 32],
            direction,
            rights,
            delegable,
            expires_at,
        };
        let signature = sk.sign(&grant.signing_bytes()).to_bytes();
        (sk.verifying_key().to_bytes(), SignedChannelGrant { grant, signature })
    }

    #[test]
    fn verify_ok_before_expiry() {
        let (pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        assert_eq!(verify(&pk, &signed, 999), Ok(()));
    }

    #[test]
    fn verify_rejects_expired() {
        let (pk, signed) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
        assert_eq!(verify(&pk, &signed, 1_000), Err(GrantError::Expired));
    }

    #[test]
    fn verify_rejects_wrong_operator_key() {
        let (_pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(verify(&other, &signed, 500), Err(GrantError::BadSignature));
    }

    #[test]
    fn verify_fresh_admits_once_then_rejects_the_replay() {
        // #88 SEC88b: an authentic, unexpired grant is admitted the first time and
        // rejected as a replay on any later presentation of the same signature —
        // while a different grant (its own signature) is still admitted, and a
        // bad-key grant is rejected on the signature before ever touching the cache.
        use crate::replay::ReplayCache;
        let (pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        let mut cache = ReplayCache::new();

        assert_eq!(verify_fresh(&pk, &signed, 500, &mut cache), Ok(()), "first use admitted");
        assert_eq!(
            verify_fresh(&pk, &signed, 600, &mut cache),
            Err(GrantError::Replayed),
            "the same grant again is a replay"
        );

        // A distinct grant has its own signature and is independently admitted.
        let (pk2, signed2) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
        assert_eq!(verify_fresh(&pk2, &signed2, 600, &mut cache), Ok(()), "a different grant is fresh");

        // A forged grant fails signature verification and is never cached.
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        let (_pk3, signed3) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_000);
        assert_eq!(
            verify_fresh(&other, &signed3, 600, &mut cache),
            Err(GrantError::BadSignature),
            "a bad-key grant is rejected before the cache"
        );
    }

    #[test]
    fn verify_rejects_tampered_scope() {
        // Escalating rights/direction/delegable/holder after signing must break the
        // signature — a grant is not a flat bearer token whose scope can be edited.
        for tamper in 0..4 {
            let (pk, mut signed) = signed_grant(Direction::Initiate, Rights::Read, false, 1_000);
            match tamper {
                0 => signed.grant.rights = Rights::ReadWrite,
                1 => signed.grant.direction = Direction::Both,
                2 => signed.grant.delegable = true,
                _ => signed.grant.holder = [0xffu8; 32],
            }
            assert_eq!(
                verify(&pk, &signed, 500),
                Err(GrantError::BadSignature),
                "tamper case {tamper} must fail verification"
            );
        }
    }

    #[test]
    fn encode_decode_roundtrip_all_variants() {
        for dir in [Direction::Initiate, Direction::Accept, Direction::Both] {
            for rights in [Rights::Read, Rights::Write, Rights::ReadWrite] {
                for delegable in [false, true] {
                    let (_pk, signed) = signed_grant(dir, rights, delegable, 4_242);
                    let bytes = signed.encode();
                    assert_eq!(SignedChannelGrant::decode(&bytes), Ok(signed));
                }
            }
        }
    }

    #[test]
    fn decode_rejects_truncated_and_trailing_and_bad_enums() {
        let (_pk, signed) = signed_grant(Direction::Both, Rights::ReadWrite, true, 1_234);
        assert_eq!(SignedChannelGrant::decode(&[0u8; 10]), Err(GrantError::Malformed));
        let mut trailing = signed.encode();
        trailing.push(0xff);
        assert_eq!(SignedChannelGrant::decode(&trailing), Err(GrantError::Malformed));
        // An out-of-range direction byte (offset 64+32+32) is rejected.
        let mut bad_dir = signed.encode();
        bad_dir[128] = 9;
        assert_eq!(SignedChannelGrant::decode(&bad_dir), Err(GrantError::Malformed));
    }

    #[test]
    fn join_request_roundtrips_and_rejects_malformed() {
        let (_pk, signed) = signed_grant(Direction::Initiate, Rights::ReadWrite, false, 5_000);
        // Grant occupies exactly the advertised fixed prefix.
        assert_eq!(signed.encode().len(), SignedChannelGrant::WIRE_LEN);

        let req = ChannelJoinRequest {
            grant: signed.clone(),
            endpoint: "203.0.113.7:5001".to_string(),
        };
        let bytes = req.encode();
        assert_eq!(ChannelJoinRequest::decode(&bytes), Ok(req));

        // A grant with no trailing endpoint is malformed (endpoint required).
        assert_eq!(
            ChannelJoinRequest::decode(&signed.encode()),
            Err(GrantError::Malformed),
            "a join request must advertise an endpoint"
        );
        // Truncated below a full grant is malformed.
        assert_eq!(ChannelJoinRequest::decode(&[0u8; 10]), Err(GrantError::Malformed));
        // Invalid UTF-8 in the endpoint tail is malformed.
        let mut bad_utf8 = signed.encode();
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        assert_eq!(ChannelJoinRequest::decode(&bad_utf8), Err(GrantError::Malformed));
    }

    #[test]
    fn relay_only_sentinel_is_recognized_and_is_not_a_socket_addr() {
        // #121 (frozen): the reserved relay-only sentinel is recognized by `is_relay_only`
        // and is deliberately NOT parseable as a SocketAddr, so it cannot collide with a real
        // advertised endpoint — the edge admits it as an explicit non-dialable marker, not as
        // an address, and `safe_endpoint` (which parses addresses) never sees it as one.
        let (_pk, signed) = signed_grant(Direction::Accept, Rights::ReadWrite, false, 1_000);
        let relay_only =
            ChannelJoinRequest { grant: signed.clone(), endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string() };
        assert!(relay_only.is_relay_only(), "the sentinel endpoint is recognized as relay-only");
        assert!(
            CHANNEL_ENDPOINT_RELAY_ONLY.parse::<std::net::SocketAddr>().is_err(),
            "the sentinel is not a socket address, so it can't collide with a real endpoint"
        );
        // A real advertised endpoint is not relay-only.
        let direct = ChannelJoinRequest { grant: signed, endpoint: "203.0.113.7:7001".to_string() };
        assert!(!direct.is_relay_only());
        // The sentinel round-trips through the join-request wire form (a normal non-empty tail).
        assert_eq!(ChannelJoinRequest::decode(&relay_only.encode()), Ok(relay_only));
    }

    #[test]
    fn reachability_class_maps_advertised_and_reflexive_to_a_class() {
        // #121 Phase B1 (frozen): the pure reachability classifier — the AutoNAT verdict the
        // edge computes from what a member advertised and the reflexive (post-NAT) source it
        // observed on the authenticated join. Five cases pin the whole matrix.
        use std::net::SocketAddr;
        let public: SocketAddr = "203.0.113.7:7001".parse().unwrap();
        let other_public: SocketAddr = "198.51.100.9:8008".parse().unwrap();
        let private_reflexive: SocketAddr = "192.168.1.5:5000".parse().unwrap();
        let loopback_reflexive: SocketAddr = "127.0.0.1:5000".parse().unwrap();

        // public advertised == reflexive → directly reachable, no NAT rewrite.
        assert_eq!(
            reachability_class("203.0.113.7:7001", public),
            Reachability::Public,
            "a global-unicast address that equals the reflexive is Public",
        );
        // private advertised + global-unicast reflexive → NAT'd but punchable at the reflexive.
        assert_eq!(
            reachability_class("192.168.1.5:5000", public),
            Reachability::Nat { reflexive: public },
            "a private advertised address behind a global reflexive is punchable Nat",
        );
        // relay-only sentinel + global-unicast reflexive → still Nat (the reflexive is usable).
        assert_eq!(
            reachability_class(CHANNEL_ENDPOINT_RELAY_ONLY, other_public),
            Reachability::Nat { reflexive: other_public },
            "the relay-only sentinel with a global reflexive is punchable Nat at the reflexive",
        );
        // public advertised + private reflexive → the observed source is not routable: relay only.
        assert_eq!(
            reachability_class("203.0.113.7:7001", private_reflexive),
            Reachability::RelayOnly,
            "a private reflexive (symmetric/CGNAT) is RelayOnly even if the advertised addr is public",
        );
        // relay-only sentinel + loopback reflexive → double-NAT, pure relay.
        assert_eq!(
            reachability_class(CHANNEL_ENDPOINT_RELAY_ONLY, loopback_reflexive),
            Reachability::RelayOnly,
            "the relay-only sentinel with a non-global reflexive is RelayOnly",
        );
    }

    #[test]
    fn is_global_unicast_matches_the_edge_ssrf_filter_ranges() {
        // #121 Phase B1: the shared global-unicast test `ct_edge::safe_endpoint` is now defined
        // in terms of — it must reject every private/internal range and accept only public unicast.
        use std::net::SocketAddr;
        for bad in [
            "127.0.0.1:22", "0.0.0.0:80", "224.0.0.1:80", "10.0.0.5:22", "172.16.0.1:22",
            "192.168.1.1:22", "169.254.169.254:80", "100.64.0.1:22", "[::1]:22", "[fe80::1]:22",
            "[fc00::1]:22", "[fd12:3456::1]:22",
            // #267: IPv4-mapped/IPv4-compatible IPv6 addresses embedding a
            // loopback/private/link-local/CGNAT IPv4 address must be rejected too --
            // these all classified as global-unicast before the fix.
            "[::ffff:127.0.0.1]:443", "[::ffff:169.254.169.254]:80", "[::ffff:10.0.0.5]:22",
            "[::ffff:192.168.1.1]:22", "[::ffff:100.64.0.1]:22", "[::ffff:0.0.0.0]:80",
        ] {
            assert!(!is_global_unicast(bad.parse::<SocketAddr>().unwrap()), "{bad} must not be global-unicast");
        }
        for ok in [
            "203.0.113.10:7001", "8.8.8.8:443", "[2001:4860:4860::8888]:443",
            // A genuinely public IPv4 address embedded in IPv4-mapped form must still
            // be admitted -- the fix is a correctness fix, not a blanket new rejection.
            "[::ffff:203.0.113.10]:7001",
        ] {
            assert!(is_global_unicast(ok.parse::<SocketAddr>().unwrap()), "{ok} must be global-unicast");
        }
    }

    #[test]
    fn is_global_unicast_v4_mapped_ssrf_bypass_is_closed() {
        // #267 (frozen): a channel member could previously advertise/offer an
        // IPv4-mapped IPv6 address pointing at loopback or cloud metadata and have it
        // pass the SSRF filter, because std's Ipv6Addr::is_loopback/is_unspecified do
        // NOT recognize `::ffff:127.0.0.1` as loopback, and the old V6 branch only
        // checked the unique-local/link-local segment masks -- never unwrapping the
        // embedded IPv4 address at all. Exercises exactly the two concrete targets the
        // finding named.
        use std::net::SocketAddr;
        let cloud_metadata: SocketAddr = "[::ffff:169.254.169.254]:80".parse().unwrap();
        let mapped_loopback: SocketAddr = "[::ffff:127.0.0.1]:443".parse().unwrap();
        assert!(!is_global_unicast(cloud_metadata), "IPv4-mapped cloud metadata must be refused");
        assert!(!is_global_unicast(mapped_loopback), "IPv4-mapped loopback must be refused");
    }

    #[test]
    fn same_local_subnet_accepts_only_a_genuinely_co_resident_private_candidate() {
        // #276 piece 1's safety gate: a peer-offered LAN-local candidate is only safe to
        // dial when it lands in the responder's OWN local /24 (v4) or /64 (v6) -- not
        // merely because it's "some private address" the peer chose to send.
        use std::net::IpAddr;
        let my_v4: IpAddr = "192.168.1.42".parse().unwrap();
        let same_subnet_v4: IpAddr = "192.168.1.7".parse().unwrap();
        let different_subnet_v4: IpAddr = "192.168.2.7".parse().unwrap();
        assert!(same_local_subnet(my_v4, same_subnet_v4), "same /24 -> accepted");
        assert!(!same_local_subnet(my_v4, different_subnet_v4), "different /24 -> refused");

        let my_v6: IpAddr = "fd12:3456:789a:1::1".parse().unwrap();
        let same_subnet_v6: IpAddr = "fd12:3456:789a:1::99".parse().unwrap();
        let different_subnet_v6: IpAddr = "fd12:3456:789a:2::99".parse().unwrap();
        assert!(same_local_subnet(my_v6, same_subnet_v6), "same ULA /64 -> accepted");
        assert!(!same_local_subnet(my_v6, different_subnet_v6), "different ULA /64 -> refused");
    }

    #[test]
    fn same_local_subnet_refuses_a_malicious_offer_regardless_of_the_responders_own_address() {
        // #276 piece 1's core SSRF-closing property: a malicious peer offering a LAN
        // admin panel or cloud-metadata-adjacent address must be refused EVEN IF it
        // happens to share the responder's public reflexive IP (that fact alone -- which
        // this function deliberately does not take as input -- must never be sufficient).
        use std::net::IpAddr;
        let my_v4: IpAddr = "192.168.1.42".parse().unwrap();
        // A LAN address that is NOT in the responder's own subnet -- e.g. a different
        // office/home network the peer happens to also be private-addressed on.
        let attacker_offered: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!same_local_subnet(my_v4, attacker_offered), "off-subnet private candidate refused");

        // link-local (169.254/16, includes the cloud-metadata-adjacent range) is only
        // ever accepted if it's in the responder's own /24 -- 169.254.169.254 specifically
        // is refused here since the responder's own address is a different /24.
        let cloud_metadata_ish: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(!same_local_subnet(my_v4, cloud_metadata_ish), "not in responder's own /24 -> refused");

        // A public/global-unicast "candidate" is never accepted through this path at all
        // (it belongs to is_global_unicast instead), regardless of any subnet match.
        let public: IpAddr = "203.0.113.10".parse().unwrap();
        assert!(!same_local_subnet(my_v4, public), "global-unicast candidate never accepted here");
    }

    #[test]
    fn same_local_subnet_never_matches_across_address_families() {
        // A v4 local address and a v6 candidate (or vice versa) can never "match" --
        // there is no meaningful subnet comparison across families, so this must be a
        // hard refusal, not a panic or a coincidental true.
        use std::net::IpAddr;
        let my_v4: IpAddr = "192.168.1.1".parse().unwrap();
        let v6_candidate: IpAddr = "fd12:3456:789a:1::1".parse().unwrap();
        assert!(!same_local_subnet(my_v4, v6_candidate));
        assert!(!same_local_subnet(v6_candidate, my_v4));
    }

    #[test]
    fn direct_upgrade_is_attempted_only_when_both_sides_are_punchable() {
        // #121 Phase B2 trigger: a hole-punch needs BOTH members to have a punchable
        // reflexive; any RelayOnly side (symmetric/CGNAT) stays on the relay.
        use std::net::SocketAddr;
        let refl: SocketAddr = "203.0.113.10:7001".parse().unwrap();
        let public = Reachability::Public;
        let natd = Reachability::Nat { reflexive: refl };
        let relay = Reachability::RelayOnly;

        // Both punchable (Public/Nat in any combination) -> attempt the direct upgrade.
        for (a, b) in [(public, public), (public, natd), (natd, public), (natd, natd)] {
            assert!(should_attempt_direct_upgrade(a, b), "punchable pair should upgrade");
        }
        // Any RelayOnly side -> stay on the relay (never punch).
        for (a, b) in [(relay, public), (public, relay), (relay, natd), (natd, relay), (relay, relay)] {
            assert!(!should_attempt_direct_upgrade(a, b), "a RelayOnly side stays relayed");
        }
    }

    #[test]
    fn elect_superpeers_picks_public_unvetoed_members_deterministically_and_fails_static() {
        // #121 Phase C: superpeer election is coordinator-free — every member computes the
        // same winners from the same view. Policy: eligible = Public AND not operator-vetoed;
        // winners are the ascending-holder tie-break; empty result = fail-static (relay stays).
        use std::net::SocketAddr;
        let refl: SocketAddr = "203.0.113.10:7001".parse().unwrap();
        let m = |b: u8, r: Reachability| MemberReachability { holder: [b; 32], reachability: r };

        // A mixed membership: two public hosts, one NAT'd, one relay-only.
        let public_hi = m(0x30, Reachability::Public);
        let public_lo = m(0x10, Reachability::Public);
        let natd = m(0x05, Reachability::Nat { reflexive: refl });
        let relay_only = m(0x01, Reachability::RelayOnly);
        let members = [public_hi, natd, public_lo, relay_only];

        // Only the two Public members are eligible, returned ascending by holder — NEVER the
        // NAT'd (0x05) or relay-only (0x01) members even though their holders sort first.
        assert_eq!(elect_superpeers(&members, &[], 8), vec![[0x10; 32], [0x30; 32]]);

        // `count` caps the winners at the smallest-holder eligible member.
        assert_eq!(elect_superpeers(&members, &[], 1), vec![[0x10; 32]]);

        // Deterministic regardless of input order — a permuted view yields the identical result
        // (self-organizing agreement needs no shared ordering).
        let permuted = [relay_only, public_lo, public_hi, natd];
        assert_eq!(
            elect_superpeers(&permuted, &[], 8),
            elect_superpeers(&members, &[], 8),
            "election is order-independent"
        );

        // Operator veto removes an otherwise-eligible Public member (the only override).
        assert_eq!(elect_superpeers(&members, &[[0x10; 32]], 8), vec![[0x30; 32]]);

        // Fail-static: no eligible member (all NAT'd/relay-only, or every public one vetoed) →
        // empty, i.e. no superpeer, so the existing grant-gated relay stays the fallback.
        assert!(elect_superpeers(&[natd, relay_only], &[], 8).is_empty());
        assert!(elect_superpeers(&members, &[[0x10; 32], [0x30; 32]], 8).is_empty());
    }

    #[test]
    fn holder_possession_proof_verifies_only_the_real_holder() {
        // #81 gap 1: the holder proves possession by signing the edge challenge.
        let holder_sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let challenge = b"edge-nonce-0123456789abcdef";

        // The genuine holder's signature over the challenge verifies.
        let sig = holder_sk.sign(challenge).to_bytes();
        assert!(verify_holder_possession(&holder, challenge, &sig));

        // A different key cannot produce a valid proof for this holder.
        let other = SigningKey::from_bytes(&[0x43u8; 32]);
        let forged = other.sign(challenge).to_bytes();
        assert!(!verify_holder_possession(&holder, challenge, &forged), "wrong key rejected");

        // A signature over a DIFFERENT challenge is rejected (no replay of an old
        // proof against a fresh nonce).
        let stale = holder_sk.sign(b"a-different-nonce").to_bytes();
        assert!(!verify_holder_possession(&holder, challenge, &stale), "stale challenge rejected");

        // A tampered signature is rejected.
        let mut tampered = sig;
        tampered[0] ^= 0xff;
        assert!(!verify_holder_possession(&holder, challenge, &tampered), "tampered signature rejected");
    }

    #[test]
    fn topology_operator_binding_proves_possession_of_the_operator_key() {
        // #107-enforce ii-a: binding an operator key to a topology requires proving possession of
        // the operator SECRET — closing the bypass where a public operator key could be bound to
        // an attacker's topology to mint admission to the victim's channels.
        let op_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let op = op_sk.verifying_key().to_bytes();
        let topo = "topology-abc";

        // The genuine operator's signature over (topology_id ‖ operator_pubkey) verifies.
        let proof = op_sk.sign(&topology_operator_binding_bytes(topo, &op)).to_bytes();
        assert!(verify_topology_operator_binding(topo, &op, &proof), "genuine operator binding verifies");

        // The ATTACK: someone who does NOT hold op's secret cannot forge a binding of op to any
        // topology — even signing with their own key claims op as the pubkey and fails.
        let attacker = SigningKey::from_bytes(&[0x22u8; 32]);
        let forged = attacker.sign(&topology_operator_binding_bytes(topo, &op)).to_bytes();
        assert!(!verify_topology_operator_binding(topo, &op, &forged), "cannot bind an operator key you don't hold");

        // A proof for a DIFFERENT topology id does not carry over (id is bound into the preimage).
        let other_topo = op_sk.sign(&topology_operator_binding_bytes("topology-xyz", &op)).to_bytes();
        assert!(!verify_topology_operator_binding(topo, &op, &other_topo), "proof is bound to its topology id");

        // A proof for a DIFFERENT operator key is rejected (preimage binds the claimed key).
        let op2_sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let op2 = op2_sk.verifying_key().to_bytes();
        let cross = op_sk.sign(&topology_operator_binding_bytes(topo, &op2)).to_bytes();
        assert!(!verify_topology_operator_binding(topo, &op2, &cross), "op cannot sign a binding for op2's key");

        // A tampered signature is rejected.
        let mut tampered = proof;
        tampered[0] ^= 0xff;
        assert!(!verify_topology_operator_binding(topo, &op, &tampered), "tampered proof rejected");
    }

    #[test]
    fn member_noise_attestation_binds_the_key_to_holder_and_channel() {
        // #101: the member signs its Noise key with its HOLDER key, binding it to
        // (channel, holder). A DB-controlling operator who substitutes the key can't
        // forge this signature, so the initiator rejects the substituted key.
        let holder_sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let holder = holder_sk.verifying_key().to_bytes();
        let channel = ChannelId([0xC1u8; 32]);
        let noise = [0xAAu8; 32];
        let sig = holder_sk.sign(&member_noise_attest_bytes(&channel, &holder, &noise)).to_bytes();

        assert!(verify_member_noise_attestation(&channel, &holder, &noise, &sig), "genuine attestation verifies");
        assert!(
            !verify_member_noise_attestation(&channel, &holder, &[0xBBu8; 32], &sig),
            "an operator-substituted Noise key is rejected"
        );
        assert!(
            !verify_member_noise_attestation(&ChannelId([0xC2u8; 32]), &holder, &noise, &sig),
            "the attestation is bound to its channel"
        );
        let other = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        assert!(
            !verify_member_noise_attestation(&channel, &other, &noise, &sig),
            "only the real holder can attest (a DB operator can't sign as the holder)"
        );
    }

    #[test]
    fn direction_and_rights_predicates() {
        assert!(Direction::Both.permits(Direction::Initiate));
        assert!(Direction::Both.permits(Direction::Accept));
        assert!(Direction::Initiate.permits(Direction::Initiate));
        assert!(!Direction::Initiate.permits(Direction::Accept));
        assert!(Rights::ReadWrite.can_read() && Rights::ReadWrite.can_write());
        assert!(Rights::Read.can_read() && !Rights::Read.can_write());
        assert!(!Rights::Write.can_read() && Rights::Write.can_write());
    }

    /// Operator-signed invitation for a deterministic invitee identity (no rng).
    fn signed_invitation(expires_at: UnixSeconds) -> ([u8; 32], SignedChannelInvitation) {
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let invitee = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes();
        let invitation = ChannelInvitation {
            channel: ChannelId([0xabu8; 32]),
            invitee_identity: invitee,
            direction: Direction::Both,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = op.sign(&invitation.signing_bytes()).to_bytes();
        (op.verifying_key().to_bytes(), SignedChannelInvitation { invitation, signature })
    }

    #[test]
    fn verify_invitation_checks_operator_signature_and_expiry() {
        let (op_pk, signed) = signed_invitation(1_000);
        assert_eq!(verify_invitation(&op_pk, &signed, 999), Ok(()));
        assert_eq!(verify_invitation(&op_pk, &signed, 1_000), Err(GrantError::Expired));
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(verify_invitation(&other, &signed, 500), Err(GrantError::BadSignature));
    }

    #[test]
    fn signed_invitation_round_trips_through_the_wire_form() {
        let (_op, signed) = signed_invitation(4_242);
        let bytes = signed.encode();
        assert_eq!(bytes.len(), SignedChannelInvitation::WIRE_LEN);
        assert_eq!(SignedChannelInvitation::decode(&bytes), Ok(signed));
        // A truncated buffer is Malformed, not a panic.
        assert_eq!(
            SignedChannelInvitation::decode(&bytes[..bytes.len() - 1]),
            Err(GrantError::Malformed)
        );
    }

    #[test]
    fn only_the_intended_invitee_can_redeem_into_the_holder_it_chose() {
        let channel = ChannelId([0xabu8; 32]);
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder = [0xcdu8; 32]; // the member key the invitee chooses

        // The invitee signs the redemption with its IDENTITY key, binding `holder`.
        let sig = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(verify_invitation_redemption(&channel, &invitee, &holder, &sig));

        // A different holder key -> the binding fails (can't redeem to another key).
        assert!(!verify_invitation_redemption(&channel, &invitee, &[0xee; 32], &sig));
        // A different channel -> fails (invitation can't be moved to another channel).
        assert!(!verify_invitation_redemption(&ChannelId([0x01; 32]), &invitee, &holder, &sig));
        // Someone else's signature over their own redeem bytes doesn't accept for the
        // invitee -> only the intended invitee can accept.
        let mallory = SigningKey::from_bytes(&[0x99u8; 32]);
        let m_sig = mallory.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(!verify_invitation_redemption(&channel, &invitee, &holder, &m_sig));
    }

    #[test]
    fn redeem_invitation_yields_membership_claims_bound_to_the_chosen_holder() {
        // End-to-end AF3: operator invites invitee_identity; the invitee accepts and
        // binds a *member* holder key; redeem_invitation checks both proofs and returns
        // the grant claims bound to the chosen holder (not the invitee identity).
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let op_pk = op.verifying_key().to_bytes();
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let channel = ChannelId([0xabu8; 32]);
        let holder = [0xcdu8; 32];

        let invitation = ChannelInvitation {
            channel,
            invitee_identity: invitee,
            direction: Direction::Initiate,
            rights: Rights::Read,
            delegable: false,
            expires_at: 1_000,
        };
        let sig = op.sign(&invitation.signing_bytes()).to_bytes();
        let signed = SignedChannelInvitation { invitation, signature: sig };
        let redeem = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();

        // Happy path -> the membership grant claims, bound to the chosen holder.
        let grant = redeem_invitation(&op_pk, &signed, &redeem, &holder, 999).unwrap();
        assert_eq!(grant.holder, holder, "claims bind the chosen member key, not the invitee identity");
        assert_eq!(grant.channel, channel);
        assert_eq!(grant.direction, Direction::Initiate);
        assert_eq!(grant.rights, Rights::Read);
        assert_eq!(grant.expires_at, 1_000);

        // Expired invitation -> Expired.
        assert_eq!(redeem_invitation(&op_pk, &signed, &redeem, &holder, 1_000), Err(GrantError::Expired));
        // Wrong operator key -> BadSignature.
        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert_eq!(redeem_invitation(&other, &signed, &redeem, &holder, 999), Err(GrantError::BadSignature));
        // A redemption that bound a different holder -> BadSignature (can't swap the key).
        assert_eq!(
            redeem_invitation(&op_pk, &signed, &redeem, &[0xee; 32], 999),
            Err(GrantError::BadSignature)
        );
    }

    #[test]
    fn challenge_bound_redemption_is_tied_to_the_nonce_and_domain_separated() {
        // #108: a redemption signed for one fresh challenge doesn't verify against another
        // nonce, and the v2 challenge bytes differ from the static v1 bytes.
        let channel = ChannelId([0xabu8; 32]);
        let invitee_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let invitee = invitee_sk.verifying_key().to_bytes();
        let holder = [0xcdu8; 32];
        let nonce = [0x77u8; 32];

        let sig = invitee_sk
            .sign(&invitation_redeem_challenge_bytes(&channel, &invitee, &holder, &nonce))
            .to_bytes();
        assert!(verify_invitation_redemption_challenge(&channel, &invitee, &holder, &nonce, &sig));
        // A different nonce -> fails (non-replayable across challenges).
        assert!(!verify_invitation_redemption_challenge(&channel, &invitee, &holder, &[0x88; 32], &sig));
        // The v2 challenge bytes are domain-separated from the v1 static bytes.
        assert_ne!(
            invitation_redeem_challenge_bytes(&channel, &invitee, &holder, &nonce),
            invitation_redeem_bytes(&channel, &invitee, &holder)
        );
        // A static v1 signature does not satisfy the challenge check, and vice-versa.
        let static_sig = invitee_sk.sign(&invitation_redeem_bytes(&channel, &invitee, &holder)).to_bytes();
        assert!(!verify_invitation_redemption_challenge(&channel, &invitee, &holder, &nonce, &static_sig));
    }

    #[test]
    fn an_invitation_is_domain_separated_from_a_grant() {
        // Same fields, but the invitation and grant signing bytes differ, so an
        // operator signature over one can never be replayed as the other.
        let (_op, inv) = signed_invitation(1_000);
        let grant = ChannelGrant {
            channel: inv.invitation.channel,
            holder: inv.invitation.invitee_identity,
            direction: inv.invitation.direction,
            rights: inv.invitation.rights,
            delegable: inv.invitation.delegable,
            expires_at: inv.invitation.expires_at,
        };
        assert_ne!(inv.invitation.signing_bytes(), grant.signing_bytes());
    }

    // ---- E-fail-static: soft-state membership staples (invariant #7) ----------------------

    /// Mint a staple for `channel`/`holder` under operator key `op` (byte fill), signed over
    /// the canonical preimage. Returns the operator pubkey and the staple.
    fn stapled(
        op: u8,
        channel: [u8; 32],
        holder: [u8; 32],
        stapled_at: UnixSeconds,
        expires_at: UnixSeconds,
    ) -> ([u8; 32], MembershipStaple) {
        let sk = SigningKey::from_bytes(&[op; 32]);
        let signature = sk
            .sign(&MembershipStaple::signing_bytes(
                &ChannelId(channel),
                &holder,
                stapled_at,
                expires_at,
            ))
            .to_bytes();
        (
            sk.verifying_key().to_bytes(),
            MembershipStaple {
                channel: ChannelId(channel),
                holder,
                stapled_at,
                expires_at,
                signature,
            },
        )
    }

    #[test]
    fn staple_cache_admits_offline_until_ttl_then_lapses() {
        // E-fail-static (frozen): a cached, operator-signed membership staple lets a node keep
        // admitting a known member with NO central round-trip, until the staple's TTL lapses —
        // fail-static, never fail-closed. Revocation latency is exactly the TTL (invariant #7):
        // stop refreshing and the cached staple dies within one TTL.
        let ch = [0x11u8; 32];
        let holder = [0xa1u8; 32];
        // Operator (op=7) staples the member at t=1000 for a 3600s TTL → expires at 4600.
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        let mut cache = StapleCache::new();
        assert!(
            cache.refresh(&operator, staple, 1_000),
            "an authentic, unexpired staple is accepted into the cache"
        );

        // (1) FAIL-STATIC: admission succeeds offline (no central) any time before expiry.
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 1_100),
            "a known member is admitted from cache while central is unreachable"
        );
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 4_599),
            "still admitted right up to the last second before the TTL lapses"
        );

        // (2) TTL BOUND / revocation latency (invariant #7): at expiry the staple is dead and
        // the entry is evicted, so a no-longer-refreshed (revoked) member is gone within the TTL.
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &holder, 4_600),
            "at expires_at the cached staple lapses — admission fails (revocation = TTL, #7)"
        );
        // A fresh mint would be needed to re-admit — the lapsed entry was dropped.
        let (_op, again) = stapled(7, ch, holder, 4_600, 8_200);
        assert!(cache.refresh(&operator, again, 4_600));
        assert!(cache.is_member(&operator, &ChannelId(ch), &holder, 5_000));
    }

    #[test]
    fn staple_cache_rejects_forged_and_never_regresses_validity() {
        let ch = [0x22u8; 32];
        let holder = [0xb2u8; 32];
        let (operator, long) = stapled(7, ch, holder, 1_000, 9_000); // long-lived, honest

        // (a) FORGED: a staple signed by a foreign operator (op=8) is neither cached nor trusted.
        let (_foreign, forged) = stapled(8, ch, holder, 1_000, 9_000);
        let mut cache = StapleCache::new();
        assert!(
            !cache.refresh(&operator, forged, 1_000),
            "a staple not signed by the channel operator is rejected, never cached"
        );
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &holder, 1_100),
            "nothing was cached, so the member is not admitted"
        );

        // (b) TAMPERED FIELD: the operator signed for THIS channel; presenting it under a
        // different channel breaks the binding, so it doesn't verify.
        let (_op, mut tampered) = stapled(7, ch, holder, 1_000, 9_000);
        tampered.channel = ChannelId([0x33u8; 32]);
        assert!(
            !tampered.is_valid(&operator, 1_100),
            "a staple whose channel was swapped after signing fails verification"
        );

        // (c) KEEP-LATEST: cache the long staple, then feed a SHORTER-lived one — it must not
        // shrink the member's validity (out-of-order/stale gossip can't regress it).
        assert!(cache.refresh(&operator, long, 1_000));
        let (_op2, short) = stapled(7, ch, holder, 1_000, 3_000); // shorter TTL
        assert!(cache.refresh(&operator, short, 1_000));
        assert!(
            cache.is_member(&operator, &ChannelId(ch), &holder, 5_000),
            "the longer-lived staple still governs at t=5000 — a stale short staple didn't regress it"
        );

        // (d) SCOPE: a staple for this pair grants nothing for a different holder.
        assert!(
            !cache.is_member(&operator, &ChannelId(ch), &[0xccu8; 32], 2_000),
            "membership is per-(channel,holder) — a different holder is not admitted"
        );
    }

    #[test]
    fn membership_staple_wire_roundtrips_and_rejects_malformed() {
        // E-staple-wire (frozen): the fixed 144-byte codec the gossip transport ships. A
        // staple round-trips byte-exact, the decoded copy still verifies (authenticity
        // survives the wire), and a truncated/over-long buffer is rejected as Malformed —
        // a partial staple is never half-decoded into a trusted one.
        let ch = [0x44u8; 32];
        let holder = [0xd4u8; 32];
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        let wire = staple.encode();
        assert_eq!(wire.len(), MembershipStaple::WIRE_LEN, "encoded length is the fixed WIRE_LEN");
        assert_eq!(wire.len(), 144);

        let decoded = MembershipStaple::decode(&wire).expect("a well-formed staple decodes");
        assert_eq!(decoded, staple, "encode -> decode is the identity");
        assert!(
            decoded.is_valid(&operator, 1_100),
            "the decoded staple still verifies under the operator key (authenticity survives the wire)"
        );

        // Truncated (one byte short) and over-long (one trailing byte) buffers are both
        // rejected — the codec never half-trusts a partial or padded record.
        assert_eq!(
            MembershipStaple::decode(&wire[..wire.len() - 1]),
            Err(GrantError::Malformed),
            "a truncated staple buffer is Malformed"
        );
        let mut too_long = wire.clone();
        too_long.push(0);
        assert_eq!(
            MembershipStaple::decode(&too_long),
            Err(GrantError::Malformed),
            "an over-long staple buffer is Malformed"
        );
    }

    #[test]
    fn staple_admission_policy_is_optional_and_only_ever_adds_a_requirement() {
        // #121 E-fail-static, option A (frozen, maintainer decision 2026-07-20): the staple
        // requirement is OPT-IN per channel. `Open` (default) is byte-for-byte today's
        // grant-only behaviour — it never consults a staple, so channels that don't opt in are
        // unaffected. `RequireStaple` additionally demands a fresh cached staple, so revocation
        // propagates within the TTL (#7). Enabling it can only ADD a requirement, never weaken
        // admission (the caller has already verified the grant before calling this).
        let ch = [0x55u8; 32];
        let holder = [0xd5u8; 32];
        let (operator, staple) = stapled(7, ch, holder, 1_000, 4_600);

        // Default policy is Open (grant-only) — the opt-out is the zero value.
        assert_eq!(ChannelAdmissionPolicy::default(), ChannelAdmissionPolicy::Open);

        let mut cache = StapleCache::new();

        // (1) OPEN: admitted with NO staple in the cache at all — grant-only, today's behaviour.
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::Open, &operator, &ChannelId(ch), &holder, 2_000),
            "Open admits a grant-verified member with no staple (backwards-compatible default)"
        );

        // (2) REQUIRE_STAPLE with no staple cached → denied (the freshness requirement bites).
        assert!(
            !cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 2_000),
            "RequireStaple denies a member with no fresh staple"
        );

        // (3) REQUIRE_STAPLE with a fresh staple cached → admitted...
        assert!(cache.refresh(&operator, staple, 1_000));
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 2_000),
            "RequireStaple admits once a fresh staple is present"
        );
        // ...and denied again once that staple lapses at its TTL (revocation latency = TTL, #7).
        assert!(
            !cache.admits_under_policy(ChannelAdmissionPolicy::RequireStaple, &operator, &ChannelId(ch), &holder, 4_600),
            "RequireStaple denies once the staple lapses (revocation propagates within the TTL)"
        );
        // Open still admits at the same instant — it never consults the staple.
        assert!(
            cache.admits_under_policy(ChannelAdmissionPolicy::Open, &operator, &ChannelId(ch), &holder, 4_600),
            "Open is unaffected by staple lapse — grant-only channels are never gated on staples"
        );
    }

    // ---- #107-nway: deterministic per-link channel id derivation --------------------------

    #[test]
    fn link_channel_id_is_canonical_operator_bound_and_collision_resistant() {
        // #107-nway (frozen): a topology's overlay link (holder_a, holder_b) under an operator
        // deterministically maps to a ChannelId both endpoints can derive locally — no round
        // trip. It must be order-independent, operator-bound (cross-operator isolation), and
        // collision-resistant across distinct pairs. It's an ADDRESS only; grants still gate.
        let op = [0x01u8; 32];
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];

        // Deterministic + canonical: both endpoints derive the SAME id regardless of order.
        let id_ab = channel_id_for_link(&op, &a, &b);
        assert_eq!(id_ab, channel_id_for_link(&op, &a, &b), "derivation is deterministic");
        assert_eq!(
            id_ab,
            channel_id_for_link(&op, &b, &a),
            "order-independent — a and b derive the same channel for their link"
        );

        // Operator-bound: a different operator gets a different id for the same pair, so two
        // operators can't collide onto one channel (cross-operator isolation).
        let op2 = [0x02u8; 32];
        assert_ne!(
            id_ab,
            channel_id_for_link(&op2, &a, &b),
            "binding the operator key isolates channels across operators"
        );

        // Collision-resistant: a distinct holder pair yields a distinct channel.
        let c = [0xccu8; 32];
        assert_ne!(id_ab, channel_id_for_link(&op, &a, &c), "a different link is a different channel");
        assert_ne!(
            channel_id_for_link(&op, &a, &c),
            channel_id_for_link(&op, &b, &c),
            "distinct pairs sharing one endpoint are still distinct channels"
        );

        // Sanity: it is a full 32-byte id and not the trivially-zero value.
        assert_ne!(id_ab.0, [0u8; 32], "a derived id is a real hash, not zero");
    }

    #[test]
    fn overlay_authorized_channels_are_exactly_the_declared_links() {
        // #107-enforce (frozen): the enforcement counterpart to `channel_id_for_link`. Given an
        // operator's declared overlay as its holder-pair links, `authorized_channels` is exactly
        // the set of channels those links derive, and `overlay_authorizes_channel` admits a
        // channel iff a declared link names it. This is what makes a drawn topology GOVERN the
        // wire: an undeclared pair's channel is refused; removing an edge stops authorizing it.
        let op = [0x01u8; 32];
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        let c = [0xccu8; 32];
        let d = [0xddu8; 32];

        // Declared overlay: a—b and b—c (a path); note (b, a) reversed + a duplicate to prove
        // canonicalization + set-collapse.
        let links = [(a, b), (b, c), (b, a), (a, b)];
        let authorized = authorized_channels(&op, &links);

        let ab = channel_id_for_link(&op, &a, &b);
        let bc = channel_id_for_link(&op, &b, &c);
        // Exactly the two distinct declared channels — reversed/duplicate links collapsed.
        assert_eq!(authorized.len(), 2, "distinct declared links only (reversed + dup collapse)");
        assert!(authorized.contains(&ab) && authorized.contains(&bc), "both declared links present");

        // The predicate authorizes exactly the declared links (order-independent) and nothing else.
        assert!(overlay_authorizes_channel(&op, &links, &ab), "a—b is declared → authorized");
        assert!(
            overlay_authorizes_channel(&op, &links, &channel_id_for_link(&op, &c, &b)),
            "b—c authorized regardless of the order the channel is queried in"
        );
        // An undeclared pair (a—c, a—d, c—d) is NOT authorized even though its endpoints are members.
        assert!(
            !overlay_authorizes_channel(&op, &links, &channel_id_for_link(&op, &a, &c)),
            "a—c is not a declared edge → refused (membership alone is not authorization)"
        );
        assert!(
            !overlay_authorizes_channel(&op, &links, &channel_id_for_link(&op, &a, &d)),
            "a link to a non-member is refused"
        );

        // Operator-bound: another operator's identically-shaped overlay authorizes different channels.
        let op2 = [0x02u8; 32];
        assert!(
            !overlay_authorizes_channel(&op2, &links, &ab),
            "the a—b channel of operator 1 is not authorized under operator 2's overlay"
        );

        // Empty overlay authorizes nothing.
        assert!(authorized_channels(&op, &[]).is_empty(), "an empty overlay authorizes no channel");
        assert!(!overlay_authorizes_channel(&op, &[], &ab), "empty overlay refuses every channel");
    }

    // ---- #132: optional agent-verifiable A2A billing commitment --------------------------

    /// Sign a billing commitment for `channel` under holder key `h` (byte fill).
    fn commit(
        h: u8,
        channel: [u8; 32],
        payee: [u8; 32],
        terms: [u8; 32],
        max_amount: u64,
        expires_at: UnixSeconds,
    ) -> BillingCommitment {
        let sk = SigningKey::from_bytes(&[h; 32]);
        let holder = sk.verifying_key().to_bytes();
        let sig = sk
            .sign(&BillingCommitment::signing_bytes(
                &ChannelId(channel),
                &holder,
                &payee,
                &terms,
                max_amount,
                expires_at,
            ))
            .to_bytes();
        BillingCommitment {
            channel: ChannelId(channel),
            holder,
            payee,
            terms_hash: terms,
            max_amount,
            expires_at,
            signature: sig,
        }
    }

    #[test]
    fn billing_commitment_verifies_and_gates_setup_only_on_matching_terms() {
        // #132 (frozen): the OPTIONAL, agent-verifiable billing coupling. A holder-signed
        // commitment is authentic + current only for its exact binding; the requiring agent's
        // `satisfies` gate at setup accepts it only for the demanded payee + terms and a
        // sufficient amount. It moves no funds — it is the verifiable coupling, not settlement.
        let ch = [0x11u8; 32];
        let payee = [0xa5u8; 32];
        let terms = [0x7eu8; 32];
        let c = commit(9, ch, payee, terms, 1_000, 5_000);

        // (1) Authentic + unexpired → valid; and satisfies the exact demanded terms with amount.
        assert!(c.is_valid(1_000), "an authentic, unexpired commitment verifies");
        assert!(
            c.satisfies(1_000, &payee, &terms, 500),
            "setup gate passes: right payee + terms, max_amount(1000) >= min(500)"
        );

        // (2) Expiry: at expires_at it is dead (#7-style TTL) — refuses setup.
        assert!(!c.is_valid(5_000), "expired commitment is invalid");
        assert!(!c.satisfies(5_000, &payee, &terms, 500), "expired → setup refused");

        // (3) Wrong payee / wrong terms / insufficient amount all refuse the setup gate.
        assert!(!c.satisfies(1_000, &[0xbbu8; 32], &terms, 500), "wrong payee refused");
        assert!(!c.satisfies(1_000, &payee, &[0xccu8; 32], 500), "wrong terms refused");
        assert!(!c.satisfies(1_000, &payee, &terms, 2_000), "amount below the demanded minimum refused");

        // (4) Tamper: flip a field after signing → the holder signature no longer verifies.
        let mut forged = c.clone();
        forged.max_amount = 1_000_000; // attacker inflates the committed cap
        assert!(!forged.is_valid(1_000), "a tampered max_amount breaks the signature (#132)");
        let mut wrong_payee = c.clone();
        wrong_payee.payee = [0xbbu8; 32];
        assert!(!wrong_payee.is_valid(1_000), "a swapped payee breaks the signature");

        // (5) Forged holder: an attacker signs with its own key but stamps the victim's holder
        // pubkey — the signature can't validate against the claimed holder.
        let victim = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let attacker = SigningKey::from_bytes(&[13u8; 32]);
        let sig = attacker
            .sign(&BillingCommitment::signing_bytes(&ChannelId(ch), &victim, &payee, &terms, 1_000, 5_000))
            .to_bytes();
        let impersonated = BillingCommitment {
            channel: ChannelId(ch), holder: victim, payee, terms_hash: terms,
            max_amount: 1_000, expires_at: 5_000, signature: sig,
        };
        assert!(!impersonated.is_valid(1_000), "a commitment not signed by its holder is rejected");
    }

    #[test]
    fn billing_policy_gate_is_opt_in_and_enforces_the_demanded_commitment() {
        // #132 BC2 (frozen): the per-channel setup gate. `None` is payment-free (admits with or
        // without a commitment); `Require` admits ONLY a present commitment that satisfies the
        // demanded payee/terms/min_amount and is still valid — mirroring ChannelAdmissionPolicy.
        let ch = [0x11u8; 32];
        let payee = [0xa5u8; 32];
        let terms = [0x7eu8; 32];
        let c = commit(9, ch, payee, terms, 1_000, 5_000);

        // Default / None: payment-free — admits regardless of any commitment.
        assert_eq!(BillingPolicy::default(), BillingPolicy::None);
        assert!(BillingPolicy::None.admits(None, 1_000), "None admits with no commitment");
        assert!(BillingPolicy::None.admits(Some(&c), 1_000), "None admits with a commitment too");

        let policy = BillingPolicy::Require { payee, terms_hash: terms, min_amount: 500 };
        // Present + satisfying → admitted.
        assert!(policy.admits(Some(&c), 1_000), "a satisfying commitment is admitted");
        // Missing commitment → refused (the requirement can't be met).
        assert!(!policy.admits(None, 1_000), "Require refuses when no commitment is presented");
        // Expired / wrong payee / wrong terms / insufficient amount → refused.
        assert!(!policy.admits(Some(&c), 5_000), "expired commitment refused");
        assert!(!BillingPolicy::Require { payee: [0xbbu8; 32], terms_hash: terms, min_amount: 500 }.admits(Some(&c), 1_000), "wrong payee refused");
        assert!(!BillingPolicy::Require { payee, terms_hash: [0xccu8; 32], min_amount: 500 }.admits(Some(&c), 1_000), "wrong terms refused");
        assert!(!BillingPolicy::Require { payee, terms_hash: terms, min_amount: 2_000 }.admits(Some(&c), 1_000), "amount below the demanded minimum refused");
        // A forged commitment (tampered after signing) never satisfies.
        let mut forged = c.clone();
        forged.max_amount = 1_000_000;
        assert!(!policy.admits(Some(&forged), 1_000), "a tampered commitment fails the gate");
    }

    #[test]
    fn settle_receipt_attests_delivery_and_defeats_send_side_forgery() {
        // #132 SR1 (frozen): the `settle` receipt. Both peers fold the same delivered bytes through
        // a TransferDigest; the RECEIVER signs a SettleReceipt over its digest; the sender confirms
        // it against its OWN digest. A short/tampered/forged/replayed claim is rejected — so
        // "delivered" is witnessed by the receiver, never asserted by the send side.
        let ch = ChannelId([0x21u8; 32]);
        let terms = [0x7eu8; 32];
        let nonce = [0x5au8; 32];
        let payload = b"the exact application bytes that crossed the tunnel";

        // Both ends fold the identical delivered stream (in the live path, as the pump moves it).
        let mut sender = TransferDigest::new();
        let mut receiver = TransferDigest::new();
        for chunk in payload.chunks(7) {
            sender.update(chunk);
            receiver.update(chunk);
        }
        assert_eq!(sender.digest(), receiver.digest(), "identical streams → identical digest");
        assert_eq!(sender.bytes(), payload.len() as u64);

        // The receiver signs a receipt over what it received.
        let recv_sk = SigningKey::from_bytes(&[0x31u8; 32]);
        let receiver_id = recv_sk.verifying_key().to_bytes();
        let sign = |rid: &[u8; 32], bytes: u64, digest: &[u8; 32], sk: &SigningKey| SettleReceipt {
            channel: ch,
            receiver: *rid,
            terms_hash: terms,
            session_nonce: nonce,
            bytes_delivered: bytes,
            transfer_digest: *digest,
            signature: sk
                .sign(&SettleReceipt::signing_bytes(&ch, rid, &terms, &nonce, bytes, digest))
                .to_bytes(),
        };
        let receipt = sign(&receiver_id, receiver.bytes(), &receiver.digest(), &recv_sk);

        // (1) Authentic + matches the sender's own digest/terms/session + is from the EXPECTED
        // receiver → confirmed.
        assert!(receipt.is_valid(), "a receiver-signed receipt verifies");
        assert!(
            receipt.confirms_delivery(&ch, &receiver_id, &terms, &nonce, payload.len() as u64, &sender.digest()),
            "settle gate passes: right receiver/channel/terms/session, full byte count, matching digest"
        );

        // (2) Under-report / truncated delivery: the receiver only got a prefix → its digest and
        // byte count differ from the sender's, so the sender's gate rejects the receipt.
        let mut short = TransferDigest::new();
        short.update(&payload[..20]);
        let short_receipt = sign(&receiver_id, short.bytes(), &short.digest(), &recv_sk);
        assert!(short_receipt.is_valid(), "the short receipt is itself authentically signed");
        assert!(
            !short_receipt.confirms_delivery(&ch, &receiver_id, &terms, &nonce, payload.len() as u64, &sender.digest()),
            "a truncated delivery digest does NOT match what was sent → rejected"
        );

        // (3) Wrong channel / terms / session / insufficient min_bytes all refuse the gate.
        assert!(!receipt.confirms_delivery(&ChannelId([0u8; 32]), &receiver_id, &terms, &nonce, 1, &sender.digest()), "wrong channel");
        assert!(!receipt.confirms_delivery(&ch, &receiver_id, &[0u8; 32], &nonce, 1, &sender.digest()), "wrong terms");
        assert!(!receipt.confirms_delivery(&ch, &receiver_id, &terms, &[0u8; 32], 1, &sender.digest()), "wrong session nonce (replay)");
        assert!(!receipt.confirms_delivery(&ch, &receiver_id, &terms, &nonce, payload.len() as u64 + 1, &sender.digest()), "below min_bytes");

        // (4) Tamper: inflate the byte count after signing → the receiver signature breaks.
        let mut forged = receipt.clone();
        forged.bytes_delivered = 1_000_000;
        assert!(!forged.is_valid(), "a tampered byte count breaks the receiver signature");

        // (5) Send-side forgery, receiver-id spoofed: an attacker signs a full-delivery receipt with
        // ITS key but stamps the real receiver's id — it can't validate against the claimed receiver.
        let attacker = SigningKey::from_bytes(&[0x99u8; 32]);
        let forged_by_sender = sign(&receiver_id, payload.len() as u64, &sender.digest(), &attacker);
        assert!(!forged_by_sender.is_valid(), "a receipt not signed by the receiver is rejected");

        // (6) #138 — the load-bearing case: a malicious SENDER self-attests delivery. It also knows
        // the transfer_digest (both peers fold the same plaintext), so it signs a receipt with
        // `receiver` = its OWN key over the true digest/terms/session/bytes. That receipt is
        // `is_valid()` (authentically self-signed!) — but `confirms_delivery` must reject it because
        // the gate pins the EXPECTED receiver (the peer we delivered to), which the sender's key is
        // not. Without the receiver binding this would pass → "no ambient send-side trust" would be
        // false.
        let sender_id = attacker.verifying_key().to_bytes(); // the send side's own key
        let self_attested = sign(&sender_id, payload.len() as u64, &sender.digest(), &attacker);
        assert!(self_attested.is_valid(), "the sender's self-signed receipt is authentic FOR ITS OWN key");
        assert!(
            !self_attested.confirms_delivery(&ch, &receiver_id, &terms, &nonce, payload.len() as u64, &sender.digest()),
            "a send-side self-attested receipt is REFUSED — it is not signed by the expected receiver (#138)"
        );
    }

    #[test]
    fn agent_card_verifies_authentic_claims_and_rejects_tampering_expiry_and_repartition() {
        // #135 L1 (frozen): a holder-signed AgentCard authenticates the holder's SELF-ASSERTED claims
        // (role_tags/skills/cells/channels) — verifies for its exact contents, dies at expiry, and
        // any tamper breaks the holder signature. The signature proves the holder ISSUED the claims,
        // never that a cell membership is ratified. Same discipline as BillingCommitment/SettleReceipt.
        let sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let holder = sk.verifying_key().to_bytes();
        let role_tags = vec!["source".to_string(), "reviewer".to_string()];
        let skills = vec![Skill {
            id: "fire_transfer_test".to_string(),
            description: "trigger a live A2A transfer of N bytes".to_string(),
            examples: vec!["fire_transfer_test(size_bytes=588895)".to_string()],
        }];
        let cells = vec![CellId([0x33u8; 32])];
        let channels = vec![ChannelId([0x9bu8; 32])];
        let (issued, expires) = (1_000u64, 5_000u64);
        let sign = |holder: &[u8; 32],
                    role_tags: &[String],
                    skills: &[Skill],
                    cells: &[CellId],
                    channels: &[ChannelId],
                    sk: &SigningKey|
         -> AgentCard {
            AgentCard {
                holder_pubkey: *holder,
                role_tags: role_tags.to_vec(),
                skills: skills.to_vec(),
                cells: cells.to_vec(),
                channels: channels.to_vec(),
                issued_at: issued,
                expires_at: expires,
                signature: sk
                    .sign(&AgentCard::signing_bytes(holder, role_tags, skills, cells, channels, issued, expires))
                    .to_bytes(),
            }
        };
        let card = sign(&holder, &role_tags, &skills, &cells, &channels, &sk);

        // (1) Authentic + unexpired → valid; (2) expiry.
        assert!(card.is_valid(1_000), "an authentic, unexpired card verifies");
        assert!(!card.is_valid(5_000), "at expires_at the card is dead");

        // (3) Tamper each collection → the holder signature no longer verifies.
        let mut t = card.clone();
        t.role_tags.push("central".to_string());
        assert!(!t.is_valid(1_000), "an added role_tag breaks the signature");
        let mut t = card.clone();
        t.skills[0].description = "do something else".to_string();
        assert!(!t.is_valid(1_000), "a changed skill breaks the signature");
        let mut t = card.clone();
        t.cells.push(CellId([0x44u8; 32]));
        assert!(!t.is_valid(1_000), "an added cell breaks the signature (self-asserted, but still signed)");
        let mut t = card.clone();
        t.channels[0] = ChannelId([0u8; 32]);
        assert!(!t.is_valid(1_000), "a swapped channel breaks the signature");

        // (4) Length-prefix injectivity: ["ab","c"] and ["a","bc"] share concatenated bytes but must
        // NOT share a preimage — re-partitioning role_tags under the same signature is rejected.
        let a = sign(&holder, &["ab".to_string(), "c".to_string()], &[], &[], &[], &sk);
        let repartitioned = AgentCard { role_tags: vec!["a".to_string(), "bc".to_string()], ..a.clone() };
        assert!(a.is_valid(1_000), "the first card is authentic");
        assert!(!repartitioned.is_valid(1_000), "re-partitioning under the same signature is rejected (length-prefixed preimage)");

        // (5) Forged holder: an attacker signs with its own key but stamps the victim's holder pubkey.
        let victim = SigningKey::from_bytes(&[0x52u8; 32]).verifying_key().to_bytes();
        let attacker = SigningKey::from_bytes(&[0x53u8; 32]);
        let impersonated = sign(&victim, &role_tags, &skills, &cells, &channels, &attacker);
        assert!(!impersonated.is_valid(1_000), "a card not signed by its holder is rejected");
    }

    #[test]
    fn agent_card_serdes_to_a_verifiable_json_profile() {
        // #135 L1 (frozen): an AgentCard round-trips through JSON as a human-readable **profile**
        // (byte fields are hex strings, not number arrays) and the holder signature STILL verifies
        // after the round-trip — JSON is only a transport/display encoding of the canonical signed
        // binary content, so a peer can read the profile from a registry/vault and re-check it.
        let sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let holder = sk.verifying_key().to_bytes();
        let role_tags = vec!["source".to_string()];
        let skills = vec![Skill {
            id: "fire_transfer_test".to_string(),
            description: "trigger a live A2A transfer".to_string(),
            examples: vec!["fire_transfer_test(size_bytes=588895)".to_string()],
        }];
        let cells = vec![CellId([0x33u8; 32])];
        let channels = vec![ChannelId([0x9bu8; 32])];
        let (issued, expires) = (1_000u64, 5_000u64);
        let card = AgentCard {
            holder_pubkey: holder,
            role_tags: role_tags.clone(),
            skills: skills.clone(),
            cells: cells.clone(),
            channels: channels.clone(),
            issued_at: issued,
            expires_at: expires,
            signature: sk
                .sign(&AgentCard::signing_bytes(&holder, &role_tags, &skills, &cells, &channels, issued, expires))
                .to_bytes(),
        };
        assert!(card.is_valid(1_000), "precondition: an authentic card");

        // Serializes to a human-readable JSON profile: hex STRING byte fields (not `[81,81,…]`
        // arrays) + the self-asserted skills/role_tags carried verbatim.
        let json = serde_json::to_string(&card).expect("card serializes to JSON");
        assert!(json.contains("\"holder_pubkey\":\""), "holder pubkey is a hex string, not a byte array");
        assert!(json.contains("\"signature\":\""), "signature is a hex string");
        assert!(json.contains("\"fire_transfer_test\""), "skills are carried in the profile");
        assert!(!json.contains("[81,81,"), "no raw number-array byte fields");

        // Lossless round-trip AND the holder signature still verifies against the binary preimage.
        let back: AgentCard = serde_json::from_str(&json).expect("card deserializes from JSON");
        assert_eq!(back, card, "the JSON round-trip is lossless");
        assert!(back.is_valid(1_000), "the holder signature still verifies after a JSON round-trip");
        assert!(!back.is_valid(5_000), "expiry survives the round-trip");
        // A tampered profile (edit the skill in the JSON) fails the signature — the profile is
        // authenticated, not just transported.
        let tampered = json.replace("trigger a live A2A transfer", "do something else entirely");
        let bad: AgentCard = serde_json::from_str(&tampered).expect("still valid JSON");
        assert!(!bad.is_valid(1_000), "editing the JSON profile breaks the holder signature");
    }

    #[test]
    fn sign_new_builds_a_valid_card_bound_to_the_signing_key() {
        // #144 ①-wiring construct-and-sign: the production path (no longer a test helper) assembles
        // + signs a card that verifies, derives holder_pubkey from the key itself, and produces the
        // SAME canonical signature the hand-built preimage would — so it drops straight into the
        // emit chain (write_agent_card_for_origin) with no hand-rolled ed25519.
        let sk = SigningKey::from_bytes(&[0x51u8; 32]);
        let role_tags = vec!["central".to_string()];
        let skills = vec![Skill {
            id: "orchestrate_task".to_string(),
            description: "coordinate an agent network".to_string(),
            examples: vec![],
        }];
        let cells = vec![CellId([0x33u8; 32])];
        let channels = vec![ChannelId([0x9bu8; 32])];
        let (issued, expires) = (1_000u64, 5_000u64);

        let card = AgentCard::sign_new(
            &sk,
            role_tags.clone(),
            skills.clone(),
            cells.clone(),
            channels.clone(),
            issued,
            expires,
        );

        // Authentic + current, and the holder key is the signing key's own public key.
        assert!(card.is_valid(1_000), "sign_new produces a card that verifies");
        assert_eq!(card.holder_pubkey, sk.verifying_key().to_bytes(), "holder_pubkey is the signer's key");
        assert!(!card.is_valid(5_000), "expiry is honoured");

        // Byte-identical to the explicit hand-built card (same canonical preimage + deterministic
        // ed25519) — sign_new is exactly the construct-and-sign the test helper used to inline.
        let expected_sig = sk
            .sign(&AgentCard::signing_bytes(
                &sk.verifying_key().to_bytes(),
                &role_tags,
                &skills,
                &cells,
                &channels,
                issued,
                expires,
            ))
            .to_bytes();
        assert_eq!(card.signature, expected_sig, "canonical signature matches the hand-built preimage");

        // The claims are carried verbatim (no re-ordering / drop).
        assert_eq!(card.role_tags, role_tags);
        assert_eq!(card.skills, skills);
        assert_eq!(card.cells, cells);
        assert_eq!(card.channels, channels);
    }

    #[test]
    fn capacity_offer_verifies_authentic_claims_and_rejects_tampering_expiry_and_forgery() {
        // #147 L1 (frozen): a holder-signed idle-capacity offer verifies for its exact contents,
        // covers both capacity kinds, honours expiry, and rejects any tampered field / forged holder —
        // the same signed-claim discipline as AgentCard, and the design-neutral marketplace foundation
        // (no settlement/proof/chain here).
        let sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let make = |kind| {
            CapacityOffer::sign_new(
                &sk,
                kind,
                vec!["claude-opus-4-8".to_string(), "local-llama".to_string()],
                1_000_000,
                50,
                "ct-llm-token-chain".to_string(),
                1_000,
                5_000,
            )
        };

        for kind in [CapacityKind::CloudApiQuota, CapacityKind::LocalHardware] {
            let offer = make(kind);
            assert!(offer.is_valid(1_000), "authentic offer verifies ({kind:?})");
            assert_eq!(offer.holder_pubkey, sk.verifying_key().to_bytes(), "bound to the signer");
            assert!(!offer.is_valid(5_000), "expiry honoured (now == expires_at)");
            assert!(!offer.is_valid(9_999), "expired offer rejected");

            let mut t = offer.clone();
            t.units_available += 1;
            assert!(!t.is_valid(1_000), "raising the units breaks the signature");
            let mut t2 = offer.clone();
            t2.min_price = 0;
            assert!(!t2.is_valid(1_000), "lowering the price floor breaks the signature");
            let mut t3 = offer.clone();
            t3.currency_id = "other-chain".to_string();
            assert!(!t3.is_valid(1_000), "swapping the settlement currency breaks the signature");
            let mut t4 = offer.clone();
            t4.models.push("smuggled-model".to_string());
            assert!(!t4.is_valid(1_000), "adding an advertised model breaks the signature");
            let mut t5 = offer.clone();
            t5.kind = if kind == CapacityKind::CloudApiQuota {
                CapacityKind::LocalHardware
            } else {
                CapacityKind::CloudApiQuota
            };
            assert!(!t5.is_valid(1_000), "flipping the capacity kind breaks the signature");
        }

        // A forged holder (someone else's key claiming this offer's pubkey) fails.
        let mut forged = make(CapacityKind::CloudApiQuota);
        forged.holder_pubkey = SigningKey::from_bytes(&[0x88u8; 32]).verifying_key().to_bytes();
        assert!(!forged.is_valid(1_000), "a holder key that didn't sign is rejected");

        // Lossless, still-verifiable JSON profile round-trip (hex byte fields), like AgentCard.
        let offer = make(CapacityKind::LocalHardware);
        let json = serde_json::to_string(&offer).expect("serializes");
        assert!(json.contains("\"holder_pubkey\":\""), "hex-string byte fields");
        let back: CapacityOffer = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, offer);
        assert!(back.is_valid(1_000), "signature still verifies after a JSON round-trip");
    }

    #[test]
    fn capacity_offer_service_catalog_is_opt_in_and_tamper_evident() {
        // #149-A.1 (frozen): an offer may declare a closed service catalog (opt-in); it rides the
        // holder-signed preimage so the advertised task-types are tamper-evident. A plain (generic)
        // offer records an empty catalog and still verifies (backward-compatible), and the catalog
        // genuinely changes the signature (it's covered, not decorative).
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let make = |services: Vec<ServiceType>| {
            CapacityOffer::sign_new_with_services(
                &sk,
                CapacityKind::CloudApiQuota,
                vec!["claude-opus-4-8".to_string()],
                1_000,
                50,
                "ct-llm-token-chain".to_string(),
                1_000,
                5_000,
                services,
            )
        };
        let declared = make(vec![ServiceType::CodeGeneration, ServiceType::SecurityReview]);
        assert!(declared.is_valid(1_000), "an offer declaring a catalog verifies");
        assert_eq!(declared.services, vec![ServiceType::CodeGeneration, ServiceType::SecurityReview]);

        // Tampering the catalog (adding/removing/swapping a service) breaks the signature.
        let mut extra = declared.clone();
        extra.services.push(ServiceType::TextGeneration);
        assert!(!extra.is_valid(1_000), "adding a service breaks the signature");
        let mut dropped = declared.clone();
        dropped.services.pop();
        assert!(!dropped.is_valid(1_000), "dropping a service breaks the signature");
        let mut swapped = declared.clone();
        swapped.services[0] = ServiceType::SafetyCheck;
        assert!(!swapped.is_valid(1_000), "swapping a service breaks the signature");

        // Opt-out: a plain offer (via sign_new) declares nothing, still verifies, and has a different
        // signature than the declared one (proving the catalog is covered).
        let generic = CapacityOffer::sign_new(
            &sk, CapacityKind::CloudApiQuota, vec!["claude-opus-4-8".to_string()], 1_000, 50, "ct-llm-token-chain".to_string(), 1_000, 5_000,
        );
        assert!(generic.is_valid(1_000), "a generic (undeclared) offer stays valid");
        assert!(generic.services.is_empty(), "no catalog = empty");
        assert_ne!(generic.signature, declared.signature, "the catalog is covered by the signature");

        // JSON round-trip preserves the catalog and still verifies.
        let back: CapacityOffer = serde_json::from_str(&serde_json::to_string(&declared).unwrap()).unwrap();
        assert_eq!(back, declared);
        assert!(back.is_valid(1_000));
    }

    #[test]
    fn usage_receipt_needs_both_parties_and_rejects_unilateral_or_tampered_claims() {
        // #147 L3 (frozen): a consumption proof is a receipt co-signed by BOTH the provider and the
        // consumer over the same units/kind/match — the highest-correctness scheme (maintainer decision
        // 2026-07-23). Neither party can forge the other's side (no unilateral over-bill/under-report),
        // every field is bound by both signatures, both capacity kinds share one shape, and it JSON
        // round-trips. This is the settlement trigger #147-L2 escrow releases on and #147-L4 finalizes.
        use ed25519_dalek::{Signer, SigningKey};
        let provider_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let consumer_key = SigningKey::from_bytes(&[0x22u8; 32]);
        let make = |kind| {
            UsageReceipt::co_sign(
                &provider_key,
                &consumer_key,
                kind,
                "claude-opus-4-8".to_string(),
                4242,
                [0x9au8; 32],
                7_000,
            )
        };

        for kind in [CapacityKind::CloudApiQuota, CapacityKind::LocalHardware] {
            let r = make(kind);
            assert!(r.is_valid(), "an authentic co-signed receipt verifies ({kind:?})");
            assert_eq!(r.provider, provider_key.verifying_key().to_bytes(), "bound to the provider");
            assert_eq!(r.consumer, consumer_key.verifying_key().to_bytes(), "bound to the consumer");

            // Every field is bound by BOTH signatures — tampering any invalidates the receipt.
            let mut t = r.clone();
            t.units_consumed += 1;
            assert!(!t.is_valid(), "inflating consumed units breaks both signatures");
            let mut t2 = r.clone();
            t2.match_ref = [0x00u8; 32];
            assert!(!t2.is_valid(), "re-pointing the receipt at another match breaks it (anti-replay)");
            let mut t3 = r.clone();
            t3.model = "cheaper-model".to_string();
            assert!(!t3.is_valid(), "swapping the served model breaks it");
            let mut t4 = r.clone();
            t4.kind = if kind == CapacityKind::CloudApiQuota {
                CapacityKind::LocalHardware
            } else {
                CapacityKind::CloudApiQuota
            };
            assert!(!t4.is_valid(), "flipping the capacity kind breaks it");
        }

        // The core property: NO unilateral claim. Neither party can produce a valid receipt the
        // other never co-signed — even though each holds its own key and knows both pubkeys.
        let r = make(CapacityKind::CloudApiQuota);
        let bytes = UsageReceipt::signing_bytes(
            &r.provider,
            &r.consumer,
            r.kind,
            &r.model,
            r.units_consumed,
            &r.match_ref,
            r.issued_at,
            &r.request_hash,
            &r.response_hash,
        );
        let mut provider_self_cosigns = r.clone();
        provider_self_cosigns.consumer_sig = provider_key.sign(&bytes).to_bytes();
        assert!(
            !provider_self_cosigns.is_valid(),
            "a provider can't stand in for the consumer's signature — no unilateral over-bill"
        );
        let mut consumer_self_cosigns = r.clone();
        consumer_self_cosigns.provider_sig = consumer_key.sign(&bytes).to_bytes();
        assert!(
            !consumer_self_cosigns.is_valid(),
            "a consumer can't stand in for the provider's signature either"
        );

        // An unrelated third party's signature in either slot is rejected.
        let outsider = SigningKey::from_bytes(&[0x33u8; 32]);
        let mut forged = r.clone();
        forged.provider_sig = outsider.sign(&bytes).to_bytes();
        assert!(!forged.is_valid(), "an outsider's signature is not the provider's");

        // Lossless, still-verifiable JSON round-trip (hex byte fields), like CapacityOffer.
        let json = serde_json::to_string(&r).expect("serializes");
        assert!(json.contains("\"provider\":\"") && json.contains("\"consumer_sig\":\""), "hex byte fields");
        let back: UsageReceipt = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, r);
        assert!(back.is_valid(), "still verifies after a JSON round-trip");
    }

    #[test]
    fn usage_receipt_audit_hashes_are_co_signed_and_tamper_evident() {
        // #149-A.4 (frozen): the forensic request/response hashes ride the co-signed preimage, so both
        // parties attest them and neither can rewrite the audit record after the fact. A plain co_sign
        // records zero hashes ("not recorded") and still verifies (backward-compatible), and the hashes
        // genuinely change the signature (they're covered, not ignored).
        use ed25519_dalek::SigningKey;
        let provider = SigningKey::from_bytes(&[0x11u8; 32]);
        let consumer = SigningKey::from_bytes(&[0x22u8; 32]);
        let (req_h, resp_h) = ([0xAAu8; 32], [0xBBu8; 32]);
        let r = UsageReceipt::co_sign_audited(
            &provider, &consumer, CapacityKind::CloudApiQuota, "m".into(), 10, [0x9u8; 32], 5_000, req_h, resp_h,
        );
        assert!(r.is_valid(), "an audited co-signed receipt verifies");
        assert_eq!((r.request_hash, r.response_hash), (req_h, resp_h), "the hashes are recorded");

        // Tampering either hash breaks BOTH signatures — a provider can't rewrite the audit trail.
        let mut t = r.clone();
        t.request_hash = [0u8; 32];
        assert!(!t.is_valid(), "altering the recorded request hash invalidates the receipt");
        let mut t2 = r.clone();
        t2.response_hash[0] ^= 1;
        assert!(!t2.is_valid(), "altering the recorded response hash invalidates the receipt");

        // Backward-compatible: a plain co_sign records zero hashes and still verifies — and its
        // signature differs from the audited one, proving the hashes are actually covered.
        let plain =
            UsageReceipt::co_sign(&provider, &consumer, CapacityKind::CloudApiQuota, "m".into(), 10, [0x9u8; 32], 5_000);
        assert!(plain.is_valid(), "a plain (unrecorded) receipt still verifies");
        assert_eq!((plain.request_hash, plain.response_hash), ([0u8; 32], [0u8; 32]), "not recorded = zero hashes");
        assert_ne!(plain.provider_sig, r.provider_sig, "the audit hashes are covered by the signature");

        // JSON round-trip preserves the hashes and still verifies.
        let back: UsageReceipt = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert!(back.is_valid());
    }

    #[test]
    fn usage_receipt_encode_round_trips_and_rejects_malformed() {
        // #147-L2 on-chain escrow (frozen): the co-signed receipt has a canonical binary wire form (the
        // release-proof payload a settlement block commits), round-tripping losslessly, still verifying
        // after decode (both signatures preserved), and rejecting truncated / trailing-byte buffers.
        use ed25519_dalek::SigningKey;
        let provider = SigningKey::from_bytes(&[0x11u8; 32]);
        let consumer = SigningKey::from_bytes(&[0x22u8; 32]);
        let r = UsageReceipt::co_sign_audited(
            &provider, &consumer, CapacityKind::LocalHardware, "claude-opus-4-8".into(), 1234, [0x9u8; 32], 5_000, [0xAu8; 32], [0xBu8; 32],
        );
        let bytes = r.encode();
        let back = UsageReceipt::decode(&bytes).expect("round-trips");
        assert_eq!(back, r, "decode is the inverse of encode");
        assert!(back.is_valid(), "the decoded receipt still verifies (both signatures preserved)");
        assert!(UsageReceipt::decode(&bytes[..bytes.len() - 1]).is_none(), "a truncated buffer is rejected");
        let mut long = bytes.clone();
        long.push(0);
        assert!(UsageReceipt::decode(&long).is_none(), "trailing bytes are rejected");

        // An empty-model, plain (zero-hash) receipt also round-trips (the length prefix handles it).
        let r2 = UsageReceipt::co_sign(&provider, &consumer, CapacityKind::CloudApiQuota, String::new(), 0, [0u8; 32], 1);
        assert_eq!(UsageReceipt::decode(&r2.encode()).unwrap(), r2, "empty-model receipt round-trips");
    }

    #[test]
    fn capacity_bid_matches_a_compatible_offer_and_threads_into_escrow() {
        // #147-L2 (frozen): a buyer's signed bid clears against a seller's offer iff kind + model +
        // units fit and the bid meets the seller's floor; the match is deterministic (same match_ref
        // both sides) and that ref threads through the escrow Hold + L3 receipt so settlement binds to
        // THIS match — advertise (L1) -> bid/match (L2) -> escrow+prove+release (L2/L3) end to end.
        use crate::settlement::{Escrow, Hold};
        use std::collections::BTreeMap;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let buyer = SigningKey::from_bytes(&[0x52u8; 32]);
        let offer = CapacityOffer::sign_new(
            &seller,
            CapacityKind::CloudApiQuota,
            vec!["claude-opus-4-8".to_string(), "local-llama".to_string()],
            1_000, // units_available
            100,   // min_price (seller floor)
            "ct-llm-token-chain".to_string(),
            1_000,
            9_000,
        );
        let bid = CapacityBid::sign_new(
            &buyer,
            CapacityKind::CloudApiQuota,
            "claude-opus-4-8".to_string(),
            200, // units (<= 1000 available)
            150, // total_price (>= 100 floor)
            1_000,
            9_000,
        );

        // Happy path: clears with the expected terms.
        let m = match_offer(&offer, &bid, 1_000).expect("a compatible bid clears");
        assert_eq!(m.provider, seller.verifying_key().to_bytes(), "provider is the offer holder");
        assert_eq!(m.consumer, buyer.verifying_key().to_bytes(), "consumer is the bidder");
        assert_eq!((m.units, m.total_price), (200, 150), "cleared at the bid's terms");
        // Deterministic: recomputing (later, while both still valid) yields the identical match_ref.
        let m2 = match_offer(&offer, &bid, 2_000).expect("still clears while both are valid");
        assert_eq!(m2.match_ref, m.match_ref, "match_ref is a deterministic function of offer+bid");

        // Reject paths -> None.
        let wrong_kind = CapacityBid::sign_new(&buyer, CapacityKind::LocalHardware, "claude-opus-4-8".into(), 10, 150, 1_000, 9_000);
        assert!(match_offer(&offer, &wrong_kind, 1_000).is_none(), "kind must match");
        let unlisted = CapacityBid::sign_new(&buyer, CapacityKind::CloudApiQuota, "gpt-9".into(), 10, 150, 1_000, 9_000);
        assert!(match_offer(&offer, &unlisted, 1_000).is_none(), "offer must serve the model");
        let too_many = CapacityBid::sign_new(&buyer, CapacityKind::CloudApiQuota, "claude-opus-4-8".into(), 5_000, 9_000, 1_000, 9_000);
        assert!(match_offer(&offer, &too_many, 1_000).is_none(), "bid can't exceed available units");
        let below_floor = CapacityBid::sign_new(&buyer, CapacityKind::CloudApiQuota, "claude-opus-4-8".into(), 10, 50, 1_000, 9_000);
        assert!(match_offer(&offer, &below_floor, 1_000).is_none(), "bid must meet the seller's floor");
        assert!(match_offer(&offer, &bid, 9_000).is_none(), "an expired offer/bid doesn't clear");
        let mut forged = bid.clone();
        forged.bidder = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        assert!(match_offer(&offer, &forged, 1_000).is_none(), "a forged bid (bidder didn't sign) is rejected");

        // End-to-end: the match_ref threads into escrow. The buyer escrows the cleared amount for the
        // provider under the match_ref; a co-signed receipt for the SAME match releases it.
        let mut esc = Escrow::new(BTreeMap::from([(m.consumer, 1_000)]));
        esc.lock(&Hold::sign_new(&buyer, m.provider, m.total_price, m.match_ref, 0, 9_000)).expect("buyer escrows the cleared amount");
        assert_eq!(esc.held_amount(&m.match_ref), 150, "the cleared amount is held under the match_ref");
        let receipt = UsageReceipt::co_sign(&seller, &buyer, m.kind, m.model.clone(), m.units, m.match_ref, 5_000);
        esc.release(&receipt).expect("the co-signed receipt for this match releases the escrow");
        assert_eq!(esc.balance(&m.provider), 150, "provider paid the cleared amount for this match");
    }

    #[test]
    fn capacity_bid_terms_ack_is_signed_and_binding() {
        // #149-A.5 (frozen): the acceptable-use acknowledgment rides the bidder-signed preimage, so a
        // bid is a non-repudiable record of accepting exactly those terms. A plain sign_new records a
        // zero ack and still verifies (backward-compatible), and the ack genuinely changes the
        // signature (it's covered, not decorative) — so a consumer can't later deny which terms it took.
        use ed25519_dalek::SigningKey;
        let buyer = SigningKey::from_bytes(&[0x52u8; 32]);
        let terms = [0x7Eu8; 32]; // SHA-256 of the provider's stated use-restriction terms
        let b = CapacityBid::sign_new_with_terms(
            &buyer, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000, terms,
        );
        assert!(b.is_valid(1_000), "an acknowledged bid verifies");
        assert_eq!(b.terms_ack, terms, "the accepted-terms hash is recorded");

        // Tampering the ack (claiming acceptance of different terms) breaks the signature.
        let mut t = b.clone();
        t.terms_ack = [0u8; 32];
        assert!(!t.is_valid(1_000), "altering the acknowledged terms invalidates the bid");

        // Backward-compatible: a plain bid records a zero ack, still verifies, and has a different
        // signature than the acknowledged one (proving terms_ack is covered by the signature).
        let plain = CapacityBid::sign_new(&buyer, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000);
        assert!(plain.is_valid(1_000), "a plain (no-ack) bid still verifies");
        assert_eq!(plain.terms_ack, [0u8; 32], "no acknowledgment = zero hash");
        assert_ne!(plain.signature, b.signature, "the acknowledgment is covered by the signature");

        // JSON round-trip preserves the ack and still verifies.
        let back: CapacityBid = serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(back, b);
        assert!(back.is_valid(1_000));
    }

    #[test]
    fn service_specific_bid_only_clears_against_an_offer_declaring_that_service() {
        // #149-A.1 enforcement (frozen): a bid requesting a specific ServiceType clears only against an
        // offer whose declared catalog serves it; a service-less bid is unconstrained (matches as
        // before); the requested service is signed (tamper-evident); a service-specific bid against a
        // generic (undeclared) or non-matching offer does NOT clear — the catalog is enforced at match.
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let buyer = SigningKey::from_bytes(&[0x52u8; 32]);
        let mk_offer = |services: Vec<ServiceType>| {
            CapacityOffer::sign_new_with_services(
                &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 1_000, 100, "c".into(), 1_000, 9_000, services,
            )
        };
        let mk_bid = |service: Option<ServiceType>| {
            CapacityBid::sign_new_full(&buyer, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000, [0u8; 32], service)
        };

        let code_offer = mk_offer(vec![ServiceType::CodeGeneration]);
        let generic_offer = mk_offer(vec![]);

        // A CodeGeneration bid clears against an offer declaring CodeGeneration...
        assert!(match_offer(&code_offer, &mk_bid(Some(ServiceType::CodeGeneration)), 1_000).is_some(), "declared service clears");
        // ...but not one that only declares SecurityReview, nor a generic (undeclared) offer.
        assert!(match_offer(&mk_offer(vec![ServiceType::SecurityReview]), &mk_bid(Some(ServiceType::CodeGeneration)), 1_000).is_none(), "non-matching catalog doesn't clear");
        assert!(match_offer(&generic_offer, &mk_bid(Some(ServiceType::CodeGeneration)), 1_000).is_none(), "a generic offer can't serve a service-specific bid");

        // A service-less bid is unconstrained: it clears against both the declared and the generic offer.
        assert!(match_offer(&code_offer, &mk_bid(None), 1_000).is_some(), "a service-less bid clears against a declared offer");
        assert!(match_offer(&generic_offer, &mk_bid(None), 1_000).is_some(), "a service-less bid clears against a generic offer");

        // The requested service is signed: tampering it invalidates the bid (so it can't clear at all).
        let mut tampered = mk_bid(Some(ServiceType::CodeGeneration));
        tampered.service = Some(ServiceType::TextGeneration);
        assert!(!tampered.is_valid(1_000), "the requested service is covered by the signature");
        assert!(match_offer(&mk_offer(vec![ServiceType::TextGeneration]), &tampered, 1_000).is_none(), "an invalid (tampered) bid never clears");
    }

    #[test]
    fn offer_commitments_prevent_double_booking_beyond_advertised_capacity() {
        // #158 (frozen): match_offer is a stateless preview; OfferCommitments is the authoritative
        // running tally that stops an offer being booked past its units_available. Two full-capacity
        // bids against the same offer can't both commit; partials fill exactly to capacity; a different
        // offer has its own independent budget.
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let offer = CapacityOffer::sign_new(
            &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 1_000, 100, "c".into(), 1_000, 9_000,
        );
        let mut book = OfferCommitments::new();
        assert_eq!(book.remaining(&offer), 1_000, "nothing committed yet");

        // First full-capacity commit succeeds; a second one can't double-book.
        assert!(book.commit(&offer, 1_000), "the first 1000-unit match commits");
        assert_eq!(book.remaining(&offer), 0, "the offer is now fully committed");
        assert!(!book.commit(&offer, 1), "a second bid can't exceed advertised capacity (#158 fixed)");

        // Partials fill exactly to capacity, never past it.
        let mut book2 = OfferCommitments::new();
        assert!(book2.commit(&offer, 600), "600 of 1000 commits");
        assert!(!book2.commit(&offer, 500), "500 more would oversell (only 400 left)");
        assert_eq!(book2.remaining(&offer), 400);
        assert!(book2.commit(&offer, 400), "400 fills it exactly");
        assert!(!book2.commit(&offer, 1), "and not one unit more");

        // A different offer (different signature) has its own budget.
        let offer_b = CapacityOffer::sign_new(
            &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 500, 100, "c".into(), 1_000, 9_000,
        );
        assert_eq!(book.remaining(&offer_b), 500, "a distinct offer is tracked separately");
        assert!(book.commit(&offer_b, 500), "and has its own full capacity");

        // A huge units value can't wrap the tally.
        assert!(!OfferCommitments::new().commit(&offer, u64::MAX), "an overflowing commit is refused");
    }
}

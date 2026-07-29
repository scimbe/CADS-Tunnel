//! Agent daemon configuration (M5.2a).
//!
//! Parsed from environment variables so the Agent runs as a configurable
//! container node in the Docker testbed.

use std::net::{IpAddr, SocketAddr};

/// Transport protocol of the local Origin the Agent bridges to (M10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OriginProto {
    /// A TCP Origin — full-duplex byte stream (default).
    #[default]
    Tcp,
    /// A UDP Origin — datagram-preserving bridge.
    Udp,
}

impl OriginProto {
    pub fn parse(s: &str) -> Result<OriginProto, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(OriginProto::Tcp),
            "udp" => Ok(OriginProto::Udp),
            other => Err(format!("invalid CT_AGENT_ORIGIN_PROTO '{other}' (expected tcp|udp)")),
        }
    }
}

/// Runtime configuration for the Agent daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Edge address to dial (outbound).
    pub edge: SocketAddr,
    /// Local Origin service to expose through the tunnel.
    pub origin: SocketAddr,
    /// Whether the Origin speaks TCP or UDP.
    pub origin_proto: OriginProto,
    /// If set, the Agent runs a direct-path listener and advertises it at this
    /// IP (with the listener's bound port) so Clients can connect directly,
    /// bypassing the Edge relay (M11.4b-v). `None` disables P2P (relay only).
    pub direct_advertise_ip: Option<IpAddr>,
    /// If set, the Agent serves its Prometheus `/metrics` endpoint on this
    /// address (M14.2). `None` disables the endpoint.
    pub metrics_listen: Option<SocketAddr>,
    /// Browser Plane (#23): when true the Agent forwards each relayed stream to
    /// the Origin **verbatim** (raw TLS passthrough) instead of terminating a
    /// Noise session — the browser's TLS terminates at the Origin. Set with
    /// `CT_AGENT_MODE=browser`. Default `false` (Mesh Plane / Noise).
    pub browser_forward: bool,
    /// Browser Plane (#23): the public hostname this Agent binds to its routing
    /// token at the Edge (`CT_AGENT_HOSTNAME`), so an SNI-routed browser reaches
    /// this tunnel. `None` = no hostname bound.
    pub hostname: Option<String>,
    /// Firewall-fallback (#46): when true, if the configured edge port is blocked
    /// the Agent also tries the edge's unified `:443` front door (TLS-TCP with
    /// `ALPN=ct-edge`). `CT_AGENT_FALLBACK_443`; default `false`.
    pub fallback_443: bool,
    /// How many TLS-TCP fallback registrations to hold parked concurrently
    /// (#229): each is single-use and one-Client-at-a-time, so with a pool of
    /// 1 (the old, implicit behavior) a real browser page load's parallel
    /// per-origin connections drop every one but the first. `CT_AGENT_TCP_
    /// FALLBACK_POOL_SIZE`; default 6, matching the per-origin HTTP/1.1
    /// connection cap real browsers (Chrome, Firefox, Safari) actually use --
    /// a smaller pool trades away exactly the parallelism a real page load
    /// needs, which is the failure mode #229 was filed over. The Edge also
    /// tolerates brief bursts past the pool size with a short bounded wait
    /// (`wait_for_tcp_agent`) rather than failing outright. Only used in
    /// TLS-TCP fallback mode; QUIC already multiplexes and needs no pool.
    pub tcp_fallback_pool_size: usize,
}

/// Resolve a `host:port` (or `IP:port`) to a [`SocketAddr`] (#45). A literal
/// IP:port parses directly (no DNS); a hostname:port is resolved via the system
/// resolver — so Compose service names like `help-origin:443` / `edge:4433` work
/// on a shared Docker network instead of requiring churning literal IPs. Returns
/// the first resolved address.
fn resolve_addr(var: &str, s: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs()
        .map_err(|e| format!("invalid {var} '{s}': {e}"))?
        .next()
        .ok_or_else(|| format!("{var} '{s}' resolved to no address"))
}

impl AgentConfig {
    pub fn parse(edge: &str, origin: &str) -> Result<AgentConfig, String> {
        let edge = resolve_addr("CT_AGENT_EDGE", edge)?;
        let origin = resolve_addr("CT_AGENT_ORIGIN", origin)?;
        Ok(AgentConfig {
            edge,
            origin,
            origin_proto: OriginProto::default(),
            direct_advertise_ip: None,
            metrics_listen: None,
            browser_forward: false,
            hostname: None,
            fallback_443: false,
            tcp_fallback_pool_size: DEFAULT_TCP_FALLBACK_POOL_SIZE,
        })
    }

    /// Read from `CT_AGENT_EDGE` (default `127.0.0.1:4433`),
    /// `CT_AGENT_ORIGIN` (default `127.0.0.1:8080`), `CT_AGENT_ORIGIN_PROTO`
    /// (`tcp` | `udp`, default `tcp`) and `CT_AGENT_DIRECT_ADVERTISE` (an IP the
    /// Agent advertises for its direct-path listener; unset = P2P disabled).
    pub fn from_env() -> Result<AgentConfig, String> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Parse the config from a variable lookup. `from_env` passes
    /// `std::env::var`; splitting the parsing out behind a getter lets every
    /// branch (defaults, blank optionals, invalid values) be unit-tested without
    /// mutating the global process environment (which races across tests).
    pub(crate) fn from_env_with(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<AgentConfig, String> {
        let edge = get("CT_AGENT_EDGE").unwrap_or_else(|| "127.0.0.1:4433".to_string());
        let origin = get("CT_AGENT_ORIGIN").unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let proto = get("CT_AGENT_ORIGIN_PROTO").unwrap_or_else(|| "tcp".to_string());
        let mut cfg = Self::parse(&edge, &origin)?;
        cfg.origin_proto = OriginProto::parse(&proto)?;
        cfg.direct_advertise_ip = match get("CT_AGENT_DIRECT_ADVERTISE") {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<IpAddr>()
                    .map_err(|e| format!("invalid CT_AGENT_DIRECT_ADVERTISE '{s}': {e}"))?,
            ),
            _ => None,
        };
        cfg.metrics_listen = match get("CT_AGENT_METRICS_LISTEN") {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("invalid CT_AGENT_METRICS_LISTEN '{s}': {e}"))?,
            ),
            _ => None,
        };
        // Browser Plane (#23): CT_AGENT_MODE=browser -> raw TLS passthrough.
        cfg.browser_forward =
            get("CT_AGENT_MODE").map(|m| m.trim().eq_ignore_ascii_case("browser")) == Some(true);
        cfg.hostname = get("CT_AGENT_HOSTNAME")
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        // Firewall-fallback (#46): CT_AGENT_FALLBACK_443 truthy -> also try :443.
        cfg.fallback_443 = get("CT_AGENT_FALLBACK_443")
            .map(|v| {
                let v = v.trim();
                !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
            })
            == Some(true);
        cfg.tcp_fallback_pool_size = match get("CT_AGENT_TCP_FALLBACK_POOL_SIZE") {
            Some(s) if !s.trim().is_empty() => s
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid CT_AGENT_TCP_FALLBACK_POOL_SIZE '{s}': {e}"))
                .and_then(|n| {
                    if n == 0 {
                        Err("CT_AGENT_TCP_FALLBACK_POOL_SIZE must be at least 1".to_string())
                    } else {
                        Ok(n)
                    }
                })?,
            _ => DEFAULT_TCP_FALLBACK_POOL_SIZE,
        };
        Ok(cfg)
    }
}

/// See [`AgentConfig::tcp_fallback_pool_size`].
const DEFAULT_TCP_FALLBACK_POOL_SIZE: usize = 6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let c = AgentConfig::parse("10.0.0.2:4433", "127.0.0.1:8080").unwrap();
        assert_eq!(c.edge, "10.0.0.2:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Tcp, "defaults to TCP");
        assert_eq!(c.direct_advertise_ip, None, "P2P disabled by default");
    }

    #[test]
    fn resolves_hostname_and_literal_addresses() {
        // #45: a Compose service name (hostname:port) must resolve, not just a
        // literal IP:port — so help-origin:443 / edge:4433 work on a Docker network.
        // `localhost` is in the container's /etc/hosts, so it stands in for a
        // resolvable service name in the hermetic gate.
        let a = resolve_addr("X", "localhost:8443").expect("hostname resolves");
        assert_eq!(a.port(), 8443);
        assert!(a.ip().is_loopback(), "localhost -> loopback");

        // A literal IP:port parses directly (no DNS).
        assert_eq!(resolve_addr("X", "10.0.0.5:4433").unwrap(), "10.0.0.5:4433".parse().unwrap());

        // Missing port / unresolvable garbage -> a clear error (not a panic).
        assert!(resolve_addr("CT_AGENT_ORIGIN", "no-port-here").is_err());
    }

    #[test]
    fn fallback_443_reads_the_env_flag() {
        // #46: off by default; truthy values enable it; 0/false/empty keep it off.
        let base = |v: Option<&str>| {
            AgentConfig::from_env_with(|k| match k {
                "CT_AGENT_EDGE" => Some("127.0.0.1:4433".into()),
                "CT_AGENT_ORIGIN" => Some("127.0.0.1:8080".into()),
                "CT_AGENT_FALLBACK_443" => v.map(str::to_string),
                _ => None,
            })
            .unwrap()
            .fallback_443
        };
        assert!(!base(None), "default off");
        assert!(!base(Some("0")), "0 -> off");
        assert!(!base(Some("false")), "false -> off");
        assert!(!base(Some("")), "empty -> off");
        assert!(base(Some("1")), "1 -> on");
        assert!(base(Some("true")), "true -> on");
    }

    #[test]
    fn parses_direct_advertise_ip() {
        assert_eq!("10.5.0.4".parse::<IpAddr>().unwrap(), "10.5.0.4".parse::<IpAddr>().unwrap());
        // A parsed IP round-trips into an advertised SocketAddr with the port.
        let ip: IpAddr = "10.5.0.4".parse().unwrap();
        let sa = SocketAddr::new(ip, 40001);
        assert_eq!(sa.to_string(), "10.5.0.4:40001");
    }

    #[test]
    fn origin_proto_parses_tcp_udp_and_rejects_others() {
        assert_eq!(OriginProto::parse("tcp").unwrap(), OriginProto::Tcp);
        assert_eq!(OriginProto::parse("UDP").unwrap(), OriginProto::Udp);
        assert_eq!(OriginProto::parse(" udp ").unwrap(), OriginProto::Udp);
        assert!(OriginProto::parse("sctp").is_err());
    }

    #[test]
    fn rejects_bad_edge() {
        assert!(AgentConfig::parse("nope", "127.0.0.1:8080").is_err());
    }

    #[test]
    fn rejects_bad_origin() {
        assert!(AgentConfig::parse("10.0.0.2:4433", "nope").is_err());
    }

    // #20 TC1: cover config.rs::from_env via the from_env_with getter seam
    // (deterministic, no global-env mutation).
    fn get_from<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn from_env_defaults_when_all_unset() {
        let c = AgentConfig::from_env_with(|_| None).unwrap();
        assert_eq!(c.edge, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Tcp);
        assert_eq!(c.direct_advertise_ip, None);
        assert_eq!(c.metrics_listen, None);
    }

    #[test]
    fn from_env_reads_every_var() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_EDGE", "10.0.0.2:4433"),
            ("CT_AGENT_ORIGIN", "127.0.0.1:9000"),
            ("CT_AGENT_ORIGIN_PROTO", "udp"),
            ("CT_AGENT_DIRECT_ADVERTISE", "10.5.0.4"),
            ("CT_AGENT_METRICS_LISTEN", "0.0.0.0:9101"),
        ]))
        .unwrap();
        assert_eq!(c.edge, "10.0.0.2:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Udp);
        assert_eq!(c.direct_advertise_ip, Some("10.5.0.4".parse().unwrap()));
        assert_eq!(c.metrics_listen, Some("0.0.0.0:9101".parse().unwrap()));
    }

    #[test]
    fn from_env_blank_optionals_are_treated_as_unset() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_DIRECT_ADVERTISE", "   "),
            ("CT_AGENT_METRICS_LISTEN", ""),
        ]))
        .unwrap();
        assert_eq!(c.direct_advertise_ip, None);
        assert_eq!(c.metrics_listen, None);
    }

    #[test]
    fn from_env_rejects_each_invalid_value() {
        for (var, needle) in [
            ("CT_AGENT_EDGE", "CT_AGENT_EDGE"),
            ("CT_AGENT_ORIGIN", "CT_AGENT_ORIGIN"),
            ("CT_AGENT_ORIGIN_PROTO", "CT_AGENT_ORIGIN_PROTO"),
            ("CT_AGENT_DIRECT_ADVERTISE", "CT_AGENT_DIRECT_ADVERTISE"),
            ("CT_AGENT_METRICS_LISTEN", "CT_AGENT_METRICS_LISTEN"),
        ] {
            let err = AgentConfig::from_env_with(get_from(&[(var, "nope")]))
                .unwrap_err();
            assert!(err.contains(needle), "{var}: unexpected error {err}");
        }
    }

    #[test]
    fn from_env_browser_mode_enables_raw_forward() {
        // #23 BP2: CT_AGENT_MODE=browser -> raw TLS passthrough; default off.
        assert!(!AgentConfig::from_env_with(|_| None).unwrap().browser_forward);
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_MODE", "Browser")])).unwrap();
        assert!(c.browser_forward, "CT_AGENT_MODE=browser enables raw forward");
    }

    #[test]
    fn from_env_wrapper_reads_the_process_environment() {
        // Exercise the thin from_env() wrapper (delegates to from_env_with with
        // std::env::var). No test in this crate sets CT_AGENT_* and the hermetic
        // gate has none, so it resolves the documented defaults.
        let c = AgentConfig::from_env().expect("defaults parse");
        assert_eq!(c.origin_proto, OriginProto::Tcp);
    }
}

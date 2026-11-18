//! Operator overview of activated ct-agents (`/admin-ui/agents`): deterministic
//! derivation of "Herausforderungen" (challenges) per agent.
//!
//! Principle bound (ADR-0016, ADR-0002, ADR-0012, ADR-0025): the inputs here are ONLY
//! what the control plane / edge structurally already know -- liveness, registration
//! counts, the relay/direct availability flag, the metadata-only session history
//! (transport, timestamps, disconnect reason) and the agent-key policy counters keyed
//! by a token hash. No payload, no client IPs, no per-connection detail, and nothing the
//! agent would have to report anew. What the server cannot see (direct-path bytes,
//! agent-local errors such as auth / clock skew / credential problems) is deliberately
//! absent and is stated as such on the page.
//!
//! Pure functions only (no I/O, `now` is a parameter) so every rule is unit-testable.

use std::collections::BTreeMap;

use serde::Serialize;

/// A tunnel with at least this many sessions opened in the last 24 h is "flapping".
pub const FLAP_SESSIONS_24H: u64 = 6;
/// A tunnel that had sessions in the last 24 h but covered less than this share of
/// the window is flagged as low-uptime.
pub const LOW_UPTIME_24H_PCT: f64 = 95.0;

/// One derived challenge: a stable machine `code`, a German `label`, and the German
/// `evidence` (the concrete observed value that triggered the rule).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Challenge {
    pub code: &'static str,
    pub label: &'static str,
    pub evidence: String,
}

/// Live edge status of one tunnel (a subset of `POST /admin/tunnel-status/bulk`).
#[derive(Debug, Clone, Default)]
pub struct LiveInput {
    pub connected: bool,
    pub registrations: usize,
    pub fallback_parked: usize,
    pub direct: bool,
    pub last_seen: Option<i64>,
}

/// 24 h history summary of one tunnel (a subset of `POST /admin/tunnel-history/bulk`).
#[derive(Debug, Clone, Default)]
pub struct HistoryInput {
    pub uptime_h24: f64,
    pub session_count_24h: u64,
    pub disconnect_reasons_24h: BTreeMap<String, u64>,
}

/// Everything the rules look at. `live: None` means the edge status could not be read
/// at all (edge unreachable): then NO live-state challenge is derived -- unknown is
/// never reported as offline. Likewise `history: None` skips the history rules.
#[derive(Debug, Clone, Default)]
pub struct ChallengeInput {
    pub live: Option<LiveInput>,
    pub history: Option<HistoryInput>,
    /// Sum of the agent-key policy violation counters for this tunnel (cumulative
    /// since the edge's `observed_since`); `0` when none or unknown.
    pub key_violations: u64,
}

/// German "vor ..." rendering of an age in seconds.
pub fn fmt_age_de(secs: i64) -> String {
    let s = secs.max(0);
    if s < 60 {
        format!("{s} s")
    } else if s < 3_600 {
        format!("{} min", s / 60)
    } else if s < 86_400 {
        format!("{} h {} min", s / 3_600, (s % 3_600) / 60)
    } else {
        format!("{} d {} h", s / 86_400, (s % 86_400) / 3_600)
    }
}

/// Derive the challenge list for one agent at `now`. Order is stable (the order of the
/// rules below) so the output is deterministic.
pub fn derive_challenges(now: i64, input: &ChallengeInput) -> Vec<Challenge> {
    let mut out = Vec::new();
    if let Some(live) = &input.live {
        if !live.connected {
            let evidence = match live.last_seen {
                Some(t) => format!("zuletzt gesehen vor {}", fmt_age_de(now - t)),
                None => "seit dem Edge-Start nicht gesehen".to_string(),
            };
            out.push(Challenge { code: "offline", label: "Offline", evidence });
        } else {
            if live.registrations == 0 && live.fallback_parked > 0 {
                out.push(Challenge {
                    code: "tcp_fallback",
                    label: "Nur TCP-Fallback (kein QUIC)",
                    evidence: format!("{} Fallback-Verbindung(en) geparkt, 0 QUIC-Registrierungen", live.fallback_parked),
                });
            }
            if !live.direct {
                out.push(Challenge {
                    code: "relay_only",
                    label: "Kein Direktpfad angekündigt (nur Relay)",
                    evidence: "derzeit keine Direktpfad-Ankündigung am Edge".to_string(),
                });
            }
        }
    }
    if let Some(h) = &input.history {
        if h.session_count_24h >= FLAP_SESSIONS_24H {
            out.push(Challenge {
                code: "flapping",
                label: "Häufige Wiederverbindungen",
                evidence: format!("{} Sitzungen in 24 h (Schwelle {})", h.session_count_24h, FLAP_SESSIONS_24H),
            });
        }
        if let Some(n) = h.disconnect_reasons_24h.get("revoked").filter(|n| **n > 0) {
            out.push(Challenge { code: "revoked", label: "Widerrufen", evidence: format!("{n}x in 24 h getrennt (revoked)") });
        }
        if let Some(n) = h.disconnect_reasons_24h.get("idle-evicted").filter(|n| **n > 0) {
            out.push(Challenge {
                code: "idle_evicted",
                label: "Wegen Inaktivität getrennt",
                evidence: format!("{n}x in 24 h getrennt (idle-evicted)"),
            });
        }
        if h.session_count_24h > 0 && h.uptime_h24 < LOW_UPTIME_24H_PCT {
            out.push(Challenge {
                code: "low_uptime",
                label: "Geringe Verfügbarkeit",
                evidence: format!("{:.1} % in 24 h (Schwelle {:.0} %)", h.uptime_h24, LOW_UPTIME_24H_PCT),
            });
        }
    }
    if input.key_violations > 0 {
        out.push(Challenge {
            code: "key_policy",
            label: "Agent-Key-Policy-Verstöße",
            evidence: format!("{} Verstöße (kumulativ seit Edge-Beobachtungsbeginn)", input.key_violations),
        });
    }
    out
}

/// Count how often each challenge code occurs, most frequent first (ties by code).
pub fn top_challenges<'a>(all: impl IntoIterator<Item = &'a Challenge>) -> Vec<(&'static str, &'static str, usize)> {
    let mut m: BTreeMap<&'static str, (&'static str, usize)> = BTreeMap::new();
    for c in all {
        m.entry(c.code).or_insert((c.label, 0)).1 += 1;
    }
    let mut v: Vec<_> = m.into_iter().map(|(code, (label, n))| (code, label, n)).collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(b.0)));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn healthy_live() -> LiveInput {
        LiveInput { connected: true, registrations: 1, fallback_parked: 0, direct: true, last_seen: Some(NOW - 5) }
    }
    fn healthy_hist() -> HistoryInput {
        HistoryInput { uptime_h24: 100.0, session_count_24h: 1, disconnect_reasons_24h: BTreeMap::new() }
    }
    fn codes(c: &[Challenge]) -> Vec<&'static str> {
        c.iter().map(|c| c.code).collect()
    }

    #[test]
    fn healthy_agent_has_no_challenges() {
        let i = ChallengeInput { live: Some(healthy_live()), history: Some(healthy_hist()), key_violations: 0 };
        assert!(derive_challenges(NOW, &i).is_empty());
    }

    #[test]
    fn offline_reports_age_or_never_seen() {
        let mut l = healthy_live();
        l.connected = false;
        l.last_seen = Some(NOW - 7_500);
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l.clone()), ..Default::default() });
        assert_eq!(codes(&c), ["offline"]);
        assert_eq!(c[0].evidence, "zuletzt gesehen vor 2 h 5 min");
        l.last_seen = None;
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l), ..Default::default() });
        assert_eq!(c[0].evidence, "seit dem Edge-Start nicht gesehen");
    }

    #[test]
    fn unknown_live_state_is_never_reported_as_offline() {
        let c = derive_challenges(NOW, &ChallengeInput { live: None, history: Some(healthy_hist()), key_violations: 0 });
        assert!(c.is_empty());
    }

    #[test]
    fn online_only_rules_do_not_fire_while_offline() {
        let l = LiveInput { connected: false, registrations: 0, fallback_parked: 2, direct: false, last_seen: None };
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l), ..Default::default() });
        assert_eq!(codes(&c), ["offline"]);
    }

    #[test]
    fn tcp_fallback_only_when_no_quic_registration() {
        let mut l = healthy_live();
        l.registrations = 0;
        l.fallback_parked = 3;
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l.clone()), ..Default::default() });
        assert_eq!(codes(&c), ["tcp_fallback"]);
        l.registrations = 1;
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l), ..Default::default() });
        assert!(c.is_empty(), "QUIC present + parked fallback pool is normal");
    }

    #[test]
    fn relay_only_when_connected_without_direct() {
        let mut l = healthy_live();
        l.direct = false;
        let c = derive_challenges(NOW, &ChallengeInput { live: Some(l), ..Default::default() });
        assert_eq!(codes(&c), ["relay_only"]);
    }

    #[test]
    fn flapping_threshold_is_inclusive() {
        let mut h = healthy_hist();
        h.session_count_24h = FLAP_SESSIONS_24H - 1;
        assert!(derive_challenges(NOW, &ChallengeInput { history: Some(h.clone()), ..Default::default() }).is_empty());
        h.session_count_24h = FLAP_SESSIONS_24H;
        let c = derive_challenges(NOW, &ChallengeInput { history: Some(h), ..Default::default() });
        assert_eq!(codes(&c), ["flapping"]);
        assert!(c[0].evidence.starts_with("6 Sitzungen"));
    }

    #[test]
    fn revoked_and_idle_evicted_disconnects_are_flagged_edge_restart_is_not() {
        let mut h = healthy_hist();
        h.disconnect_reasons_24h.insert("revoked".into(), 1);
        h.disconnect_reasons_24h.insert("idle-evicted".into(), 2);
        h.disconnect_reasons_24h.insert("edge-restart".into(), 4);
        h.disconnect_reasons_24h.insert("registration-closed".into(), 3);
        let c = derive_challenges(NOW, &ChallengeInput { history: Some(h), ..Default::default() });
        assert_eq!(codes(&c), ["revoked", "idle_evicted"]);
        assert_eq!(c[1].evidence, "2x in 24 h getrennt (idle-evicted)");
    }

    #[test]
    fn low_uptime_needs_sessions_and_is_below_threshold() {
        let mut h = healthy_hist();
        h.uptime_h24 = 94.9;
        let c = derive_challenges(NOW, &ChallengeInput { history: Some(h.clone()), ..Default::default() });
        assert_eq!(codes(&c), ["low_uptime"]);
        h.uptime_h24 = 95.0;
        assert!(derive_challenges(NOW, &ChallengeInput { history: Some(h.clone()), ..Default::default() }).is_empty());
        h.uptime_h24 = 0.0;
        h.session_count_24h = 0;
        assert!(
            derive_challenges(NOW, &ChallengeInput { history: Some(h), ..Default::default() }).is_empty(),
            "no sessions at all is 'offline', not 'low uptime'"
        );
    }

    #[test]
    fn key_policy_violations_are_flagged() {
        let c = derive_challenges(NOW, &ChallengeInput { key_violations: 3, ..Default::default() });
        assert_eq!(codes(&c), ["key_policy"]);
    }

    #[test]
    fn top_challenges_sorts_by_count_then_code() {
        let mk = |code, label| Challenge { code, label, evidence: String::new() };
        let all = vec![mk("b", "B"), mk("a", "A"), mk("b", "B"), mk("c", "C")];
        assert_eq!(top_challenges(&all), vec![("b", "B", 2), ("a", "A", 1), ("c", "C", 1)]);
    }

    #[test]
    fn fmt_age_de_buckets() {
        assert_eq!(fmt_age_de(-5), "0 s");
        assert_eq!(fmt_age_de(59), "59 s");
        assert_eq!(fmt_age_de(125), "2 min");
        assert_eq!(fmt_age_de(90_000), "1 d 1 h");
    }
}

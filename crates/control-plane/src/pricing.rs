//! Admin-only pricing/plan preview (`GET /admin-ui/pricing-preview`): the real
//! €/Credit rates and plan prices scimbe designed must never be committed to this
//! repo (a `git push` is an upload to GitHub -- explicitly out of scope for this
//! confidential business data). This module is the *mechanism* -- fully public,
//! ordinary code -- that reads the real numbers at runtime from
//! `docker/deploy/.env.pricing`, a `.gitignore`d file (see the `.env.*` rule) that
//! only ever exists on scimbe's own server, created from his own local copy. See
//! `docker/deploy/.env.pricing.example` for every var name this reads, with
//! obviously-fake placeholder values.
//!
//! Every field is `Option`: a deployment with no `.env.pricing` file at all (every
//! CI run, every fresh clone) gets an all-`None` [`PricingConfig`], and the preview
//! page renders a plain "pricing not configured" message instead of erroring --
//! the same fail-soft posture as this crate's other optional config (e.g.
//! `oidc_issuer: Option<Arc<str>>`).

/// One paid plan tier's numbers -- absent entirely (not just `None` fields) when
/// its price var isn't set, so a partially-filled-in `.env.pricing` renders only
/// the tiers that are actually configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaidTier {
    pub name: &'static str,
    /// Monthly price in euro-cents, or `None` for Business (individually priced --
    /// see `note` instead).
    pub price_cents: Option<u32>,
    pub credits: Option<u32>,
    pub tunnels: Option<u32>,
    pub relay_free_gb: Option<u32>,
    /// Business-only: a free-text note shown instead of a fixed price.
    pub note: Option<String>,
}

/// The Free tier's numbers -- always zero-price by definition, so it carries no
/// `price_cents`/`credits` fields at all, just its (still-configurable) limits.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FreeTier {
    pub tunnels: Option<u32>,
    pub relay_free_gb: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PricingConfig {
    pub standard_ai_credits_per_1k_tokens: Option<u32>,
    pub standard_stt_credits_per_minute: Option<u32>,
    pub premium_ai_margin_percent: Option<u32>,
    pub relay_overage_credits_per_gb: Option<u32>,
    pub free: FreeTier,
    pub starter: Option<PaidTier>,
    pub medium: Option<PaidTier>,
    pub pro: Option<PaidTier>,
    pub business: Option<PaidTier>,
}

impl PricingConfig {
    /// Whether ANY pricing var is set at all -- the preview page's "not
    /// configured" gate.
    pub fn is_configured(&self) -> bool {
        self != &PricingConfig::default()
    }

    /// Read every `CT_PRICING_*` var from the process environment. Never fails --
    /// a missing or unparseable var is simply absent from the result (fail-soft,
    /// see this module's doc comment).
    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable version of [`Self::from_env`]: reads through an injected lookup
    /// closure instead of the real process environment, the same
    /// dependency-injection shape this crate's other `from_env`-style
    /// constructors already use (e.g. `PortalOidc::from_lookup`).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let u32_var = |k: &str| get(k).and_then(|v| v.trim().parse::<u32>().ok());
        let paid_tier = |prefix: &str, name: &'static str| -> Option<PaidTier> {
            let price_cents = u32_var(&format!("CT_PRICING_{prefix}_PRICE_CENTS"));
            let note = get(&format!("CT_PRICING_{prefix}_NOTE")).filter(|s| !s.trim().is_empty());
            // A tier "exists" once its price (or, for Business, its note) is set --
            // an operator filling in a tier does so by setting at least that much.
            if price_cents.is_none() && note.is_none() {
                return None;
            }
            Some(PaidTier {
                name,
                price_cents,
                credits: u32_var(&format!("CT_PRICING_{prefix}_CREDITS")),
                tunnels: u32_var(&format!("CT_PRICING_{prefix}_TUNNELS")),
                relay_free_gb: u32_var(&format!("CT_PRICING_{prefix}_RELAY_GB")),
                note,
            })
        };
        PricingConfig {
            standard_ai_credits_per_1k_tokens: u32_var("CT_PRICING_STANDARD_AI_CREDITS_PER_1K_TOKENS"),
            standard_stt_credits_per_minute: u32_var("CT_PRICING_STANDARD_STT_CREDITS_PER_MINUTE"),
            premium_ai_margin_percent: u32_var("CT_PRICING_PREMIUM_AI_MARGIN_PERCENT"),
            relay_overage_credits_per_gb: u32_var("CT_PRICING_RELAY_OVERAGE_CREDITS_PER_GB"),
            free: FreeTier {
                tunnels: u32_var("CT_PRICING_FREE_TUNNELS"),
                relay_free_gb: u32_var("CT_PRICING_FREE_RELAY_GB"),
            },
            starter: paid_tier("STARTER", "Starter"),
            medium: paid_tier("MEDIUM", "Medium"),
            pro: paid_tier("PRO", "Pro"),
            business: paid_tier("BUSINESS", "Business"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        move |k: &str| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn all_unset_is_the_default_unconfigured_state() {
        let cfg = PricingConfig::from_lookup(lookup(&[]));
        assert_eq!(cfg, PricingConfig::default());
        assert!(!cfg.is_configured());
    }

    #[test]
    fn partially_set_only_populates_what_was_actually_set() {
        let cfg = PricingConfig::from_lookup(lookup(&[
            ("CT_PRICING_STANDARD_AI_CREDITS_PER_1K_TOKENS", "1234"),
            ("CT_PRICING_STARTER_PRICE_CENTS", "1234"),
        ]));
        assert!(cfg.is_configured());
        assert_eq!(cfg.standard_ai_credits_per_1k_tokens, Some(1234));
        assert_eq!(cfg.standard_stt_credits_per_minute, None, "not set -> stays None");
        let starter = cfg.starter.expect("price was set -> tier exists");
        assert_eq!(starter.price_cents, Some(1234));
        assert_eq!(starter.credits, None, "not set -> stays None even though the tier exists");
        assert!(cfg.medium.is_none(), "an entirely unset tier is absent, not a half-empty struct");
    }

    #[test]
    fn business_tier_can_exist_via_note_alone_with_no_fixed_price() {
        let cfg = PricingConfig::from_lookup(lookup(&[(
            "CT_PRICING_BUSINESS_NOTE",
            "individual pricing, contact sales",
        )]));
        let business = cfg.business.expect("note alone is enough for Business to exist");
        assert_eq!(business.price_cents, None);
        assert_eq!(business.note.as_deref(), Some("individual pricing, contact sales"));
    }

    #[test]
    fn an_unparseable_number_is_treated_as_unset_not_an_error() {
        let cfg = PricingConfig::from_lookup(lookup(&[
            ("CT_PRICING_STANDARD_AI_CREDITS_PER_1K_TOKENS", "not-a-number"),
        ]));
        assert_eq!(cfg.standard_ai_credits_per_1k_tokens, None);
        assert!(!cfg.is_configured(), "a garbage value never crashes and never counts as configured");
    }
}

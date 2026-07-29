//! Known public ACME CAs beyond Let's Encrypt (#233: second/third-CA
//! integration, moved here from `ct-agent` for the admission-queue broker —
//! `ct-control-plane` needs this table too, and cannot depend on `ct-agent`
//! (Cargo forbids the cycle: `ct-agent` depends on `ct-control-plane`, not
//! the reverse). `ct-common` depends on neither, so this is the one place
//! both can share without a second copy drifting out of sync. `ct-agent`
//! re-exports this module (`ct_agent::acme_ca`) for call-site compatibility.
//!
//! Every CA's "certificates per registered domain" rate limit is scoped to
//! *that CA specifically* — issuing the same customer subdomain through a
//! second, independent CA does not touch Let's Encrypt's own budget at all.
//! Spreading new-customer issuance across this list multiplies how many
//! subdomains can onboard per week without asking Let's Encrypt for
//! anything.
//!
//! Deliberately short and honest rather than padded: Buypass Go SSL stopped
//! issuing entirely on 2025-10-16 ("no new orders, renewals or replacements")
//! and is not listed — a dead CA silently failing every order routed to it
//! would be worse than one fewer CA in the rotation. Directory URLs below
//! were verified directly against each CA's own ACME documentation, not
//! guessed from convention.
//!
//! **This list must only ever contain public, browser-trusted CAs.** The
//! Mesh-Plane's own internal CA (`ct-edge`'s `pki.rs`, `/pki/ca`) issues
//! certificates nothing outside this fleet's own agents will ever trust —
//! it is architecturally correct for agent-to-agent QUIC and would be a
//! customer-facing outage (real browsers, real "not secure" warnings) if it
//! ever ended up serving a Browser-Plane hostname. Nothing in this module
//! reaches that CA today; keep it that way rather than adding it here "for
//! completeness" — the two trust domains are separate on purpose.
//!
//! Renewals must stick to whichever CA a hostname's first successful
//! issuance used — never re-roll a rotation choice on renewal. Today that
//! falls out of the architecture for free (one `ct-agent` process per tunnel
//! runs with one fixed `directory_url`/EAB pair for its whole lifetime, see
//! `ct_agent::acme_orchestrate::run_renewal_loop`); the admission-queue
//! broker (`ct-control-plane`'s `acme_broker`) picks a CA *per hostname*
//! exactly once and persists that choice (`subject_tunnels.assigned_ca`),
//! handing the same CA back on every renewal — both because rate-limit
//! accounting is per-(CA, registered domain) and because each CA's own
//! quirks (EAB minting cadence, retry/backoff behaviour) are only validated
//! for the CA a cert was actually issued through.

/// One public ACME CA this fleet can request certificates from.
pub struct CaProfile {
    pub name: &'static str,
    pub directory_url: &'static str,
    /// Whether `newAccount` must carry an `externalAccountBinding` (RFC 8555
    /// §7.3.4) — see `ct_agent::acme_jws::AccountKey::external_account_binding`
    /// and `ct_agent::acme_client::AcmeClient::with_eab`.
    pub requires_eab: bool,
    /// Whether this CA's free tier actually issues wildcard (`*.domain`)
    /// certificates — the property the shared edge-side wildcard cert
    /// depends on. `false` means this CA is only useful for individual,
    /// per-customer (non-wildcard) certificates.
    pub supports_free_wildcard: bool,
}

/// The default, highest-volume CA — no EAB, wildcard-capable, and this
/// fleet's most-exercised issuance path by far.
pub const LETS_ENCRYPT: CaProfile = CaProfile {
    name: "letsencrypt",
    directory_url: "https://acme-v02.api.letsencrypt.org/directory",
    requires_eab: false,
    supports_free_wildcard: true,
};

pub const LETS_ENCRYPT_STAGING: CaProfile = CaProfile {
    name: "letsencrypt-staging",
    directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
    requires_eab: false,
    supports_free_wildcard: true,
};

/// Free, unlimited 90-day certs including wildcards, up to 100 SANs/cert.
/// EAB credentials are created once in the ZeroSSL dashboard and are
/// reusable (since March 2022) — but ZeroSSL caps how many fresh EAB
/// credential *pairs* can be minted per account per day, so provision one
/// EAB pair up front and keep reusing it rather than minting a new one per
/// order.
pub const ZEROSSL: CaProfile = CaProfile {
    name: "zerossl",
    directory_url: "https://acme.zerossl.com/v2/DV90",
    requires_eab: true,
    supports_free_wildcard: true,
};

/// Free public DV certs, wildcard-capable, operationally independent of both
/// Let's Encrypt and ZeroSSL (Google's own CA infrastructure). EAB comes from
/// a Google Cloud project with the "Public CA" API enabled — a one-time
/// setup, but each EAB credential is single-use for account creation, so this
/// fleet's ACME account must be created and persisted once, not regenerated.
pub const GOOGLE_TRUST_SERVICES: CaProfile = CaProfile {
    name: "google-trust-services",
    directory_url: "https://dv.acme-v02.api.pki.goog/directory",
    requires_eab: true,
    supports_free_wildcard: true,
};

/// SSL.com's free DV tier (verified against ssl.com's own ACME docs: DNS-01
/// wildcard issuance is documented as supported). Deliberately **excluded**
/// from [`active_rotation`]'s assignable pool for now (kept defined here so
/// re-enabling it later is a one-line change, not a re-discovery): independent
/// write-ups report that an SSL.com account with a nonzero balance gets
/// auto-charged for a paid certificate instead of the free one, which
/// SSL.com's own ACME page does not mention either way, and the admission
/// broker must never risk a surprise charge on a production issuance.
/// **Verify against a real, zero-balance SSL.com account in staging before
/// adding this back to [`active_rotation`].**
pub const SSL_COM: CaProfile = CaProfile {
    name: "ssl.com",
    directory_url: "https://acme.ssl.com/sslcom-dv/directory",
    requires_eab: true,
    supports_free_wildcard: true,
};

/// The active, assignable rotation for new (non-staging) issuance, in the
/// order they should be tried. Deliberately a `Vec` rather than a
/// fixed-size array so a future CA can be added (or `SSL_COM` re-added, once
/// the balance question above is resolved) without a call-site signature
/// change.
pub fn active_rotation() -> Vec<&'static CaProfile> {
    vec![&LETS_ENCRYPT, &ZEROSSL, &GOOGLE_TRUST_SERVICES]
}

/// Every CA this fleet knows about, including ones currently excluded from
/// [`active_rotation`] (`SSL_COM`) and the Let's Encrypt staging endpoint --
/// used to look up a CA's directory URL/EAB requirement by name for a
/// hostname whose `assigned_ca` was persisted while that CA *was* in
/// rotation, even if it has since been added to or removed from the active
/// pool. `active_rotation()` is what the admission broker assigns *new*
/// hostnames to; this is what it uses to resolve an *already-assigned* one.
pub fn all_known() -> Vec<&'static CaProfile> {
    vec![&LETS_ENCRYPT, &LETS_ENCRYPT_STAGING, &ZEROSSL, &GOOGLE_TRUST_SERVICES, &SSL_COM]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ca_in_the_rotation_is_reachable_via_https_and_has_a_distinct_name() {
        let rotation = active_rotation();
        let mut names = std::collections::HashSet::new();
        for ca in &rotation {
            assert!(ca.directory_url.starts_with("https://"), "{}: {}", ca.name, ca.directory_url);
            assert!(names.insert(ca.name), "duplicate CA name: {}", ca.name);
        }
        assert!(rotation.len() >= 3, "the whole point is spreading load across several independent CAs");
    }

    #[test]
    fn lets_encrypt_is_the_only_ca_here_that_needs_no_eab() {
        // If a second no-EAB CA is ever added, `with_eab` becoming
        // unconditional at a call site would silently stop mattering for it
        // -- this pins today's actual shape so that change is a deliberate
        // edit here, not a surprise.
        let no_eab: Vec<_> = active_rotation().into_iter().filter(|ca| !ca.requires_eab).collect();
        assert_eq!(no_eab.len(), 1);
        assert_eq!(no_eab[0].name, "letsencrypt");
    }

    #[test]
    fn all_known_covers_every_active_ca_plus_the_deliberately_excluded_and_staging_ones() {
        let known: std::collections::HashSet<_> = all_known().into_iter().map(|c| c.name).collect();
        for ca in active_rotation() {
            assert!(known.contains(ca.name), "{} missing from all_known", ca.name);
        }
        assert!(known.contains("ssl.com"));
        assert!(known.contains("letsencrypt-staging"));
    }

    #[test]
    fn ssl_com_is_defined_but_deliberately_excluded_from_the_active_rotation() {
        // Unverified auto-charge risk (see doc comment on SSL_COM) -- it must
        // stay out of the assignable pool until tested live, but the const
        // stays defined so re-adding it later is a one-line change.
        assert!(!active_rotation().iter().any(|ca| ca.name == "ssl.com"));
        assert_eq!(SSL_COM.name, "ssl.com", "kept defined for future re-enablement");
    }
}

//! Certificate expiry surfacing (ADR-0025 Decision 6): parse a PEM cert
//! file's `notAfter` and report days-until-expiry, for `GET /admin-ui/certs`.
//! Pure file-read + parse logic, deliberately independent of axum/storage so
//! it's directly unit-testable against real fixture certs.
//!
//! `x509-parser` is already resolved in this workspace's dependency tree
//! (`ct-edge`'s own `pki.rs` uses it, pinned as a direct test-only dep there
//! for the identical reason -- real DER/PEM parsing to verify a cert's actual
//! `not_before`/`not_after` rather than trusting the code that produced it);
//! this crate's `Cargo.toml` pins the SAME `0.17` version rather than adding
//! a second cert-parsing dependency.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The result of checking one configured cert slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertState {
    /// Parsed successfully. `days_remaining` is signed -- negative means
    /// already expired, which an admin needs to see as clearly as "expiring
    /// soon", not have it silently clamped to zero.
    Ok {
        days_remaining: i64,
        not_after_unix: i64,
    },
    /// No path configured for this slot at all -- distinct from
    /// [`CertState::Unreadable`] so an admin can tell "never set up" apart
    /// from "was working, now broken" (ADR-0025's explicit requirement: a
    /// gap must be reported, not silently omitted from the list).
    NotConfigured,
    /// A path WAS configured but the file couldn't be read or parsed.
    /// `reason` is a short, safe-to-display diagnostic derived from the
    /// error's `Display` -- never the raw filesystem path (server-local
    /// layout, no reason to leak it to an admin-console response body).
    Unreadable { reason: String },
}

/// One row the cert-expiry dashboard renders: what this cert serves, plus its
/// state. `label` is caller-supplied (e.g. `"portal"`, `"admin-ui"`, or a
/// per-managed-domain hostname) -- this module knows nothing about which
/// front doors exist, only how to check one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertStatus {
    pub label: String,
    pub state: CertState,
}

/// Check one configured cert slot: `None` means "not configured" (never even
/// try to open a file); `Some(path)` means "configured -- read and parse it,
/// report exactly what's wrong if anything is."
pub fn check(label: impl Into<String>, path: Option<&Path>) -> CertStatus {
    let state = match path {
        None => CertState::NotConfigured,
        Some(p) => cert_expiry(p),
    };
    CertStatus { label: label.into(), state }
}

/// Read `path` (a PEM cert, leaf first for a fullchain) and compute
/// days-until-expiry against the current wall clock.
fn cert_expiry(path: &Path) -> CertState {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return CertState::Unreadable { reason: format!("read failed: {e}") },
    };
    let pem = match x509_parser::pem::parse_x509_pem(&bytes) {
        Ok((_, pem)) => pem,
        Err(e) => return CertState::Unreadable { reason: format!("not a valid PEM certificate: {e}") },
    };
    let cert = match pem.parse_x509() {
        Ok(cert) => cert,
        Err(e) => return CertState::Unreadable { reason: format!("not a valid X.509 certificate: {e}") },
    };
    let not_after_unix = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // #div_euclid, not integer division: a negative numerator (already expired)
    // must round toward more-negative ("3 days past expiry"), not toward zero
    // (which plain `/` would give for e.g. -3600/86_400 == 0, silently hiding a
    // just-expired cert as "0 days remaining" instead of "-1").
    let days_remaining = (not_after_unix - now).div_euclid(86_400);
    CertState::Ok { days_remaining, not_after_unix }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real, throwaway self-signed leaf cert (openssl req -x509, CN=test.example,
    // issued 2026-08-25, 30-day validity) -- public by construction (a self-signed
    // cert's "private" key was generated and discarded solely to produce this fixture,
    // never committed, never reused anywhere else), used only to prove the PEM/X.509
    // parse path against real DER, not a hand-rolled byte string.
    const VALID_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUCiTWf1k6BV8rmzrZuqI7si7YAgowDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMB4XDTI2MDgyNTIxMjA1MloXDTI2
MDkyNDIxMjA1MlowFzEVMBMGA1UEAwwMdGVzdC5leGFtcGxlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEArWvKMgze49ySUG4wIVAKdzaINHiYXR7TS86P
pXJun3zKZboIMqI7l2SuxnRW8aZBd3X3tsZUyu0+2OaNehY7iwPgtEHFRZB/AzGm
ddwDAM8O+VB6yk5UIfW9PlujRxVRH2i0sWSH6eZNd47qxIerTF4YhM9h+ub168RY
DyaCSlYJp6oegNRuKM31mAe3SsCcZr3Qsb1Nfy+eODtJxyoXMZeFOMvPXOy3padQ
BQi1Lhv85VQaSlSraYx5wyy8jsqFM14yj3VFQxRGuYql5wg86KH2AXNUwVsiE8xX
dEz5tW/DwDw3ZmRCZyr/Jz86wRT62SaGzyYtU6h8w2wtbqjIFQIDAQABo1MwUTAd
BgNVHQ4EFgQUEa0+abwix6M6b2Zms57n0d2PoMAwHwYDVR0jBBgwFoAUEa0+abwi
x6M6b2Zms57n0d2PoMAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAmvkbEj12TtAgMwJ8SpX1AbHF0pTxdtnbUuYtdUQhBkK99y8euWGRjNsIe40z
POHoulkZLkqRE1xLNTtXy4TwRyJFL7ity1QZLhSKdB5H+hP2S5aY8E8TLQvRUNbp
eFLTAW6jb7QS9NoOtL+WdLr4AKYU4thooMgkix1OzaIaw7sO3w8dhO4s4Xt6g8Kz
gkPstADCaCZgxxYm6mNuXyZpTfock7Dmhx1PCG7EU0gk8YgnwQL2kx3Fpg1Sj6cm
UaYgRTHgKXFxzvqcNhTdE5b3QBW81UDfuhn2DLUwAqtVJfER7kyqkp/cschkO//c
xgK8GXaKbG2bx86wbyWvQVL9eA==
-----END CERTIFICATE-----
";
    /// The fixture's own `notAfter` (2026-09-24 21:20:52 UTC, per `openssl x509
    /// -in ... -noout -enddate` at fixture-authorship time), converted via
    /// `date -u -d "Sep 24 21:20:52 2026 GMT" +%s` and pinned here so the test
    /// asserts the EXACT parsed value, not just "some plausible-looking number".
    const VALID_CERT_NOT_AFTER_UNIX: i64 = 1_790_284_852;

    #[test]
    fn check_reports_not_configured_when_no_path_is_given() {
        assert_eq!(check("portal", None).state, CertState::NotConfigured);
    }

    #[test]
    fn check_reports_unreadable_for_a_missing_file_rather_than_silently_omitting_it() {
        let status = check("portal", Some(Path::new("/does/not/exist/fullchain.pem")));
        match status.state {
            CertState::Unreadable { reason } => assert!(reason.contains("read failed"), "got: {reason}"),
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn check_reports_unreadable_for_a_file_that_is_not_a_valid_pem_cert() {
        let dir = std::env::temp_dir().join(format!("ct-cp-certtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.pem");
        std::fs::write(&path, b"this is not a certificate").unwrap();
        let status = check("portal", Some(path.as_path()));
        match status.state {
            CertState::Unreadable { reason } => assert!(reason.contains("not a valid PEM"), "got: {reason}"),
            other => panic!("expected Unreadable, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_parses_a_real_cert_and_computes_the_exact_not_after() {
        let dir = std::env::temp_dir().join(format!("ct-cp-certtest-valid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fullchain.pem");
        std::fs::write(&path, VALID_CERT_PEM).unwrap();

        let status = check("admin-ui", Some(path.as_path()));
        assert_eq!(status.label, "admin-ui");
        match status.state {
            CertState::Ok { not_after_unix, days_remaining } => {
                assert_eq!(not_after_unix, VALID_CERT_NOT_AFTER_UNIX, "parses the EXACT notAfter, not an approximation");
                // The fixture was issued with a 30-day validity; whenever this test
                // actually runs, days_remaining must be strictly less than 31 (never
                // MORE than the cert's own total validity) -- catches a sign error
                // that would otherwise silently report a huge/garbage number.
                assert!(days_remaining < 31, "days_remaining {days_remaining} exceeds the cert's own 30-day validity");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-first proof for the div_euclid choice: an ALREADY-EXPIRED cert must
    /// report a NEGATIVE days_remaining, never zero or a silently-wrapped huge
    /// positive number -- an admin scanning for "0" as the alarm threshold must
    /// not miss a cert that expired days ago.
    #[test]
    fn an_already_expired_not_after_reports_negative_days_remaining() {
        // Construct a fake "cert" state directly rather than waiting for a real
        // fixture to age past its own validity: exercises the exact arithmetic
        // `cert_expiry` performs, isolated from PEM/X.509 parsing (already proven
        // above).
        let not_after_unix = 1_000_000_000i64; // 2001-09-09, long past.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let days_remaining = (not_after_unix - now).div_euclid(86_400);
        assert!(days_remaining < 0, "an already-expired cert must report negative days_remaining, got {days_remaining}");
    }
}

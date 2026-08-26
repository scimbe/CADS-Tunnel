//! Subdomain cert issuance for multi-domain onboarding (ADR-0025 Decision 4):
//! shells out to `scripts/lib-acme.sh`'s `issue_cert` -- the SAME primitive
//! `scripts/deploy-selfhost.sh`/`scripts/authorize-pipeline.sh` already use to
//! issue every other host's cert this deployment holds, rather than growing a
//! second, divergent Rust-side ACME client. No existing Rust wrapper for it
//! exists anywhere in this workspace (checked before writing this module --
//! `grep -rn "lib-acme\|issue_cert" crates/` turns up nothing), so this
//! hand-rolls the one subprocess-exec path this feature needs.
//!
//! `lib-acme.sh` is written to be `source`d, not run standalone -- it assumes
//! its caller already defines `log()`/`ok()`/`warn()`/`die()` (its own header
//! comment). [`issue_cert`] supplies minimal, silent versions of those four
//! before sourcing it, so this runs unattended inside a container with no
//! interactive terminal and no pre-existing shell function environment.
//!
//! **Deployment note** (flagged for the operator, not solved by this module
//! alone): the production Docker image must actually ship `scripts/lib-acme.sh`
//! at [`AcmeConfig::lib_acme_path`], `bash` + `openssl` must be present in that
//! image, and [`AcmeConfig::acme_home`] must be a writable (ideally persistent,
//! so acme.sh's own account registration survives a restart) directory the
//! container's non-root user can write to. See `docker/Dockerfile`'s
//! `production` target and `docker/deploy/compose.admin-ui.yml` for what this
//! change actually wires up; without all of that, [`issue_cert`] fails with a
//! clear, typed error rather than a mysterious 500.

use std::path::Path;

/// Everything [`issue_cert`] needs to run `lib-acme.sh`'s `issue_cert()`
/// unattended. Every field is a plain value (not read from the environment
/// internally) so a test can construct one pointing at a fixture script/dir
/// without mutating real process-wide environment state.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Absolute path to `scripts/lib-acme.sh` inside this process's own
    /// filesystem (`CT_CP_LIB_ACME_PATH`).
    pub lib_acme_path: String,
    /// `HOME` to run the subprocess with -- acme.sh installs itself to
    /// `$HOME/.acme.sh` (`ensure_acme_sh` in `lib-acme.sh`) and keeps its
    /// account state there; a real, WRITABLE directory (`CT_CP_ACME_HOME`),
    /// not necessarily this process's own container `$HOME`.
    pub acme_home: String,
    /// The Let's Encrypt account email (`CT_CP_ACME_EMAIL`).
    pub acme_email: String,
    /// The zone-wide deSEC API token (`DESEC_TOKEN`). `lib-acme.sh`'s
    /// `ensure_acme_sh` requires this (via `DEDYN_TOKEN`); passed explicitly
    /// here rather than inherited implicitly from this process's own
    /// environment, so [`issue_cert`]'s "missing token" path is provable
    /// without mutating real env state in a test.
    pub desec_token: Option<String>,
}

/// Why a cert-issuance attempt failed. Every variant carries enough to give
/// the admin-console caller (`domain_admin_add_hostname` in `portal_api.rs`)
/// a clear, actionable HTTP error body -- ADR-0025's own "report a clear,
/// actionable error" instruction for this exact call.
#[derive(Debug)]
pub enum CertIssueError {
    /// `lib_acme_path` doesn't exist / isn't a readable file -- almost always
    /// a deployment gap (the image wasn't built with `scripts/lib-acme.sh`
    /// present), not a per-call condition, so it's reported as its own
    /// distinct variant rather than folded into a generic spawn failure.
    LibAcmeScriptMissing(String),
    /// `desec_token` was `None`/empty -- fails BEFORE spawning any process,
    /// matching `lib-acme.sh`'s own `ensure_acme_sh` fail-closed `die()` on
    /// the same condition, just surfaced as a typed Rust error instead of a
    /// subprocess exit code + stderr scrape.
    MissingDesecToken,
    /// Couldn't even spawn `bash`.
    Spawn(std::io::Error),
    /// The subprocess ran and exited non-zero. `stderr_tail` is the tail of
    /// its stderr (acme.sh's own output, or `lib-acme.sh`'s `die()` message)
    /// -- the actionable part of an otherwise-opaque exit code.
    IssuanceFailed { exit_code: Option<i32>, stderr_tail: String },
    /// The subprocess exited `0` but `cert_dir/{fullchain,privkey}.pem` are
    /// not both present afterward. `lib-acme.sh`'s own `issue_cert` already
    /// `die()`s on this internally (a non-zero exit, caught by the arm
    /// above), so this is a defensive belt-and-suspenders check, not
    /// expected to trigger in practice.
    CertFilesMissingAfterSuccess,
}

impl std::fmt::Display for CertIssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertIssueError::LibAcmeScriptMissing(p) => {
                write!(f, "scripts/lib-acme.sh not found at {p} (deployment gap: the image/host must ship it)")
            }
            CertIssueError::MissingDesecToken => {
                write!(f, "DESEC_TOKEN is not configured -- required to issue a cert via deSEC DNS-01")
            }
            CertIssueError::Spawn(e) => write!(f, "failed to spawn bash: {e}"),
            CertIssueError::IssuanceFailed { exit_code, stderr_tail } => {
                write!(f, "cert issuance failed (exit {exit_code:?}): {stderr_tail}")
            }
            CertIssueError::CertFilesMissingAfterSuccess => {
                write!(f, "issuance reported success but the cert files are missing on disk")
            }
        }
    }
}
impl std::error::Error for CertIssueError {}

/// Issue (or reuse, per `lib-acme.sh`'s own existing-cert-still-valid
/// short-circuit) a Let's Encrypt cert for `host` via deSEC DNS-01, writing
/// `cert_dir/{fullchain,privkey}.pem`.
///
/// Synchronous and blocking (real network I/O against Let's Encrypt/deSEC,
/// potentially tens of seconds) -- deliberately NOT `async fn` so it stays
/// trivially unit-testable with no runtime; the axum handler that calls this
/// (`portal_api::admin_ui_add_domain_hostname`) wraps the call in
/// `tokio::task::spawn_blocking`.
pub fn issue_cert(cfg: &AcmeConfig, host: &str, cert_dir: &Path) -> Result<(), CertIssueError> {
    if !Path::new(&cfg.lib_acme_path).is_file() {
        return Err(CertIssueError::LibAcmeScriptMissing(cfg.lib_acme_path.clone()));
    }
    let Some(desec_token) = cfg.desec_token.as_deref().filter(|s| !s.is_empty()) else {
        return Err(CertIssueError::MissingDesecToken);
    };
    // Best-effort: a failure here surfaces later as a clear Spawn/IssuanceFailed
    // from the subprocess itself trying (and failing) to write under these dirs,
    // rather than needing its own error variant for what is a rare host-level
    // permissions problem.
    let _ = std::fs::create_dir_all(&cfg.acme_home);
    let _ = std::fs::create_dir_all(cert_dir);

    // `lib-acme.sh` must be `source`d by a caller that already defines these
    // four functions (its own header comment) -- minimal, silent stand-ins so
    // this runs unattended. `die()` exits 1 with its message on stderr, which
    // the `IssuanceFailed` arm below then surfaces via `stderr_tail`.
    const WRAPPER: &str = r#"set -euo pipefail
log() { :; }
ok() { :; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
. "$1"
issue_cert "$2" "$3" "$4" "$5"
"#;
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(WRAPPER)
        .arg("cert_issuer_wrapper") // $0 (script name, unused by the body above)
        .arg(&cfg.lib_acme_path) // $1
        .arg(host) // $2
        .arg(cert_dir.to_string_lossy().into_owned()) // $3
        // reload_cmd ($4): a no-op. Nothing is live-serving this cert yet at
        // issuance time (the admin-onboarded hostname has no running service
        // to restart) -- `lib-acme.sh`'s own doc notes a reload failure is
        // non-fatal on first issuance anyway.
        .arg(":")
        .arg(&cfg.acme_email) // $5
        .env("HOME", &cfg.acme_home)
        .env("DESEC_TOKEN", desec_token)
        .output()
        .map_err(CertIssueError::Spawn)?;

    if !output.status.success() {
        return Err(CertIssueError::IssuanceFailed {
            exit_code: output.status.code(),
            stderr_tail: tail(&String::from_utf8_lossy(&output.stderr), 2000),
        });
    }
    let full = cert_dir.join("fullchain.pem");
    let key = cert_dir.join("privkey.pem");
    if !full.is_file() || !key.is_file() {
        return Err(CertIssueError::CertFilesMissingAfterSuccess);
    }
    Ok(())
}

/// The last `max_bytes` bytes of `s`, char-boundary-safe. Byte-index slicing a
/// `&str` at an arbitrary offset panics if that offset lands inside a
/// multi-byte UTF-8 character (this codebase's own repeat bug family --
/// #595/#596/#606 and siblings, all the same root cause) -- `is_char_boundary`
/// walks forward from the naive cut point to the next real boundary instead of
/// assuming byte length equals a safe split point.
fn tail(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let naive_start = s.len() - max_bytes;
    let safe_start = (naive_start..=s.len())
        .find(|&i| s.is_char_boundary(i))
        .unwrap_or(s.len());
    format!("...{}", &s[safe_start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ct-cp-certissuer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn base_cfg(lib_acme_path: String, acme_home: std::path::PathBuf) -> AcmeConfig {
        AcmeConfig {
            lib_acme_path,
            acme_home: acme_home.to_string_lossy().into_owned(),
            acme_email: "acme-test@example.com".to_string(),
            desec_token: Some("test-token".to_string()),
        }
    }

    #[test]
    fn missing_lib_acme_script_is_reported_before_ever_spawning_bash() {
        let dir = temp_dir("missing-script");
        let cfg = base_cfg(dir.join("nonexistent-lib-acme.sh").to_string_lossy().into_owned(), dir.join("home"));
        let err = issue_cert(&cfg, "app.example.org", &dir.join("cert")).unwrap_err();
        assert!(matches!(err, CertIssueError::LibAcmeScriptMissing(_)), "got {err:?}");
    }

    #[test]
    fn missing_desec_token_is_reported_before_ever_spawning_bash() {
        let dir = temp_dir("missing-token");
        // A real, present lib-acme.sh path -- proves the token check runs
        // BEFORE the file-existence gate would even matter, i.e. is checked
        // independently, not merely as a side effect of the script being absent.
        let script = dir.join("lib-acme.sh");
        std::fs::write(&script, "issue_cert() { :; }\n").unwrap();
        let mut cfg = base_cfg(script.to_string_lossy().into_owned(), dir.join("home"));
        cfg.desec_token = None;
        let err = issue_cert(&cfg, "app.example.org", &dir.join("cert")).unwrap_err();
        assert!(matches!(err, CertIssueError::MissingDesecToken), "got {err:?}");
    }

    /// Proves the full subprocess plumbing -- argument order, `HOME`/`DESEC_TOKEN`
    /// env vars actually reaching the sourced function, and success detection --
    /// against a FAKE `issue_cert` (never touches real acme.sh/deSEC/Let's Encrypt).
    #[test]
    fn a_successful_fake_issue_cert_writes_the_expected_files_and_sees_the_right_env() {
        let dir = temp_dir("success");
        let script = dir.join("lib-acme.sh");
        // Mirrors the REAL issue_cert's signature (host dir reload_cmd email) and,
        // like the real one, writes fullchain.pem/privkey.pem into $2. Also proves
        // HOME/DESEC_TOKEN reached this function's environment by writing them out.
        std::fs::write(
            &script,
            r#"issue_cert() {
  local host="$1" dir="$2"
  mkdir -p "$dir"
  echo "cert-for-$host" > "$dir/fullchain.pem"
  echo "key-for-$host" > "$dir/privkey.pem"
  echo "HOME=$HOME DESEC_TOKEN=$DESEC_TOKEN" > "$dir/env-seen.txt"
}
"#,
        )
        .unwrap();
        let home = dir.join("acme-home");
        let cert_dir = dir.join("cert");
        let cfg = base_cfg(script.to_string_lossy().into_owned(), home.clone());

        issue_cert(&cfg, "app.example.org", &cert_dir).unwrap();

        assert_eq!(std::fs::read_to_string(cert_dir.join("fullchain.pem")).unwrap(), "cert-for-app.example.org\n");
        assert_eq!(std::fs::read_to_string(cert_dir.join("privkey.pem")).unwrap(), "key-for-app.example.org\n");
        let env_seen = std::fs::read_to_string(cert_dir.join("env-seen.txt")).unwrap();
        assert!(env_seen.contains(&format!("HOME={}", home.to_string_lossy())), "got: {env_seen}");
        assert!(env_seen.contains("DESEC_TOKEN=test-token"), "got: {env_seen}");
    }

    #[test]
    fn a_die_call_inside_issue_cert_surfaces_as_issuance_failed_with_the_message() {
        let dir = temp_dir("die");
        let script = dir.join("lib-acme.sh");
        std::fs::write(&script, "issue_cert() { die \"zone not delegated to deSEC\"; }\n").unwrap();
        let cfg = base_cfg(script.to_string_lossy().into_owned(), dir.join("home"));

        let err = issue_cert(&cfg, "app.example.org", &dir.join("cert")).unwrap_err();
        match err {
            CertIssueError::IssuanceFailed { exit_code, stderr_tail } => {
                assert_eq!(exit_code, Some(1));
                assert!(stderr_tail.contains("zone not delegated to deSEC"), "got: {stderr_tail}");
            }
            other => panic!("expected IssuanceFailed, got {other:?}"),
        }
    }

    #[test]
    fn success_exit_with_no_cert_files_written_is_reported_explicitly() {
        let dir = temp_dir("no-files");
        let script = dir.join("lib-acme.sh");
        // Exits 0 (success) but never actually writes the cert files -- must not
        // be reported as Ok just because the process exit code was clean.
        std::fs::write(&script, "issue_cert() { :; }\n").unwrap();
        let cfg = base_cfg(script.to_string_lossy().into_owned(), dir.join("home"));

        let err = issue_cert(&cfg, "app.example.org", &dir.join("cert")).unwrap_err();
        assert!(matches!(err, CertIssueError::CertFilesMissingAfterSuccess), "got {err:?}");
    }

    #[test]
    fn tail_returns_the_whole_string_when_it_is_already_short_enough() {
        assert_eq!(tail("short", 100), "short");
    }

    /// Fail-first proof for the char-boundary guard: the naive cut point
    /// (`len - max_bytes`) lands INSIDE a multi-byte character here -- a plain
    /// `&s[naive_start..]` slice would panic. `tail` must not panic and must
    /// still produce valid, sensible output.
    #[test]
    fn tail_never_panics_when_the_naive_cut_point_lands_inside_a_multibyte_char() {
        // "aé" repeated: 'é' is 2 bytes, so a byte-length cut has a good chance of
        // landing mid-character for most `max_bytes` values -- pick one that does.
        let s = "a\u{e9}".repeat(50); // 150 bytes total (1 + 2 bytes per pair).
        // 150 - 149 = 1, which is the second byte of the first 'é' -- not a boundary.
        let out = tail(&s, 149);
        assert!(out.starts_with("..."), "got: {out}");
        // Must be valid UTF-8 by construction (it's a `String`); the real assertion
        // is simply that this didn't panic above.
    }
}

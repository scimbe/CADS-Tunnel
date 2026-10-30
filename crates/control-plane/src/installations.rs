//! "Meine Installationen" (WP6): a customer's saved marketplace installations, bound to
//! their platform account.
//!
//! Each record mirrors the marketplace's rendered prompt (template + the customer's
//! prompt inputs + component digests + target). The record is defined locally on purpose:
//! this crate does not depend on the marketplace's manifest crate.
//!
//! * **Account binding.** The OIDC `sub` is resolved to the ledger [`AccountId`]
//!   ([`SqliteLedger::account_for_subject`]); every row carries that account and every
//!   query filters on it. A record of another account is indistinguishable from a
//!   missing one (`404`, never `403`), so ids cannot be enumerated.
//! * **No secrets (best effort).** `values` is customer input that gets stored, so credential-looking
//!   keys and values are refused with `422` ([`scan_for_secrets`]). The filter catches accidents (names such as `token`,
//!   `password`, `api_key`, `ssh_key`; JWTs, well-known key prefixes, PEM blocks, random
//!   key material); it cannot stop someone who disguises a secret, and says so in its 422.
//! * **Optimistic concurrency.** `PUT` needs `If-Match: <revision>`; each update archives
//!   the superseded state in `installation_revisions` (the last [`MAX_REVISIONS`]).
//! * **Soft delete.** `DELETE` sets `status = removed`; the newest [`KEEP_REMOVED`]
//!   removed records stay restorable, older ones are purged on the next write.
//!
//! * **Bounds.** At most [`MAX_INSTALLATIONS_PER_ACCOUNT`] (200) active installations per
//!   account (removed ones do not count), [`MAX_REVISIONS`] (50) superseded revisions per
//!   installation and [`KEEP_REMOVED`] (100) removed records per account; beyond that the
//!   oldest are hard-deleted on the next write so storage cannot grow without bound.
//! * **Formats.** `template_id`, `template_digest`, `values_digest`, `components[].sha256`
//!   and `target.agent_holder_pubkey` are exactly 64 lowercase hex characters.
//! * **Account deletion.** [`purge_subject`] hard-deletes everything of a subject's account
//!   (both tables); `/portal/account/delete` and the admin account delete call it.
//!
//! Auth, state and error conventions follow `/me/service-accounts` and `/me/topologies`
//! (portal session cookie or OIDC bearer, plain-text errors).
//!
//! * **Delegated access.** A gallery behind the login gate knows its visitor only by
//!   `ct_gate_session`, and a browser cannot call this API from a tunnel origin (no CORS, and
//!   [`csrf_guard`] refuses `same-site`). [`InstallationsDelegate`] lets exactly one configured
//!   origin call it server to server. It needs BOTH proofs: the delegate token (this is that
//!   origin, not any tunnel on the zone, all of which see the `Domain=`-scoped cookie) and the
//!   visitor's live gate session for that origin's host (this visitor is present, so a leaked
//!   token alone reads nothing). Off unless `CT_INSTALLATIONS_DELEGATE_SHA256` and
//!   `CT_INSTALLATIONS_DELEGATE_HOST` are both set.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::header::{CONTENT_DISPOSITION, ETAG, LOCATION};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ct_common::sync::MutexExt;
use ct_common::time::now_secs;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::accounts::AccountId;
use crate::oidc::OidcVerifierHandle;
use crate::storage::{open_tuned, sqlite_store_ctors, SqliteLedger};

/// Serialized size cap for `values`.
pub const MAX_VALUES_BYTES: usize = 32 * 1024;
/// Active (not removed) installations per account.
pub const MAX_INSTALLATIONS_PER_ACCOUNT: usize = 200;
pub const MAX_NAME_CHARS: usize = 120;
/// Superseded revisions kept per installation (oldest are pruned).
pub const MAX_REVISIONS: i64 = 50;
/// Removed (soft-deleted) records kept per account; older ones are purged on write.
pub const KEEP_REMOVED: i64 = 100;
const MAX_LIST_ITEMS: usize = 256;
const MAX_ID_CHARS: usize = 200;
const MAX_VALUES_DEPTH: usize = 16;
const DEFAULT_PAGE: usize = 25;
const MAX_PAGE: usize = 50;
/// 200 records of up to 32 KiB `values` plus envelope, with headroom (axum's default is 2 MiB).
const IMPORT_BODY_LIMIT: usize = 8 * 1024 * 1024;
const EXPORT_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Draft,
    Installed,
    Removed,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Draft => "draft",
            Status::Installed => "installed",
            Status::Removed => "removed",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Status::Draft),
            "installed" => Some(Status::Installed),
            "removed" => Some(Status::Removed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub os: String,
    #[serde(default)]
    pub device_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_holder_pubkey: Option<String>,
}

/// What a client may set. `id`, timestamps and `revision` are server-owned; unknown
/// fields (for example those of an exported record) are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallationInput {
    pub name: String,
    pub template_id: String,
    #[serde(default)]
    pub template_digest: String,
    #[serde(default = "empty_object")]
    pub values: Value,
    #[serde(default)]
    pub values_digest: String,
    #[serde(default)]
    pub components: Vec<Component>,
    #[serde(default)]
    pub manifest_ids: Vec<String>,
    pub target: Target,
    /// Defaults to `draft` on create and to the current status on update.
    #[serde(default)]
    pub status: Option<Status>,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Installation {
    pub id: String,
    pub name: String,
    pub template_id: String,
    pub template_digest: String,
    pub values: Value,
    pub values_digest: String,
    pub components: Vec<Component>,
    pub manifest_ids: Vec<String>,
    pub target: Target,
    pub status: Status,
    pub created_at: i64,
    pub updated_at: i64,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionEntry {
    pub revision: i64,
    pub saved_at: i64,
    pub installation: Installation,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn nfkc(text: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfkc()
        .normalize(text)
        .into_owned()
}

/// Lowercase word segments of a key: NFKC first (fullwidth and other lookalikes become
/// ASCII), then split on every non-alphanumeric character and on camelCase boundaries
/// (`apiKey` and `APIKey` both give `api`, `key`).
fn key_segments(key: &str) -> Vec<String> {
    let chars: Vec<char> = nfkc(key).chars().collect();
    let mut segments: Vec<String> = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                segments.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some(&prev) = i.checked_sub(1).and_then(|j| chars.get(j)) {
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let boundary = c.is_uppercase()
                && prev.is_alphanumeric()
                && (prev.is_lowercase()
                    || prev.is_numeric()
                    || (prev.is_uppercase() && next_lower));
            if boundary && !cur.is_empty() {
                segments.push(std::mem::take(&mut cur));
            }
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        segments.push(cur);
    }
    segments
}

/// Is `key` a name that holds a secret? Best effort: after normalisation, the key must not
/// contain `token`, `secret`, `password`, `passwd`, `credential`, `bearer`, `apikey`,
/// `privatekey`, `accesskey`, `sshkey`, `signingkey` or `authkey` (separators and case
/// ignored), have a segment `pwd`, `auth` or `authorization`, or end in a segment `key`
/// (`ssh_key`, `sshKey`, `key`). Words that merely end in the letters (`monkey`, `hotkey`,
/// `keyboard_layout`) pass.
fn secret_like_key(key: &str) -> bool {
    const CONTAINS: [&str; 11] = [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "bearer",
        "apikey",
        "privatekey",
        "accesskey",
        "sshkey",
        "signingkey",
    ];
    let segments = key_segments(key);
    let compact: String = segments.concat();
    CONTAINS.iter().any(|w| compact.contains(w))
        || compact.contains("authkey")
        || segments
            .iter()
            .any(|s| matches!(s.as_str(), "pwd" | "auth" | "authorization"))
        || segments.last().is_some_and(|s| s == "key")
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut n = 0f64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0f64) += 1.0;
        n += 1.0;
    }
    counts
        .values()
        .map(|c| {
            let p = c / n;
            -p * p.log2()
        })
        .sum()
}

/// A 32+ character token of the base64/hex alphabet that mixes upper case, lower case and
/// digits and has more than 4.0 bits of Shannon entropy per character: random key material.
/// Hex digests (at most 4.0 bits), UUIDs, paths and prose do not qualify.
fn high_entropy_token(w: &str) -> bool {
    w.chars().count() >= 32
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'))
        && w.chars().any(|c| c.is_ascii_uppercase())
        && w.chars().any(|c| c.is_ascii_lowercase())
        && w.chars().any(|c| c.is_ascii_digit())
        && shannon_entropy(w) > 4.0
}

/// `eyJ...` with three base64url segments (a JWT).
fn jwt_shaped(w: &str) -> bool {
    let parts: Vec<&str> = w.split('.').collect();
    let b64url = |p: &str| {
        p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    };
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts[0].len() >= 4
        && parts[1].len() >= 4
        && parts.iter().all(|p| b64url(p))
}

/// Does `text` look like a credential? Best effort, aimed at accidents, not at someone who
/// disguises a secret on purpose: PEM blocks; words of 10+ characters starting `sk-`,
/// `ghp_` (and `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), `xox`, `AKIA`, `AIza`,
/// `glpat-`; JWT-shaped words (`eyJ.x.y`); `Bearer <8+ chars>`; and 32+ character
/// high-entropy base64/hex tokens. Short words (`"sk-SK"`, `"xoxo"`) pass.
fn credential_like_text(text: &str) -> bool {
    let text = nfkc(text);
    if text.contains("-----BEGIN") {
        return true;
    }
    let words: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '=' | ':'))
        .collect();
    const PREFIXES: [&str; 11] = [
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "xox",
        "AKIA",
        "AIza",
        "glpat-",
    ];
    if words.iter().any(|w| {
        (w.chars().count() >= 10 && PREFIXES.iter().any(|p| w.starts_with(p))) || jwt_shaped(w)
    }) {
        return true;
    }
    let spaced: Vec<&str> = text.split_whitespace().collect();
    if spaced
        .windows(2)
        .any(|w| w[0].eq_ignore_ascii_case("bearer") && w[1].chars().count() >= 8)
    {
        return true;
    }
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .any(high_entropy_token)
}

fn clip(s: &str) -> String {
    let c: String = s.chars().take(64).collect();
    if c.len() < s.len() {
        format!("{c}...")
    } else {
        c
    }
}

/// Walk `v` (objects, arrays, strings) and refuse secret-looking keys and credential-looking
/// string values. Error text names the JSON path, never the offending value.
fn scan_for_secrets(v: &Value, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_VALUES_DEPTH {
        return Err(format!(
            "{path}: nested deeper than {MAX_VALUES_DEPTH} levels"
        ));
    }
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let child_path = format!("{path}.{}", clip(k));
                if secret_like_key(k) {
                    return Err(format!(
                        "{child_path}: key looks like a secret (token, secret, password, credential, auth, bearer, api/private/ssh key ...); \
                         secrets are never stored, enter them on the target device instead. \
                         This filter is best-effort: do not put secrets in any field"
                    ));
                }
                scan_for_secrets(child, &child_path, depth + 1)?;
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                scan_for_secrets(child, &format!("{path}[{i}]"), depth + 1)?;
            }
        }
        Value::String(s) if credential_like_text(s) => {
            return Err(format!(
                "{path}: value looks like a credential (API key prefix, JWT, Bearer header, PEM block or random key material); \
                 secrets are never stored, enter them on the target device instead. \
                 This filter is best-effort: do not put secrets in any field"
            ));
        }
        _ => {}
    }
    Ok(())
}

fn charset_ok(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '/' | '@' | '+'))
}

fn check_label(what: &str, s: &str, max: usize, required: bool) -> Result<(), String> {
    if required && s.trim().is_empty() {
        return Err(format!("{what} is required"));
    }
    if s.chars().count() > max {
        return Err(format!("{what} must be at most {max} characters"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{what} must not contain control characters"));
    }
    if credential_like_text(s) {
        return Err(format!(
            "{what} looks like a credential; secrets are never stored"
        ));
    }
    Ok(())
}

/// Exactly 64 lowercase hex characters (32 bytes), as manifest-core emits them.
fn check_hex64(what: &str, s: &str) -> Result<(), String> {
    if s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(format!(
            "{what} must be exactly 64 lowercase hex characters"
        ))
    }
}

fn check_ident(what: &str, s: &str, required: bool) -> Result<(), String> {
    if required && s.is_empty() {
        return Err(format!("{what} is required"));
    }
    if s.len() > MAX_ID_CHARS || !charset_ok(s) {
        return Err(format!(
            "{what} must be at most {MAX_ID_CHARS} characters of [A-Za-z0-9:._-/@+]"
        ));
    }
    Ok(())
}

/// Validate a client-supplied record. `Err` is the `422` message.
pub fn validate(input: &InstallationInput) -> Result<(), String> {
    check_label("name", &input.name, MAX_NAME_CHARS, true)?;
    check_hex64("template_id", &input.template_id)?;
    check_hex64("template_digest", &input.template_digest)?;
    check_hex64("values_digest", &input.values_digest)?;
    if !input.values.is_object() {
        return Err("values must be a JSON object".to_string());
    }
    let size = serde_json::to_vec(&input.values).map_or(usize::MAX, |b| b.len());
    if size > MAX_VALUES_BYTES {
        return Err(format!(
            "values must be at most {} KiB when serialized",
            MAX_VALUES_BYTES / 1024
        ));
    }
    scan_for_secrets(&input.values, "values", 0)?;
    if input.components.len() > MAX_LIST_ITEMS {
        return Err(format!("components: at most {MAX_LIST_ITEMS} entries"));
    }
    for (i, c) in input.components.iter().enumerate() {
        check_label(
            &format!("components[{i}].name"),
            &c.name,
            MAX_NAME_CHARS,
            true,
        )?;
        check_hex64(&format!("components[{i}].sha256"), &c.sha256)?;
    }
    if input.manifest_ids.len() > MAX_LIST_ITEMS {
        return Err(format!("manifest_ids: at most {MAX_LIST_ITEMS} entries"));
    }
    for (i, m) in input.manifest_ids.iter().enumerate() {
        check_ident(&format!("manifest_ids[{i}]"), m, true)?;
    }
    check_label("target.os", &input.target.os, 32, true)?;
    check_label(
        "target.device_label",
        &input.target.device_label,
        MAX_NAME_CHARS,
        false,
    )?;
    if let Some(k) = &input.target.agent_holder_pubkey {
        check_hex64("target.agent_holder_pubkey", k)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

pub struct SqliteInstallationStore {
    conn: Mutex<Connection>,
}

sqlite_store_ctors!(SqliteInstallationStore);

const COLS: &str = "id, name, template_id, template_digest, values_json, values_digest, \
                    components_json, manifest_ids_json, target_json, status, created_at, updated_at, revision";

#[derive(Debug, PartialEq)]
pub enum CreateOutcome {
    Created(Box<Installation>),
    /// The account already has [`MAX_INSTALLATIONS_PER_ACCOUNT`] active installations.
    LimitReached,
}

#[derive(Debug, PartialEq)]
pub enum UpdateOutcome {
    Updated(Box<Installation>),
    NotFound,
    /// `If-Match` named another revision; carries the current one.
    Conflict(i64),
    /// Reviving a removed record would exceed [`MAX_INSTALLATIONS_PER_ACCOUNT`].
    LimitReached,
}

#[derive(Debug, PartialEq)]
pub enum DeleteOutcome {
    Removed,
    NotFound,
    Conflict(i64),
}

fn json_col<T: serde::de::DeserializeOwned>(
    r: &rusqlite::Row<'_>,
    idx: usize,
) -> rusqlite::Result<T> {
    let s: String = r.get(idx)?;
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn row_to_installation(r: &rusqlite::Row<'_>) -> rusqlite::Result<Installation> {
    let status: String = r.get(9)?;
    Ok(Installation {
        id: r.get(0)?,
        name: r.get(1)?,
        template_id: r.get(2)?,
        template_digest: r.get(3)?,
        values: json_col(r, 4)?,
        values_digest: r.get(5)?,
        components: json_col(r, 6)?,
        manifest_ids: json_col(r, 7)?,
        target: json_col(r, 8)?,
        status: Status::parse(&status).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                9,
                rusqlite::types::Type::Text,
                "unknown installation status".into(),
            )
        })?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
        revision: r.get(12)?,
    })
}

fn to_json<T: Serialize>(v: &T) -> rusqlite::Result<String> {
    serde_json::to_string(v).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn fetch(
    conn: &Connection,
    account: &AccountId,
    id: &str,
) -> rusqlite::Result<Option<Installation>> {
    conn.query_row(
        &format!("SELECT {COLS} FROM installations WHERE account = ?1 AND id = ?2"),
        params![&account.0[..], id],
        row_to_installation,
    )
    .optional()
}

fn active_count(conn: &Connection, account: &AccountId) -> rusqlite::Result<usize> {
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM installations WHERE account = ?1 AND status <> 'removed'",
        params![&account.0[..]],
        |r| r.get(0),
    )?;
    Ok(n as usize)
}

fn insert_row(conn: &Connection, account: &AccountId, rec: &Installation) -> rusqlite::Result<()> {
    conn.execute(
        &format!("INSERT INTO installations (account, {COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"),
        params![
            &account.0[..],
            rec.id,
            rec.name,
            rec.template_id,
            rec.template_digest,
            to_json(&rec.values)?,
            rec.values_digest,
            to_json(&rec.components)?,
            to_json(&rec.manifest_ids)?,
            to_json(&rec.target)?,
            rec.status.as_str(),
            rec.created_at,
            rec.updated_at,
            rec.revision,
        ],
    )?;
    Ok(())
}

/// Keep only the newest [`KEEP_REMOVED`] removed records of `account` (and drop their history).
fn purge_old_removed(conn: &Connection, account: &AccountId) -> rusqlite::Result<()> {
    let doomed = "SELECT id FROM installations WHERE account = ?1 AND status = 'removed' \
                  ORDER BY updated_at DESC, rowid DESC LIMIT -1 OFFSET ?2";
    conn.execute(
        &format!("DELETE FROM installation_revisions WHERE account = ?1 AND id IN ({doomed})"),
        params![&account.0[..], KEEP_REMOVED],
    )?;
    conn.execute(
        &format!("DELETE FROM installations WHERE account = ?1 AND id IN ({doomed})"),
        params![&account.0[..], KEEP_REMOVED],
    )?;
    Ok(())
}

fn archive(
    conn: &Connection,
    account: &AccountId,
    cur: &Installation,
    now: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO installation_revisions (account, id, revision, saved_at, snapshot_json) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&account.0[..], cur.id, cur.revision, now, to_json(cur)?],
    )?;
    conn.execute(
        "DELETE FROM installation_revisions WHERE account = ?1 AND id = ?2 AND revision <= ?3",
        params![&account.0[..], cur.id, cur.revision - MAX_REVISIONS],
    )?;
    Ok(())
}

fn materialize(input: &InstallationInput, id: String, now: i64, status: Status) -> Installation {
    Installation {
        id,
        name: input.name.trim().to_string(),
        template_id: input.template_id.clone(),
        template_digest: input.template_digest.clone(),
        values: input.values.clone(),
        values_digest: input.values_digest.clone(),
        components: input.components.clone(),
        manifest_ids: input.manifest_ids.clone(),
        target: input.target.clone(),
        status,
        created_at: now,
        updated_at: now,
        revision: 1,
    }
}

/// Random RFC 4122 version-4 UUID.
fn new_uuid() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = ct_common::hex::encode(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

impl SqliteInstallationStore {
    /// Additive: two new tables, no change to any existing one.
    fn from_connection(conn: Connection) -> rusqlite::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS installations (
                 id                TEXT PRIMARY KEY,
                 account           BLOB NOT NULL,
                 name              TEXT NOT NULL,
                 template_id       TEXT NOT NULL,
                 template_digest   TEXT NOT NULL,
                 values_json       TEXT NOT NULL,
                 values_digest     TEXT NOT NULL,
                 components_json   TEXT NOT NULL,
                 manifest_ids_json TEXT NOT NULL,
                 target_json       TEXT NOT NULL,
                 status            TEXT NOT NULL,
                 created_at        INTEGER NOT NULL,
                 updated_at        INTEGER NOT NULL,
                 revision          INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_installations_account
                 ON installations (account, status, updated_at);
             CREATE TABLE IF NOT EXISTS installation_revisions (
                 account       BLOB NOT NULL,
                 id            TEXT NOT NULL,
                 revision      INTEGER NOT NULL,
                 saved_at      INTEGER NOT NULL,
                 snapshot_json TEXT NOT NULL,
                 PRIMARY KEY (id, revision)
             );
             CREATE INDEX IF NOT EXISTS idx_installation_revisions_account
                 ON installation_revisions (account, id);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Test hook: make every later purge fail, to prove callers do not claim success.
    #[cfg(test)]
    pub(crate) fn break_for_test(&self) {
        self.conn
            .lock_safe()
            .execute_batch("DROP TABLE installation_revisions")
            .unwrap();
    }

    /// Insert a new installation (count check and insert under one lock and transaction).
    pub fn create(
        &self,
        account: &AccountId,
        input: &InstallationInput,
        now: i64,
    ) -> rusqlite::Result<CreateOutcome> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if active_count(&tx, account)? >= MAX_INSTALLATIONS_PER_ACCOUNT {
            return Ok(CreateOutcome::LimitReached);
        }
        let rec = materialize(
            input,
            new_uuid(),
            now,
            input.status.unwrap_or(Status::Draft),
        );
        insert_row(&tx, account, &rec)?;
        purge_old_removed(&tx, account)?;
        tx.commit()?;
        Ok(CreateOutcome::Created(Box::new(rec)))
    }

    pub fn get(&self, account: &AccountId, id: &str) -> rusqlite::Result<Option<Installation>> {
        fetch(&self.conn.lock_safe(), account, id)
    }

    /// One page of `account`'s installations, newest first, plus the total matching.
    /// `status = None` lists every status except `removed`.
    pub fn list(
        &self,
        account: &AccountId,
        status: Option<Status>,
        limit: usize,
        offset: usize,
    ) -> rusqlite::Result<(Vec<Installation>, usize)> {
        let conn = self.conn.lock_safe();
        let filter = match status {
            Some(_) => "status = ?2",
            None => "status <> 'removed' AND ?2 IS NULL",
        };
        let st = status.map(Status::as_str);
        let total: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM installations WHERE account = ?1 AND {filter}"),
            params![&account.0[..], st],
            |r| r.get(0),
        )?;
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLS} FROM installations WHERE account = ?1 AND {filter} \
             ORDER BY updated_at DESC, rowid DESC LIMIT ?3 OFFSET ?4"
        ))?;
        let rows = stmt.query_map(
            params![&account.0[..], st, limit as i64, offset as i64],
            row_to_installation,
        )?;
        Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total as usize))
    }

    /// Replace the mutable fields if `expected_revision` is still current; the superseded
    /// state goes to the history table in the same transaction.
    pub fn update(
        &self,
        account: &AccountId,
        id: &str,
        expected_revision: i64,
        input: &InstallationInput,
        now: i64,
    ) -> rusqlite::Result<UpdateOutcome> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(cur) = fetch(&tx, account, id)? else {
            return Ok(UpdateOutcome::NotFound);
        };
        if cur.revision != expected_revision {
            return Ok(UpdateOutcome::Conflict(cur.revision));
        }
        // Reviving a removed record must fit under the active cap.
        let next_status = input.status.unwrap_or(cur.status);
        if cur.status == Status::Removed
            && next_status != Status::Removed
            && active_count(&tx, account)? >= MAX_INSTALLATIONS_PER_ACCOUNT
        {
            return Ok(UpdateOutcome::LimitReached);
        }
        archive(&tx, account, &cur, now)?;
        let mut next = materialize(input, cur.id.clone(), now, next_status);
        next.created_at = cur.created_at;
        next.revision = cur.revision + 1;
        tx.execute(
            "UPDATE installations SET name = ?3, template_id = ?4, template_digest = ?5, values_json = ?6, \
             values_digest = ?7, components_json = ?8, manifest_ids_json = ?9, target_json = ?10, status = ?11, \
             updated_at = ?12, revision = ?13 WHERE account = ?1 AND id = ?2",
            params![
                &account.0[..],
                next.id,
                next.name,
                next.template_id,
                next.template_digest,
                to_json(&next.values)?,
                next.values_digest,
                to_json(&next.components)?,
                to_json(&next.manifest_ids)?,
                to_json(&next.target)?,
                next.status.as_str(),
                next.updated_at,
                next.revision,
            ],
        )?;
        purge_old_removed(&tx, account)?;
        tx.commit()?;
        Ok(UpdateOutcome::Updated(Box::new(next)))
    }

    /// Soft delete: `status = removed`, revision bumped, previous state archived. Removing an
    /// already removed record is a no-op success. `expected_revision` is checked when given.
    pub fn soft_delete(
        &self,
        account: &AccountId,
        id: &str,
        expected_revision: Option<i64>,
        now: i64,
    ) -> rusqlite::Result<DeleteOutcome> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(cur) = fetch(&tx, account, id)? else {
            return Ok(DeleteOutcome::NotFound);
        };
        if expected_revision.is_some_and(|r| r != cur.revision) {
            return Ok(DeleteOutcome::Conflict(cur.revision));
        }
        if cur.status != Status::Removed {
            archive(&tx, account, &cur, now)?;
            tx.execute(
                "UPDATE installations SET status = 'removed', updated_at = ?3, revision = ?4 WHERE account = ?1 AND id = ?2",
                params![&account.0[..], cur.id, now, cur.revision + 1],
            )?;
            purge_old_removed(&tx, account)?;
        }
        tx.commit()?;
        Ok(DeleteOutcome::Removed)
    }

    /// Superseded revisions of an owned installation, newest first. `None` if not owned.
    pub fn revisions(
        &self,
        account: &AccountId,
        id: &str,
    ) -> rusqlite::Result<Option<Vec<RevisionEntry>>> {
        let conn = self.conn.lock_safe();
        if fetch(&conn, account, id)?.is_none() {
            return Ok(None);
        }
        let mut stmt = conn.prepare(
            "SELECT revision, saved_at, snapshot_json FROM installation_revisions \
             WHERE account = ?1 AND id = ?2 ORDER BY revision DESC",
        )?;
        let rows = stmt.query_map(params![&account.0[..], id], |r| {
            Ok(RevisionEntry {
                revision: r.get(0)?,
                saved_at: r.get(1)?,
                installation: json_col(r, 2)?,
            })
        })?;
        Ok(Some(rows.collect::<rusqlite::Result<Vec<_>>>()?))
    }

    /// Copy an owned installation as a fresh `draft`.
    pub fn duplicate(
        &self,
        account: &AccountId,
        id: &str,
        name: Option<&str>,
        now: i64,
    ) -> rusqlite::Result<Option<CreateOutcome>> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(src) = fetch(&tx, account, id)? else {
            return Ok(None);
        };
        if active_count(&tx, account)? >= MAX_INSTALLATIONS_PER_ACCOUNT {
            return Ok(Some(CreateOutcome::LimitReached));
        }
        let name = name.map(str::to_string).unwrap_or_else(|| {
            let suffix = " (copy)";
            let base: String = src
                .name
                .chars()
                .take(MAX_NAME_CHARS - suffix.len())
                .collect();
            format!("{base}{suffix}")
        });
        let rec = Installation {
            id: new_uuid(),
            name,
            status: Status::Draft,
            created_at: now,
            updated_at: now,
            revision: 1,
            ..src
        };
        insert_row(&tx, account, &rec)?;
        purge_old_removed(&tx, account)?;
        tx.commit()?;
        Ok(Some(CreateOutcome::Created(Box::new(rec))))
    }

    /// Hard-delete every installation and all revision history of `account` (account
    /// deletion). Returns the number of installations removed.
    pub fn delete_all_for_account(&self, account: &AccountId) -> rusqlite::Result<usize> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM installation_revisions WHERE account = ?1",
            params![&account.0[..]],
        )?;
        let n = tx.execute(
            "DELETE FROM installations WHERE account = ?1",
            params![&account.0[..]],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// Every non-removed installation of `account`, oldest first.
    pub fn export_all(&self, account: &AccountId) -> rusqlite::Result<Vec<Installation>> {
        let conn = self.conn.lock_safe();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLS} FROM installations WHERE account = ?1 AND status <> 'removed' ORDER BY created_at ASC, rowid ASC"
        ))?;
        let rows = stmt.query_map(params![&account.0[..]], row_to_installation)?;
        rows.collect()
    }

    /// All-or-nothing import as new records (fresh ids, revision 1). `None` if it would
    /// exceed the per-account cap.
    pub fn import(
        &self,
        account: &AccountId,
        inputs: &[InstallationInput],
        now: i64,
    ) -> rusqlite::Result<Option<Vec<Installation>>> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if active_count(&tx, account)? + inputs.len() > MAX_INSTALLATIONS_PER_ACCOUNT {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(inputs.len());
        for input in inputs {
            let rec = materialize(
                input,
                new_uuid(),
                now,
                input.status.unwrap_or(Status::Draft),
            );
            insert_row(&tx, account, &rec)?;
            out.push(rec);
        }
        purge_old_removed(&tx, account)?;
        tx.commit()?;
        Ok(Some(out))
    }
}

/// Account-deletion hook: hard-delete all installations (and history) of the ledger account
/// bound to `subject`. A subject that never had an account has nothing to delete. Must run
/// before the ledger row is removed, or the subject -> account link is lost.
pub fn purge_subject(
    store: &SqliteInstallationStore,
    ledger: &SqliteLedger,
    subject: &str,
) -> Result<usize, String> {
    let Some(account) = ledger
        .account_if_exists(subject)
        .map_err(|e| e.to_string())?
    else {
        return Ok(0);
    };
    store
        .delete_all_for_account(&account)
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthedInstallationState {
    store: Arc<SqliteInstallationStore>,
    ledger: Arc<SqliteLedger>,
    verifier: OidcVerifierHandle,
    session_key: Arc<[u8]>,
    delegate: Option<InstallationsDelegate>,
}

/// `/me/installations*`, owner = the caller's platform account.
///
/// * `GET    /me/installations?status=&limit=&offset=` -> `{items, total, limit, offset}`
///   (without `status`: all but `removed`)
/// * `POST   /me/installations` -> `201` + record, `ETag: "<revision>"`
/// * `GET    /me/installations/:id`
/// * `PUT    /me/installations/:id` with `If-Match: <revision>` (`428` without, `409` on mismatch)
/// * `DELETE /me/installations/:id` soft delete (`204`; honours `If-Match` when sent)
/// * `GET    /me/installations/:id/revisions` superseded revisions, newest first
/// * `POST   /me/installations/:id/duplicate` optional `{name}` -> `201`, a new draft
/// * `GET    /me/installations/export`, `POST /me/installations/import`
pub fn authed_installations_router(
    store: Arc<SqliteInstallationStore>,
    ledger: Arc<SqliteLedger>,
    verifier: OidcVerifierHandle,
    session_key: Arc<[u8]>,
    delegate: Option<InstallationsDelegate>,
) -> Router {
    Router::new()
        .route("/me/installations", post(create).get(list))
        .route("/me/installations/export", get(export))
        .route(
            "/me/installations/import",
            post(import).layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT)),
        )
        .route(
            "/me/installations/:id",
            get(get_one).put(update).delete(remove),
        )
        .route("/me/installations/:id/revisions", get(revisions))
        .route("/me/installations/:id/duplicate", post(duplicate))
        .layer(axum::middleware::from_fn(csrf_guard))
        .with_state(AuthedInstallationState {
            store,
            ledger,
            verifier,
            session_key,
            delegate,
        })
}

/// The delegate token, as a request header. A browser cannot attach it cross-site without CORS.
const DELEGATE_HEADER: &str = "x-ct-installations-delegate";
/// The visitor's `ct_gate_session` value, as the delegate forwards it.
const DELEGATE_SESSION_HEADER: &str = "x-ct-gate-session";

/// The one origin allowed to act for its gate-authenticated visitors. See the module docs.
#[derive(Clone)]
pub struct InstallationsDelegate {
    token_sha256: [u8; 32],
    host: String,
}

impl InstallationsDelegate {
    pub fn new(token_sha256: [u8; 32], host: impl Into<String>) -> Self {
        Self { token_sha256, host: host.into() }
    }

    /// `None` when neither variable is set. One without the other, or a malformed hash, is a
    /// misconfiguration and refuses to start rather than silently leaving the feature off.
    pub fn from_env() -> Result<Option<Self>, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        match (var("CT_INSTALLATIONS_DELEGATE_SHA256"), var("CT_INSTALLATIONS_DELEGATE_HOST")) {
            (None, None) => Ok(None),
            (Some(hash), Some(host)) => {
                let bytes = ct_common::hex::decode(hash.trim())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or("CT_INSTALLATIONS_DELEGATE_SHA256 must be 64 hex characters")?;
                Ok(Some(Self::new(bytes, host.trim().to_ascii_lowercase())))
            }
            _ => Err("CT_INSTALLATIONS_DELEGATE_SHA256 and CT_INSTALLATIONS_DELEGATE_HOST go together".to_string()),
        }
    }
}

/// CSRF guard for the state-changing routes. A request that carries an `Authorization`
/// header cannot be forged cross-site (no CORS), so bearer callers pass. Anything else is
/// cookie-authenticated and must be same-origin: `Sec-Fetch-Site` must be `same-origin` or
/// `none` (`same-site` is refused: tunnel origins on the shared zone are same-site), and an
/// `Origin`, when present, must equal the portal's own host. `SameSite=Lax` alone is not enough.
async fn csrf_guard(req: Request, next: Next) -> Response {
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if mutating
        && !req
            .headers()
            .contains_key(axum::http::header::AUTHORIZATION)
        && !req.headers().contains_key(DELEGATE_HEADER)
        && !same_origin_strict(req.headers())
    {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    next.run(req).await
}

fn same_origin_strict(headers: &HeaderMap) -> bool {
    if !crate::service::is_same_origin_request(headers) {
        return false;
    }
    // `Sec-Fetch-Site: same-origin` short-circuits that helper; still compare a present
    // `Origin` with `Host` by evaluating the header-only branch.
    let mut without_fetch_site = headers.clone();
    without_fetch_site.remove("sec-fetch-site");
    crate::service::is_same_origin_request(&without_fetch_site)
}

type ApiError = (StatusCode, String);

fn internal(context: &str, e: impl std::fmt::Display) -> ApiError {
    eprintln!("ct-cp installations: {context}: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error".to_string(),
    )
}

fn not_found() -> ApiError {
    (StatusCode::NOT_FOUND, "installation not found".to_string())
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    (StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

fn limit_reached() -> ApiError {
    unprocessable(format!(
        "at most {MAX_INSTALLATIONS_PER_ACCOUNT} installations per account; remove one first"
    ))
}

/// A request naming the delegate header is judged as a delegate only; it never falls through to the
/// session or bearer path, so a wrong token cannot be mistaken for any other kind of login.
fn delegated_subject_of(st: &AuthedInstallationState, headers: &HeaderMap, token: &HeaderValue) -> Result<String, ApiError> {
    let refused = || (StatusCode::UNAUTHORIZED, "delegate refused".to_string());
    let delegate = st.delegate.as_ref().ok_or_else(refused)?;
    let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !ct_common::ct::eq(&presented, &delegate.token_sha256) {
        return Err(refused());
    }
    let session = headers
        .get(DELEGATE_SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(refused)?;
    crate::gate::delegated_subject(&st.session_key, session, &delegate.host, now_secs()).ok_or_else(refused)
}

fn account_of(st: &AuthedInstallationState, headers: &HeaderMap) -> Result<AccountId, ApiError> {
    let subject = match headers.get(DELEGATE_HEADER) {
        Some(token) => delegated_subject_of(st, headers, token)?,
        None => crate::service::subject_of_topology(&st.session_key, &st.verifier, headers)?,
    };
    st.ledger
        .account_for_subject(&subject)
        .map_err(|e| internal("account_for_subject", e))
}

fn etag(rev: i64) -> [(HeaderName, HeaderValue); 1] {
    [(
        ETAG,
        HeaderValue::from_str(&format!("\"{rev}\"")).expect("digits are a valid header value"),
    )]
}

/// `If-Match: 3`, `"3"` or `W/"3"`.
fn if_match(headers: &HeaderMap) -> Result<Option<i64>, ApiError> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    let s = s.strip_prefix("W/").unwrap_or(s).trim_matches('"');
    s.parse::<i64>().ok().filter(|n| *n >= 1).map(Some).ok_or((
        StatusCode::BAD_REQUEST,
        "If-Match must be a revision number".to_string(),
    ))
}

fn conflict(current: i64) -> ApiError {
    (
        StatusCode::CONFLICT,
        format!("revision mismatch: the installation is at revision {current}; reload and retry"),
    )
}

async fn create(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Json(input): Json<InstallationInput>,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    validate(&input).map_err(unprocessable)?;
    if input.status == Some(Status::Removed) {
        return Err(unprocessable(
            "cannot create an installation with status removed",
        ));
    }
    match st
        .store
        .create(&account, &input, now_secs() as i64)
        .map_err(|e| internal("create", e))?
    {
        CreateOutcome::Created(rec) => Ok(created(*rec)),
        CreateOutcome::LimitReached => Err(limit_reached()),
    }
}

fn created(rec: Installation) -> Response {
    let loc = HeaderValue::from_str(&format!("/me/installations/{}", rec.id))
        .expect("uuid is a valid header value");
    (
        StatusCode::CREATED,
        etag(rec.revision),
        [(LOCATION, loc)],
        Json(rec),
    )
        .into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    status: Option<Status>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Serialize)]
struct ListResp {
    items: Vec<Installation>,
    total: usize,
    limit: usize,
    offset: usize,
}

async fn list(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResp>, ApiError> {
    let account = account_of(&st, &headers)?;
    let limit = q.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let offset = q.offset.unwrap_or(0);
    let (items, total) = st
        .store
        .list(&account, q.status, limit, offset)
        .map_err(|e| internal("list", e))?;
    Ok(Json(ListResp {
        items,
        total,
        limit,
        offset,
    }))
}

async fn get_one(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    let rec = st
        .store
        .get(&account, &id)
        .map_err(|e| internal("get", e))?
        .ok_or_else(not_found)?;
    Ok((etag(rec.revision), Json(rec)).into_response())
}

async fn update(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<InstallationInput>,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    validate(&input).map_err(unprocessable)?;
    // Existence (and so ownership) is answered before the precondition, so a foreign id is
    // a plain 404 whatever the headers say.
    if st
        .store
        .get(&account, &id)
        .map_err(|e| internal("update/get", e))?
        .is_none()
    {
        return Err(not_found());
    }
    let expected = if_match(&headers)?.ok_or((
        StatusCode::PRECONDITION_REQUIRED,
        "If-Match: <revision> is required".to_string(),
    ))?;
    match st
        .store
        .update(&account, &id, expected, &input, now_secs() as i64)
        .map_err(|e| internal("update", e))?
    {
        UpdateOutcome::Updated(rec) => Ok((etag(rec.revision), Json(*rec)).into_response()),
        UpdateOutcome::NotFound => Err(not_found()),
        UpdateOutcome::LimitReached => Err(limit_reached()),
        UpdateOutcome::Conflict(current) => Err(conflict(current)),
    }
}

async fn remove(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let account = account_of(&st, &headers)?;
    let expected = if_match(&headers)?;
    match st
        .store
        .soft_delete(&account, &id, expected, now_secs() as i64)
        .map_err(|e| internal("delete", e))?
    {
        DeleteOutcome::Removed => Ok(StatusCode::NO_CONTENT),
        DeleteOutcome::NotFound => Err(not_found()),
        DeleteOutcome::Conflict(current) => Err(conflict(current)),
    }
}

#[derive(Serialize)]
struct RevisionsResp {
    items: Vec<RevisionEntry>,
}

async fn revisions(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RevisionsResp>, ApiError> {
    let account = account_of(&st, &headers)?;
    let items = st
        .store
        .revisions(&account, &id)
        .map_err(|e| internal("revisions", e))?
        .ok_or_else(not_found)?;
    Ok(Json(RevisionsResp { items }))
}

#[derive(Deserialize)]
struct DuplicateReq {
    name: Option<String>,
}

async fn duplicate(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    let req: DuplicateReq = if body.iter().all(u8::is_ascii_whitespace) {
        DuplicateReq { name: None }
    } else {
        let is_json = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.trim()
                    .to_ascii_lowercase()
                    .starts_with("application/json")
            });
        if !is_json {
            return Err((
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type: application/json is required".to_string(),
            ));
        }
        serde_json::from_slice(&body).map_err(|e| unprocessable(format!("invalid body: {e}")))?
    };
    if let Some(name) = &req.name {
        check_label("name", name, MAX_NAME_CHARS, true).map_err(unprocessable)?;
    }
    match st
        .store
        .duplicate(
            &account,
            &id,
            req.name.as_deref().map(str::trim),
            now_secs() as i64,
        )
        .map_err(|e| internal("duplicate", e))?
    {
        None => Err(not_found()),
        Some(CreateOutcome::LimitReached) => Err(limit_reached()),
        Some(CreateOutcome::Created(rec)) => Ok(created(*rec)),
    }
}

#[derive(Serialize)]
struct ExportResp {
    version: u64,
    exported_at: i64,
    installations: Vec<Installation>,
}

async fn export(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    let installations = st
        .store
        .export_all(&account)
        .map_err(|e| internal("export", e))?;
    let body = ExportResp {
        version: EXPORT_VERSION,
        exported_at: now_secs() as i64,
        installations,
    };
    Ok((
        [(
            CONTENT_DISPOSITION,
            "attachment; filename=\"installations.json\"",
        )],
        Json(body),
    )
        .into_response())
}

#[derive(Deserialize)]
struct ImportReq {
    #[serde(default)]
    version: Option<u64>,
    installations: Vec<InstallationInput>,
}

#[derive(Serialize)]
struct ImportResp {
    imported: usize,
    ids: Vec<String>,
}

async fn import(
    State(st): State<AuthedInstallationState>,
    headers: HeaderMap,
    Json(req): Json<ImportReq>,
) -> Result<Response, ApiError> {
    let account = account_of(&st, &headers)?;
    if req.version.is_some_and(|v| v != EXPORT_VERSION) {
        return Err(unprocessable(format!(
            "unsupported export version; expected {EXPORT_VERSION}"
        )));
    }
    if req.installations.len() > MAX_INSTALLATIONS_PER_ACCOUNT {
        return Err(limit_reached());
    }
    for (i, input) in req.installations.iter().enumerate() {
        validate(input).map_err(|m| unprocessable(format!("installations[{i}]: {m}")))?;
        if input.status == Some(Status::Removed) {
            return Err(unprocessable(format!(
                "installations[{i}]: cannot import a removed installation"
            )));
        }
    }
    let recs = st
        .store
        .import(&account, &req.installations, now_secs() as i64)
        .map_err(|e| internal("import", e))?
        .ok_or_else(limit_reached)?;
    let resp = ImportResp {
        imported: recs.len(),
        ids: recs.into_iter().map(|r| r.id).collect(),
    };
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::OidcVerifier;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use tower::ServiceExt;

    const SECRET: &[u8] = b"realm-secret";
    const ISSUER: &str = "https://kc/realms/ct";
    const SESSION_KEY: &[u8] = b"session-key";

    struct Env {
        app: Router,
        store: Arc<SqliteInstallationStore>,
        ledger: Arc<SqliteLedger>,
    }

    fn env() -> Env {
        let store = Arc::new(SqliteInstallationStore::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(SECRET, ISSUER));
        let app = authed_installations_router(
            store.clone(),
            ledger.clone(),
            OidcVerifierHandle::new(Some(verifier)),
            Arc::from(SESSION_KEY),
            Some(InstallationsDelegate::new(
                Sha256::digest(DELEGATE_TOKEN).into(),
                DELEGATE_HOST,
            )),
        );
        Env { app, store, ledger }
    }

    fn jwt(sub: &str) -> String {
        let exp = now_secs() + 3600;
        let claims = json!({ "sub": sub, "iss": ISSUER, "exp": exp });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Value,
        text: String,
    }

    async fn send(
        app: &Router,
        method: &str,
        uri: &str,
        sub: &str,
        if_match: Option<&str>,
        body: Option<Value>,
    ) -> Reply {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", jwt(sub)));
        if let Some(m) = if_match {
            req = req.header("if-match", m);
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let text = String::from_utf8_lossy(&to_bytes(body, usize::MAX).await.unwrap()).into_owned();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_str(&text).unwrap_or(Value::Null),
            text,
        }
    }

    fn payload(name: &str) -> Value {
        json!({
            "name": name,
            "template_id": "11".repeat(32),
            "template_digest": "22".repeat(32),
            "values": { "region": "eu", "port": 8443, "labels": ["a", "b"] },
            "values_digest": "33".repeat(32),
            "components": [{ "name": "agent", "sha256": "ab".repeat(32) }],
            "manifest_ids": ["m-1", "m-2"],
            "target": { "os": "linux", "device_label": "nuc-1" },
        })
    }

    async fn create_as(app: &Router, sub: &str, name: &str) -> Value {
        let r = send(
            app,
            "POST",
            "/me/installations",
            sub,
            None,
            Some(payload(name)),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
        r.body
    }

    fn input(name: &str) -> InstallationInput {
        serde_json::from_value(payload(name)).unwrap()
    }

    #[tokio::test]
    async fn crud_round_trip() {
        let e = env();
        let r = send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(payload("Gateway")),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
        let rec = r.body.clone();
        let id = rec["id"].as_str().unwrap().to_string();
        let b = id.as_bytes();
        assert_eq!(id.len(), 36);
        assert!(b[14] == b'4' && b"89ab".contains(&b[19]), "uuid v4: {id}");
        assert_eq!(rec["status"], "draft");
        assert_eq!(rec["revision"], 1);
        assert_eq!(rec["values"]["port"], 8443);
        assert_eq!(rec["components"][0]["name"], "agent");
        assert_eq!(rec["target"]["device_label"], "nuc-1");
        assert_eq!(r.headers[ETAG], "\"1\"");
        assert_eq!(
            r.headers[LOCATION],
            format!("/me/installations/{id}").as_str()
        );

        let r = send(
            &e.app,
            "GET",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body, rec);

        let mut upd = payload("Gateway v2");
        upd["status"] = json!("installed");
        upd["target"]["agent_holder_pubkey"] = json!("cd".repeat(32));
        let r = send(
            &e.app,
            "PUT",
            &format!("/me/installations/{id}"),
            "alice",
            Some("1"),
            Some(upd),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.text);
        assert_eq!(r.body["revision"], 2);
        assert_eq!(r.body["name"], "Gateway v2");
        assert_eq!(r.body["status"], "installed");
        assert_eq!(r.body["created_at"], rec["created_at"]);
        assert_eq!(r.headers[ETAG], "\"2\"");

        let r = send(&e.app, "GET", "/me/installations", "alice", None, None).await;
        assert_eq!(r.body["total"], 1);
        assert_eq!(r.body["items"][0]["id"], id.as_str());

        let r = send(
            &e.app,
            "DELETE",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let r = send(&e.app, "GET", "/me/installations", "alice", None, None).await;
        assert_eq!(
            r.body["total"], 0,
            "removed records are hidden from the default list"
        );
        let r = send(
            &e.app,
            "GET",
            "/me/installations?status=removed",
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.body["total"], 1);
        let r = send(
            &e.app,
            "GET",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.body["status"], "removed");
        assert_eq!(r.body["revision"], 3, "soft delete is a revision");

        // Deleting again is idempotent; a removed record can be restored with PUT.
        let r = send(
            &e.app,
            "DELETE",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let mut back = payload("Gateway v2");
        back["status"] = json!("draft");
        let r = send(
            &e.app,
            "PUT",
            &format!("/me/installations/{id}"),
            "alice",
            Some("3"),
            Some(back),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert_eq!(r.body["status"], "draft");
    }

    #[tokio::test]
    async fn put_needs_a_matching_if_match() {
        let e = env();
        let id = create_as(&e.app, "alice", "A").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let url = format!("/me/installations/{id}");

        let r = send(&e.app, "PUT", &url, "alice", None, Some(payload("x"))).await;
        assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);
        let r = send(
            &e.app,
            "PUT",
            &url,
            "alice",
            Some("abc"),
            Some(payload("x")),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);

        // Two writers both read revision 1: the first wins, the second gets 409.
        let r = send(
            &e.app,
            "PUT",
            &url,
            "alice",
            Some("\"1\""),
            Some(payload("first")),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let r = send(
            &e.app,
            "PUT",
            &url,
            "alice",
            Some("1"),
            Some(payload("second")),
        )
        .await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        assert!(r.text.contains("revision 2"), "{}", r.text);
        let r = send(&e.app, "GET", &url, "alice", None, None).await;
        assert_eq!(r.body["name"], "first", "the losing write changed nothing");
        assert_eq!(r.body["revision"], 2);

        // W/ prefix is accepted; a stale DELETE precondition is refused too.
        let r = send(
            &e.app,
            "PUT",
            &url,
            "alice",
            Some("W/\"2\""),
            Some(payload("third")),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let r = send(&e.app, "DELETE", &url, "alice", Some("2"), None).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        let r = send(&e.app, "DELETE", &url, "alice", Some("3"), None).await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revision_history_keeps_every_superseded_state() {
        let e = env();
        let id = create_as(&e.app, "alice", "v1").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let url = format!("/me/installations/{id}");
        send(&e.app, "PUT", &url, "alice", Some("1"), Some(payload("v2"))).await;
        let mut v3 = payload("v3");
        v3["values"] = json!({ "region": "us" });
        send(&e.app, "PUT", &url, "alice", Some("2"), Some(v3)).await;
        send(&e.app, "DELETE", &url, "alice", None, None).await;

        let r = send(
            &e.app,
            "GET",
            &format!("{url}/revisions"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        let items = r.body["items"].as_array().unwrap();
        let seen: Vec<(i64, &str)> = items
            .iter()
            .map(|i| {
                (
                    i["revision"].as_i64().unwrap(),
                    i["installation"]["name"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![(3, "v3"), (2, "v2"), (1, "v1")],
            "newest first; current (rev 4, removed) is not in the history"
        );
        assert_eq!(items[0]["installation"]["values"]["region"], "us");
        assert_eq!(items[1]["installation"]["values"]["region"], "eu");
        assert_eq!(items[0]["installation"]["revision"], 3);
    }

    #[test]
    fn revision_history_is_bounded() {
        let store = SqliteInstallationStore::open_in_memory().unwrap();
        let acct = AccountId([1; 32]);
        let CreateOutcome::Created(rec) = store.create(&acct, &input("n"), 100).unwrap() else {
            panic!()
        };
        for rev in 1..=(MAX_REVISIONS + 10) {
            let out = store
                .update(&acct, &rec.id, rev, &input("n"), 100 + rev)
                .unwrap();
            assert!(matches!(out, UpdateOutcome::Updated(_)));
        }
        let revs = store.revisions(&acct, &rec.id).unwrap().unwrap();
        assert_eq!(revs.len() as i64, MAX_REVISIONS);
        assert_eq!(revs[0].revision, MAX_REVISIONS + 10);
        assert_eq!(revs.last().unwrap().revision, 11);
    }

    fn pem() -> String {
        format!(
            "-----BEGIN {} KEY-----\nMIIB\n-----END {} KEY-----",
            "PRIVATE", "PRIVATE"
        )
    }

    #[tokio::test]
    async fn secrets_are_rejected_with_422_and_never_stored() {
        let e = env();
        let aws = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let gh = ["ghp_", "0123456789abcdefghijklmnop"].concat();
        let sk = ["sk-", "proj-0123456789abcdef"].concat();
        let slack = ["xoxb", "-1234567890-abcdefghij"].concat();
        let bad_keys = [
            "token",
            "auth_Token",
            "client_SECRET",
            "Password",
            "db_password",
            "API_KEY",
            "ssh_key",
            "key",
            "privateKey",
        ];
        for k in bad_keys {
            let mut p = payload("x");
            p["values"] = json!({ "region": "eu", "nested": { "deep": [ { k: "v" } ] } });
            let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
            assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "key {k}");
            assert!(r.text.contains("looks like a secret"), "{}", r.text);
        }
        for v in [aws.clone(), gh, sk, slack, pem(), format!("export X={aws}")] {
            let mut p = payload("x");
            p["values"] = json!({ "note": "fine", "list": ["ok", v.clone()] });
            let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
            assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "value {v}");
            assert!(r.text.contains("looks like a credential"), "{}", r.text);
            assert!(
                r.text.contains("values.list[1]") || r.text.contains("values.note"),
                "{}",
                r.text
            );
            assert!(
                !r.text.contains(&v),
                "the error must not echo the credential"
            );
        }
        // Credential-looking free text in other fields is refused too.
        let mut p = payload(&aws);
        let r = send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(p.clone()),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        p["name"] = json!("ok");
        p["target"]["device_label"] = json!(pem());
        let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

        // Update path too, and the stored record is untouched by the refusal.
        let id = create_as(&e.app, "alice", "clean").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut p = payload("clean");
        p["values"] = json!({ "api_key": "x" });
        let r = send(
            &e.app,
            "PUT",
            &format!("/me/installations/{id}"),
            "alice",
            Some("1"),
            Some(p),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        let r = send(
            &e.app,
            "GET",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.body["revision"], 1);
        let r = send(&e.app, "GET", "/me/installations", "alice", None, None).await;
        assert_eq!(r.body["total"], 1, "no refused create left a row");

        // Ordinary values that merely resemble the patterns pass.
        let mut p = payload("benign");
        p["values"] = json!({ "keyboard_layout": "de", "tokenizer": "off".to_string().replace("off", "none"), "lang": "sk-SK", "greeting": "xoxo", "ssh_port": 22 });
        let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "tokenizer contains 'token' and is refused, as specified"
        );
        let mut p = payload("benign");
        p["values"] =
            json!({ "keyboard_layout": "de", "lang": "sk-SK", "greeting": "xoxo", "ssh_port": 22 });
        let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    }

    #[tokio::test]
    async fn size_and_shape_limits_are_422() {
        let e = env();
        let post = |p: Value| {
            let app = e.app.clone();
            async move { send(&app, "POST", "/me/installations", "alice", None, Some(p)).await }
        };
        let r = post(payload(&"n".repeat(MAX_NAME_CHARS))).await;
        assert_eq!(r.status, StatusCode::CREATED, "120 characters are fine");
        let r = post(payload(&"n".repeat(MAX_NAME_CHARS + 1))).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.text.contains("120"), "{}", r.text);
        assert_eq!(
            post(payload("   ")).await.status,
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let mut p = payload("big");
        p["values"] = json!({ "blob": "x".repeat(MAX_VALUES_BYTES) });
        let r = post(p).await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.text.contains("32 KiB"), "{}", r.text);
        let mut p = payload("just under");
        p["values"] = json!({ "blob": "x".repeat(MAX_VALUES_BYTES - 64) });
        assert_eq!(post(p).await.status, StatusCode::CREATED);

        for bad in [json!([1]), json!("s"), json!(null)] {
            let mut p = payload("shape");
            p["values"] = bad;
            assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let mut p = payload("deep");
        let mut v = json!("leaf");
        for _ in 0..40 {
            v = json!({ "n": v });
        }
        p["values"] = v;
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);

        for (field, bad) in [
            ("template_id", "tpl-web-gateway".to_string()),
            ("template_id", "AB".repeat(32)),
            ("template_digest", "sha256:abc123".to_string()),
            ("template_digest", "11".repeat(31)),
            ("values_digest", "AB".repeat(32)),
            ("values_digest", String::new()),
            ("template_id", String::new()),
        ] {
            let mut p = payload("fmt");
            p[field] = json!(bad);
            let r = post(p).await;
            assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{field}={bad}");
            assert!(r.text.contains("64 lowercase hex"), "{}", r.text);
        }
        let mut p = payload("upper sha");
        p["components"] = json!([{ "name": "a", "sha256": "AB".repeat(32) }]);
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("upper pk");
        p["target"]["agent_holder_pubkey"] = json!("CD".repeat(32));
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("sha");
        p["components"] = json!([{ "name": "a", "sha256": "xyz" }]);
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("pk");
        p["target"]["agent_holder_pubkey"] = json!("short");
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("status");
        p["status"] = json!("removed");
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("status");
        p["status"] = json!("bogus");
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
        let mut p = payload("os");
        p["target"]["os"] = json!("");
        assert_eq!(post(p).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn per_account_cap_counts_active_records_only() {
        let e = env();
        let acct = e.ledger.account_for_subject("alice").unwrap();
        for i in 0..MAX_INSTALLATIONS_PER_ACCOUNT {
            assert!(matches!(
                e.store.create(&acct, &input(&format!("i{i}")), 1).unwrap(),
                CreateOutcome::Created(_)
            ));
        }
        let r = send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(payload("one too many")),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.text.contains("200"), "{}", r.text);
        // Another account is unaffected.
        create_as(&e.app, "bob", "mine").await;

        let (items, total) = e.store.list(&acct, None, 1, 0).unwrap();
        assert_eq!(total, MAX_INSTALLATIONS_PER_ACCOUNT);
        let id = &items[0].id;
        let r = send(
            &e.app,
            "POST",
            &format!("/me/installations/{id}/duplicate"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "duplicate respects the cap"
        );
        let r = send(
            &e.app,
            "DELETE",
            &format!("/me/installations/{id}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::NO_CONTENT);
        let r = send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(payload("fits again")),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "a removed record frees its slot"
        );
        // ... and reviving the removed one is now over the cap.
        let r = send(
            &e.app,
            "PUT",
            &format!("/me/installations/{id}"),
            "alice",
            Some("2"),
            Some(payload("revive")),
        )
        .await;
        assert_eq!(
            r.status,
            StatusCode::OK,
            "no status given keeps it removed, which is allowed"
        );
        let mut revive = payload("revive");
        revive["status"] = json!("draft");
        let r = send(
            &e.app,
            "PUT",
            &format!("/me/installations/{id}"),
            "alice",
            Some("3"),
            Some(revive),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn old_removed_records_are_purged_with_their_history() {
        let store = SqliteInstallationStore::open_in_memory().unwrap();
        let acct = AccountId([7; 32]);
        let mut ids = Vec::new();
        for i in 0..(KEEP_REMOVED + 5) {
            let CreateOutcome::Created(rec) = store.create(&acct, &input("r"), 10 + i).unwrap()
            else {
                panic!()
            };
            assert_eq!(
                store.soft_delete(&acct, &rec.id, None, 10 + i).unwrap(),
                DeleteOutcome::Removed
            );
            ids.push(rec.id);
        }
        let (_, removed) = store.list(&acct, Some(Status::Removed), 1, 0).unwrap();
        assert_eq!(removed as i64, KEEP_REMOVED);
        assert!(
            store.get(&acct, &ids[0]).unwrap().is_none(),
            "oldest removed record is gone"
        );
        assert!(store.revisions(&acct, &ids[0]).unwrap().is_none());
        assert!(store.get(&acct, ids.last().unwrap()).unwrap().is_some());
        let orphans: i64 = store
            .conn
            .lock_safe()
            .query_row("SELECT COUNT(*) FROM installation_revisions WHERE id NOT IN (SELECT id FROM installations)", [], |r| r.get(0))
            .unwrap();
        assert_eq!(orphans, 0);
    }

    #[tokio::test]
    async fn account_a_cannot_touch_account_b() {
        let e = env();
        let a = create_as(&e.app, "alice", "alice's").await;
        let id = a["id"].as_str().unwrap();
        let url = format!("/me/installations/{id}");
        let before = send(&e.app, "GET", &url, "alice", None, None).await.body;

        let steps: Vec<(&str, String, Option<&str>, Option<Value>)> = vec![
            ("GET", url.clone(), None, None),
            ("PUT", url.clone(), Some("1"), Some(payload("hijacked"))),
            ("PUT", url.clone(), None, Some(payload("hijacked"))),
            ("PUT", url.clone(), Some("99"), Some(payload("hijacked"))),
            ("DELETE", url.clone(), None, None),
            ("DELETE", url.clone(), Some("1"), None),
            ("GET", format!("{url}/revisions"), None, None),
            ("POST", format!("{url}/duplicate"), None, None),
        ];
        for (m, u, im, body) in steps {
            let r = send(&e.app, m, &u, "bob", im, body).await;
            assert_eq!(
                r.status,
                StatusCode::NOT_FOUND,
                "{m} {u} must be 404 (not 403) for a foreign record: {}",
                r.text
            );
        }
        // An id that never existed answers identically.
        let ghost = send(
            &e.app,
            "GET",
            "/me/installations/00000000-0000-4000-8000-000000000000",
            "bob",
            None,
            None,
        )
        .await;
        let foreign = send(&e.app, "GET", &url, "bob", None, None).await;
        assert_eq!(
            (ghost.status, ghost.text.clone()),
            (foreign.status, foreign.text.clone())
        );

        // Listing/exporting shows nothing; nothing of alice's changed or was copied.
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "bob", None, None)
                .await
                .body["total"],
            0
        );
        assert_eq!(
            send(
                &e.app,
                "GET",
                "/me/installations?status=removed",
                "bob",
                None,
                None
            )
            .await
            .body["total"],
            0
        );
        assert_eq!(
            send(&e.app, "GET", "/me/installations/export", "bob", None, None)
                .await
                .body["installations"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            send(&e.app, "GET", &url, "alice", None, None).await.body,
            before
        );
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            1
        );

        // Importing alice's exported file (ids included) into bob creates new records only.
        let exported = send(
            &e.app,
            "GET",
            "/me/installations/export",
            "alice",
            None,
            None,
        )
        .await
        .body;
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "bob",
            None,
            Some(exported),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert_ne!(r.body["ids"][0], a["id"]);
        assert_eq!(
            send(&e.app, "GET", &url, "bob", None, None).await.status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            send(&e.app, "GET", &url, "alice", None, None).await.body,
            before
        );

        // The binding is the ledger account: a store query with the wrong account sees nothing.
        let alice_acct = e.ledger.account_for_subject("alice").unwrap();
        let bob_acct = e.ledger.account_for_subject("bob").unwrap();
        assert_ne!(alice_acct, bob_acct);
        assert!(e.store.get(&bob_acct, id).unwrap().is_none());
        assert!(e.store.get(&alice_acct, id).unwrap().is_some());
    }

    #[tokio::test]
    async fn requires_authentication() {
        let e = env();
        // Bodies are valid for their route, so the 401 is about auth, not parsing.
        for (m, u, body) in [
            ("GET", "/me/installations", json!(null)),
            ("POST", "/me/installations", payload("x")),
            ("GET", "/me/installations/export", json!(null)),
            (
                "POST",
                "/me/installations/import",
                json!({ "installations": [] }),
            ),
        ] {
            let req = Request::builder()
                .method(m)
                .uri(u)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let resp = e.app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{m} {u}");
        }
        let req = Request::get("/me/installations")
            .header("authorization", "Bearer not-a-jwt")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            e.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    const DELEGATE_TOKEN: &[u8] = b"delegate-token-for-tests";
    const DELEGATE_HOST: &str = "gallery.example";

    fn gate_token(host: &str, email: &str, subject: Option<&str>, exp: u64) -> String {
        crate::gate::sign_gate_session_for_test(SESSION_KEY, host, email, subject, exp)
    }

    fn delegated(method: &str, path: &str, token: Option<&[u8]>, session: Option<&str>, body: Body) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path).header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header(DELEGATE_HEADER, HeaderValue::from_bytes(t).unwrap());
        }
        if let Some(s) = session {
            b = b.header(DELEGATE_SESSION_HEADER, s);
        }
        b.body(body).unwrap()
    }

    #[tokio::test]
    async fn a_delegate_acts_for_its_gate_visitor_on_the_same_account_as_the_portal() {
        let e = env();
        let id = create_as(&e.app, "alice", "via bearer").await["id"].as_str().unwrap().to_string();
        let s = gate_token(DELEGATE_HOST, "alice@example.com", Some("alice"), now_secs() + 60);
        let path = format!("/me/installations/{id}");
        let get = delegated("GET", &path, Some(DELEGATE_TOKEN), Some(&s), Body::empty());
        assert_eq!(e.app.clone().oneshot(get).await.unwrap().status(), StatusCode::OK);
        let body = Body::from(payload("from the gallery").to_string());
        let post = delegated("POST", "/me/installations", Some(DELEGATE_TOKEN), Some(&s), body);
        assert_eq!(e.app.clone().oneshot(post).await.unwrap().status(), StatusCode::CREATED);
        let del = delegated("DELETE", &path, Some(DELEGATE_TOKEN), Some(&s), Body::empty());
        assert_eq!(e.app.clone().oneshot(del).await.unwrap().status(), StatusCode::NO_CONTENT);
        let other = gate_token(DELEGATE_HOST, "bob@example.com", Some("bob"), now_secs() + 60);
        let get = delegated("GET", &path, Some(DELEGATE_TOKEN), Some(&other), Body::empty());
        assert_eq!(e.app.clone().oneshot(get).await.unwrap().status(), StatusCode::NOT_FOUND, "bob sees nothing of alice");
    }

    #[tokio::test]
    async fn a_delegate_needs_both_proofs_and_the_right_session() {
        let e = env();
        let now = now_secs();
        let good = gate_token(DELEGATE_HOST, "alice@example.com", Some("alice"), now + 60);
        let cases: Vec<(&str, Option<&[u8]>, Option<String>)> = vec![
            ("cookie alone: any tunnel on the zone sees it", None, Some(good.clone())),
            ("token alone: a leaked token reads nothing", Some(DELEGATE_TOKEN), None),
            ("wrong token", Some(b"nope"), Some(good.clone())),
            ("session of another host", Some(DELEGATE_TOKEN), Some(gate_token("evil.example", "alice@example.com", Some("alice"), now + 60))),
            ("share-link session", Some(DELEGATE_TOKEN), Some(gate_token(DELEGATE_HOST, "share:abc", Some("alice"), now + 60))),
            ("session from before the subject field", Some(DELEGATE_TOKEN), Some(gate_token(DELEGATE_HOST, "alice@example.com", None, now + 60))),
            ("expired session", Some(DELEGATE_TOKEN), Some(gate_token(DELEGATE_HOST, "alice@example.com", Some("alice"), now - 1))),
            ("forged session", Some(DELEGATE_TOKEN), Some(format!("{good}00"))),
        ];
        for (what, token, session) in cases {
            let req = delegated("GET", "/me/installations", token, session.as_deref(), Body::empty());
            assert_eq!(e.app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED, "{what}");
        }
    }

    #[tokio::test]
    async fn a_wrong_delegate_token_does_not_fall_through_to_a_valid_bearer() {
        let e = env();
        let req = Request::get("/me/installations")
            .header("authorization", format!("Bearer {}", jwt("alice")))
            .header(DELEGATE_HEADER, "nope")
            .body(Body::empty())
            .unwrap();
        assert_eq!(e.app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn without_a_configured_delegate_the_header_opens_nothing() {
        let store = Arc::new(SqliteInstallationStore::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(SECRET, ISSUER));
        let app = authed_installations_router(store, ledger, OidcVerifierHandle::new(Some(verifier)), Arc::from(SESSION_KEY), None);
        let s = gate_token(DELEGATE_HOST, "alice@example.com", Some("alice"), now_secs() + 60);
        let req = delegated("GET", "/me/installations", Some(DELEGATE_TOKEN), Some(&s), Body::empty());
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn portal_session_cookie_resolves_to_the_same_account() {
        let e = env();
        let id = create_as(&e.app, "alice", "via bearer").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let cookie = crate::portal::sign_session_for_test(SESSION_KEY, "alice");
        let req = Request::get(format!("/me/installations/{id}"))
            .header("cookie", format!("ct_portal_session={cookie}"))
            .body(Body::empty())
            .unwrap();
        let resp = e.app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let other = crate::portal::sign_session_for_test(SESSION_KEY, "mallory");
        let req = Request::get(format!("/me/installations/{id}"))
            .header("cookie", format!("ct_portal_session={other}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            e.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn list_is_paginated_newest_first() {
        let e = env();
        for i in 0..7 {
            create_as(&e.app, "alice", &format!("n{i}")).await;
        }
        let page = |q: &'static str| {
            let app = e.app.clone();
            async move {
                send(
                    &app,
                    "GET",
                    &format!("/me/installations{q}"),
                    "alice",
                    None,
                    None,
                )
                .await
                .body
            }
        };
        let p1 = page("?limit=3").await;
        assert_eq!(
            (
                p1["total"].as_u64(),
                p1["limit"].as_u64(),
                p1["offset"].as_u64()
            ),
            (Some(7), Some(3), Some(0))
        );
        let names = |p: &Value| {
            p["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["name"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&p1), ["n6", "n5", "n4"]);
        assert_eq!(names(&page("?limit=3&offset=3").await), ["n3", "n2", "n1"]);
        assert_eq!(names(&page("?limit=3&offset=6").await), ["n0"]);
        assert_eq!(names(&page("?limit=3&offset=60").await).len(), 0);
        assert_eq!(page("?limit=100000").await["limit"], MAX_PAGE);
        assert_eq!(page("?limit=0").await["limit"], 1);
        assert_eq!(page("").await["limit"], DEFAULT_PAGE);
        let r = send(
            &e.app,
            "GET",
            "/me/installations?status=nonsense",
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        let r = send(
            &e.app,
            "GET",
            "/me/installations?status=draft",
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.body["total"], 7);
        let r = send(
            &e.app,
            "GET",
            "/me/installations?status=installed",
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.body["total"], 0);
    }

    #[tokio::test]
    async fn duplicate_makes_an_independent_draft() {
        let e = env();
        let mut p = payload("Original");
        p["status"] = json!("installed");
        let src = send(&e.app, "POST", "/me/installations", "alice", None, Some(p))
            .await
            .body;
        let url = format!(
            "/me/installations/{}/duplicate",
            src["id"].as_str().unwrap()
        );

        let r = send(&e.app, "POST", &url, "alice", None, None).await;
        assert_eq!(r.status, StatusCode::CREATED);
        assert_ne!(r.body["id"], src["id"]);
        assert_eq!(r.body["name"], "Original (copy)");
        assert_eq!(r.body["status"], "draft");
        assert_eq!(r.body["revision"], 1);
        for f in [
            "template_id",
            "template_digest",
            "values",
            "values_digest",
            "components",
            "manifest_ids",
            "target",
        ] {
            assert_eq!(r.body[f], src[f], "{f} is copied");
        }
        let r = send(
            &e.app,
            "POST",
            &url,
            "alice",
            None,
            Some(json!({ "name": "Zweitgeraet" })),
        )
        .await;
        assert_eq!(r.body["name"], "Zweitgeraet");
        let r = send(
            &e.app,
            "POST",
            &url,
            "alice",
            None,
            Some(json!({ "name": "" })),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        let long = send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(payload(&"n".repeat(MAX_NAME_CHARS))),
        )
        .await
        .body;
        let r = send(
            &e.app,
            "POST",
            &format!(
                "/me/installations/{}/duplicate",
                long["id"].as_str().unwrap()
            ),
            "alice",
            None,
            None,
        )
        .await;
        assert!(r.body["name"].as_str().unwrap().chars().count() <= MAX_NAME_CHARS);
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            5
        );
    }

    #[tokio::test]
    async fn export_import_round_trip() {
        let e = env();
        let mut installed = payload("Zwei");
        installed["status"] = json!("installed");
        installed["target"]["agent_holder_pubkey"] = json!("ef".repeat(32));
        send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(payload("Eins")),
        )
        .await;
        send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            None,
            Some(installed),
        )
        .await;
        let gone = create_as(&e.app, "alice", "Entfernt").await;
        send(
            &e.app,
            "DELETE",
            &format!("/me/installations/{}", gone["id"].as_str().unwrap()),
            "alice",
            None,
            None,
        )
        .await;

        let r = send(
            &e.app,
            "GET",
            "/me/installations/export",
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(r.status, StatusCode::OK);
        assert!(r.headers[CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("installations.json"));
        let file = r.body.clone();
        assert_eq!(file["version"], 1);
        let exported = file["installations"].as_array().unwrap();
        assert_eq!(exported.len(), 2, "removed records are not exported");

        // Into a fresh account: same content, new identities.
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "bob",
            None,
            Some(file.clone()),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
        assert_eq!(r.body["imported"], 2);
        let again = send(&e.app, "GET", "/me/installations/export", "bob", None, None)
            .await
            .body;
        let imported = again["installations"].as_array().unwrap();
        assert_eq!(imported.len(), 2);
        for (a, b) in exported.iter().zip(imported) {
            assert_ne!(a["id"], b["id"], "import never reuses ids");
            assert_eq!(b["revision"], 1);
            for f in [
                "name",
                "template_id",
                "template_digest",
                "values",
                "values_digest",
                "components",
                "manifest_ids",
                "target",
                "status",
            ] {
                assert_eq!(a[f], b[f], "{f} survives the round trip");
            }
        }
        // Importing again into the same account duplicates; the cap is enforced atomically.
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "bob",
            None,
            Some(file),
        )
        .await;
        assert_eq!(r.body["imported"], 2);
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "bob", None, None)
                .await
                .body["total"],
            4
        );
    }

    #[tokio::test]
    async fn import_is_all_or_nothing() {
        let e = env();
        let mut secret = payload("bad");
        secret["values"] = json!({ "password": "x" });
        let body = json!({ "version": 1, "installations": [payload("ok"), secret] });
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "alice",
            None,
            Some(body),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(r.text.starts_with("installations[1]:"), "{}", r.text);
        let mut removed = payload("r");
        removed["status"] = json!("removed");
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "alice",
            None,
            Some(json!({ "installations": [removed] })),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "alice",
            None,
            Some(json!({ "version": 2, "installations": [] })),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            0
        );

        // Over the cap: nothing at all is imported.
        for _ in 0..(MAX_INSTALLATIONS_PER_ACCOUNT - 1) {
            e.store
                .create(
                    &e.ledger.account_for_subject("alice").unwrap(),
                    &input("f"),
                    1,
                )
                .unwrap();
        }
        let body = json!({ "installations": [payload("a"), payload("b")] });
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "alice",
            None,
            Some(body),
        )
        .await;
        assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            MAX_INSTALLATIONS_PER_ACCOUNT - 1
        );
        let r = send(
            &e.app,
            "POST",
            "/me/installations/import",
            "alice",
            None,
            Some(json!({ "installations": [payload("last")] })),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
    }

    #[test]
    fn migration_is_additive_and_survives_reopen() {
        let path = std::env::temp_dir().join(format!("ct-installations-{}.db", new_uuid()));
        let path_s = path.to_str().unwrap();
        // The same DB file already holds other stores' tables.
        let ledger = SqliteLedger::open(path_s).unwrap();
        let acct = ledger.account_for_subject("alice").unwrap();
        let rec = {
            let store = SqliteInstallationStore::open(path_s).unwrap();
            let CreateOutcome::Created(rec) = store.create(&acct, &input("durable"), 5).unwrap()
            else {
                panic!()
            };
            rec
        };
        let store = SqliteInstallationStore::open(path_s).unwrap();
        assert_eq!(store.get(&acct, &rec.id).unwrap().unwrap(), *rec);
        assert_eq!(
            ledger.account_for_subject("alice").unwrap(),
            acct,
            "existing tables untouched"
        );
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path_s}{suffix}"));
        }
    }

    // ---- review fixes -----------------------------------------------------

    fn jwt_like() -> String {
        [
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiJ4In0",
            "c2lnbmF0dXJlMTIz",
        ]
        .join(".")
    }

    #[test]
    fn secret_key_names_match_on_word_segments() {
        for k in [
            "token",
            "auth_token",
            "client_SECRET",
            "Password",
            "passwd",
            "pwd",
            "db_pwd",
            "credentials",
            "credential",
            "auth",
            "Authorization",
            "bearer",
            "api_key",
            "API_KEY",
            "apikey",
            "ApiKey",
            "APIKey",
            "api-key",
            "secret_key",
            "secretKey",
            "private_key",
            "privateKey",
            "privatekey",
            "ssh_key",
            "key",
            "access.key",
            "to\u{200b}ken",
            "\u{ff54}\u{ff4f}\u{ff4b}\u{ff45}\u{ff4e}", // fullwidth "token"
            "\u{ff21}\u{ff30}\u{ff29}_\u{ff2b}\u{ff25}\u{ff39}", // fullwidth "API_KEY"
        ] {
            assert!(secret_like_key(k), "{k:?} must be refused");
        }
        for k in [
            "monkey",
            "hotkey",
            "turkey",
            "keyboard_layout",
            "keyword",
            "author",
            "authority",
            "region",
            "port",
            "labels",
            "device_label",
            "hostname",
            "cwd",
        ] {
            assert!(!secret_like_key(k), "{k:?} must pass");
        }
    }

    #[test]
    fn credential_values_are_caught_and_ordinary_text_passes() {
        let aws = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        let google = ["AIza", "SyA-0123456789abcdefghijklmnopqrstu"].concat();
        let gitlab = ["glpat-", "abcdefghij0123456789"].concat();
        let high = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fG3hJ5kL7n".to_string();
        let fullwidth_sk = "\u{ff53}\u{ff4b}-proj0123456789abcdef".to_string();
        for v in [
            jwt_like(),
            format!("Authorization: Bearer {}", "abcdefgh12345678"),
            "bearer abcdefgh".to_string(),
            google,
            gitlab,
            aws,
            pem(),
            high.clone(),
            format!("key={high}"),
            fullwidth_sk,
            ["gho_", "0123456789abcdefghijklmnop"].concat(),
        ] {
            assert!(credential_like_text(&v), "{v:?} must be refused");
        }
        for v in [
            "hello world",
            "sk-SK",
            "xoxo",
            "eyJ is a prefix",
            "eyJhbGci.short",
            "Bearer",
            "bearer of good news",
            "https://example.com/some/long/path/segment/that/goes/on/and/on",
            "/usr/local/share/applications/some-application-name.desktop",
            "11111111-2222-4333-8444-555555555555",
            &"ab".repeat(32),              // sha256-style hex digest
            &"0123456789abcdef".repeat(4), // hex, 4.0 bits at most
            "the-quick-brown-fox-jumps-over-the-lazy-dog-1234567890",
            "Europe/Berlin",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(!credential_like_text(v), "{v:?} must pass");
        }
    }

    #[tokio::test]
    async fn new_secret_rules_apply_over_http_and_the_422_says_best_effort() {
        let e = env();
        for (k, v) in [
            ("db_pwd", json!("x")),
            ("credential", json!("x")),
            ("private_key", json!("x")),
            ("note", json!(jwt_like())),
            ("note", json!("aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fG3hJ5kL7n")),
        ] {
            let mut p = payload("x");
            p["values"] = json!({ k: v });
            let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
            assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY, "{k}");
            assert!(r.text.contains("best-effort"), "{}", r.text);
        }
        let mut p = payload("ok");
        p["values"] = json!({
            "monkey": "business", "hotkey": "ctrl+k", "digest": "ab".repeat(32), "tz": "Europe/Berlin",
            "uuid": "11111111-2222-4333-8444-555555555555",
        });
        let r = send(&e.app, "POST", "/me/installations", "alice", None, Some(p)).await;
        assert_eq!(r.status, StatusCode::CREATED, "{}", r.text);
    }

    /// Request as a browser would send it with the portal session cookie (no bearer).
    async fn cookie_send(
        app: &Router,
        method: &str,
        uri: &str,
        sub: &str,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> StatusCode {
        let cookie = crate::portal::sign_session_for_test(SESSION_KEY, sub);
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "portal.example.test")
            .header("cookie", format!("ct_portal_session={cookie}"));
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn cookie_authenticated_writes_must_be_same_origin() {
        let e = env();
        let id = create_as(&e.app, "alice", "mine").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let item = format!("/me/installations/{id}");
        let dup = format!("{item}/duplicate");
        let writes: Vec<(&str, String, Option<Value>)> = vec![
            (
                "POST",
                "/me/installations".to_string(),
                Some(payload("csrf")),
            ),
            ("PUT", item.clone(), Some(payload("csrf"))),
            ("DELETE", item.clone(), None),
            ("POST", dup.clone(), None),
            (
                "POST",
                "/me/installations/import".to_string(),
                Some(json!({ "installations": [] })),
            ),
        ];
        let foreign: [&[(&str, &str)]; 5] = [
            &[("origin", "https://evil.example")],
            &[("origin", "https://tunnel.portal.example.test")], // same site, other origin
            &[("sec-fetch-site", "cross-site")],
            &[("sec-fetch-site", "same-site")],
            &[
                ("sec-fetch-site", "same-origin"),
                ("origin", "https://evil.example"),
            ],
        ];
        for (m, u, b) in &writes {
            for hdrs in foreign {
                let mut h = hdrs.to_vec();
                if *m == "PUT" {
                    h.push(("if-match", "1"));
                }
                assert_eq!(
                    cookie_send(&e.app, m, u, "alice", &h, b.clone()).await,
                    StatusCode::FORBIDDEN,
                    "{m} {u} {hdrs:?}"
                );
            }
        }
        // Nothing happened.
        let r = send(&e.app, "GET", &item, "alice", None, None).await;
        assert_eq!(
            (r.body["revision"].as_i64(), r.body["status"].as_str()),
            (Some(1), Some("draft"))
        );
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            1
        );

        // Same-origin cookie requests, and cookie-less tools, still work.
        let ok = cookie_send(
            &e.app,
            "POST",
            &dup,
            "alice",
            &[
                ("origin", "https://portal.example.test"),
                ("sec-fetch-site", "same-origin"),
            ],
            None,
        )
        .await;
        assert_eq!(ok, StatusCode::CREATED);
        let ok = cookie_send(
            &e.app,
            "POST",
            "/me/installations",
            "alice",
            &[],
            Some(payload("no browser headers")),
        )
        .await;
        assert_eq!(ok, StatusCode::CREATED);
        // Cookie GET with a foreign origin is a read and stays allowed (CORS blocks reading it).
        assert_eq!(
            cookie_send(
                &e.app,
                "GET",
                &item,
                "alice",
                &[("origin", "https://evil.example")],
                None
            )
            .await,
            StatusCode::OK
        );

        // Bearer callers are exempt: they cannot be forged cross-site.
        let mut req = Request::post("/me/installations")
            .header("authorization", format!("Bearer {}", jwt("alice")))
            .header("origin", "https://evil.example")
            .header("content-type", "application/json")
            .body(Body::from(payload("bearer").to_string()))
            .unwrap();
        req.headers_mut()
            .insert("host", "portal.example.test".parse().unwrap());
        assert_eq!(
            e.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn duplicate_requires_a_json_content_type_for_a_body() {
        let e = env();
        let id = create_as(&e.app, "alice", "src").await["id"]
            .as_str()
            .unwrap()
            .to_string();
        let url = format!("/me/installations/{id}/duplicate");
        for ct in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ] {
            let req = Request::post(&url)
                .header("authorization", format!("Bearer {}", jwt("alice")))
                .header("content-type", ct)
                .body(Body::from(r#"{"name":"x"}"#))
                .unwrap();
            assert_eq!(
                e.app.clone().oneshot(req).await.unwrap().status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{ct}"
            );
        }
        let req = Request::post(&url)
            .header("authorization", format!("Bearer {}", jwt("alice")))
            .body(Body::from(r#"{"name":"x"}"#))
            .unwrap();
        assert_eq!(
            e.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "no content type"
        );
        let req = Request::post(&url)
            .header("authorization", format!("Bearer {}", jwt("alice")))
            .header("content-type", "application/json; charset=utf-8")
            .body(Body::from(r#"{"name":"x"}"#))
            .unwrap();
        assert_eq!(
            e.app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::CREATED
        );
        assert_eq!(
            send(&e.app, "GET", "/me/installations", "alice", None, None)
                .await
                .body["total"],
            2,
            "refused calls created nothing"
        );
    }

    #[test]
    fn concurrent_writers_on_one_database_file_never_hit_a_busy_upgrade() {
        let path = std::env::temp_dir().join(format!("ct-installations-conc-{}.db", new_uuid()));
        let path_s = path.to_str().unwrap().to_string();
        let acct = AccountId([9; 32]);
        SqliteInstallationStore::open(&path_s).unwrap();
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let path_s = path_s.clone();
                std::thread::spawn(move || {
                    let acct = AccountId([9; 32]);
                    let store = SqliteInstallationStore::open(&path_s).unwrap();
                    for i in 0..25 {
                        let out = store
                            .create(&acct, &input(&format!("t{t}-{i}")), 1)
                            .unwrap();
                        assert!(matches!(out, CreateOutcome::Created(_)));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let store = SqliteInstallationStore::open(&path_s).unwrap();
        assert_eq!(store.list(&acct, None, 1, 0).unwrap().1, 100);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path_s}{suffix}"));
        }
    }
}

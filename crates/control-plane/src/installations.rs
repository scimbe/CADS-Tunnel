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
//! * **No secrets.** `values` is customer input that gets stored, so credential-looking
//!   keys and values are refused with `422` ([`scan_for_secrets`]).
//! * **Optimistic concurrency.** `PUT` needs `If-Match: <revision>`; each update archives
//!   the superseded state in `installation_revisions` (the last [`MAX_REVISIONS`]).
//! * **Soft delete.** `DELETE` sets `status = removed`; the newest [`KEEP_REMOVED`]
//!   removed records stay restorable, older ones are purged on the next write.
//!
//! Auth, state and error conventions follow `/me/service-accounts` and `/me/topologies`
//! (portal session cookie or OIDC bearer, plain-text errors).

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, ETAG, LOCATION};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ct_common::sync::MutexExt;
use ct_common::time::now_secs;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Is `key` a name that holds a secret (`token|secret|password|api_key|key$`, case-insensitive)?
fn secret_like_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.contains("token")
        || k.contains("secret")
        || k.contains("password")
        || k.contains("api_key")
        || k.ends_with("key")
}

/// Does `text` contain a word that starts like a well-known credential, or a PEM block?
/// Credential prefixes only count on words of 10+ characters, so ordinary short words
/// (`"sk-SK"`, `"xoxo"`) do not trip it.
fn credential_like_text(text: &str) -> bool {
    if text.contains("-----BEGIN") {
        return true;
    }
    text.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '=' | ':'))
        .any(|w| {
            w.chars().count() >= 10
                && ["sk-", "ghp_", "xox", "AKIA"]
                    .iter()
                    .any(|p| w.starts_with(p))
        })
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
                        "{child_path}: key looks like a secret (token, secret, password, api_key or *key); \
                         secrets are never stored, enter them on the target device instead"
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
                "{path}: value looks like a credential (sk-, ghp_, xox, AKIA or a PEM block); \
                 secrets are never stored, enter them on the target device instead"
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
    check_ident("template_id", &input.template_id, true)?;
    check_ident("template_digest", &input.template_digest, false)?;
    check_ident("values_digest", &input.values_digest, false)?;
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
        if c.sha256.len() != 64 || !c.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("components[{i}].sha256 must be 64 hex characters"));
        }
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
        if k.len() != 64 || !k.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("target.agent_holder_pubkey must be 64 hex characters".to_string());
        }
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

    /// Insert a new installation (count check and insert under one lock and transaction).
    pub fn create(
        &self,
        account: &AccountId,
        input: &InstallationInput,
        now: i64,
    ) -> rusqlite::Result<CreateOutcome> {
        let mut guard = self.conn.lock_safe();
        let tx = guard.transaction()?;
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
        let tx = guard.transaction()?;
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
        let tx = guard.transaction()?;
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
        let tx = guard.transaction()?;
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
        let tx = guard.transaction()?;
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

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthedInstallationState {
    store: Arc<SqliteInstallationStore>,
    ledger: Arc<SqliteLedger>,
    verifier: OidcVerifierHandle,
    session_key: Arc<[u8]>,
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
        .with_state(AuthedInstallationState {
            store,
            ledger,
            verifier,
            session_key,
        })
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

fn account_of(st: &AuthedInstallationState, headers: &HeaderMap) -> Result<AccountId, ApiError> {
    let subject = crate::service::subject_of_topology(&st.session_key, &st.verifier, headers)?;
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

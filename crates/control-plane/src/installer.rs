//! Per-OS agent install one-liners (#28) — pure command renderers.
//!
//! The portal offers a customer a copy-paste command that downloads, onboards
//! and starts a `ct-agent` for one of their tunnels, realising it over the
//! Plane edge. This module renders that command string for each OS family.
//!
//! **Secret handling (critical).** The join token is a secret. It is minted
//! server-side, single-use and short-lived by the caller (a later sub-packet);
//! this renderer only *embeds* a token it is given — it never mints, stores or
//! logs one. The token is passed to the install script through an **environment
//! variable**, never as a positional argument, so it stays out of the script's
//! `argv`. Tests use dummy tokens only.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

/// Default GitHub-Releases asset base the served scripts download `ct-agent` from
/// (#75 IS2 — matches the asset names `release.yml` publishes). Overridable at
/// deploy time via `CT_RELEASE_BASE` (e.g. a mirror or a pinned tag).
pub const DEFAULT_RELEASE_BASE: &str =
    "https://github.com/scimbe/CADS-Tunnel/releases/latest/download";

/// Target OS family for the copy-paste installer command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOs {
    /// Linux and macOS — POSIX `sh`.
    Unix,
    /// Windows — PowerShell.
    Windows,
}

impl InstallOs {
    /// Parse the `os` query/path value used by the portal (`linux`, `macos`,
    /// `darwin`, `unix` → Unix; `windows`, `win` → Windows). Case-insensitive.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "linux" | "macos" | "darwin" | "unix" | "mac" => Some(Self::Unix),
            "windows" | "win" => Some(Self::Windows),
            _ => None,
        }
    }
}

/// Render the copy-paste one-liner that installs + onboards a `ct-agent`.
///
/// `portal_base` is the public portal origin (e.g. `https://portal.example`).
/// `join_token` is a freshly-minted, single-use join token. `routing_token` is
/// the tunnel's persistent routing token (#27 RB1) so the agent registers at the
/// edge under the token the portal knows — the linkage a revocation acts on
/// (#27 RB2). Both are carried in environment variables so they never land in the
/// piped shell's argument vector.
pub fn install_one_liner(
    portal_base: &str,
    join_token: &str,
    routing_token: &str,
    os: InstallOs,
) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        // curl the installer, hand the tokens to it via the environment, run it.
        InstallOs::Unix => format!(
            "curl -fsSL {base}/install.sh | CT_JOIN_TOKEN={join_token} CT_AGENT_TOKEN={routing_token} sh"
        ),
        // Set the env vars for the child scope, then fetch + invoke the script.
        InstallOs::Windows => format!(
            "$env:CT_JOIN_TOKEN='{join_token}'; $env:CT_AGENT_TOKEN='{routing_token}'; irm {base}/install.ps1 | iex"
        ),
    }
}

/// Encode the real install secrets — the single-use `join_token` and the tunnel's
/// persistent `routing_token` — as the opaque `secret` payload a bootstrap token
/// carries (#90/#97 SEC90b). The portal mints a bootstrap token over this bundle
/// (`SqliteBootstrap::mint`); the agent redeems the bootstrap token server-side
/// (`POST /bootstrap/redeem`) and [`parse_install_bundle`]s the result back into the
/// two tokens — so the real secrets travel in the TLS response body, never in the
/// one-liner's command string.
///
/// The format is the deliberately shell-tractable `CT_JOIN_TOKEN=<hex>;CT_AGENT_TOKEN=<hex>`:
/// the redeem JSON nests this whole bundle inside its `secret` string, and the tokens
/// are hex (no quotes/whitespace/`;`/`=` collisions), so the install script extracts
/// `secret` and then each token with a single `sed` each — no nested-JSON parsing and
/// no `eval` of server data.
pub fn install_bundle_secret(join_token: &str, routing_token: &str) -> String {
    format!("CT_JOIN_TOKEN={join_token};CT_AGENT_TOKEN={routing_token}")
}

/// Parse the bundle produced by [`install_bundle_secret`] back into
/// `(join_token, routing_token)`. Returns `None` if either field is missing.
pub fn parse_install_bundle(secret: &str) -> Option<(String, String)> {
    let mut join = None;
    let mut routing = None;
    for field in secret.split(';') {
        if let Some(v) = field.strip_prefix("CT_JOIN_TOKEN=") {
            join = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("CT_AGENT_TOKEN=") {
            routing = Some(v.to_string());
        }
    }
    Some((join?, routing?))
}

/// Render the copy-paste one-liner in its **bootstrap-token** form (#90/#97 SEC90b):
/// the command carries only a short-lived, single-use `bootstrap_token` — never the
/// real join/routing tokens — so nothing secret lands in shell history or `ps`. The
/// install script redeems `CT_BOOTSTRAP` server-side (`POST {portal}/bootstrap/redeem`)
/// for the real [`install_bundle_secret`] bundle. This is the secret-hygiene upgrade
/// over [`install_one_liner`], whose embedded-token form remains for the manual path
/// and back-compat until the live install flow (#75) adopts this.
pub fn install_one_liner_bootstrap(portal_base: &str, bootstrap_token: &str, os: InstallOs) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        InstallOs::Unix => {
            format!("curl -fsSL {base}/install.sh | CT_BOOTSTRAP={bootstrap_token} sh")
        }
        InstallOs::Windows => {
            format!("$env:CT_BOOTSTRAP='{bootstrap_token}'; irm {base}/install.ps1 | iex")
        }
    }
}

/// Which side of an Agent-Fabric channel a one-liner brings the machine up as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelSide {
    /// Binds and waits for the peer to dial (grant `Direction::Accept`).
    Responder,
    /// Dials the responder's advertised endpoint (grant `Direction::Initiate`).
    Initiator,
}

/// Everything a per-test-system A2A channel one-liner needs (#100). The keys/cert
/// travel in **environment variables** (never argv), matching the `ct-agent channel`
/// subcommand's `CT_CHANNEL_*` contract and the install one-liner's secret hygiene.
pub struct ChannelOneLiner<'a> {
    pub side: ChannelSide,
    /// Responder: the local bind address (`0.0.0.0:<port>`). Initiator: the peer's
    /// advertised `host:port`.
    pub addr: &'a str,
    /// This member's Noise (X25519) **private** key, hex.
    pub own_noise_private_hex: &'a str,
    /// The peer member's Noise **public** key, hex (pinned by the initiator).
    pub peer_noise_public_hex: &'a str,
    /// Initiator only: the responder's QUIC cert (hex DER) to trust for the dial.
    pub peer_cert_hex: Option<&'a str>,
}

/// Render the copy-paste command that brings a machine up as one side of an A2A
/// channel and pipes stdin/stdout over the encrypted tunnel (#100). It targets the
/// already-installed `ct-agent channel` subcommand (run the install one-liner first),
/// setting the `CT_CHANNEL_*` env the subcommand reads. The Noise keys/cert ride in
/// the environment, never the argument vector (SEC90 hygiene; the still-inline-secret
/// concern is #97). `os` selects the POSIX `env VAR=… cmd` vs PowerShell `$env:` form.
pub fn channel_one_liner(p: &ChannelOneLiner, os: InstallOs) -> String {
    let role = match p.side {
        ChannelSide::Responder => "accept",
        ChannelSide::Initiator => "initiate",
    };
    match os {
        InstallOs::Unix => {
            let mut cmd = format!(
                "CT_CHANNEL_ROLE={role} CT_CHANNEL_ADDR={addr} \
                 CT_CHANNEL_NOISE_KEY={own} CT_CHANNEL_PEER_NOISE_KEY={peer}",
                addr = p.addr,
                own = p.own_noise_private_hex,
                peer = p.peer_noise_public_hex,
            );
            if let Some(cert) = p.peer_cert_hex {
                cmd.push_str(&format!(" CT_CHANNEL_PEER_CERT={cert}"));
            }
            cmd.push_str(" ct-agent channel");
            cmd
        }
        InstallOs::Windows => {
            let mut cmd = format!(
                "$env:CT_CHANNEL_ROLE='{role}'; $env:CT_CHANNEL_ADDR='{addr}'; \
                 $env:CT_CHANNEL_NOISE_KEY='{own}'; $env:CT_CHANNEL_PEER_NOISE_KEY='{peer}'; ",
                addr = p.addr,
                own = p.own_noise_private_hex,
                peer = p.peer_noise_public_hex,
            );
            if let Some(cert) = p.peer_cert_hex {
                cmd.push_str(&format!("$env:CT_CHANNEL_PEER_CERT='{cert}'; "));
            }
            cmd.push_str("ct-agent channel");
            cmd
        }
    }
}

/// Encode a channel member's `CT_CHANNEL_*` config as the opaque `secret` payload a
/// bootstrap token carries (#100 / #97 SEC90b) — the A2A analog of
/// [`install_bundle_secret`]. The member's **Noise private key** is a real secret, so
/// carrying it inline in the one-liner (as `channel_one_liner` does) exposes it to
/// shell history / `ps`. Instead the operator mints a bootstrap token over this bundle
/// and the channel one-liner carries only that; `channel.sh` redeems it server-side.
/// Flat, shell-tractable `K=V;K=V` (values are hex / `host:port` / `accept|initiate` —
/// no quotes/`;`/`=` collisions), so the script lifts each field with one `sed`.
pub fn channel_bundle_secret(p: &ChannelOneLiner) -> String {
    let role = match p.side {
        ChannelSide::Responder => "accept",
        ChannelSide::Initiator => "initiate",
    };
    let mut s = format!(
        "CT_CHANNEL_ROLE={role};CT_CHANNEL_ADDR={addr};CT_CHANNEL_NOISE_KEY={own};CT_CHANNEL_PEER_NOISE_KEY={peer}",
        addr = p.addr,
        own = p.own_noise_private_hex,
        peer = p.peer_noise_public_hex,
    );
    if let Some(cert) = p.peer_cert_hex {
        s.push_str(&format!(";CT_CHANNEL_PEER_CERT={cert}"));
    }
    s
}

/// Render the channel one-liner in its **bootstrap-token** form (#100 / #97 SEC90b):
/// the command carries only a short-lived, single-use `bootstrap_token` — never the
/// member's Noise private key — so nothing secret lands in shell history / `ps`.
/// `channel.sh` redeems `CT_BOOTSTRAP` server-side (`POST {portal}/bootstrap/redeem`)
/// for the [`channel_bundle_secret`] config. The secret-hygiene upgrade over
/// [`channel_one_liner`], whose inline-secret form remains for the manual path.
pub fn channel_one_liner_bootstrap(portal_base: &str, bootstrap_token: &str, os: InstallOs) -> String {
    let base = portal_base.trim_end_matches('/');
    match os {
        InstallOs::Unix => {
            format!("curl -fsSL {base}/channel.sh | CT_BOOTSTRAP={bootstrap_token} sh")
        }
        InstallOs::Windows => {
            format!("$env:CT_BOOTSTRAP='{bootstrap_token}'; irm {base}/channel.ps1 | iex")
        }
    }
}

/// Everything the **broker-mediated** A2A one-liner needs (#100): the plane path where
/// two members rendezvous through the edge channel broker (and fall back to the edge
/// relay) rather than exchanging endpoints out of band. Mirrors the `CT_CHANNEL_*`
/// brokered env `ct-agent channel` reads (`ChannelJoinCliConfig`). The grant + the two
/// private keys ride in the environment, never argv (SEC90; the still-inline-secret
/// concern is #97, addressed for the direct form by [`channel_one_liner_bootstrap`]).
pub struct BrokeredChannelOneLiner<'a> {
    pub side: ChannelSide,
    /// Edge rendezvous endpoint (`CT_CHANNEL_BROKER`, host:port).
    pub broker: &'a str,
    /// Edge relay endpoint used on direct-dial failure (`CT_CHANNEL_RELAY`, host:port).
    pub relay: &'a str,
    /// The operator-signed channel grant this member holds (`CT_CHANNEL_GRANT`, hex).
    pub grant_hex: &'a str,
    /// The holder ed25519 **private** key proving possession (`CT_CHANNEL_HOLDER_KEY`, hex).
    pub holder_key_hex: &'a str,
    /// This member's Noise (X25519) **private** key (`CT_CHANNEL_NOISE_KEY`, hex).
    pub noise_key_hex: &'a str,
    /// The host:port this member advertises for the direct path (`CT_CHANNEL_LISTEN`).
    pub listen: &'a str,
}

/// Render the copy-paste command that brings a machine up as a channel member via the
/// **edge broker** (#100 plane path): it rendezvous through `CT_CHANNEL_BROKER`, dials the
/// peer direct, and falls back to `CT_CHANNEL_RELAY` — the broker relays the peer's
/// attested Noise key, so no out-of-band peer key is needed. Targets the shipped
/// `ct-agent channel` subcommand (brokered branch); keys/grant ride in `CT_CHANNEL_*`
/// env, never argv. `os` selects POSIX `env VAR=… cmd` vs PowerShell `$env:`.
pub fn brokered_channel_one_liner(p: &BrokeredChannelOneLiner, os: InstallOs) -> String {
    let role = match p.side {
        ChannelSide::Responder => "accept",
        ChannelSide::Initiator => "initiate",
    };
    match os {
        InstallOs::Unix => format!(
            "CT_CHANNEL_ROLE={role} CT_CHANNEL_BROKER={broker} CT_CHANNEL_RELAY={relay} \
             CT_CHANNEL_GRANT={grant} CT_CHANNEL_HOLDER_KEY={hk} CT_CHANNEL_NOISE_KEY={nk} \
             CT_CHANNEL_LISTEN={listen} ct-agent channel",
            broker = p.broker,
            relay = p.relay,
            grant = p.grant_hex,
            hk = p.holder_key_hex,
            nk = p.noise_key_hex,
            listen = p.listen,
        ),
        InstallOs::Windows => format!(
            "$env:CT_CHANNEL_ROLE='{role}'; $env:CT_CHANNEL_BROKER='{broker}'; \
             $env:CT_CHANNEL_RELAY='{relay}'; $env:CT_CHANNEL_GRANT='{grant}'; \
             $env:CT_CHANNEL_HOLDER_KEY='{hk}'; $env:CT_CHANNEL_NOISE_KEY='{nk}'; \
             $env:CT_CHANNEL_LISTEN='{listen}'; ct-agent channel",
            broker = p.broker,
            relay = p.relay,
            grant = p.grant_hex,
            hk = p.holder_key_hex,
            nk = p.noise_key_hex,
            listen = p.listen,
        ),
    }
}

/// Render the POSIX `/channel.sh` script the A2A one-liner pipes into `sh` (#100).
/// It detects OS+arch, downloads the matching prebuilt `ct-agent` from `release_base`,
/// and execs `ct-agent channel` — which reads the `CT_CHANNEL_*` config (role, addr,
/// Noise keys) from the environment the one-liner set, so no key is ever a script
/// argument. The served route is in [`installer_router`].
pub fn render_channel_sh(portal_base: &str, release_base: &str) -> String {
    let base = release_base.trim_end_matches('/');
    let portal = portal_base.trim_end_matches('/');
    format!(
        r#"#!/bin/sh
# CADS-Tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   curl -fsSL <portal>/channel.sh | CT_BOOTSTRAP=... sh
# Brings this machine up as a channel member and pipes stdin/stdout over the
# encrypted agent-to-agent tunnel.
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "ct-agent channel: unsupported architecture '$arch'" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "ct-agent channel: unsupported OS '$os'" >&2; exit 1 ;;
esac

# #100 / #97 SEC90b: if a short-lived bootstrap token is set, redeem it server-side
# over TLS for the channel config (keeps the Noise private key off the command line /
# shell history / ps); otherwise fall back to CT_CHANNEL_* set directly (manual path).
if [ -n "${{CT_BOOTSTRAP:-}}" ]; then
  resp=$(curl -fsSL -X POST -H 'content-type: application/json' \
    --data "{{\"token\":\"$CT_BOOTSTRAP\"}}" "{portal}/bootstrap/redeem")
  bundle=$(printf '%s' "$resp" | sed -n 's/.*"secret":"\([^"]*\)".*/\1/p')
  CT_CHANNEL_ROLE=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_ROLE=\([^;"]*\).*/\1/p')
  CT_CHANNEL_ADDR=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_ADDR=\([^;"]*\).*/\1/p')
  CT_CHANNEL_NOISE_KEY=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_NOISE_KEY=\([^;"]*\).*/\1/p')
  CT_CHANNEL_PEER_NOISE_KEY=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_PEER_NOISE_KEY=\([^;"]*\).*/\1/p')
  export CT_CHANNEL_ROLE CT_CHANNEL_ADDR CT_CHANNEL_NOISE_KEY CT_CHANNEL_PEER_NOISE_KEY
  cert=$(printf '%s' "$bundle" | sed -n 's/.*CT_CHANNEL_PEER_CERT=\([^;"]*\).*/\1/p')
  [ -n "$cert" ] && export CT_CHANNEL_PEER_CERT="$cert"
fi
: "${{CT_CHANNEL_ROLE:?set CT_BOOTSTRAP (or CT_CHANNEL_ROLE: accept|initiate)}}"
: "${{CT_CHANNEL_ADDR:?set CT_BOOTSTRAP (or CT_CHANNEL_ADDR: bind host:port for accept, peer host:port for initiate)}}"
: "${{CT_CHANNEL_NOISE_KEY:?set CT_BOOTSTRAP (or CT_CHANNEL_NOISE_KEY: this member's Noise private key, hex)}}"
: "${{CT_CHANNEL_PEER_NOISE_KEY:?set CT_BOOTSTRAP (or CT_CHANNEL_PEER_NOISE_KEY: the peer's Noise public key, hex)}}"

asset="ct-agent-${{os}}-${{arch}}"
url="{base}/${{asset}}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "ct-agent channel: downloading $url" >&2
curl -fsSL "$url" -o "$tmp/ct-agent"
chmod +x "$tmp/ct-agent"
# Keys are inherited from the environment (never on the command line).
exec "$tmp/ct-agent" channel
"#,
        base = base,
        portal = portal,
    )
}

/// Render the PowerShell `/channel.ps1` script (#100 — the Windows analog of
/// [`render_channel_sh`]). Detects the arch, downloads `ct-agent-windows-<arch>.exe`
/// from `release_base`, and runs `ct-agent channel` reading `CT_CHANNEL_*` from the
/// environment. Placeholder + replace so PowerShell's `{}` need no brace-escaping.
pub fn render_channel_ps1(portal_base: &str, release_base: &str) -> String {
    CHANNEL_PS1_TEMPLATE
        .replace("__RELEASE_BASE__", release_base.trim_end_matches('/'))
        .replace("__PORTAL_BASE__", portal_base.trim_end_matches('/'))
}

const CHANNEL_PS1_TEMPLATE: &str = r#"#Requires -Version 5
# CADS-Tunnel agent-to-agent channel runner (#100). Piped from the operator one-liner:
#   $env:CT_BOOTSTRAP='...'; irm <portal>/channel.ps1 | iex
$ErrorActionPreference = 'Stop'
# #100 / #97 SEC90b: redeem a short-lived bootstrap token server-side over TLS for the
# channel config (keeps the Noise private key off the command line); else fall back to
# CT_CHANNEL_* set directly (manual path).
if ($env:CT_BOOTSTRAP) {
  $resp = Invoke-RestMethod -Method Post -Uri '__PORTAL_BASE__/bootstrap/redeem' -ContentType 'application/json' -Body (ConvertTo-Json @{ token = $env:CT_BOOTSTRAP })
  $bundle = $resp.secret
  if ($bundle -match 'CT_CHANNEL_ROLE=([^;]*)')           { $env:CT_CHANNEL_ROLE = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_ADDR=([^;]*)')           { $env:CT_CHANNEL_ADDR = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_NOISE_KEY=([^;]*)')      { $env:CT_CHANNEL_NOISE_KEY = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_PEER_NOISE_KEY=([^;]*)') { $env:CT_CHANNEL_PEER_NOISE_KEY = $Matches[1] }
  if ($bundle -match 'CT_CHANNEL_PEER_CERT=([^;]*)')      { $env:CT_CHANNEL_PEER_CERT = $Matches[1] }
}
if (-not $env:CT_CHANNEL_ROLE)            { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_ROLE: accept|initiate)'; exit 1 }
if (-not $env:CT_CHANNEL_ADDR)            { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_ADDR)'; exit 1 }
if (-not $env:CT_CHANNEL_NOISE_KEY)       { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_NOISE_KEY)'; exit 1 }
if (-not $env:CT_CHANNEL_PEER_NOISE_KEY)  { Write-Error 'ct-agent channel: set CT_BOOTSTRAP (or CT_CHANNEL_PEER_NOISE_KEY)'; exit 1 }
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64' }
  'ARM64' { 'aarch64' }
  default { Write-Error "ct-agent channel: unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'"; exit 1 }
}
$asset = "ct-agent-windows-$arch.exe"
$url = "__RELEASE_BASE__/$asset"
$dir = Join-Path $env:TEMP ("ct-agent-" + [System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$exe = Join-Path $dir $asset
Write-Host "ct-agent channel: downloading $url"
Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing
# Keys are inherited from the environment (never on the command line).
& $exe channel
"#;

/// `/install.sh` and `/install.ps1` (#75 IS3b originally, now retired in favor of
/// ct-agent's own richer setup script) redirect to that script's raw content
/// (`serve_install_sh`/`serve_install_ps1`) rather than serving a rendered one —
/// any existing `curl -fsSL <portal>/install.sh | … sh` one-liner keeps working
/// transparently. `/channel.sh`/`/channel.ps1` are unaffected: a different
/// subcommand (Agent-Fabric channel setup, not the tunnel-install path this
/// script's replacement covers), still rendered and served directly.
pub fn installer_router(portal_base: String, release_base: String) -> Router {
    Router::new()
        .route("/install.sh", get(serve_install_sh))
        .route("/install.ps1", get(serve_install_ps1))
        // #100: the A2A channel runner scripts, served the same way as the installer.
        .route("/channel.sh", get(serve_channel_sh))
        .route("/channel.ps1", get(serve_channel_ps1))
        .with_state(InstallerState {
            portal_base: Arc::new(portal_base),
            release_base: Arc::new(release_base),
        })
}

/// Served-script config: the portal origin (for the bootstrap-redeem call
/// /channel.sh|.ps1 make) and the release asset base (for the `ct-agent`
/// download). `/install.sh`|`.ps1` need neither -- they're a plain redirect.
#[derive(Clone)]
struct InstallerState {
    portal_base: Arc<String>,
    release_base: Arc<String>,
}

/// `ct-agent` moved to its own repo (scimbe/ct-agent), which ships a much richer
/// guided setup script (environment checks, a Docker mode, Rot/Gelb/Grün status
/// reporting, stop/reset commands) than this thin one-liner ever did. Rather than
/// leave old `curl -fsSL <portal>/install.sh | sh` links/docs dead, redirect them
/// straight to that script's raw content -- `curl -fsSL` follows redirects, so
/// existing invocations keep working transparently and just get the better script.
const CT_AGENT_SETUP_SH: &str = "https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh";
const CT_AGENT_SETUP_PS1: &str = "https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1";

/// #448: a self-hosting operator (this product's own stated audience) previously had
/// no way to point this redirect at their own mirror without patching the crate --
/// a single chokepoint on `raw.githubusercontent.com` for a censorship-resistant,
/// explicitly self-hostable service. `CT_AGENT_SETUP_URL`/`CT_AGENT_SETUP_PS1_URL`
/// override the default when set; unset behaves exactly as before (verified by the
/// existing tests below, which set neither). Pinning to a release tag + publishing a
/// SHA-256 for `channel.sh`/`channel.ps1` to verify (this issue's other half) is
/// deliberately NOT done here -- it needs a real tagged `ct-agent` release to pin to,
/// which doesn't exist yet (this workspace's other git-dependency pins are all by
/// commit rev for the same reason); tracked separately, not attempted in this pass.
fn ct_agent_setup_sh_url() -> String {
    std::env::var("CT_AGENT_SETUP_URL").unwrap_or_else(|_| CT_AGENT_SETUP_SH.to_string())
}

fn ct_agent_setup_ps1_url() -> String {
    std::env::var("CT_AGENT_SETUP_PS1_URL").unwrap_or_else(|_| CT_AGENT_SETUP_PS1.to_string())
}

async fn serve_install_sh() -> Redirect {
    Redirect::temporary(&ct_agent_setup_sh_url())
}

async fn serve_install_ps1() -> Redirect {
    Redirect::temporary(&ct_agent_setup_ps1_url())
}

async fn serve_channel_sh(State(st): State<InstallerState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        render_channel_sh(&st.portal_base, &st.release_base),
    )
        .into_response()
}

async fn serve_channel_ps1(State(st): State<InstallerState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        render_channel_ps1(&st.portal_base, &st.release_base),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn channel_scripts_are_served_and_exec_ct_agent_channel() {
        // #100: /channel.sh + /channel.ps1 are served (like /install.sh) and run
        // `ct-agent channel`, requiring the CT_CHANNEL_* keys from the environment
        // (never argv) and downloading the agent from the release base.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let portal = "https://portal.example";
        let base = "https://github.com/scimbe/CADS-Tunnel/releases/latest/download";

        // Content: POSIX script requires the channel env, execs the subcommand.
        let sh = render_channel_sh(portal, base);
        assert!(sh.starts_with("#!/bin/sh") && sh.contains("set -eu"), "POSIX + fail-fast");
        assert!(sh.contains("CT_CHANNEL_ROLE:?") && sh.contains("CT_CHANNEL_NOISE_KEY:?"), "requires channel env");
        assert!(sh.contains(r#"exec "$tmp/ct-agent" channel"#), "execs ct-agent channel");
        assert!(sh.contains(&format!("{base}/${{asset}}")), "downloads from the release base");
        assert!(!sh.contains("channel $CT_CHANNEL_NOISE_KEY"), "keys stay in the env, not argv");
        // #100/#97 SEC90b: the channel script also redeems CT_BOOTSTRAP against the portal.
        assert!(sh.contains(r#"if [ -n "${CT_BOOTSTRAP:-}" ]; then"#), "has the bootstrap-redeem branch");
        assert!(sh.contains("https://portal.example/bootstrap/redeem"), "redeems against the portal");
        let ps = render_channel_ps1(portal, base);
        assert!(ps.contains("#Requires -Version 5") && ps.contains("& $exe channel"), "ps runs channel");
        assert!(ps.contains("$env:CT_CHANNEL_ROLE"), "ps requires the channel env");
        assert!(ps.contains("if ($env:CT_BOOTSTRAP)"), "ps has the bootstrap-redeem branch");

        // Route: GET /channel.sh -> 200 serving exactly the rendered script.
        let app = installer_router(portal.to_string(), base.to_string());
        let resp = app
            .clone()
            .oneshot(Request::get("/channel.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "/channel.sh is served");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(String::from_utf8(body.to_vec()).unwrap(), render_channel_sh(portal, base), "serves the rendered script");
        let resp2 = app
            .oneshot(Request::get("/channel.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK, "/channel.ps1 is served");
    }

    #[test]
    fn channel_one_liner_renders_the_ct_agent_channel_command() {
        // #100: the copy-paste A2A one-liner. Keys ride in CT_CHANNEL_* env, never
        // argv; the responder needs no peer cert, the initiator carries one; the
        // command invokes `ct-agent channel`.
        let responder = ChannelOneLiner {
            side: ChannelSide::Responder,
            addr: "0.0.0.0:9443",
            own_noise_private_hex: "a1a1",
            peer_noise_public_hex: "b2b2",
            peer_cert_hex: None,
        };
        let sh = channel_one_liner(&responder, InstallOs::Unix);
        assert!(sh.starts_with("CT_CHANNEL_ROLE=accept "), "role prefix");
        assert!(sh.contains("CT_CHANNEL_ADDR=0.0.0.0:9443"), "bind addr");
        assert!(sh.contains("CT_CHANNEL_NOISE_KEY=a1a1") && sh.contains("CT_CHANNEL_PEER_NOISE_KEY=b2b2"), "keys in env");
        assert!(sh.trim_end().ends_with("ct-agent channel"), "invokes the subcommand");
        assert!(!sh.contains("CT_CHANNEL_PEER_CERT"), "responder needs no peer cert");
        // Secret hygiene: the private key is an env assignment, not a bare argv token.
        assert!(!sh.contains("channel a1a1"), "key never in argv");

        // Self-contained initiator: no peer cert (accept-any dial; Noise authenticates).
        let initiator = ChannelOneLiner {
            side: ChannelSide::Initiator,
            addr: "198.51.100.7:9443",
            own_noise_private_hex: "c3c3",
            peer_noise_public_hex: "d4d4",
            peer_cert_hex: None,
        };
        let sh_i = channel_one_liner(&initiator, InstallOs::Unix);
        assert!(sh_i.contains("CT_CHANNEL_ROLE=initiate"), "initiator role");
        assert!(!sh_i.contains("CT_CHANNEL_PEER_CERT"), "no cert needed — accept-any dial");
        assert!(sh_i.trim_end().ends_with("ct-agent channel"), "invokes the subcommand");

        // An optional pinned cert, if supplied, is included.
        let pinned = ChannelOneLiner { peer_cert_hex: Some("deadbeef"), ..initiator };
        assert!(channel_one_liner(&pinned, InstallOs::Unix).contains("CT_CHANNEL_PEER_CERT=deadbeef"), "optional pin");

        // Windows analog uses $env: assignments and the same subcommand.
        let ps = channel_one_liner(&initiator, InstallOs::Windows);
        assert!(ps.contains("$env:CT_CHANNEL_ROLE='initiate';"), "ps role");
        assert!(ps.trim_end().ends_with("ct-agent channel"), "ps invokes the subcommand");
    }

    #[test]
    fn channel_bootstrap_one_liner_carries_no_noise_private_key() {
        // #100/#97 SEC90b: the bootstrap form of the channel one-liner carries only
        // CT_BOOTSTRAP — never the member's Noise private key (which the inline form
        // exposes in shell history / ps). The config is recovered from the bundle the
        // channel script redeems.
        let p = ChannelOneLiner {
            side: ChannelSide::Initiator,
            addr: "peer.example:4500",
            own_noise_private_hex: "aa11deadbeefsecretprivatekey00",
            peer_noise_public_hex: "bb22peerpublickey00",
            peer_cert_hex: None,
        };
        let bundle = channel_bundle_secret(&p);
        assert_eq!(
            bundle,
            "CT_CHANNEL_ROLE=initiate;CT_CHANNEL_ADDR=peer.example:4500;\
             CT_CHANNEL_NOISE_KEY=aa11deadbeefsecretprivatekey00;CT_CHANNEL_PEER_NOISE_KEY=bb22peerpublickey00"
        );
        // The optional cert is appended when pinned.
        let pinned = channel_bundle_secret(&ChannelOneLiner { peer_cert_hex: Some("deadbeef"), ..p });
        assert!(pinned.ends_with(";CT_CHANNEL_PEER_CERT=deadbeef"), "cert appended when pinned");

        let boot = "dummy-bootstrap-token-cccc";
        let unix = channel_one_liner_bootstrap("https://portal.example/", boot, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/channel.sh | CT_BOOTSTRAP=dummy-bootstrap-token-cccc sh"
        );
        let win = channel_one_liner_bootstrap("https://portal.example/", boot, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_BOOTSTRAP='dummy-bootstrap-token-cccc'; irm https://portal.example/channel.ps1 | iex"
        );
        // The critical property: the Noise private key never appears in the one-liner.
        for cmd in [&unix, &win] {
            assert!(!cmd.contains("aa11deadbeefsecretprivatekey00"), "noise private key must not appear");
            assert_eq!(cmd.matches(boot).count(), 1, "bootstrap token carried exactly once");
        }
    }

    #[test]
    fn brokered_channel_one_liner_renders_the_plane_path_command() {
        // #100: the broker-mediated A2A command. Keys/grant ride in CT_CHANNEL_* env,
        // never argv; the command targets `ct-agent channel` (brokered branch).
        let p = BrokeredChannelOneLiner {
            side: ChannelSide::Initiator,
            broker: "45.133.9.145:4435",
            relay: "45.133.9.145:4436",
            grant_hex: "abcd",
            holder_key_hex: "hk-secret",
            noise_key_hex: "nk-secret",
            listen: "0.0.0.0:5000",
        };
        let unix = brokered_channel_one_liner(&p, InstallOs::Unix);
        assert!(unix.contains("CT_CHANNEL_ROLE=initiate"), "initiator role");
        for kv in [
            "CT_CHANNEL_BROKER=45.133.9.145:4435",
            "CT_CHANNEL_RELAY=45.133.9.145:4436",
            "CT_CHANNEL_GRANT=abcd",
            "CT_CHANNEL_HOLDER_KEY=hk-secret",
            "CT_CHANNEL_NOISE_KEY=nk-secret",
            "CT_CHANNEL_LISTEN=0.0.0.0:5000",
        ] {
            assert!(unix.contains(kv), "carries {kv}");
        }
        assert!(unix.trim_end().ends_with("ct-agent channel"), "invokes the subcommand");
        // Secrets ride in the env, never as positional args to the subcommand.
        assert!(!unix.contains("channel hk-secret") && !unix.contains("channel nk-secret"), "no secret in argv");

        // Windows analog uses $env: and the same subcommand + role mapping.
        let win = brokered_channel_one_liner(
            &BrokeredChannelOneLiner { side: ChannelSide::Responder, ..p },
            InstallOs::Windows,
        );
        assert!(win.contains("$env:CT_CHANNEL_ROLE='accept';"), "responder -> accept");
        assert!(win.contains("$env:CT_CHANNEL_BROKER='45.133.9.145:4435';"), "ps broker env");
        assert!(win.trim_end().ends_with("ct-agent channel"), "ps invokes the subcommand");
    }

    #[test]
    fn setup_script_urls_are_overridable_for_self_hosting_operators_448() {
        // #448: a self-hosting operator must be able to point this at their own
        // mirror without patching the crate. Unset -> today's exact default
        // (matches install_routes_redirect_to_the_ct_agent_setup_scripts above,
        // which sets neither and still asserts the raw.githubusercontent.com URL).
        assert_eq!(ct_agent_setup_sh_url(), CT_AGENT_SETUP_SH);
        assert_eq!(ct_agent_setup_ps1_url(), CT_AGENT_SETUP_PS1);

        // SAFETY: this crate's test binary runs single-process; scoped strictly to
        // this test's own two reads immediately below, restored before returning.
        unsafe {
            std::env::set_var("CT_AGENT_SETUP_URL", "https://mirror.example/setup.sh");
            std::env::set_var("CT_AGENT_SETUP_PS1_URL", "https://mirror.example/setup.ps1");
        }
        assert_eq!(ct_agent_setup_sh_url(), "https://mirror.example/setup.sh");
        assert_eq!(ct_agent_setup_ps1_url(), "https://mirror.example/setup.ps1");
        unsafe {
            std::env::remove_var("CT_AGENT_SETUP_URL");
            std::env::remove_var("CT_AGENT_SETUP_PS1_URL");
        }
    }

    #[test]
    fn parse_maps_os_aliases() {
        assert_eq!(InstallOs::parse("Linux"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse("macos"), Some(InstallOs::Unix));
        assert_eq!(InstallOs::parse(" Windows "), Some(InstallOs::Windows));
        assert_eq!(InstallOs::parse("plan9"), None);
    }

    /// ct-agent moved to its own repo with a much richer setup script; `/install.sh`
    /// and `/install.ps1` now redirect to it rather than serving a rendered
    /// one-liner, so any existing `curl -fsSL <portal>/install.sh | sh` (curl
    /// follows redirects) keeps working transparently and gets the better script.
    #[tokio::test]
    async fn install_routes_redirect_to_the_ct_agent_setup_scripts() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = installer_router(
            "https://portal.example".to_string(),
            "http://release.invalid/base".to_string(),
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/install.sh").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT, "/install.sh redirects, not 404");
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh")
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/install.ps1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT, "/install.ps1 redirects, not 404");
        assert_eq!(
            resp.headers().get("location").and_then(|v| v.to_str().ok()),
            Some("https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1")
        );
    }

    #[test]
    fn one_liners_embed_both_tokens_via_env_per_os() {
        // #28/#27 RB2: dummy tokens only — never a real secret in tests.
        let jt = "dummy-join-token-xyz";
        let rt = "dummy-routing-token-abc";
        let base = "https://portal.example/"; // trailing slash must be trimmed

        let unix = install_one_liner(base, jt, rt, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/install.sh | \
             CT_JOIN_TOKEN=dummy-join-token-xyz CT_AGENT_TOKEN=dummy-routing-token-abc sh"
        );
        // Tokens carried via env, not as positional arguments to sh.
        assert!(unix.contains("CT_JOIN_TOKEN=") && unix.contains("CT_AGENT_TOKEN="));
        assert!(!unix.contains("sh -s -- dummy"), "tokens are not CLI args");

        let win = install_one_liner(base, jt, rt, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_JOIN_TOKEN='dummy-join-token-xyz'; \
             $env:CT_AGENT_TOKEN='dummy-routing-token-abc'; irm https://portal.example/install.ps1 | iex"
        );

        // Each command embeds each token exactly once.
        for cmd in [&unix, &win] {
            assert_eq!(cmd.matches(jt).count(), 1);
            assert_eq!(cmd.matches(rt).count(), 1);
        }
    }

    #[test]
    fn bootstrap_one_liner_carries_only_the_bootstrap_token_not_the_real_secrets() {
        // #90/#97 SEC90b: the bootstrap form of the one-liner must NOT contain the
        // real join/routing tokens — only the short-lived bootstrap token. The real
        // secrets ride in the TLS redeem response, recovered via the bundle codec.
        let jt = "dummy-join-token-xyz";
        let rt = "dummy-routing-token-abc";
        let boot = "dummy-bootstrap-token-0123456789";
        let base = "https://portal.example/"; // trailing slash trimmed

        // The bundle the portal mints a bootstrap token over round-trips exactly, in
        // the shell-tractable CT_JOIN_TOKEN=..;CT_AGENT_TOKEN=.. form.
        let bundle = install_bundle_secret(jt, rt);
        assert_eq!(bundle, "CT_JOIN_TOKEN=dummy-join-token-xyz;CT_AGENT_TOKEN=dummy-routing-token-abc");
        assert_eq!(parse_install_bundle(&bundle), Some((jt.to_string(), rt.to_string())));
        assert_eq!(parse_install_bundle("garbage"), None);
        assert_eq!(parse_install_bundle("CT_JOIN_TOKEN=x"), None, "missing routing token -> None");

        let unix = install_one_liner_bootstrap(base, boot, InstallOs::Unix);
        assert_eq!(
            unix,
            "curl -fsSL https://portal.example/install.sh | CT_BOOTSTRAP=dummy-bootstrap-token-0123456789 sh"
        );
        let win = install_one_liner_bootstrap(base, boot, InstallOs::Windows);
        assert_eq!(
            win,
            "$env:CT_BOOTSTRAP='dummy-bootstrap-token-0123456789'; irm https://portal.example/install.ps1 | iex"
        );

        // The critical property: neither the real join nor routing token appears in
        // the shown command — only the bootstrap token does.
        for cmd in [&unix, &win] {
            assert!(!cmd.contains(jt), "join token must not appear in the one-liner");
            assert!(!cmd.contains(rt), "routing token must not appear in the one-liner");
            assert_eq!(cmd.matches(boot).count(), 1, "bootstrap token carried exactly once");
        }
    }
}

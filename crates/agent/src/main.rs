//! CADS Tunnel Agent daemon (M5.4c).
//!
//! Waits for the Edge cert on a shared path, mints a Capability (written to the
//! shared volume for the Client), registers its tunnel, and serves the Origin.

use std::time::Duration;
use tokio::time::Instant;

use ct_agent::capability::{parse_routing_token_hex, resolve_serving_identity_with_token};
use ct_agent::config::AgentConfig;
use ct_agent::onboard::{onboard_or_restore, OnboardEnv};
use ct_agent::serve::run_agent;
use ct_agent::transport::load_cert;

const EDGE_CERT_WAIT_LOG_THROTTLE_SECS: u64 = 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // `rotate` subcommand (#12 K4): rotate the origin key while KEEPING the
    // routing token, then exit. Re-mints the capability (same token, new origin),
    // retires the old key into CT_AGENT_ORIGIN_KEY_DIR, and promotes the new key.
    // Restart the agent (with that dir set) to serve both identities.
    if std::env::args().nth(1).as_deref() == Some("rotate") {
        let key_path = std::env::var("CT_AGENT_ORIGIN_KEY")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY (the primary key path)")?;
        let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
            .unwrap_or_else(|_| "/shared/capability.bin".to_string());
        let dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY_DIR (the retired-key dir)")?;
        let new_cap = ct_agent::capability::rotate_origin_key(&key_path, &cap_out, &dir)?;
        eprintln!(
            "ct-agent: rotated origin key — new capability at {cap_out} (same token, new origin); \
             old key retired to {dir}. Restart the agent to serve both, then distribute the new \
             capability and remove the retired key once the window closes."
        );
        let _ = new_cap;
        return Ok(());
    }

    // `channel` subcommand (#72 AF4 / #98/#100): bring this agent up as one side of
    // an Agent-Fabric A2A channel and pipe stdin/stdout over the encrypted Noise_IK
    // tunnel to the paired peer. Config comes from CT_CHANNEL_* so it fits a one-liner.
    if std::env::args().nth(1).as_deref() == Some("channel") {
        // #117 `ct-agent channel init`: mint a fresh channel identity LOCALLY and print
        // the copy-pasteable env block (private keys never leave this machine — the
        // self-service, provider-blind alternative to hand-crafted keys / central
        // provisioning). The participant `eval`s it, hands the public keys to the
        // operator, then runs `ct-agent channel` with the operator-supplied grant.
        if std::env::args().nth(2).as_deref() == Some("init") {
            print!("{}", ct_agent::channel_run::ChannelIdentity::generate().env_block());
            return Ok(());
        }
        // #117 `ct-agent channel operator-init`: mint a channel OPERATOR key locally and
        // print its env block (the operator authorizes a channel + signs member grants).
        if std::env::args().nth(2).as_deref() == Some("operator-init") {
            print!("{}", ct_agent::channel_run::OperatorIdentity::generate().operator_env_block());
            return Ok(());
        }
        // #207 `ct-agent channel member-material`: compute the (holder_pubkey, noise_pubkey,
        // channel_id, noise_attestation) a MEMBER hands its operator/central to be admitted to a link
        // channel — so a member never hand-rolls channel_id_for_link / member_noise_attest_bytes.
        // Reads CT_CHANNEL_OPERATOR_PUBKEY + CT_CHANNEL_BRIDGE_HOLDER (from central) + the member's
        // CT_CHANNEL_HOLDER_KEY (private) + CT_CHANNEL_NOISE_PUBKEY. Pure local compute.
        if std::env::args().nth(2).as_deref() == Some("member-material") {
            let req = ct_agent::channel_run::MemberMaterialRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            print!("{}", req.render());
            return Ok(());
        }
        // #214 follow-up `ct-agent channel join-pipeline-role`: the generic-provisioning analogue
        // of `member-material` — derives a PUBLISHED PIPELINE's role channel_id (from
        // CT_CHANNEL_OPERATOR_PUBKEY + CT_PIPELINE_ID + CT_PIPELINE_ROLE, all public/discoverable
        // via GET /registry/pipelines/:id) instead of a pairwise link, so a bridge and a
        // role-serving agent never need to exchange keys before either can compute the same id.
        if std::env::args().nth(2).as_deref() == Some("join-pipeline-role") {
            let req = ct_agent::channel_run::PipelineRoleMaterialRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            print!("{}", req.render());
            return Ok(());
        }
        // #117 `ct-agent channel grant`: as the operator, sign a member's grant (from
        // CT_CHANNEL_OPERATOR_KEY + CT_GRANT_*) and print the CT_CHANNEL_GRANT hex the
        // member uses — self-service admission, no central provisioning.
        if std::env::args().nth(2).as_deref() == Some("grant") {
            let req = ct_agent::channel_run::OperatorGrantRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            println!("{}", req.issue());
            return Ok(());
        }
        // #117 `ct-agent channel register`: register the operator's channel authority with
        // the control plane (POST /me/channels, owner = the OIDC subject) so the edge
        // accepts the grants that operator signs — the last CP round-trip that makes an
        // Agent-Fabric channel fully self-service. Reads CT_AGENT_CP_URL + CT_GRANT_CHANNEL
        // + CT_OIDC_TOKEN + the operator key (CT_CHANNEL_OPERATOR_KEY / _PUBKEY).
        if std::env::args().nth(2).as_deref() == Some("register") {
            let req = ct_agent::channel_run::ChannelRegisterRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone())
                .register_channel(&req.channel_hex, &req.operator_pubkey_hex, &req.token)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            eprintln!("registered channel {} with the control plane", req.channel_hex);
            return Ok(());
        }
        // #144 ①-wiring `ct-agent channel agent-card`: assemble + sign this agent's holder
        // AgentCard from CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_* claims and write it to
        // <CT_AGENT_CARD_OUT>/.well-known/agent-card.json for the origin to serve — the runnable
        // path that closes the discovery chain (no hand-rolled ed25519). Prints the written path.
        if std::env::args().nth(2).as_deref() == Some("agent-card") {
            // `agent-card --verify <file>`: the fetcher/operator self-check — parse the card and
            // re-verify its holder signature + expiry, exiting non-zero on any failure so it
            // scripts cleanly. No key needed; the trust anchor is the signature in the file.
            if std::env::args().nth(3).as_deref() == Some("--verify") {
                let file = std::env::args()
                    .nth(4)
                    .ok_or("usage: ct-agent channel agent-card --verify <file>")?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                    .as_secs();
                let card = ct_agent::well_known::read_and_verify_agent_card(
                    std::path::Path::new(&file),
                    now,
                )
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let holder: String =
                    card.holder_pubkey.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "valid  holder={holder}  role_tags={:?}  expires_at={}",
                    card.role_tags, card.expires_at
                );
                return Ok(());
            }
            let cfg = ct_agent::channel_run::AgentCardCliConfig::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .as_secs();
            let path = cfg.write_card(now)?;
            println!("{}", path.display());
            return Ok(());
        }
        // Plane-brokered flow (#98/#103) when an edge rendezvous is configured: present
        // the grant, learn the peer via the broker (keys relayed), connect
        // direct-then-relay. Otherwise the direct-address path (CT_CHANNEL_ADDR).
        if std::env::var("CT_CHANNEL_BROKER").map(|v| !v.is_empty()).unwrap_or(false) {
            let cfg = ct_agent::channel_run::ChannelJoinCliConfig::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            return ct_agent::channel_run::run_channel_join_command(cfg).await;
        }
        let cfg = ct_agent::channel_run::ChannelRunConfig::from_env()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        return ct_agent::channel_run::run_channel_command(cfg).await;
    }

    // One-command onboarding: if a join token is present (env or `onboard`
    // subcommand), auto-enroll against the control plane before serving. This
    // is the "install -> enroll -> tunnel" single step — the operator supplies
    // only a control-plane URL and a single-use join token.
    let onboarding = std::env::args().nth(1).as_deref() == Some("onboard")
        || std::env::var("CT_AGENT_JOIN_TOKEN").is_ok();
    let config = if onboarding {
        let env = OnboardEnv::from_env()?;
        let edge = env.config.edge;
        let cp_url = env.cp_url.clone();
        // Onboarding redeems a SINGLE-USE join token. A timeout here that fires
        // after the token is already spent server-side would, on restart, re-onboard
        // with a dead token and never recover (#36). So the timeout is OPT-IN: unset
        // ⇒ wait indefinitely (prior behaviour, resilient); set only where a bounded
        // fail-fast is wanted (CI / the e2e smoke script).
        //
        // #141 restart-safety: with CT_AGENT_STATE_DIR set (a persistent volume), the
        // FIRST boot redeems + persists the bound identity/tenant there and every
        // later boot RESTORES it — so a container restart never replays the spent
        // token into a crash-loop (the help-agent outage). Unset ⇒ prior always-redeem.
        let state_dir = std::env::var("CT_AGENT_STATE_DIR").ok();
        let run = async move {
            match state_dir.as_deref() {
                Some(dir) => onboard_or_restore(
                    &env.cp_url,
                    &env.join_token,
                    env.agent_id,
                    env.config,
                    std::path::Path::new(dir),
                )
                .await
                .map_err(|e| e.to_string()),
                None => env.onboard().await.map_err(|e| e.to_string()),
            }
        };
        let onboarded = match std::env::var("CT_AGENT_ONBOARD_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(secs) => tokio::time::timeout(Duration::from_secs(secs), run)
                .await
                .map_err(|_| format!("ct-agent: onboarding timed out after {secs}s"))??,
            None => run.await?,
        };
        eprintln!(
            "ct-agent: onboarded agent={} tenant={} via {} (edge={})",
            onboarded.agent_id.0, onboarded.tenant.0, cp_url, edge
        );
        onboarded.config
    } else {
        AgentConfig::from_env()?
    };
    let cert_path =
        std::env::var("CT_AGENT_EDGE_CERT").unwrap_or_else(|_| "/shared/edge-cert.der".to_string());
    let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
        .unwrap_or_else(|_| "/shared/capability.bin".to_string());

    // Obtain the Edge CA root. With CT_AGENT_EDGE_CERT_URL set, fetch it from the
    // control plane's published /pki/ca (#11 C2) — self-serve cross-host, no
    // out-of-band copy. Otherwise wait for it on the shared-volume path.
    let edge_cert = if let Ok(url) = std::env::var("CT_AGENT_EDGE_CERT_URL") {
        let der = ct_control_plane::client::ControlPlaneClient::new(url.clone())
            .fetch_edge_cert()
            .await
            .map_err(|e| format!("ct-agent: fetch edge cert from {url}: {e:?}"))?;
        eprintln!(
            "ct-agent: fetched edge cert from {url} ({} bytes)",
            der.len()
        );
        rustls::pki_types::CertificateDer::from(der)
    } else {
        // This wait runs AFTER onboarding has spent the single-use token, so the
        // bound is OPT-IN too: unset ⇒ wait indefinitely for the edge to publish its
        // cert on the shared volume (prior behaviour — an agent that can't re-onboard
        // must not give up), set only for fail-fast (CI / smoke). Log throttling is
        // always on so a long wait doesn't spam the log twice a second.
        let cert_deadline = std::env::var("CT_AGENT_EDGE_CERT_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| (Instant::now() + Duration::from_secs(secs), secs));
        let cert_log_interval_secs = std::env::var("CT_AGENT_EDGE_CERT_LOG_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(EDGE_CERT_WAIT_LOG_THROTTLE_SECS);
        let mut next_log_at = Instant::now();
        loop {
            let now = Instant::now();
            match load_cert(&cert_path) {
                Ok(cert) => break cert,
                Err(_) => {
                    if let Some((deadline, secs)) = cert_deadline {
                        if now >= deadline {
                            return Err(format!(
                                "ct-agent: edge cert not available within {secs}s at {cert_path}"
                            )
                            .into());
                        }
                    }
                    if now >= next_log_at {
                        eprintln!("ct-agent: waiting for edge cert at {cert_path} ...");
                        next_log_at = now + Duration::from_secs(cert_log_interval_secs);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    };

    // Resolve the serving identity (Capability + Origin static key). The Agent is
    // custodian of the Origin static Noise keypair; only its public half travels
    // in the Capability. The private half stays here to terminate the E2E
    // handshake (M8.3). With CT_AGENT_ORIGIN_KEY set, the key + capability are
    // persisted/shared so multiple agents can serve one tunnel (redundancy, #8).
    // With CT_AGENT_ORIGIN_KEY_DIR set, additional (retired) origin keys in that
    // directory are also served, so old capabilities keep working during a key
    // rotation window (#12).
    let origin_key_path = std::env::var("CT_AGENT_ORIGIN_KEY").ok();
    let origin_key_dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR").ok();
    // #27 RB2b: if the portal supplied the tunnel's routing token (CT_AGENT_TOKEN,
    // set by the install one-liner), register at the edge under THAT token so a
    // revocation can find and drop this tunnel. Otherwise mint a random token.
    let forced_token = std::env::var("CT_AGENT_TOKEN")
        .ok()
        .and_then(|s| parse_routing_token_hex(&s));
    let identity = resolve_serving_identity_with_token(
        origin_key_path.as_deref(),
        &cap_out,
        &config.edge.to_string(),
        origin_key_dir.as_deref(),
        forced_token,
    )?;
    eprintln!(
        "ct-agent: edge={} origin={} capability -> {} (serving {} origin identit{}){}",
        config.edge,
        config.origin,
        cap_out,
        identity.origin_keys.len(),
        if identity.origin_keys.len() == 1 {
            "y"
        } else {
            "ies"
        },
        match &origin_key_path {
            Some(p) => format!(", shared origin key {p}"),
            None => String::new(),
        }
    );

    run_agent(
        &config,
        edge_cert,
        identity.cap.token,
        std::sync::Arc::new(identity.origin_keys),
    )
    .await
}

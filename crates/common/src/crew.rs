//! Crew-bridge assembly (#171): turn the role agents' JSON fragments into the
//! `{safety, auction, config}` response the flappy-demo browser (`POST /crew/build`) expects.
//!
//! This is the **pure core** of the real Agent-Fabric crew bridge — the field-mapping + wire
//! contract, decoupled from I/O. The channel-dialing client (that calls `service/safety_check`
//! and per-role `service/<slug>` over real A2A channels to sink/source-2, discovered via
//! `/registry/agents?role=`) and the small HTTP server that fronts it are the bridge binary
//! (follow slices); they feed their fragment JSON into this module and serialize its output
//! straight back to the browser.
//!
//! The field names on the wire match exactly what the demo and central's proven b1 handlers use:
//! the physics handler emits `{gravity, flapPower, pipeGap, pipeSpeed}` and the art handler emits
//! `{theme, birdColor, birdEmoji, title}`; the demo's game `CONFIG` uses `{gravity, jump, gap,
//! speed, theme, birdColor, birdEmoji, title}`. This module is the single place that reconciles
//! them (`flapPower→jump`, `pipeGap→gap`, `pipeSpeed→speed`), so the mapping can't drift.

use serde::{Deserialize, Serialize};

/// The physics agent's fragment — central's b1 physics handler output shape.
#[derive(Debug, Clone, Deserialize)]
pub struct PhysicsFragment {
    pub gravity: u32,
    #[serde(rename = "flapPower")]
    pub flap_power: u32,
    #[serde(rename = "pipeGap")]
    pub pipe_gap: u32,
    #[serde(rename = "pipeSpeed")]
    pub pipe_speed: u32,
}

/// A fully custom colour palette the art agent can invent (#176) instead of only picking one of the
/// demo's 5 named themes — the exact shape a studio `THEMES` entry has. Optional: when the art agent
/// omits it, the coarse `theme` label still selects a preset. All fields are `#rrggbb`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Palette {
    #[serde(rename = "skyTop")]
    pub sky_top: String,
    #[serde(rename = "skyBottom")]
    pub sky_bottom: String,
    pub pipe: String,
    #[serde(rename = "pipeEdge")]
    pub pipe_edge: String,
    pub ground: String,
    #[serde(rename = "groundEdge")]
    pub ground_edge: String,
    pub accent: String,
}

/// The art agent's fragment — central's b1 art handler output shape, plus an optional #176 custom
/// `palette` so the LLM can invent a full sky/pipe/ground colour scheme, not just name one of five.
#[derive(Debug, Clone, Deserialize)]
pub struct ArtFragment {
    pub theme: String,
    #[serde(rename = "birdColor")]
    pub bird_color: String,
    #[serde(rename = "birdEmoji")]
    pub bird_emoji: String,
    pub title: String,
    /// #176: a full custom palette. `None`/absent → the studio uses the named `theme` preset.
    #[serde(default)]
    pub palette: Option<Palette>,
}

/// The demo's game config — serialized with exactly the field names the studio's `CONFIG` /
/// `applyLiveConfig` read (`birdColor`/`birdEmoji` camelCase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrewConfig {
    pub gravity: u32,
    pub jump: u32,
    pub gap: u32,
    pub speed: u32,
    pub theme: String,
    #[serde(rename = "birdColor")]
    pub bird_color: String,
    #[serde(rename = "birdEmoji")]
    pub bird_emoji: String,
    pub title: String,
    /// #176: the art agent's optional full custom palette. Serialized only when present, so existing
    /// consumers (and the named-theme path) are unaffected; the studio applies it directly when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palette: Option<Palette>,
}

impl CrewConfig {
    /// Merge the physics + art fragments into the demo config, reconciling the handlers' field
    /// names with the game's (`flapPower→jump`, `pipeGap→gap`, `pipeSpeed→speed`).
    pub fn from_fragments(physics: &PhysicsFragment, art: &ArtFragment) -> Self {
        CrewConfig {
            gravity: physics.gravity,
            jump: physics.flap_power,
            gap: physics.pipe_gap,
            speed: physics.pipe_speed,
            theme: art.theme.clone(),
            bird_color: art.bird_color.clone(),
            bird_emoji: art.bird_emoji.clone(),
            title: art.title.clone(),
            palette: art.palette.clone(),
        }
    }

    /// Parse the two fragment JSON blobs (as returned by the role handlers over the channel) and
    /// merge them. A malformed/missing-field fragment is a hard error (the bridge fails closed).
    pub fn from_fragment_json(physics_json: &str, art_json: &str) -> Result<Self, serde_json::Error> {
        let p: PhysicsFragment = serde_json::from_str(physics_json)?;
        let a: ArtFragment = serde_json::from_str(art_json)?;
        Ok(Self::from_fragments(&p, &a))
    }
}

/// The safety verdict from the `service/safety_check` agent (#171): is the prompt a legit game
/// request or a subversion attempt?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Safety {
    pub ok: bool,
    pub reason: String,
}

/// One clearing agent's bid, as shown in the demo's visible auction.
#[derive(Debug, Clone, Serialize)]
pub struct RoleBid {
    pub who: String,
    pub model: String,
    pub units: u64,
    pub price: u64,
    pub win: bool,
}

/// The auction for one role (the candidate bids; the winner is the one that produced the fragment).
#[derive(Debug, Clone, Serialize)]
pub struct RoleAuction {
    pub role: String,
    pub bids: Vec<RoleBid>,
}

/// The exact `{safety, auction, config}` the browser expects from `POST /crew/build`.
///
/// **Fail-closed:** when `safety.ok` is false, `auction` and `config` are omitted, so a rejected
/// prompt can never carry a build downstream (matching the browser's own reject handling).
#[derive(Debug, Clone, Serialize)]
pub struct CrewBuildResponse {
    pub safety: Safety,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auction: Option<Vec<RoleAuction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<CrewConfig>,
}

impl CrewBuildResponse {
    /// A safety rejection — no build carried.
    pub fn rejected(reason: impl Into<String>) -> Self {
        CrewBuildResponse {
            safety: Safety { ok: false, reason: reason.into() },
            auction: None,
            config: None,
        }
    }

    /// An accepted build with the cleared auction + assembled config.
    pub fn built(config: CrewConfig, auction: Vec<RoleAuction>) -> Self {
        CrewBuildResponse {
            safety: Safety { ok: true, reason: String::new() },
            auction: Some(auction),
            config: Some(config),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crew_fragments_map_to_config_and_response_is_failclosed() {
        // #171 (frozen): the assembly core. Central's proven b1 fragment outputs map to the demo's
        // CONFIG with the field names reconciled, and the response is fail-closed on a rejection.
        // Physics/art blobs are the EXACT ones central reported for the #170 repro prompt.
        let physics = r#"{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}"#;
        let art = r##"{"theme":"night","birdColor":"#00ff41","birdEmoji":"🕶️","title":"Neo: Matrix Flap"}"##;

        let cfg = CrewConfig::from_fragment_json(physics, art).expect("valid fragments parse");
        assert_eq!(
            cfg,
            CrewConfig {
                gravity: 2200, jump: 420, gap: 115, speed: 220,
                theme: "night".into(), bird_color: "#00ff41".into(),
                bird_emoji: "🕶️".into(), title: "Neo: Matrix Flap".into(),
                palette: None,
            },
            "flapPower→jump, pipeGap→gap, pipeSpeed→speed; art carried verbatim (emoji intact)"
        );
        // #176 backward-compat: an art fragment with no palette → None.
        assert!(cfg.palette.is_none());

        // The config serializes with the camelCase names the browser's applyLiveConfig reads.
        let cfg_json = serde_json::to_string(&cfg).unwrap();
        assert!(cfg_json.contains("\"birdColor\":\"#00ff41\""), "birdColor camelCase: {cfg_json}");
        assert!(cfg_json.contains("\"birdEmoji\":\"🕶️\""), "birdEmoji camelCase + grapheme");
        assert!(cfg_json.contains("\"jump\":420"), "jump (from flapPower)");
        assert!(!cfg_json.contains("flapPower"), "the handler's field name does not leak to the browser");
        assert!(!cfg_json.contains("palette"), "#176: no palette key serialized when the art agent didn't invent one");

        // #176: an art fragment WITH a custom palette carries it through to the config + wire (the
        // studio then applies the invented sky/pipe/ground colours directly, not one of 5 presets).
        let art_pal = r##"{"theme":"night","birdColor":"#00ff41","birdEmoji":"","title":"Dusk","palette":{"skyTop":"#2a0f3a","skyBottom":"#7a3b1f","pipe":"#c85a2a","pipeEdge":"#8a3b18","ground":"#3a2a1a","groundEdge":"#241a10","accent":"#ffd18a"}}"##;
        let cfg2 = CrewConfig::from_fragment_json(physics, art_pal).expect("fragment with palette parses");
        let pal = cfg2.palette.as_ref().expect("custom palette carried through");
        assert_eq!((pal.sky_top.as_str(), pal.pipe.as_str(), pal.accent.as_str()), ("#2a0f3a", "#c85a2a", "#ffd18a"));
        let cfg2_json = serde_json::to_string(&cfg2).unwrap();
        assert!(cfg2_json.contains("\"skyTop\":\"#2a0f3a\""), "palette serializes camelCase for the browser: {cfg2_json}");

        // built() carries safety.ok + auction + config.
        let auction = vec![RoleAuction {
            role: "physics".into(),
            bids: vec![RoleBid { who: "source-2".into(), model: "claude-sonnet-5".into(), units: 20, price: 50, win: true }],
        }];
        let built = serde_json::to_value(CrewBuildResponse::built(cfg.clone(), auction)).unwrap();
        assert_eq!(built["safety"]["ok"], serde_json::json!(true));
        assert_eq!(built["config"]["speed"], serde_json::json!(220));
        assert_eq!(built["auction"][0]["bids"][0]["who"], serde_json::json!("source-2"));

        // Fail-closed: a rejection omits auction + config entirely (a rejected prompt carries no build).
        let rej = serde_json::to_value(CrewBuildResponse::rejected("attempted to subvert the system")).unwrap();
        assert_eq!(rej["safety"]["ok"], serde_json::json!(false));
        assert!(rej.get("config").is_none(), "no config on a rejection");
        assert!(rej.get("auction").is_none(), "no auction on a rejection");

        // A malformed fragment fails closed (Err), never a partial/garbage config.
        assert!(CrewConfig::from_fragment_json("{\"gravity\":1}", art).is_err(), "missing physics fields → Err");
    }
}

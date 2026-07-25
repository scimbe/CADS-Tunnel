//! `ct-crew-bridge` (#171/#173 c3): the HTTP bridge the flappy-demo browser POSTs prompts to.
//!
//! A static Caddy page can't speak the QUIC/Noise channel, so the browser `POST`s `{prompt}` here
//! and this service runs the crew — **safety_check first**, then **physics** + **art** — via one
//! configurable command per role, assembles the result with [`ct_common::crew`], and returns the
//! `{safety, auction, config}` the browser (already wired, fail-closed) expects.
//!
//! Each role command is *how to reach that role's `service/<slug>`*: in production a
//! `ct-agent channel … --call service/<slug>` over the real Agent-Fabric tunnel to sink/source-2;
//! in a co-located/dev setup, the reference handler script directly. Configure via env:
//!   * `CREW_SAFETY_CMD`  — reads the prompt on stdin → `{"ok":bool,"reason":str}`
//!   * `CREW_PHYSICS_CMD` — reads the prompt on stdin → `{gravity,flapPower,pipeGap,pipeSpeed}`
//!   * `CREW_ART_CMD`     — reads the prompt on stdin → `{theme,birdColor,birdEmoji,title}`
//!   * `CREW_BRIDGE_LISTEN` (default `0.0.0.0:8788`)
//!
//! **Fail-closed:** safety runs first and a `{ok:false}` short-circuits to a rejection (no fragment
//! calls); a role command failing / malformed output → `502`, so the browser falls back to its
//! local stand-in. Reuses the tested `ct_common::crew` assembly + contract.

use axum::{http::StatusCode, routing::post, Json, Router};
use ct_common::crew::{CrewBuildResponse, CrewConfig, RoleAuction, RoleBid};
use serde_json::Value;

/// Run one role command with `input` on stdin, returning trimmed stdout. Blocking (run via
/// `spawn_blocking`); a non-zero exit or spawn failure is an `Err` (the caller fails closed).
fn run_cmd(cmd: &str, input: &str) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn role command failed: {e}"))?;
    // Write the prompt on its OWN thread so it proceeds concurrently with the wait/read below.
    // Best-effort: a role command that exits before draining stdin (a fast reply, or a channel
    // call that answers without reading all input) makes this write fail with a broken pipe —
    // deliberately IGNORED, since the command's own exit status + stdout is the verdict, not
    // whether every stdin byte landed. Writing before wait_with_output() (as the first cut did)
    // races that early exit and 502s intermittently. Same fix already proven for
    // run_service_handler_with_timeout in channel_run.rs.
    let mut stdin = child.stdin.take().ok_or("no stdin handle")?;
    let input_owned = input.to_string();
    std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });
    let out = child.wait_with_output().map_err(|e| format!("role command wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("role command exited {:?}", out.status.code()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn run_cmd_async(cmd: String, input: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || run_cmd(&cmd, &input))
        .await
        .map_err(|e| format!("role task join failed: {e}"))?
}

/// The visible auction for the demo crew (the winners that produced each fragment). A real
/// marketplace clear (`match_offer`/`convene`) would supply this; the demo shows its known crew.
fn demo_auction() -> Vec<RoleAuction> {
    vec![
        RoleAuction {
            role: "physics".into(),
            bids: vec![RoleBid { who: "source-2".into(), model: "claude".into(), units: 20, price: 50, win: true }],
        },
        RoleAuction {
            role: "art".into(),
            bids: vec![RoleBid { who: "sink".into(), model: "claude".into(), units: 20, price: 40, win: true }],
        },
    ]
}

/// The bridge core: safety → (physics, art) → assemble. `Err` = infrastructure failure (the HTTP
/// layer 5xx's so the browser fails closed); `Ok(rejected)` = a safety rejection; `Ok(built)` = a
/// clean build. Testable without the network by passing shell commands that emit fixed JSON.
async fn run_crew(prompt: String, safety_cmd: String, physics_cmd: String, art_cmd: String) -> Result<CrewBuildResponse, String> {
    let safety_out = run_cmd_async(safety_cmd, prompt.clone()).await.map_err(|e| format!("safety_check unreachable: {e}"))?;
    let verdict: Value = serde_json::from_str(&safety_out).map_err(|e| format!("safety_check reply not JSON: {e}"))?;
    if verdict.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = verdict.get("reason").and_then(Value::as_str).unwrap_or("rejected by the safety agent");
        return Ok(CrewBuildResponse::rejected(reason.to_string()));
    }
    // physics + art are independent once safety passes — run them CONCURRENTLY, not sequentially, so
    // the wall-clock is safety + max(physics, art) rather than the sum. Each role command is a real
    // `ct-agent channel … --call service/<slug>` that ends up doing a ~14s `claude -p` (#173,
    // measured), so joining the two independent roles cuts a ~40s crew to ~28s. (run_cmd_async is a
    // spawn_blocking, so two concurrent calls genuinely run their subprocesses in parallel.)
    let (physics_out, art_out) = tokio::join!(
        run_cmd_async(physics_cmd, prompt.clone()),
        run_cmd_async(art_cmd, prompt),
    );
    let physics_out = physics_out.map_err(|e| format!("physics role unreachable: {e}"))?;
    let art_out = art_out.map_err(|e| format!("art role unreachable: {e}"))?;
    let cfg = CrewConfig::from_fragment_json(&physics_out, &art_out).map_err(|e| format!("crew fragments malformed: {e}"))?;
    Ok(CrewBuildResponse::built(cfg, demo_auction()))
}

async fn build_handler(Json(body): Json<Value>) -> Result<Json<CrewBuildResponse>, (StatusCode, String)> {
    let prompt = body.get("prompt").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if prompt.len() < 3 {
        return Err((StatusCode::BAD_REQUEST, "say a bit more about the game you want".into()));
    }
    let env = |k: &str| std::env::var(k).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, format!("{k} not configured")));
    let (safety, physics, art) = (env("CREW_SAFETY_CMD")?, env("CREW_PHYSICS_CMD")?, env("CREW_ART_CMD")?);
    match run_crew(prompt, safety, physics, art).await {
        Ok(resp) => Ok(Json(resp)),
        // Infra failure → 502 so the browser fails closed to its local stand-in.
        Err(e) => Err((StatusCode::BAD_GATEWAY, e)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("CREW_BRIDGE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8788".to_string());
    let app = Router::new().route("/crew/build", post(build_handler));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("ct-crew-bridge: serving POST /crew/build on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_crew_assembles_from_role_commands_and_fails_closed() {
        // #171/#173 c3 (frozen): the bridge core, exercised with shell commands that emit fixed
        // JSON (local fakes) — no network. Happy build maps physics/art; safety reject carries no
        // build; a failing role command → Err (→ 502 → browser fallback).
        let safety_ok = r#"printf '{"ok":true,"reason":""}'"#.to_string();
        let physics = r#"printf '{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}'"#.to_string();
        let art = r##"printf '{"theme":"night","birdColor":"#00ff41","birdEmoji":"X","title":"Neo"}'"##.to_string();

        let r = run_crew("matrix".into(), safety_ok.clone(), physics.clone(), art.clone()).await.unwrap();
        assert!(r.safety.ok, "built when safety passes");
        let cfg = r.config.as_ref().expect("built carries config");
        assert_eq!((cfg.speed, cfg.jump, cfg.gap), (220, 420, 115), "physics fragment mapped");
        assert!(r.auction.as_ref().map(|a| !a.is_empty()).unwrap_or(false), "auction present");

        let safety_no = r#"printf '{"ok":false,"reason":"anti-prompt"}'"#.to_string();
        let r2 = run_crew("evil".into(), safety_no, physics.clone(), art.clone()).await.unwrap();
        assert!(!r2.safety.ok && r2.config.is_none(), "safety reject carries no build (short-circuit)");

        let r3 = run_crew("x".into(), safety_ok, "false".into(), art).await;
        assert!(r3.is_err(), "a failing role command → Err (fail closed)");
    }

    #[tokio::test]
    async fn run_crew_runs_physics_and_art_concurrently() {
        // #173 (frozen, regression guard): the DEPLOYED bridge path must run physics ∥ art, not
        // sequentially (each role is a ~14s claude -p over the tunnel; serial ≈ 40s, concurrent ≈
        // 28s). Proven deterministically with a rendezvous BARRIER, not a timing margin: each role
        // records that it started, then waits for the OTHER to start. Run concurrently, both see the
        // pair and finish in <1s. Serialized, physics can never see art start (art hasn't run yet),
        // so it spins its full ~6s bound before emitting — blowing the 3s timeout and failing the test.
        let dir = std::env::temp_dir().join(format!("crew_conc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let barrier = |emit: &str| {
            format!(
                "echo x >> {d}/started; for _ in $(seq 1 300); do [ \"$(wc -l < {d}/started)\" -ge 2 ] && break; sleep 0.02; done; printf '{}'",
                emit,
                d = dir.display(),
            )
        };
        let safety = r#"printf '{"ok":true,"reason":""}'"#.to_string();
        let physics = barrier(r#"{"gravity":1800,"flapPower":430,"pipeGap":140,"pipeSpeed":130}"#);
        let art = barrier(r##"{"theme":"day","birdColor":"#f7d51d","birdEmoji":"","title":"T"}"##);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            run_crew("go".into(), safety, physics, art),
        )
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        let built = res.expect("physics+art must run concurrently — a serialized crew hangs on the barrier past 3s").unwrap();
        assert!(built.config.is_some(), "the concurrently-produced fragments assemble into a build");
    }
}

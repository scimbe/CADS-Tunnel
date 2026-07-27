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

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ct_common::crew::{CrewBuildResponse, CrewConfig, RoleAuction, RoleBid};
use serde_json::{json, Value};
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;

/// Hard cap on a single role command (#188). A role is a `ct-agent channel … --call` doing a ~14s
/// `claude -p`; generous so a legitimately slow crew isn't cut, but bounded so a *wedged* handler /
/// stalled channel call can't leak a zombie subprocess and hang `/crew/build` forever.
const ROLE_CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run one role command with `input` on stdin, returning trimmed stdout. Blocking (run via
/// `spawn_blocking`); a non-zero exit or spawn failure is an `Err` (the caller fails closed).
fn run_cmd(cmd: &str, input: &str) -> Result<String, String> {
    run_cmd_with_timeout(cmd, input, ROLE_CMD_TIMEOUT)
}

fn run_cmd_with_timeout(cmd: &str, input: &str, timeout: std::time::Duration) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn role command failed: {e}"))?;
    let pid = child.id();
    // Write the prompt on its OWN thread so it proceeds concurrently with the wait/read below.
    // Best-effort: a role command that exits before draining stdin (a fast reply, or a channel
    // call that answers without reading all input) makes this write fail with a broken pipe —
    // deliberately IGNORED, since the command's own exit status + stdout is the verdict, not
    // whether every stdin byte landed. Writing before wait (as the first cut did) races that early
    // exit and 502s intermittently. Same fix as run_service_handler_with_timeout in channel_run.rs.
    let mut stdin = child.stdin.take().ok_or("no stdin handle")?;
    let input_owned = input.to_string();
    std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });
    // #188: bound wait_with_output (which itself reads stdout on its own thread) so a hung command
    // can't wait forever — run it on a background thread and, on timeout, KILL the child by the pid
    // captured above so it can't linger as a zombie. Same shape as channel_run.rs's timed handler.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| format!("role command wait failed: {e}"))?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            return Err(format!("role command timed out after {}s (pid {pid} killed)", timeout.as_secs()));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("role command wait thread disconnected".to_string());
        }
    };
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

/// #207 Slice A — ordered-candidate failover. Try an ORDERED list of role commands, first success
/// wins: candidate 0 is the primary (source-2's serve); on error (unreachable / non-zero / empty-#206
/// / timeout — i.e. source-2 down) fall through to the next (sink's parallel standby serve). So the
/// primary "always wins while it's up" and a standby "takes over when it can't connect", no reconfig.
/// OPT-IN: a single-candidate list behaves exactly as before. Returns the last candidate's error if
/// all fail. (Separate copy from the cookbook bridge — separate-bridge-per-pipeline, per the directive.)
/// Returns `(output, winning_candidate_index)` — the index lets the caller report WHO actually
/// served the request (the previous version discarded this, so the demo's "auction" display always
/// claimed the primary won even when a standby served — misleading exactly when failover matters).
async fn run_with_fallbacks(candidates: &[String], input: String) -> Result<(String, usize), String> {
    let mut last = Err("no role command configured".to_string());
    for (i, cmd) in candidates.iter().enumerate() {
        match run_cmd_async(cmd.clone(), input.clone()).await {
            Ok(out) => return Ok((out, i)),
            Err(e) => {
                if candidates.len() > 1 {
                    eprintln!(
                        "ct-crew-bridge: role candidate {}/{} failed ({e}); trying next (#207)",
                        i + 1,
                        candidates.len()
                    );
                }
                last = Err(e);
            }
        }
    }
    last
}

/// The label to show for a failover role's winning candidate. Index 0 is always the documented
/// primary; any later index is a standby. Not fully general (a 3rd+ candidate would also show
/// "standby"), but accurate for the current at-most-one-standby-per-role deployments.
fn candidate_label(primary: &str, standby: &str, winning_index: usize) -> String {
    if winning_index == 0 { primary.to_string() } else { standby.to_string() }
}

/// #207 Slice A — a role's ordered candidate list from env: primary `<primary_key>` + contiguous
/// fallbacks `<primary_key>_2`, `_3`, … (stop at the first unset). No fallbacks ⇒ single candidate.
fn role_candidates<F: Fn(&str) -> Option<String>>(env: &F, primary_key: &str, primary: String) -> Vec<String> {
    let mut v = vec![primary];
    let mut n = 2;
    while let Some(c) = env(&format!("{primary_key}_{n}")) {
        v.push(c);
        n += 1;
    }
    v
}

/// The visible auction for the demo crew (the winners that produced each fragment). A real
/// marketplace clear (`match_offer`/`convene`) would supply this; the demo shows its known crew —
/// but `physics_who` now reflects which candidate ACTUALLY served (source-2 vs a standby), not a
/// hardcoded guess, so the display stays honest under #207's failover.
fn demo_auction(physics_who: &str) -> Vec<RoleAuction> {
    vec![
        RoleAuction {
            role: "physics".into(),
            bids: vec![RoleBid { who: physics_who.into(), model: "claude".into(), units: 20, price: 50, win: true }],
        },
        RoleAuction {
            role: "art".into(),
            bids: vec![RoleBid { who: "sink".into(), model: "claude".into(), units: 20, price: 40, win: true }],
        },
    ]
}

/// Emit one NDJSON progress event (a JSON object + `\n`) to the response stream. Best-effort: if the
/// browser has gone away the receiver is dropped and the send just fails, which is fine.
async fn emit(tx: &Sender<String>, ev: Value) {
    let _ = tx.send(ev.to_string() + "\n").await;
}

/// The bridge core, **streaming** (#173 A): drive the crew safety → (physics ∥ art) → assemble and
/// emit a per-stage NDJSON event as each step starts/finishes, so the browser can show the real
/// role-chain working live instead of one opaque ~28s wait. The stream's terminal event is exactly
/// one of:
///   * `{"stage":"built", safety, auction, config}` — a clean build (the full CrewBuildResponse),
///   * `{"stage":"rejected", safety:{ok:false,reason}}` — the live safety guard refused,
///   * `{"stage":"error", message}` — an infrastructure failure (browser falls back to its stand-in).
/// Intermediate events: `{"stage":"safety|physics|art","status":"start|ok|done"}`.
async fn run_crew_streaming(prompt: String, safety_cmd: String, physics_cmds: Vec<String>, art_cmd: String, tx: Sender<String>) {
    // 1. safety_check — authoritative live guard.
    emit(&tx, json!({"stage": "safety", "status": "start"})).await;
    let safety_out = match run_cmd_async(safety_cmd, prompt.clone()).await {
        Ok(o) => o,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("safety_check unreachable: {e}")})).await,
    };
    let verdict: Value = match serde_json::from_str(&safety_out) {
        Ok(v) => v,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("safety_check reply not JSON: {e}")})).await,
    };
    if verdict.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = verdict.get("reason").and_then(Value::as_str).unwrap_or("rejected by the safety agent");
        return emit(&tx, json!({"stage": "rejected", "safety": {"ok": false, "reason": reason}})).await;
    }
    emit(&tx, json!({"stage": "safety", "status": "ok"})).await;

    // 2. physics + art — independent once safety clears, run CONCURRENTLY (each ~14s claude -p over
    //    the tunnel; #173). Each branch emits its own start/done so the browser marks that crew
    //    member live and done as it actually happens — the live role-chain, not a canned replay.
    emit(&tx, json!({"stage": "physics", "status": "start"})).await;
    emit(&tx, json!({"stage": "art", "status": "start"})).await;
    let (tx_p, tx_a) = (tx.clone(), tx.clone());
    let physics = async {
        // #207 Slice A: dial physics (source-2) across its candidate list — primary first, standby
        // on connect-failure. Single candidate ⇒ identical to before.
        let r = run_with_fallbacks(&physics_cmds, prompt.clone()).await;
        if r.is_ok() {
            emit(&tx_p, json!({"stage": "physics", "status": "done"})).await;
        }
        r
    };
    let art = async {
        let r = run_cmd_async(art_cmd, prompt.clone()).await;
        if r.is_ok() {
            emit(&tx_a, json!({"stage": "art", "status": "done"})).await;
        }
        r
    };
    let (physics_out, art_out) = tokio::join!(physics, art);
    let (physics_out, physics_winner) = match physics_out {
        Ok((o, i)) => (o, i),
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("physics role unreachable: {e}")})).await,
    };
    let art_out = match art_out {
        Ok(o) => o,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("art role unreachable: {e}")})).await,
    };
    let cfg = match CrewConfig::from_fragment_json(&physics_out, &art_out) {
        Ok(c) => c,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("crew fragments malformed: {e}")})).await,
    };

    // 3. terminal: the full CrewBuildResponse, tagged stage=built.
    let physics_who = candidate_label("source-2", "central (standby)", physics_winner);
    let mut built = serde_json::to_value(CrewBuildResponse::built(cfg, demo_auction(&physics_who))).unwrap_or_else(|_| json!({}));
    if let Value::Object(m) = &mut built {
        m.insert("stage".into(), json!("built"));
    }
    emit(&tx, built).await;
}

async fn build_handler(Json(body): Json<Value>) -> Response {
    let prompt = body.get("prompt").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if prompt.len() < 3 {
        return (StatusCode::BAD_REQUEST, "say a bit more about the game you want").into_response();
    }
    let env = |k: &str| std::env::var(k).ok();
    let (safety, physics, art) = match (env("CREW_SAFETY_CMD"), env("CREW_PHYSICS_CMD"), env("CREW_ART_CMD")) {
        (Some(s), Some(p), Some(a)) => (s, p, a),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "crew role commands not configured").into_response(),
    };
    // #207 Slice A: physics is source-2's role — the one that goes dark if source-2's box dies — so it
    // gets an ordered candidate list (CREW_PHYSICS_CMD + optional _2/_3 standbys).
    let physics_cmds = role_candidates(&env, "CREW_PHYSICS_CMD", physics);
    // Stream NDJSON progress events as the crew runs. run_crew_streaming pushes lines onto the
    // channel; the response body drains them. On any failure it emits a terminal {"stage":"error"}
    // and the browser falls back to its local stand-in — same fail-closed contract as before.
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(32);
    tokio::spawn(run_crew_streaming(prompt, safety, physics_cmds, art, tx));
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|line| Ok::<Vec<u8>, std::io::Error>(line.into_bytes()));
    Response::builder()
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .body(Body::from_stream(stream))
        .expect("valid streaming response")
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
    async fn run_with_fallbacks_tries_candidates_in_order_first_success_wins() {
        // #207 Slice A (frozen): primary up ⇒ its output + index 0 (standby not run); primary down
        // ⇒ standby's output + index 1; all down ⇒ error; single candidate ⇒ unchanged, index 0.
        // The index is what candidate_label() uses to report WHO actually served, not a guess.
        assert_eq!(
            run_with_fallbacks(&["printf primary".into(), "printf standby".into()], String::new()).await.unwrap(),
            ("primary".to_string(), 0)
        );
        assert_eq!(
            run_with_fallbacks(&["false".into(), "printf standby".into()], String::new()).await.unwrap(),
            ("standby".to_string(), 1)
        );
        assert!(run_with_fallbacks(&["false".into(), "false".into()], String::new()).await.is_err());
        assert_eq!(
            run_with_fallbacks(&["printf only".into()], String::new()).await.unwrap(),
            ("only".to_string(), 0)
        );
    }

    #[test]
    fn candidate_label_reports_primary_at_index_0_and_standby_otherwise() {
        assert_eq!(candidate_label("source-2", "central (standby)", 0), "source-2");
        assert_eq!(candidate_label("source-2", "central (standby)", 1), "central (standby)");
        assert_eq!(candidate_label("source-2", "central (standby)", 2), "central (standby)");
    }

    #[test]
    fn role_candidates_reads_primary_plus_contiguous_fallbacks() {
        // #207 Slice A (frozen): primary + contiguous _2/_3; gap stops enumeration; none ⇒ single.
        let env = |k: &str| match k {
            "R_2" => Some("cmd2".to_string()),
            "R_3" => Some("cmd3".to_string()),
            _ => None,
        };
        assert_eq!(role_candidates(&env, "R", "cmd1".to_string()), vec!["cmd1", "cmd2", "cmd3"]);
        let gap = |k: &str| if k == "R_3" { Some("cmd3".to_string()) } else { None };
        assert_eq!(role_candidates(&gap, "R", "cmd1".to_string()), vec!["cmd1"]);
        assert_eq!(role_candidates(&(|_: &str| None), "R", "cmd1".to_string()), vec!["cmd1"]);
    }

    /// Drive run_crew_streaming to completion and collect its NDJSON events as parsed JSON objects.
    async fn collect(prompt: &str, safety: String, physics: String, art: String) -> Vec<Value> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
        let h = tokio::spawn(run_crew_streaming(prompt.to_string(), safety, vec![physics], art, tx));
        let mut evs = Vec::new();
        while let Some(chunk) = rx.recv().await {
            for line in chunk.split('\n') {
                let t = line.trim();
                if !t.is_empty() {
                    evs.push(serde_json::from_str::<Value>(t).expect("each streamed line is valid JSON"));
                }
            }
        }
        h.await.unwrap();
        evs
    }

    #[tokio::test]
    async fn streaming_crew_emits_stage_events_and_fails_closed() {
        // #173 A (frozen): the streaming bridge emits per-role progress and exactly one terminal
        // event — built / rejected / error — exercised with fixed-JSON local fakes (no network).
        let safety_ok = r#"printf '{"ok":true,"reason":""}'"#.to_string();
        let physics = r#"printf '{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}'"#.to_string();
        let art = r##"printf '{"theme":"night","birdColor":"#00ff41","birdEmoji":"X","title":"Neo"}'"##.to_string();

        let evs = collect("matrix", safety_ok.clone(), physics.clone(), art.clone()).await;
        let stages: Vec<&str> = evs.iter().map(|e| e["stage"].as_str().unwrap_or("")).collect();
        assert!(stages.contains(&"safety"), "a safety stage event is emitted");
        assert!(stages.contains(&"physics") && stages.contains(&"art"), "per-role events for both roles");
        let last = evs.last().unwrap();
        assert_eq!(last["stage"], "built", "terminal event is a build");
        assert_eq!(last["config"]["speed"], 220, "the built event carries the assembled config");
        assert!(last["auction"].as_array().map(|a| !a.is_empty()).unwrap_or(false), "and the auction");

        // safety reject → terminal 'rejected', and NO fragment calls happen after it.
        let safety_no = r#"printf '{"ok":false,"reason":"anti-prompt"}'"#.to_string();
        let evs2 = collect("evil", safety_no, physics.clone(), art.clone()).await;
        assert_eq!(evs2.last().unwrap()["stage"], "rejected");
        assert_eq!(evs2.last().unwrap()["safety"]["ok"], false);
        assert!(!evs2.iter().any(|e| e["stage"] == "physics"), "no physics/art after a safety reject");

        // a failing role command → terminal 'error' (→ browser falls back to its stand-in).
        let evs3 = collect("x", safety_ok, "false".into(), art).await;
        assert_eq!(evs3.last().unwrap()["stage"], "error");
    }

    #[test]
    fn run_cmd_kills_and_errors_a_role_that_exceeds_its_timeout() {
        // #188 (frozen): a hung role command is killed and reported as a timeout, not left to hang
        // /crew/build forever (the unbounded-subprocess bug reintroduced from channel_run.rs).
        let start = std::time::Instant::now();
        let err = run_cmd_with_timeout("sleep 5", "", std::time::Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("timed out"), "reports a timeout: {err}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "returns promptly on timeout, doesn't wait out the sleep");
        // A prompt command well within the bound still returns its output.
        let ok = run_cmd_with_timeout("printf hi", "", std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(ok, "hi");
    }

    #[tokio::test]
    async fn streaming_crew_runs_physics_and_art_concurrently() {
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
        let res = tokio::time::timeout(std::time::Duration::from_secs(3), collect("go", safety, physics, art)).await;
        let _ = std::fs::remove_dir_all(&dir);
        let evs = res.expect("physics+art must run concurrently — a serialized crew hangs on the barrier past 3s");
        assert_eq!(evs.last().unwrap()["stage"], "built", "the concurrently-produced fragments assemble into a build");
    }
}

//! `ct-cookbook-bridge` (#201): the HTTP bridge the cookbook-demo browser POSTs `{prompt, image?}`
//! to. Runs the crew — **safety_check**, then **structure** (source-2, with the photo), then
//! **presentation** (sink, over the structure output) — streaming per-stage NDJSON, assembling via
//! [`ct_common::cookbook`]. Unlike the flappy bridge (physics ∥ art are independent), the recipe crew
//! is **sequential**: presentation names/themes the actual recipe, so it depends on structure's
//! output. Fail-closed: any role failure → a terminal `{"stage":"error"}` → the browser falls back.
//!
//! A **separate, self-contained bridge per pipeline** by design (maintainer 2026-07-26): the agents
//! (source-2/sink/central) are reused across pipelines, but each pipeline gets its own bridge — no
//! shared bridge abstraction — so `ct-crew-bridge` stays untouched/stable and the two pipelines'
//! (very different) role/fragment shapes evolve independently. The small `run_cmd`/streaming helpers
//! are therefore intentionally duplicated here rather than shared; each copy carries the #188 timeout.
//!
//! Role commands (each a `ct-agent channel … --call service/<slug>` over the tunnel, or a handler):
//!   * `COOKBOOK_SAFETY_CMD`       — prompt → `{"ok":bool,"reason":str}` (text-only for v1)
//!   * `COOKBOOK_STRUCTURE_CMD`    — `{prompt, image?}` → IngredientsFragment JSON (source-2)
//!   * `COOKBOOK_PRESENTATION_CMD` — `{prompt, structure}` → RecipeFragment JSON (sink)
//!   * `COOKBOOK_REVIEW_CMD`       — `{prompt, recipe}` → `{"ok":bool,"reason":str}` — a
//!     post-generation LLM review of the FINISHED recipe (inedible/poison items, dietary-constraint
//!     contradictions, plausible flavour sense); `{ok:false}` refuses the recipe (#201 safety addenda)
//!   * `COOKBOOK_BRIDGE_LISTEN` (default `0.0.0.0:8789`)

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ct_common::cookbook::{RecipeBuildResponse, RecipeCard};
use ct_common::crew::{RoleAuction, RoleBid};
use serde_json::{json, Value};
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;

/// #304: cap concurrently in-flight builds -- each one drives up to 4 sequential paid `claude -p`
/// role calls (up to ~60s each, `ROLE_CMD_TIMEOUT`), unbounded before this. Same rationale as
/// `ct-crew-bridge`'s own `build_semaphore` (duplicated per this crate's "separate, self-contained
/// bridge per pipeline" convention, see the module doc). `COOKBOOK_MAX_CONCURRENT_BUILDS`-tunable.
fn build_semaphore() -> Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        let n = std::env::var("COOKBOOK_MAX_CONCURRENT_BUILDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(2);
        Arc::new(Semaphore::new(n))
    })
    .clone()
}

/// Hard cap on a single role command (#188). A role is a `ct-agent channel … --call` doing a ~14s
/// `claude -p`; generous so a legitimately slow role isn't cut, but bounded so a *wedged* handler /
/// stalled channel call can't leak a zombie subprocess and hang `/cookbook/build` forever.
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
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn role command failed: {e}"))?;
    let pid = child.id();
    // Write the input on its OWN thread so it proceeds concurrently with the wait/read below.
    // Best-effort: a command that exits before draining stdin makes this write fail with a broken
    // pipe — deliberately IGNORED, since exit status + stdout is the verdict. (Same fix as
    // run_service_handler_with_timeout in channel_run.rs.)
    let mut stdin = child.stdin.take().ok_or("no stdin handle")?;
    let input_owned = input.to_string();
    std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });
    // #188: bound wait_with_output so a hung command can't wait forever — run it on a background
    // thread and, on timeout, KILL the child by pid so it can't linger as a zombie.
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
        // Was silently `Stdio::null()`'d before — the underlying `ct-agent channel --call-service`
        // process's OWN diagnostic (admission timeout, connection refused, channel-join stalled,
        // etc.) was thrown away, leaving only a useless bare exit code ("role command exited
        // Some(1)") with no way to tell a real outage from a transient admission race. Capture and
        // surface it now, same as run_service_handler_with_timeout in channel_run.rs already does.
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!(
            "role command exited {:?}{}",
            out.status.code(),
            if stderr.is_empty() { String::new() } else { format!(": {stderr}") }
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stdout.is_empty() {
        // Same principle as #206's server-side fix (channel_run.rs's run_service_handler): a
        // successful exit with genuinely empty stdout is never a legitimate role response — it
        // silently produced the cryptic "recipe fragments malformed: EOF while parsing a value"
        // instead of an honest, attributable error. #206 covers the case where the SERVER's own
        // handler process gets killed mid-run; this closes the equivalent gap on the CLIENT side
        // (the bridge's own `ct-agent channel --call-service` dial exiting 0 with nothing printed —
        // e.g. a response-read race, not necessarily #206's exact mechanism) so an empty result is
        // ALWAYS treated as an error regardless of which side or layer produced it.
        return Err(format!("role command exited {:?} but produced no output", out.status.code()));
    }
    Ok(stdout)
}

/// Up to `max_attempts` tries on failure. Root-caused live (2026-07-27): the edge's own
/// `RelayHandoffError` (`crates/edge/src/channel_broker.rs`, #148) explicitly documents that a
/// mid-handoff ack-write failure against ONE side of a relay pair is a "transient handoff race,
/// not an admission refusal" and that "a bare retry by the survivor should re-pair" — but nothing
/// on the client side ever actually retried, so every role dial that raced this (observed hitting
/// art/presentation under back-to-back load, surfacing as "edge broker refused the channel join")
/// or the related #140 "admission exchange stalled" condition surfaced as a hard, permanent-
/// looking failure even though a later attempt routinely succeeds.
async fn run_cmd_async_with_retries(cmd: String, input: String, max_attempts: u32) -> Result<String, String> {
    let mut last = Err("no attempts made".to_string());
    for _ in 0..max_attempts.max(1) {
        let (cmd, input) = (cmd.clone(), input.clone());
        last = tokio::task::spawn_blocking(move || run_cmd(&cmd, &input))
            .await
            .map_err(|e| format!("role task join failed: {e}"))?;
        if last.is_ok() {
            return last;
        }
    }
    last
}

/// 3 total attempts — the default for a role with no configured standby (nowhere else to fall
/// through to, so it's worth paying the retry cost in full to recover a transient race).
async fn run_cmd_async(cmd: String, input: String) -> Result<String, String> {
    run_cmd_async_with_retries(cmd, input, 3).await
}

/// #207 Slice A — ordered-candidate failover. Run a role against an ORDERED list of candidate
/// commands, trying each until one succeeds. Candidate 0 is the primary (e.g. source-2's serve); if it
/// errs — unreachable, non-zero exit, empty output (#206), or timeout — the next candidate (e.g.
/// sink's parallel standby serve) is tried, and so on. First success wins, so the primary "always
/// wins while it's up" and a standby "takes over when it can't connect", with no reconfig. OPT-IN: a
/// role with a single candidate behaves exactly as before (this just wraps `run_cmd_async`). Returns
/// the LAST candidate's error if every candidate fails.
/// Returns `(output, winning_candidate_index)` — the index lets the caller report WHO actually
/// served the request (the previous version discarded this, so the demo's "auction" display always
/// claimed the primary won even when a standby served — misleading exactly when failover matters).
async fn run_with_fallbacks(candidates: &[String], input: String) -> Result<(String, usize), String> {
    // Live-observed (2026-07-27, real browser test): giving EVERY candidate the full 3-attempt
    // retry meant a persistently-down primary (source-2, mid-outage — not just racing a transient
    // #148 blip) wasted up to 3x its own timeout before ever reaching a working standby, pushing a
    // real build past 120s on the ingredients stage alone. A candidate with somewhere else to fall
    // through to should fail fast; only the LAST candidate (nowhere further to go) is worth paying
    // the full retry cost for, since that's exactly the #148/#140 transient-race case retries fix.
    let last_index = candidates.len().saturating_sub(1);
    let mut last = Err("no role command configured".to_string());
    for (i, cmd) in candidates.iter().enumerate() {
        let attempts = if i == last_index { 3 } else { 1 };
        match run_cmd_async_with_retries(cmd.clone(), input.clone(), attempts).await {
            Ok(out) => return Ok((out, i)),
            Err(e) => {
                if candidates.len() > 1 {
                    eprintln!(
                        "ct-cookbook-bridge: role candidate {}/{} failed ({e}); trying next (#207)",
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

/// #207 Slice A — build a role's ordered candidate list from env: the primary `<primary_key>` plus any
/// CONTIGUOUS fallbacks `<primary_key>_2`, `<primary_key>_3`, … (stopping at the first unset). With no
/// fallbacks set this is a single-candidate list, i.e. unchanged behaviour.
fn role_candidates<F: Fn(&str) -> Option<String>>(env: &F, primary_key: &str, primary: String) -> Vec<String> {
    let mut v = vec![primary];
    let mut n = 2;
    while let Some(c) = env(&format!("{primary_key}_{n}")) {
        v.push(c);
        n += 1;
    }
    v
}

/// Emit one NDJSON progress event (a JSON object + `\n`) to the response stream.
async fn emit(tx: &Sender<String>, ev: Value) {
    let _ = tx.send(ev.to_string() + "\n").await;
}

/// The visible auction for the demo recipe crew (the winners that produced each fragment).
/// `structure_who` reflects which candidate ACTUALLY served (source-2 vs a standby), not a
/// hardcoded guess, so the display stays honest under #207's failover.
fn demo_auction(structure_who: &str) -> Vec<RoleAuction> {
    vec![
        RoleAuction {
            role: "structure".into(),
            bids: vec![RoleBid { who: structure_who.into(), model: "claude".into(), units: 20, price: 50, win: true }],
        },
        RoleAuction {
            role: "presentation".into(),
            bids: vec![RoleBid { who: "sink".into(), model: "claude".into(), units: 20, price: 40, win: true }],
        },
    ]
}

/// Drive the recipe crew and stream per-stage NDJSON. Terminal event is exactly one of `built` /
/// `rejected` / `error`; intermediate events are `{"stage":"safety|structure|presentation","status"}`.
async fn run_cookbook_streaming(
    prompt: String,
    image: Option<String>,
    lang: String,
    safety_cmd: String,
    structure_cmds: Vec<String>,
    presentation_cmd: String,
    review_cmd: String,
    tx: Sender<String>,
) {
    // 1. safety_check — text-only for v1 (image moderation is a fast-follow).
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

    // #304: the browser already gave up (dropped the response stream, closing `rx`) -- don't start
    // the remaining paid role calls for nobody to read. Doesn't abort work already in flight, only
    // what hasn't started yet; checked again before each later paid stage below for the same reason.
    if tx.is_closed() {
        return;
    }

    // 2. structure (source-2) — the photo bytes travel over the channel here, as base64 in the JSON
    //    the role receives; source-2's handler decodes it to a local temp file for its own claude -p.
    emit(&tx, json!({"stage": "structure", "status": "start"})).await;
    // #201 i18n: the desired output language rides to the generating roles so the recipe text comes
    // back in it (a German prompt yields a German recipe). safety/review are language-agnostic
    // classifiers, so they don't need it.
    let structure_input = json!({"prompt": prompt, "image": image, "lang": lang}).to_string();
    // #207 Slice A: dial the structure role (source-2) across its candidate list — primary first,
    // then any configured standby — so source-2 wins while up and sink's standby takes over when it
    // can't connect. Single candidate ⇒ identical to before.
    let (structure_out, structure_winner) = match run_with_fallbacks(&structure_cmds, structure_input).await {
        Ok((o, i)) => (o, i),
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("structure role unreachable: {e}")})).await,
    };
    emit(&tx, json!({"stage": "structure", "status": "done"})).await;

    if tx.is_closed() {
        return;
    }

    // 3. presentation (sink) — names/themes/plates over the ACTUAL recipe, so it takes structure's
    //    output as context. Sequential (not parallel) because of this dependency.
    emit(&tx, json!({"stage": "presentation", "status": "start"})).await;
    let structure_val: Value = serde_json::from_str(&structure_out).unwrap_or(Value::Null);
    let presentation_input = json!({"prompt": prompt, "structure": structure_val, "lang": lang}).to_string();
    let presentation_out = match run_cmd_async(presentation_cmd, presentation_input).await {
        Ok(o) => o,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("presentation role unreachable: {e}")})).await,
    };
    emit(&tx, json!({"stage": "presentation", "status": "done"})).await;

    // 4. assemble the recipe card (fail-closed on a malformed fragment).
    let card = match RecipeCard::from_fragment_json(&structure_out, &presentation_out) {
        Ok(c) => c,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("recipe fragments malformed: {e}")})).await,
    };

    if tx.is_closed() {
        return;
    }

    // 5. review (#201 safety addenda) — a post-generation LLM review of the FINISHED recipe:
    //    inedible/poisonous items, contradictions with a stated dietary constraint (e.g.
    //    "vegetarian" + Schnitzel), plausible flavour sense — evaluated holistically, the
    //    machine-checkable layer on top of prompting (which alone isn't reliable for this class,
    //    and the stakes are higher than a wrong game colour). A `{ok:false}` verdict REFUSES the
    //    recipe with the reviewer's reason.
    emit(&tx, json!({"stage": "review", "status": "start"})).await;
    let review_input = json!({"prompt": prompt, "recipe": serde_json::to_value(&card).unwrap_or(Value::Null)}).to_string();
    let review_out = match run_cmd_async(review_cmd, review_input).await {
        Ok(o) => o,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("review role unreachable: {e}")})).await,
    };
    let review_verdict: Value = match serde_json::from_str(&review_out) {
        Ok(v) => v,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("review reply not JSON: {e}")})).await,
    };
    if review_verdict.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = review_verdict
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("the recipe review flagged a safety/consistency problem");
        return emit(&tx, json!({"stage": "rejected", "safety": {"ok": false, "reason": reason}})).await;
    }
    emit(&tx, json!({"stage": "review", "status": "ok"})).await;

    // 6. built — the reviewed, assembled recipe.
    let structure_who = candidate_label("source-2", "central (standby)", structure_winner);
    let mut built = serde_json::to_value(RecipeBuildResponse::built(card, demo_auction(&structure_who))).unwrap_or_else(|_| json!({}));
    if let Value::Object(m) = &mut built {
        m.insert("stage".into(), json!("built"));
    }
    emit(&tx, built).await;
}

async fn build_handler(Json(body): Json<Value>) -> Response {
    let prompt = body.get("prompt").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if prompt.len() < 3 {
        return (StatusCode::BAD_REQUEST, "tell me a bit more about what you want to cook").into_response();
    }
    // #304: admit against the concurrency cap BEFORE spawning anything -- an over-cap request never
    // starts a single paid role call. The permit is held by the spawned task for its whole lifetime
    // (moved in below) and released automatically when it finishes.
    let Ok(permit) = build_semaphore().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many builds in flight right now — try again shortly",
        )
            .into_response();
    };
    // Optional photo of the ingredients, base64 in the JSON payload (#201 image transport).
    let image = body.get("image").and_then(Value::as_str).map(str::to_string);
    // #201 i18n: desired recipe language (BCP-47-ish, e.g. "en"/"de"); default English.
    let lang = body.get("lang").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("en").to_string();
    let env = |k: &str| std::env::var(k).ok();
    let (safety, structure, presentation, review) = match (
        env("COOKBOOK_SAFETY_CMD"),
        env("COOKBOOK_STRUCTURE_CMD"),
        env("COOKBOOK_PRESENTATION_CMD"),
        env("COOKBOOK_REVIEW_CMD"),
    ) {
        (Some(s), Some(st), Some(p), Some(r)) => (s, st, p, r),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "cookbook role commands not configured").into_response(),
    };
    // #207 Slice A: the structure role (source-2's) is the one that goes dark if source-2's box dies,
    // so it gets an ordered candidate list (primary COOKBOOK_STRUCTURE_CMD + optional _2/_3 standbys).
    let structure_cmds = role_candidates(&env, "COOKBOOK_STRUCTURE_CMD", structure);
    // Stream NDJSON progress events as the crew runs. run_cookbook_streaming pushes lines onto the
    // channel; on any failure it emits a terminal {"stage":"error"} and the browser falls back.
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(32);
    tokio::spawn(async move {
        let _permit = permit; // held for the whole build, released when this task ends
        run_cookbook_streaming(prompt, image, lang, safety, structure_cmds, presentation, review, tx).await;
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(|line| Ok::<Vec<u8>, std::io::Error>(line.into_bytes()));
    Response::builder()
        .header("content-type", "application/x-ndjson")
        .header("cache-control", "no-store")
        .body(Body::from_stream(stream))
        .expect("valid streaming response")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = std::env::var("COOKBOOK_BRIDGE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8789".to_string());
    let app = Router::new().route("/cookbook/build", post(build_handler));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    eprintln!("ct-cookbook-bridge: serving POST /cookbook/build on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_semaphore_caps_concurrent_admits_at_the_configured_limit_304() {
        // #304: default cap is 2 (no COOKBOOK_MAX_CONCURRENT_BUILDS set in the test env). The
        // semaphore is a process-global OnceLock, so this is the only test in this file allowed to
        // touch it.
        let sem = build_semaphore();
        let p1 = sem.clone().try_acquire_owned().expect("first permit admits");
        let p2 = sem.clone().try_acquire_owned().expect("second permit admits (default cap is 2)");
        assert!(
            sem.clone().try_acquire_owned().is_err(),
            "a third concurrent build is refused, not queued/spawned"
        );
        drop(p1);
        assert!(sem.try_acquire_owned().is_ok(), "releasing a permit frees a slot for the next build");
        drop(p2);
    }

    async fn collect(prompt: &str, image: Option<String>, safety: String, structure: String, presentation: String, review: String) -> Vec<Value> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
        let h = tokio::spawn(run_cookbook_streaming(prompt.to_string(), image, "en".to_string(), safety, vec![structure], presentation, review, tx));
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

    #[test]
    fn run_cmd_kills_and_errors_a_role_that_exceeds_its_timeout() {
        // #188 (frozen): a hung role command is killed and reported as a timeout (this bridge's own
        // copy — separate-bridge-per-pipeline by design, each carries the timeout).
        let start = std::time::Instant::now();
        let err = run_cmd_with_timeout("sleep 5", "", std::time::Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("timed out"), "reports a timeout: {err}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2), "returns promptly on timeout");
        assert_eq!(run_cmd_with_timeout("printf hi", "", std::time::Duration::from_secs(5)).unwrap(), "hi");
    }

    #[test]
    fn run_cmd_errors_instead_of_silently_succeeding_on_empty_stdout() {
        // Frozen: closes the client-side equivalent of #206 — a command that exits 0 with
        // genuinely empty stdout ("true") must be reported as an error, not silently accepted as
        // Ok(""), which previously flowed on to produce the cryptic "recipe fragments malformed:
        // EOF while parsing a value" instead of an honest, attributable error.
        let err = run_cmd("true", "").unwrap_err();
        assert!(err.contains("no output"), "empty-but-successful stdout must error, got: {err}");
    }

    #[tokio::test]
    async fn run_cmd_async_retries_up_to_3_attempts_recovering_from_transient_failures() {
        // Frozen (root-caused live 2026-07-27, see the doc comment on run_cmd_async): a role dial
        // that fails on its first attempt (the edge's own documented "transient handoff race") must
        // succeed anyway if a retry would have worked. A counter file makes the command fail exactly
        // once, then succeed — proving the retry (not just luck) recovers it.
        let marker = std::env::temp_dir().join(format!(
            "ct-retry-test-1fail-{}-{:?}.marker",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let m = marker.to_string_lossy().replace('\'', "");
        let cmd = format!("if [ -f '{m}' ]; then printf ok; else : > '{m}'; exit 1; fi");
        let out = run_cmd_async(cmd, String::new()).await;
        let _ = std::fs::remove_file(&marker);
        assert_eq!(out.unwrap(), "ok", "recovers a command that only fails on its first try");
    }

    #[tokio::test]
    async fn run_cmd_async_recovers_from_two_consecutive_transient_failures() {
        // Frozen: live testing found a SINGLE retry insufficient under sustained concurrent load —
        // the same request raced two consecutive attempts, not just one. A counter file makes the
        // command fail exactly twice, then succeed on the 3rd (final) attempt.
        let marker = std::env::temp_dir().join(format!(
            "ct-retry-test-2fail-{}-{:?}.count",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let m = marker.to_string_lossy().replace('\'', "");
        let cmd = format!(
            "n=$(cat '{m}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{m}'; \
             if [ \"$n\" -ge 3 ]; then printf ok; else exit 1; fi"
        );
        let out = run_cmd_async(cmd, String::new()).await;
        let _ = std::fs::remove_file(&marker);
        assert_eq!(out.unwrap(), "ok", "3 total attempts recovers a command that fails its first 2 tries");
    }

    #[tokio::test]
    async fn run_cmd_async_gives_up_after_3_attempts_on_a_genuine_failure() {
        // Frozen: a command that ALWAYS fails must still fail after exhausting all 3 attempts —
        // the retry is bounded, not an infinite loop that would hang a real outage forever.
        assert!(run_cmd_async("false".to_string(), String::new()).await.is_err());
    }

    #[tokio::test]
    async fn run_with_fallbacks_gives_a_non_last_candidate_only_1_attempt_but_the_last_candidate_3() {
        // Frozen (root-caused live 2026-07-27, real browser test): giving EVERY candidate the full
        // 3-attempt retry meant a persistently-down primary wasted up to 3x its own timeout before
        // ever reaching a working standby — a real build took 120s+ on ingredients alone. A counter
        // file proves candidate 0 is tried exactly ONCE (not retried) before falling through, while
        // the LAST candidate still gets its full 3 attempts to recover a genuine transient race.
        let marker = std::env::temp_dir().join(format!(
            "ct-fastfail-test-{}-{:?}.count",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&marker);
        let m = marker.to_string_lossy().replace('\'', "");
        // Candidate 0 always fails but COUNTS its own invocations; candidate 1 (the last) succeeds
        // only on ITS 3rd attempt, proving both halves of the policy in one pass.
        let primary = format!("n=$(cat '{m}' 2>/dev/null || echo 0); echo $((n+1)) > '{m}'; exit 1");
        let standby_marker = std::env::temp_dir().join(format!(
            "ct-fastfail-test-standby-{}-{:?}.count",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&standby_marker);
        let sm = standby_marker.to_string_lossy().replace('\'', "");
        let standby = format!(
            "n=$(cat '{sm}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{sm}'; \
             if [ \"$n\" -ge 3 ]; then printf ok; else exit 1; fi"
        );
        let (out, idx) = run_with_fallbacks(&[primary, standby], String::new()).await.unwrap();
        let primary_calls: u32 = std::fs::read_to_string(&marker).unwrap_or_default().trim().parse().unwrap_or(0);
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(&standby_marker);
        assert_eq!(primary_calls, 1, "the non-last candidate must be tried exactly once, not retried");
        assert_eq!((out, idx), ("ok".to_string(), 1), "the last candidate still gets its full retries");
    }

    #[tokio::test]
    async fn run_with_fallbacks_tries_candidates_in_order_first_success_wins() {
        // #207 Slice A (frozen): the failover primitive. Primary up ⇒ its output + index 0, standby
        // not run; primary down ⇒ standby's output + index 1; all down ⇒ error. `false` exits
        // non-zero (a down provider); `printf X` is a live one. The index is what candidate_label()
        // uses to report WHO actually served, not a guess.
        // primary succeeds → standby never runs (its output must NOT appear).
        let (out, idx) = run_with_fallbacks(
            &["printf primary".to_string(), "printf standby".to_string()],
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!((out, idx), ("primary".to_string(), 0), "primary wins while it's up");
        // primary fails (exit 1) → standby takes over.
        let (out, idx) = run_with_fallbacks(
            &["false".to_string(), "printf standby".to_string()],
            String::new(),
        )
        .await
        .unwrap();
        assert_eq!((out, idx), ("standby".to_string(), 1), "standby takes over when the primary can't serve");
        // every candidate fails → error (the last one's).
        assert!(
            run_with_fallbacks(&["false".to_string(), "false".to_string()], String::new())
                .await
                .is_err(),
            "all-down ⇒ error"
        );
        // single candidate ⇒ unchanged behaviour.
        assert_eq!(
            run_with_fallbacks(&["printf only".to_string()], String::new()).await.unwrap(),
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
        // #207 Slice A (frozen): primary + contiguous _2/_3 fallbacks; stops at the first gap; no
        // fallbacks ⇒ single-candidate list (unchanged behaviour).
        let env = |k: &str| match k {
            "R_2" => Some("cmd2".to_string()),
            "R_3" => Some("cmd3".to_string()),
            _ => None,
        };
        assert_eq!(role_candidates(&env, "R", "cmd1".to_string()), vec!["cmd1", "cmd2", "cmd3"]);
        // a gap at _2 stops enumeration even if _3 is set.
        let gap = |k: &str| if k == "R_3" { Some("cmd3".to_string()) } else { None };
        assert_eq!(role_candidates(&gap, "R", "cmd1".to_string()), vec!["cmd1"]);
        // no fallbacks ⇒ just the primary.
        let none = |_: &str| None;
        assert_eq!(role_candidates(&none, "R", "cmd1".to_string()), vec!["cmd1"]);
    }

    #[tokio::test]
    async fn streaming_cookbook_emits_sequential_stages_and_fails_closed() {
        // #201 (frozen): safety → structure → presentation (SEQUENTIAL) → built, exercised with
        // fixed-JSON local fakes. Terminal is built/rejected/error; a reject skips the roles.
        let safety_ok = r#"printf '{"ok":true,"reason":""}'"#.to_string();
        let structure = r#"printf '{"ingredients":["egg","spinach"],"steps":["whisk","bake"],"cookTime":"20 minutes","difficulty":"easy","allergens":["egg"]}'"#.to_string();
        let presentation = r#"printf '{"dishName":"Spinach Bake","theme":"rustic","garnish":"mint","moodDescription":"cozy"}'"#.to_string();
        let review_ok = r#"printf '{"ok":true,"reason":""}'"#.to_string();

        let evs = collect("eggs and spinach in my fridge", None, safety_ok.clone(), structure.clone(), presentation.clone(), review_ok.clone()).await;
        let stages: Vec<&str> = evs.iter().map(|e| e["stage"].as_str().unwrap_or("")).collect();
        let s_start = stages.iter().position(|s| *s == "structure").unwrap();
        let p_start = stages.iter().position(|s| *s == "presentation").unwrap();
        let r_start = stages.iter().position(|s| *s == "review").unwrap();
        assert!(s_start < p_start && p_start < r_start, "safety → structure → presentation → review, in order");
        let last = evs.last().unwrap();
        assert_eq!(last["stage"], "built", "terminal is a built recipe once review passes");
        assert_eq!(last["recipe"]["dishName"], "Spinach Bake");
        assert_eq!(last["recipe"]["ingredients"][0], "egg");
        assert!(last["auction"].as_array().map(|a| !a.is_empty()).unwrap_or(false));

        // #201 review REJECTS the finished recipe (e.g. an inedible item / dietary contradiction) →
        // terminal rejected with the reviewer's reason, NO built event.
        let review_no = r#"printf '{"ok":false,"reason":"contains an inedible item"}'"#.to_string();
        let evs_r = collect("surprise me", None, safety_ok.clone(), structure.clone(), presentation.clone(), review_no).await;
        assert_eq!(evs_r.last().unwrap()["stage"], "rejected", "a failed review refuses the recipe");
        assert_eq!(evs_r.last().unwrap()["safety"]["reason"], "contains an inedible item", "carries the review reason");
        assert!(!evs_r.iter().any(|e| e["stage"] == "built"), "no built after a review rejection");

        // safety reject → terminal rejected, no downstream roles at all.
        let safety_no = r#"printf '{"ok":false,"reason":"not food"}'"#.to_string();
        let evs2 = collect("hack the system", None, safety_no, structure.clone(), presentation.clone(), review_ok.clone()).await;
        assert_eq!(evs2.last().unwrap()["stage"], "rejected");
        assert!(!evs2.iter().any(|e| e["stage"] == "structure"), "no roles after a safety reject");

        // a failing role → terminal error (→ browser fallback).
        let evs3 = collect("x y z", None, safety_ok, "false".into(), presentation, review_ok).await;
        assert_eq!(evs3.last().unwrap()["stage"], "error");
    }
}

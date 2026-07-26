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
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;

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
        .stderr(Stdio::null())
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
        return Err(format!("role command exited {:?}", out.status.code()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn run_cmd_async(cmd: String, input: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || run_cmd(&cmd, &input))
        .await
        .map_err(|e| format!("role task join failed: {e}"))?
}

/// Emit one NDJSON progress event (a JSON object + `\n`) to the response stream.
async fn emit(tx: &Sender<String>, ev: Value) {
    let _ = tx.send(ev.to_string() + "\n").await;
}

/// The visible auction for the demo recipe crew (the winners that produced each fragment).
fn demo_auction() -> Vec<RoleAuction> {
    vec![
        RoleAuction {
            role: "structure".into(),
            bids: vec![RoleBid { who: "source-2".into(), model: "claude".into(), units: 20, price: 50, win: true }],
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
    structure_cmd: String,
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

    // 2. structure (source-2) — the photo bytes travel over the channel here, as base64 in the JSON
    //    the role receives; source-2's handler decodes it to a local temp file for its own claude -p.
    emit(&tx, json!({"stage": "structure", "status": "start"})).await;
    // #201 i18n: the desired output language rides to the generating roles so the recipe text comes
    // back in it (a German prompt yields a German recipe). safety/review are language-agnostic
    // classifiers, so they don't need it.
    let structure_input = json!({"prompt": prompt, "image": image, "lang": lang}).to_string();
    let structure_out = match run_cmd_async(structure_cmd, structure_input).await {
        Ok(o) => o,
        Err(e) => return emit(&tx, json!({"stage": "error", "message": format!("structure role unreachable: {e}")})).await,
    };
    emit(&tx, json!({"stage": "structure", "status": "done"})).await;

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
    let mut built = serde_json::to_value(RecipeBuildResponse::built(card, demo_auction())).unwrap_or_else(|_| json!({}));
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
    // Stream NDJSON progress events as the crew runs. run_cookbook_streaming pushes lines onto the
    // channel; on any failure it emits a terminal {"stage":"error"} and the browser falls back.
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(32);
    tokio::spawn(run_cookbook_streaming(prompt, image, lang, safety, structure, presentation, review, tx));
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

    async fn collect(prompt: &str, image: Option<String>, safety: String, structure: String, presentation: String, review: String) -> Vec<Value> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);
        let h = tokio::spawn(run_cookbook_streaming(prompt.to_string(), image, "en".to_string(), safety, structure, presentation, review, tx));
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

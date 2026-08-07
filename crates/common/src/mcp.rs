//! #135 L2.3 — MCP tool dispatch over an Agent-Fabric channel.
//!
//! The application layer that turns the persistent request/response session ([`crate::a2a::serve_request_loop`],
//! L2.1) into a **callable service**: each framed request body is a JSON-RPC 2.0 message, this module
//! routes it to a registered tool and produces the JSON-RPC response body. It is transport-agnostic —
//! it never sees the Noise tunnel or the channel; the runner frames these bytes and the pump carries
//! them encrypted. MCP (Model Context Protocol) is JSON-RPC 2.0, so we model exactly the subset an
//! agent needs to expose capabilities: `tools/list` (advertise) and `tools/call` (invoke), plus a
//! minimal `initialize` handshake. Trust is unchanged: the channel already authenticated the peer via
//! Noise + the holder-attested membership (invariants #1–#3); a tool decides its own authorization.
//!
//! Envelope note: the frame envelope stays `noise::frame` (L2.1/L2.2) — JSON-RPC carries its own `id`
//! for request/response correlation inside the body, so no richer wire envelope is required here; any
//! version/type framing (the open L2.2 question) remains additive underneath this.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The JSON-RPC protocol version every message carries.
const JSONRPC_VERSION: &str = "2.0";
/// The MCP protocol version this dispatcher advertises at `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

// Standard JSON-RPC 2.0 error codes.
const PARSE_ERROR: i64 = -32700;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
/// Implementation-defined server error range (JSON-RPC reserves -32000..=-32099); a tool that fails.
const TOOL_ERROR: i64 = -32000;

/// A parsed JSON-RPC 2.0 request. `id` is echoed verbatim into the response so a caller can correlate
/// concurrent calls; `params` is method-specific.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// A JSON-RPC 2.0 response — exactly one of `result` / `error` is set.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: JSONRPC_VERSION.to_string(), id, result: Some(result), error: None }
    }
    fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
    /// Serialize to the bytes that become one framed message body.
    fn into_bytes(self) -> Vec<u8> {
        // A response we constructed always serializes; fall back to a hand-built parse-error object.
        serde_json::to_vec(&self).unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response encode failed"}}"#
                .to_vec()
        })
    }
}

/// The identity of the channel-authenticated peer making a call — its Noise/holder public key — or
/// `None` for an anonymous/self call (the plain [`ToolRegistry::dispatch`] path). Threaded to
/// identity-aware tools (#163 `chat`/`propose`) so they can key on the **unspoofable** authenticated
/// identity, never a payload field a caller controls. Most tools ignore it; the ones that need it take
/// the [`register_ctx`](ToolRegistry::register_ctx) handler shape.
#[derive(Debug, Clone, Copy, Default)]
pub struct CallContext {
    /// The authenticated peer's 32-byte public key, or `None` when the caller is anonymous.
    pub peer: Option<[u8; 32]>,
}

impl CallContext {
    /// A call from an authenticated peer with the given public key.
    pub fn authenticated(peer: [u8; 32]) -> Self {
        Self { peer: Some(peer) }
    }
}

/// A tool the agent advertises + can be asked to run. `handler` maps the call's [`CallContext`] +
/// `arguments` object to a result value (or an error message → a JSON-RPC tool error). Handlers are
/// `Send + Sync` so the registry can live behind an `Arc` in the persistent serve loop.
type ToolHandler = Box<dyn Fn(&CallContext, &Value) -> Result<Value, String> + Send + Sync>;

struct Tool {
    description: String,
    handler: ToolHandler,
}

/// A set of MCP tools an agent exposes over its channel. Dispatches JSON-RPC requests against them;
/// unknown methods/tools and malformed input all produce a well-formed JSON-RPC error response (never
/// a panic, never a dropped request), so one bad call can't wedge the persistent session.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Tool>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: BTreeMap::new() }
    }

    /// Register a tool by `name`, with a human `description` and a `handler(arguments) -> result`. The
    /// handler ignores the caller's identity — the shape every existing tool uses. Identity-aware tools
    /// (#163) use [`register_ctx`](Self::register_ctx) instead.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        handler: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static,
    ) -> &mut Self {
        self.register_ctx(name, description, move |_ctx, args| handler(args))
    }

    /// Register an **identity-aware** tool whose handler also receives the [`CallContext`] — the
    /// channel-authenticated peer making the call (#163). Used by tools that must key on the
    /// unspoofable authenticated identity (rate-limiting `chat`, binding a `propose` decision to its
    /// proposer) rather than a caller-supplied field.
    pub fn register_ctx(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        handler: impl Fn(&CallContext, &Value) -> Result<Value, String> + Send + Sync + 'static,
    ) -> &mut Self {
        self.tools.insert(
            name.into(),
            Tool { description: description.into(), handler: Box::new(handler) },
        );
        self
    }

    /// The `tools/list` payload — each tool's `name` + `description`.
    fn list(&self) -> Value {
        let tools: Vec<Value> = self
            .tools
            .iter()
            .map(|(name, t)| json!({ "name": name, "description": t.description }))
            .collect();
        json!({ "tools": tools })
    }

    /// Route one already-parsed request to a response, in the given caller [`CallContext`].
    fn route(&self, ctx: &CallContext, req: JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id;
        match req.method.as_str() {
            // Minimal MCP handshake — advertise the protocol version + that we serve tools.
            "initialize" => JsonRpcResponse::ok(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ct-agent", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "tools/list" => JsonRpcResponse::ok(id, self.list()),
            "tools/call" => {
                let name = match req.params.get("name").and_then(Value::as_str) {
                    Some(n) => n,
                    None => {
                        return JsonRpcResponse::err(id, INVALID_PARAMS, "tools/call requires a string `name`")
                    }
                };
                let arguments = req.params.get("arguments").cloned().unwrap_or(Value::Null);
                match self.tools.get(name) {
                    Some(tool) => match (tool.handler)(ctx, &arguments) {
                        Ok(result) => JsonRpcResponse::ok(id, result),
                        Err(msg) => JsonRpcResponse::err(id, TOOL_ERROR, msg),
                    },
                    None => JsonRpcResponse::err(id, INVALID_PARAMS, format!("unknown tool `{name}`")),
                }
            }
            other => JsonRpcResponse::err(id, METHOD_NOT_FOUND, format!("unknown method `{other}`")),
        }
    }

    /// Dispatch one JSON-RPC request **body** to its response body (#135 L2.3), as an **anonymous**
    /// caller (no authenticated peer identity). Malformed JSON yields a JSON-RPC parse-error response
    /// (id `null`) rather than an error — so `serve_request_loop` keeps serving. This is the `handle` a
    /// channel-`--serve` session runs when it does not thread peer identity; identity-aware tools (#163)
    /// see `CallContext::peer == None` and refuse.
    pub fn dispatch(&self, request: &[u8]) -> Vec<u8> {
        self.dispatch_ctx(&CallContext::default(), request)
    }

    /// Dispatch one JSON-RPC request **body** on behalf of the given authenticated caller
    /// [`CallContext`] (#163). Identical to [`dispatch`](Self::dispatch) except identity-aware tools
    /// receive the channel-authenticated peer key. The serve loop calls this with the peer's Noise
    /// static key once it threads it through the handshake boundary.
    pub fn dispatch_ctx(&self, ctx: &CallContext, request: &[u8]) -> Vec<u8> {
        let req: JsonRpcRequest = match serde_json::from_slice(request) {
            Ok(r) => r,
            Err(e) => {
                return JsonRpcResponse::err(Value::Null, PARSE_ERROR, format!("invalid JSON-RPC: {e}"))
                    .into_bytes()
            }
        };
        self.route(ctx, req).into_bytes()
    }
}

/// Encode a JSON-RPC 2.0 request **body** (#135 L2.3, client side) — the bytes a caller frames and
/// sends to a peer's `--serve` MCP endpoint. `id` correlates the eventual response; `params` is
/// method-specific (`Value::Null` when a method takes none).
pub fn encode_request(id: impl Into<Value>, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id.into(),
        "method": method,
        "params": params,
    }))
    .expect("a request we constructed always serializes")
}

/// Decode a JSON-RPC 2.0 response **body** a peer's MCP endpoint returned (#135 L2.3, client side).
pub fn decode_response(bytes: &[u8]) -> Result<JsonRpcResponse, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON-RPC response: {e}"))
}

/// A minimal default tool registry for `ct-agent channel --serve` (#135 L2.3): a `ping` liveness tool,
/// so the persistent service is callable out of the box (`tools/list` → `[ping]`, `tools/call ping` →
/// `pong`). A real agent extends this with its own capability tools.
pub fn default_registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    r.register("ping", "liveness check → returns pong", |_| Ok(json!({ "reply": "pong" })));
    r
}

fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Register #147-L4.3 settlement-chain **gossip** tools on a registry, over a shared `chain`, so the
/// ledger propagates over the SAME authenticated #135 Agent-Fabric channel agents discover + cooperate
/// on (no separate P2P layer):
/// - `settlement/block` `{block: <hex>}` — decode + [`accept_block`](crate::settlement::Chain::accept_block)
///   a peer's block; returns the new `height` + `tip` (or a JSON-RPC tool error if it doesn't extend
///   the tip / is invalid — the ledger stays unchanged).
/// - `settlement/balance` `{account: <hex 32-byte>}` — query an account balance.
///
/// The send side is an agent calling `settlement/block` on its peers with `chain.tip_block().encode()`.
pub fn register_settlement_tools(
    reg: &mut ToolRegistry,
    chain: std::sync::Arc<std::sync::Mutex<crate::settlement::Chain>>,
) {
    let accept = std::sync::Arc::clone(&chain);
    reg.register(
        "settlement/block",
        "accept a gossiped settlement block (hex-encoded) into the ledger",
        move |args| {
            let hex = args.get("block").and_then(Value::as_str).ok_or("missing hex `block`")?;
            let bytes = from_hex(hex).ok_or("`block` is not valid hex")?;
            let block = crate::settlement::Block::decode(&bytes).ok_or("malformed block encoding")?;
            let mut chain = accept.lock().map_err(|_| "settlement chain lock poisoned")?;
            chain.accept_block(block).map_err(|e| e.to_string())?;
            Ok(json!({ "accepted": true, "height": chain.height(), "tip": to_hex(&chain.tip_hash()) }))
        },
    );
    let query = std::sync::Arc::clone(&chain);
    reg.register(
        "settlement/balance",
        "query a settlement account balance (32-byte hex account)",
        move |args| {
            let hex = args.get("account").and_then(Value::as_str).ok_or("missing hex `account`")?;
            let account: [u8; 32] = from_hex(hex)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or("`account` must be 32-byte hex")?;
            let mut chain = query.lock().map_err(|_| "settlement chain lock poisoned")?;
            Ok(json!({ "balance": chain.balance(&account) }))
        },
    );
}

/// Register #147-L2 **auction** tools on a registry so a seller-agent runs the idle-capacity auction
/// over the SAME authenticated #135 channel it's discovered + cooperated on:
/// - `auction/offer` `{}` — return the agent's holder-signed [`CapacityOffer`](crate::channel::CapacityOffer)
///   so a buyer discovers its advertised capacity + floor terms over the live session (like `agent/card`).
/// - `auction/bid` `{bid: <CapacityOffer-style JSON>}` — decode a buyer's signed
///   [`CapacityBid`](crate::channel::CapacityBid), clear it against *this agent's* offer with
///   [`match_offer`](crate::channel::match_offer), and return the [`CapacityMatch`](crate::channel::CapacityMatch)
///   (its deterministic `match_ref` keys the escrow `Hold` + L3 receipt), or a JSON-RPC tool error if it
///   doesn't clear.
///
/// Time is stamped by **this serving agent** via `now_fn`, never taken from the caller's request — so a
/// buyer can't pass a fake `now` to make an expired offer/bid clear.
///
/// #149-A.3 abuse control: `auction/bid` is per-consumer rate-limited (at most `max_bids_per_window`
/// bids per `window_secs`-second fixed window, reusing [`KeyedRateLimiter`](crate::ratelimit::KeyedRateLimiter)
/// — no new mechanism), keyed by the **authenticated** bidder. The bid's signature is verified *before*
/// the limiter is charged, so a forged bid carrying a victim's `bidder` can't exhaust that victim's
/// budget. This bounds how fast a single malicious consumer can hammer a provider with abuse attempts.
/// A `window_secs` of 0 disables windowing (a single all-time window).
pub fn register_auction_tools(
    reg: &mut ToolRegistry,
    offer: crate::channel::CapacityOffer,
    now_fn: impl Fn() -> crate::channel::UnixSeconds + Send + Sync + 'static,
    max_bids_per_window: u32,
    window_secs: u64,
) {
    let offer_for_get = offer.clone();
    reg.register(
        "auction/offer",
        "the agent's holder-signed CapacityOffer — its advertised idle capacity + floor terms",
        move |_| serde_json::to_value(&offer_for_get).map_err(|e| e.to_string()),
    );
    let limiter = std::sync::Arc::new(std::sync::Mutex::new(
        crate::ratelimit::KeyedRateLimiter::<[u8; 32]>::new(max_bids_per_window),
    ));
    // #158: authoritative per-offer capacity tally so cleared matches can't oversell this offer beyond
    // its `units_available` (match_offer alone is a stateless preview and would double-book).
    let commitments =
        std::sync::Arc::new(std::sync::Mutex::new(crate::channel::OfferCommitments::new()));
    reg.register_ctx(
        "auction/bid",
        "submit a signed CapacityBid; returns the cleared CapacityMatch, or a no-match tool error",
        move |ctx, args| {
            // #268: key the rate limiter on the channel-authenticated peer (the
            // unspoofable Noise/holder key), never `bid.bidder` -- that field is
            // self-declared inside the request body, so a consumer that rotates its
            // ed25519 keypair per bid got a fresh rate budget every call under the
            // old keying, exactly the "keyed on an unauthenticated caller-supplied
            // field" mistake #163's chat/propose tools (register_ctx + ctx.peer)
            // already avoid.
            let peer = ctx.peer.ok_or("auction/bid requires an authenticated channel peer")?;
            let bid_val = args.get("bid").ok_or("missing `bid` object")?;
            let bid: crate::channel::CapacityBid =
                serde_json::from_value(bid_val.clone()).map_err(|e| format!("malformed bid: {e}"))?;
            let now = now_fn();
            // Signature check retained: still the gate against a caller submitting a
            // forged bid *content* (wrong price/units) even once the rate limiter
            // itself can no longer be evaded via bidder-key rotation.
            if !bid.is_valid(now) {
                return Err("bid signature invalid or expired".to_string());
            }
            let window = now.checked_div(window_secs).unwrap_or(0);
            if !limiter
                .lock()
                .map_err(|_| "auction rate limiter lock poisoned")?
                .allow(&peer, window)
            {
                return Err("bid rate limit exceeded for this consumer — slow down".to_string());
            }
            match crate::channel::match_offer(&offer, &bid, now) {
                Some(m) => {
                    // #158: reserve the matched units against the offer's running capacity; refuse the
                    // match if the offer is already fully booked, so it can't be oversold.
                    if !commitments
                        .lock()
                        .map_err(|_| "auction commitments lock poisoned")?
                        .commit(&offer, m.units)
                    {
                        return Err(
                            "offer capacity already committed to prior matches — not enough units remain"
                                .to_string(),
                        );
                    }
                    serde_json::to_value(m).map_err(|e| e.to_string())
                }
                None => Err(
                    "bid does not clear against this offer (kind/model/units/floor/expiry)".to_string(),
                ),
            }
        },
    );
}

/// The stable slug naming a service's MCP tool (`service/<slug>`) — kept next to the registration so
/// the tool name is one place, not derived from the serde rename. [`crate::channel::ServiceType::Custom`]
/// (#382 follow-up) has no fixed slug, so its name is slugified (lowercased, non-alphanumeric ->
/// `_`) into a valid tool-name segment instead. `pub` so a downstream role-filler (e.g. ct-agent's
/// own `CT_AGENT_SERVICE_HANDLER_CMD` wiring) can derive the SAME slug for its own bookkeeping
/// (e.g. a `CT_SERVICE_TYPE` env var) instead of maintaining a second, driftable copy of this match.
pub fn service_slug(service: &crate::channel::ServiceType) -> std::borrow::Cow<'static, str> {
    use crate::channel::ServiceType::*;
    match service {
        CodeGeneration => "code_generation".into(),
        SecurityReview => "security_review".into(),
        SafetyCheck => "safety_check".into(),
        TextGeneration => "text_generation".into(),
        Custom(name) => name
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .into(),
    }
}

/// Register **one schema-typed MCP tool per declared service** (#149-A.1 — the structural core of the
/// abuse mitigation: a provider exposes ONLY the typed service endpoints its `CapacityOffer` catalog
/// declares, never a generic completion proxy). Each `ServiceType` in `services` gets a
/// `service/<slug>` tool with a **fixed request shape** `{ "input": <string> }` → `{ "output":
/// <string> }`: consumer text can only occupy the `input` slot (never a system-prompt / instruction-
/// priority slot), which is what makes a schema-typed task far harder to jailbreak than an open chat
/// endpoint, and a service the offer doesn't declare is simply never exposed. `handler(service, input)`
/// runs the typed task (the agent's actual LLM call); its `Err` becomes a JSON-RPC tool error.
/// #183: the largest `input` a single `service/<slug>` call may carry. A legitimate-but-abusive
/// channel member (already past the crypto/membership gate) could otherwise send an arbitrarily large
/// `input`, growing memory server-side (the JSON-RPC request, the `String` copy, and the handler's own
/// `"$(cat)"` buffer are all unbounded) and — for an LLM-backed handler — driving an arbitrarily large,
/// costed prompt. Capping at the dispatch boundary rejects it with a clean JSON-RPC error before any
/// subprocess is spawned. 4 MiB comfortably fits a resized cookbook ingredient photo (the client caps
/// it at 1024px JPEG → a few hundred KB of base64) while bounding abuse.
pub const MAX_SERVICE_INPUT_BYTES: usize = 4 * 1024 * 1024;

pub fn register_service_tools(
    reg: &mut ToolRegistry,
    services: &[crate::channel::ServiceType],
    handler: impl Fn(crate::channel::ServiceType, &str) -> Result<String, String> + Send + Sync + 'static,
) {
    let handler = std::sync::Arc::new(handler);
    // Found while running clippy across the whole workspace for an unrelated
    // change (#382-follow, gate.rs): clippy's `unnecessary_to_owned` suggestion
    // (iterate by reference instead) doesn't account for `service` being moved
    // into the `'static` `move |args| ...` closure below (stored in `reg` past
    // this function's return) -- a borrowed `&ServiceType` tied to this
    // function's own `services: &[..]` parameter can't satisfy that. The owned
    // clone per iteration is real, not unnecessary.
    #[allow(clippy::unnecessary_to_owned)]
    for service in services.iter().cloned() {
        let slug = service_slug(&service);
        let h = std::sync::Arc::clone(&handler);
        reg.register(
            format!("service/{slug}"),
            format!("typed {slug} service — fixed {{input:string}} -> {{output:string}} shape"),
            move |args| {
                let input = args
                    .get("input")
                    .and_then(Value::as_str)
                    .ok_or("this service requires a string `input` (fixed schema — no free-form slot)")?;
                // #183: bound the input BEFORE it reaches the handler subprocess.
                if input.len() > MAX_SERVICE_INPUT_BYTES {
                    return Err(format!(
                        "service `input` too large: {} bytes exceeds the {}-byte cap (#183)",
                        input.len(),
                        MAX_SERVICE_INPUT_BYTES
                    ));
                }
                // ServiceType (#382 follow-up: gained a Custom(String) variant, so it's Clone but
                // no longer Copy) -- this closure is called once per request, so clone the
                // captured value in rather than moving it out on the first call only.
                let output = h(service.clone(), input)?;
                Ok(json!({ "output": output }))
            },
        );
    }
}

/// The largest `chat` message a single call may carry (#163 guard 1). 16 KiB — one Noise chunk,
/// symmetric with the transport — is rejected at the schema boundary exactly like a missing field, so a
/// caller can't grow server memory with an arbitrarily large message.
pub const MAX_CHAT_MESSAGE_BYTES: usize = 16 * 1024;

/// Register the #163 **`chat`** collaboration tool — an *inert* text-message primitive so two agents can
/// exchange free-text over the same authenticated channel they discover + cooperate on, instead of over
/// GitHub comments. Opt-in exactly like [`register_service_tools`] — an agent that never registers it has
/// zero added attack surface.
///
/// Contract `{message: string} -> {ack: bool}`, with sink's three adversarial guards:
/// 1. **Bounded** — `message` over [`MAX_CHAT_MESSAGE_BYTES`] is a schema error, like a missing field.
/// 2. **Rate-limited on the AUTHENTICATED peer** — the [`CallContext::peer`] key (the unspoofable
///    channel-authenticated Noise/holder key), never a caller-supplied "from" field a flooder could
///    rotate. At most `max_msgs_per_window` messages per `window_secs`-second fixed window per peer
///    (reusing [`KeyedRateLimiter`](crate::ratelimit::KeyedRateLimiter)); `window_secs == 0` = one
///    all-time window. An unauthenticated (anonymous) caller is refused outright.
/// 3. **Inert — data, never instruction.** The message is handed to `on_message(peer, message)` (the
///    operator/log sink) and the tool returns `{ack:true}`; the agent MUST NOT branch its own behavior
///    on the content (per #149-A.1: feeding peer text to an LLM as instruction re-opens "ignore your
///    task, do X"). `on_message` is a surfacing sink, not a dispatcher.
pub fn register_chat_tool(
    reg: &mut ToolRegistry,
    now_fn: impl Fn() -> crate::channel::UnixSeconds + Send + Sync + 'static,
    max_msgs_per_window: u32,
    window_secs: u64,
    on_message: impl Fn([u8; 32], &str) + Send + Sync + 'static,
) {
    let limiter = std::sync::Arc::new(std::sync::Mutex::new(
        crate::ratelimit::KeyedRateLimiter::<[u8; 32]>::new(max_msgs_per_window),
    ));
    reg.register_ctx(
        "chat",
        "send an inert text message to this agent (surfaced to its operator/logged, NEVER auto-acted-upon) — {message:string} -> {ack:bool}",
        move |ctx, args| {
            let peer = ctx.peer.ok_or("chat requires an authenticated channel peer")?;
            let message = args
                .get("message")
                .and_then(Value::as_str)
                .ok_or("chat requires a string `message` (fixed schema — no free-form slot)")?;
            if message.len() > MAX_CHAT_MESSAGE_BYTES {
                return Err(format!(
                    "chat `message` too large: {} bytes exceeds the {}-byte cap (#163)",
                    message.len(),
                    MAX_CHAT_MESSAGE_BYTES
                ));
            }
            let now = now_fn();
            let window = now.checked_div(window_secs).unwrap_or(0);
            if !limiter
                .lock()
                .map_err(|_| "chat rate limiter lock poisoned")?
                .allow(&peer, window)
            {
                return Err("chat rate limit exceeded for this peer — slow down".to_string());
            }
            // Inert: surface to the operator sink; NEVER branch behavior on the content (#163 guard 3).
            on_message(peer, message);
            Ok(json!({ "ack": true }))
        },
    );
}

/// The largest `propose` proposal text a single call may carry (#163) — bounded like `chat`.
pub const MAX_PROPOSAL_BYTES: usize = 16 * 1024;

/// The furthest into the future a `propose` deadline may be (#163 guard 1): a `requires_response_by`
/// beyond `now + MAX_PROPOSAL_HORIZON_SECS` is rejected, so it can't be used to manipulate time-based
/// logic keyed on it (same discipline as RelayChallenger TTLs / escrow expiry). 30 days.
pub const MAX_PROPOSAL_HORIZON_SECS: u64 = 30 * 24 * 60 * 60;

/// Register the #163 **`propose`** collaboration tool — a narrow design/coordination decision primitive
/// (accept / reject / counter) whose response is a **co-signed, non-repudiable record**, not a bare
/// bool. Opt-in like [`register_chat_tool`].
///
/// Contract `{proposal: string, requires_response_by: u64} -> `[`SignedAcceptance`](crate::channel::SignedAcceptance),
/// with sink's two adversarial fixes:
/// 1. **Bounded deadline** — `requires_response_by` must be strictly in the future and no further than
///    [`MAX_PROPOSAL_HORIZON_SECS`] ahead (`now` is the SERVING agent's via `now_fn`, never the caller's);
///    `proposal` over [`MAX_PROPOSAL_BYTES`] is a schema error.
/// 2. **Attributable record** — the response is the accepter's holder signature over
///    `hash(proposal ‖ decision ‖ requires_response_by ‖ proposer)`, so anyone can later prove *who*
///    decided *what* on *which* proposal (the collaboration analog of `UsageReceipt`). The proposer is
///    the [`CallContext::peer`] (authenticated), not a caller-supplied field; an anonymous caller is
///    refused. `decide(proposer, proposal, requires_response_by)` is the agent's own policy hook.
pub fn register_propose_tool(
    reg: &mut ToolRegistry,
    accepter_key: ed25519_dalek::SigningKey,
    now_fn: impl Fn() -> crate::channel::UnixSeconds + Send + Sync + 'static,
    decide: impl Fn([u8; 32], &str, crate::channel::UnixSeconds) -> crate::channel::ProposalDecision
        + Send
        + Sync
        + 'static,
) {
    reg.register_ctx(
        "propose",
        "make a design/coordination proposal; returns the agent's holder-signed SignedAcceptance (accept/reject/counter) — {proposal:string, requires_response_by:u64} -> SignedAcceptance",
        move |ctx, args| {
            let proposer = ctx.peer.ok_or("propose requires an authenticated channel peer")?;
            let proposal = args
                .get("proposal")
                .and_then(Value::as_str)
                .ok_or("propose requires a string `proposal` (fixed schema — no free-form slot)")?;
            if proposal.len() > MAX_PROPOSAL_BYTES {
                return Err(format!(
                    "`proposal` too large: {} bytes exceeds the {}-byte cap (#163)",
                    proposal.len(),
                    MAX_PROPOSAL_BYTES
                ));
            }
            let requires_response_by = args
                .get("requires_response_by")
                .and_then(Value::as_u64)
                .ok_or("propose requires an integer `requires_response_by` (unix seconds)")?;
            let now = now_fn();
            if requires_response_by <= now {
                return Err("`requires_response_by` must be strictly in the future".to_string());
            }
            if requires_response_by > now.saturating_add(MAX_PROPOSAL_HORIZON_SECS) {
                return Err(format!(
                    "`requires_response_by` is unreasonably far in the future (> {MAX_PROPOSAL_HORIZON_SECS}s horizon)"
                ));
            }
            let decision = decide(proposer, proposal, requires_response_by);
            let record = crate::channel::SignedAcceptance::sign_new(
                &accepter_key,
                proposer,
                decision,
                proposal,
                requires_response_by,
            );
            serde_json::to_value(record).map_err(|e| e.to_string())
        },
    );
}

/// The [`default_registry`] plus an **`agent/card`** tool returning `card_json` (#144 × #135): a peer
/// that has connected over the authenticated channel can fetch the agent's holder-signed `AgentCard`
/// directly, bound to the live session — the channel is authenticated by the same holder key, so the
/// card the peer gets here is provably the one the connected agent holds (not merely one served at a
/// URL). `card_json` is the card's JSON profile (`serde_json::to_value(&card)`).
pub fn registry_with_card(card_json: Value) -> ToolRegistry {
    let mut r = default_registry();
    r.register(
        "agent/card",
        "the agent's holder-signed AgentCard — identity over the authenticated channel",
        move |_| Ok(card_json.clone()),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ToolRegistry {
        let mut r = ToolRegistry::new();
        r.register("ping", "liveness check → pong", |_args| Ok(json!({ "reply": "pong" })));
        r.register("echo", "echo the `text` argument", |args| {
            let text = args.get("text").and_then(Value::as_str).ok_or("missing `text`")?;
            Ok(json!({ "text": text }))
        });
        r
    }

    fn call(reg: &ToolRegistry, body: Value) -> JsonRpcResponse {
        let bytes = reg.dispatch(&serde_json::to_vec(&body).unwrap());
        serde_json::from_slice(&bytes).expect("response is valid JSON-RPC")
    }

    /// Dispatch as a specific (or anonymous) authenticated peer — for the #163 identity-aware tools.
    fn call_as(reg: &ToolRegistry, peer: Option<[u8; 32]>, body: Value) -> JsonRpcResponse {
        let bytes = reg.dispatch_ctx(&CallContext { peer }, &serde_json::to_vec(&body).unwrap());
        serde_json::from_slice(&bytes).expect("response is valid JSON-RPC")
    }

    #[test]
    fn tools_list_advertises_registered_tools() {
        // #135 L2.3 (frozen): tools/list returns each registered tool's name + description, id echoed.
        let resp = call(&registry(), json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" }));
        assert_eq!(resp.id, json!(7), "the request id is echoed back for correlation");
        let tools = resp.result.unwrap();
        let names: Vec<&str> =
            tools["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"ping") && names.contains(&"echo"), "advertises both tools, got {names:?}");
    }

    #[test]
    fn tools_call_invokes_the_named_tool_and_returns_its_result() {
        // #135 L2.3 (frozen): tools/call routes to the handler by name and returns its result.
        let resp = call(
            &registry(),
            json!({ "jsonrpc": "2.0", "id": "a", "method": "tools/call",
                    "params": { "name": "echo", "arguments": { "text": "hi" } } }),
        );
        assert_eq!(resp.id, json!("a"));
        assert_eq!(resp.result.unwrap(), json!({ "text": "hi" }), "the echo tool's result flows back");
        assert!(resp.error.is_none());
    }

    #[test]
    fn tools_call_reports_a_tool_error_without_wedging() {
        // A handler that fails on bad args returns a JSON-RPC tool error (not a panic / dropped request).
        let resp = call(
            &registry(),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": "echo", "arguments": {} } }),
        );
        let err = resp.error.expect("a failing tool yields an error object");
        assert_eq!(err.code, TOOL_ERROR);
        assert!(err.message.contains("text"), "the handler's message is surfaced: {}", err.message);
        assert!(resp.result.is_none());
    }

    #[test]
    fn unknown_tool_and_unknown_method_and_malformed_all_return_wellformed_errors() {
        let reg = registry();

        // Unknown tool → invalid params.
        let unknown_tool = call(
            &reg,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "nope" } }),
        );
        assert_eq!(unknown_tool.error.unwrap().code, INVALID_PARAMS);

        // Unknown method → method not found.
        let unknown_method =
            call(&reg, json!({ "jsonrpc": "2.0", "id": 3, "method": "does/not/exist" }));
        assert_eq!(unknown_method.error.unwrap().code, METHOD_NOT_FOUND);

        // Malformed JSON → parse error, id null, still a well-formed JSON-RPC response.
        let bytes = reg.dispatch(b"{ this is not json");
        let resp: JsonRpcResponse = serde_json::from_slice(&bytes).expect("parse-error response is valid JSON-RPC");
        assert_eq!(resp.id, Value::Null);
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn client_encode_and_server_dispatch_interoperate_round_trip() {
        // #135 L2.3 (frozen): the client encodes a JSON-RPC request, the server's ToolRegistry
        // dispatches it, and the client decodes the response — the full call/serve pair interoperates
        // at exactly the message layer that rides one framed message over the channel.
        let reg = registry();

        let req = encode_request(42, "tools/call", json!({ "name": "ping" }));
        let resp = decode_response(&reg.dispatch(&req)).expect("a valid JSON-RPC response");
        assert_eq!(resp.id, json!(42), "the id correlates the response to the request");
        assert_eq!(resp.result.unwrap(), json!({ "reply": "pong" }), "ping answered over the pair");
        assert!(resp.error.is_none());

        // A string id and a params-less method also round-trip.
        let list = decode_response(&reg.dispatch(&encode_request("c1", "tools/list", Value::Null)))
            .expect("valid response");
        assert_eq!(list.id, json!("c1"));
        assert!(list.result.unwrap()["tools"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn settlement_tools_gossip_a_block_over_mcp_and_report_balances() {
        // #147-L4.3 (frozen): a producer mines a block, encodes it, and gossips it via the
        // `settlement/block` MCP tool to a replica — which accepts it and converges; `settlement/balance`
        // reads the result. So the settlement ledger rides the #135 authenticated channel. A malformed
        // block returns a JSON-RPC tool error and leaves the ledger unchanged.
        use crate::settlement::{Chain, Transfer};
        use ed25519_dalek::SigningKey;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);
        let (a, b) = (alice.verifying_key().to_bytes(), bob.verifying_key().to_bytes());
        let genesis = BTreeMap::from([(a, 100u64)]);

        let mut producer = Chain::new(genesis.clone());
        producer.append(vec![Transfer::sign_new(&alice, b, 40, 0)]).unwrap();
        let block_hex = to_hex(&producer.tip_block().encode());

        // The replica exposes the gossip tools over its own (same-genesis) chain.
        let replica = Arc::new(Mutex::new(Chain::new(genesis)));
        let mut reg = default_registry();
        register_settlement_tools(&mut reg, Arc::clone(&replica));

        // Gossip the block over MCP → accepted, height 1.
        let resp = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "settlement/block", "arguments": { "block": block_hex } } }));
        let r = resp.result.expect("settlement/block succeeds");
        assert_eq!(r["accepted"], json!(true));
        assert_eq!(r["height"], json!(1), "the replica advanced to height 1");

        // Query bob's balance over MCP → 40.
        let bal = call(&reg, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "settlement/balance", "arguments": { "account": to_hex(&b) } } }));
        assert_eq!(bal.result.unwrap()["balance"], json!(40), "settlement/balance reads the replicated ledger");

        // A malformed block → JSON-RPC tool error, ledger unchanged.
        let bad = call(&reg, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "settlement/block", "arguments": { "block": "zz" } } }));
        assert!(bad.error.is_some(), "a malformed block is a tool error, not a panic");
        assert_eq!(replica.lock().unwrap().height(), 1, "no bad block was committed");
    }

    #[test]
    fn auction_tools_serve_the_offer_and_clear_a_bid_over_mcp() {
        // #147-L2 (frozen): a seller-agent runs the auction over the #135 channel — `auction/offer`
        // returns its signed CapacityOffer; `auction/bid` clears a buyer's signed CapacityBid against
        // it and returns the deterministic CapacityMatch (or a tool error). Time is the SELLER's (via
        // now_fn), not the caller's — so a buyer can't pass a fake `now` to revive an expired offer.
        use crate::channel::{match_offer, CapacityBid, CapacityKind, CapacityMatch, CapacityOffer};
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let buyer = SigningKey::from_bytes(&[0x52u8; 32]);
        let offer = CapacityOffer::sign_new(
            &seller,
            CapacityKind::CloudApiQuota,
            vec!["claude-opus-4-8".to_string()],
            1_000,
            100,
            "ct-llm-token-chain".to_string(),
            1_000,
            9_000,
        );
        let bid = CapacityBid::sign_new(
            &buyer,
            CapacityKind::CloudApiQuota,
            "claude-opus-4-8".to_string(),
            200,
            150,
            1_000,
            9_000,
        );

        let mut reg = default_registry();
        register_auction_tools(&mut reg, offer.clone(), || 1_000, 1_000, 1); // generous limit: not under test here

        // auction/offer → the seller's signed offer, round-tripping to the same CapacityOffer.
        let got = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "auction/offer", "arguments": {} } }));
        let back: CapacityOffer = serde_json::from_value(got.result.expect("auction/offer succeeds")).unwrap();
        assert_eq!(back, offer, "auction/offer serves the agent's exact signed offer");

        // #268: auction/bid is identity-aware (register_ctx) -- calls go through call_as with the
        // buyer's channel-authenticated peer, standing in for its Noise/holder key.
        let buyer_peer = buyer.verifying_key().to_bytes();

        // auction/bid with a compatible bid → the deterministic match (same match_ref as computed locally).
        let resp = call_as(&reg, Some(buyer_peer), json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&bid).unwrap() } } }));
        let m: CapacityMatch = serde_json::from_value(resp.result.expect("a compatible bid clears")).unwrap();
        assert_eq!(m.match_ref, match_offer(&offer, &bid, 1_000).unwrap().match_ref, "same deterministic match_ref");
        assert_eq!((m.units, m.total_price), (200, 150), "cleared at the bid's terms");

        // A below-floor bid → tool error (no clear).
        let low = CapacityBid::sign_new(&buyer, CapacityKind::CloudApiQuota, "claude-opus-4-8".into(), 10, 50, 1_000, 9_000);
        let no = call_as(&reg, Some(buyer_peer), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&low).unwrap() } } }));
        assert!(no.error.is_some(), "a bid below the seller's floor doesn't clear");

        // A malformed bid payload → tool error, not a panic.
        let bad = call_as(&reg, Some(buyer_peer), json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": { "not": "a bid" } } } }));
        assert!(bad.error.is_some(), "a malformed bid is a tool error");

        // An unauthenticated (anonymous) caller is refused outright (#268).
        let anon = call(&reg, json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&bid).unwrap() } } }));
        assert!(anon.error.unwrap().message.contains("authenticated"), "an anonymous caller is refused");

        // Seller stamps time: a registry whose clock is past the offer's expiry won't clear the same
        // good bid — the caller can't fake `now` to revive an expired offer.
        let mut expired = default_registry();
        register_auction_tools(&mut expired, offer.clone(), || 9_000, 1_000, 1); // generous limit
        let past = call_as(&expired, Some(buyer_peer), json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&bid).unwrap() } } }));
        assert!(past.error.is_some(), "past the seller's clock the offer has expired and nothing clears");
    }

    #[test]
    fn auction_bid_is_rate_limited_per_authenticated_consumer() {
        // #149-A.3 / #268 (frozen): auction/bid caps how fast one consumer can hammer a provider — at
        // most `max_bids_per_window` bids per window, keyed by ctx.peer, the channel-AUTHENTICATED
        // identity (never the self-declared `bid.bidder` field, #268's fix). A forged bid carrying a
        // victim's `bidder` is rejected before the limiter, so it can't burn the victim's budget; a
        // distinct authenticated peer has its own independent budget.
        use crate::channel::{CapacityBid, CapacityKind, CapacityOffer};
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let buyer = SigningKey::from_bytes(&[0x52u8; 32]);
        let other = SigningKey::from_bytes(&[0x53u8; 32]);
        let buyer_peer = buyer.verifying_key().to_bytes();
        let other_peer = other.verifying_key().to_bytes();
        let offer = CapacityOffer::sign_new(
            &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 1_000, 100, "c".into(), 1_000, 9_000,
        );
        let mk_bid = |k: &SigningKey| {
            CapacityBid::sign_new(k, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000)
        };

        // Two bids per window; the seller's clock is fixed at 1_000 → all in one window.
        let mut reg = default_registry();
        register_auction_tools(&mut reg, offer.clone(), || 1_000, 2, 100);
        let bid_call = |reg: &ToolRegistry, id: i64, peer: [u8; 32], b: &CapacityBid| {
            call_as(reg, Some(peer), json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(b).unwrap() } } }))
        };

        let buyer_bid = mk_bid(&buyer);
        assert!(bid_call(&reg, 1, buyer_peer, &buyer_bid).result.is_some(), "1st bid within the limit clears");
        assert!(bid_call(&reg, 2, buyer_peer, &buyer_bid).result.is_some(), "2nd bid within the limit clears");
        let third = bid_call(&reg, 3, buyer_peer, &buyer_bid);
        assert!(third.error.is_some(), "3rd bid in the same window is rate-limited");
        assert!(third.error.unwrap().message.contains("rate limit"), "the error names the rate limit");

        // A different authenticated PEER has its own budget — not blocked by the buyer's, even though
        // this bid's own `bid.bidder` field happens to equal the buyer's (proving the limiter no
        // longer keys off that self-declared field at all).
        let same_bidder_field_different_peer = mk_bid(&buyer);
        assert!(
            bid_call(&reg, 4, other_peer, &same_bidder_field_different_peer).result.is_some(),
            "a distinct authenticated peer isn't rate-limited, regardless of bid.bidder"
        );

        // A FORGED bid (victim's `bidder`, someone else's signature) is rejected before the limiter,
        // so it can't be used to exhaust the victim's budget.
        let mut forged = mk_bid(&buyer);
        forged.bidder = other.verifying_key().to_bytes(); // claim `other` but keep buyer's signature
        let f = bid_call(&reg, 5, other_peer, &forged);
        assert!(f.error.unwrap().message.contains("invalid"), "a forged bid is rejected as invalid, not rate-limited");
        // `other`'s real budget is untouched: it still has room after the forged attempt.
        assert!(bid_call(&reg, 6, other_peer, &mk_bid(&other)).result.is_some(), "the forged bid didn't burn the victim's budget");
    }

    #[test]
    fn auction_bid_rate_limit_survives_bidder_key_rotation_268() {
        // #268: the exact attack this issue describes. A consumer that generates a FRESH ed25519
        // keypair for `bid.bidder` on every call used to get a brand-new, empty rate-limiter bucket
        // each time (keyed on that self-declared field), completely defeating max_bids_per_window.
        // Proves the fix: the SAME channel-authenticated peer submitting bids under N DIFFERENT,
        // freshly-rotated (but validly self-signed) bidder identities still hits the same budget.
        use crate::channel::{CapacityBid, CapacityKind, CapacityOffer};
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let attacker_peer = [0x77u8; 32]; // the one fixed channel-authenticated identity
        let offer = CapacityOffer::sign_new(
            &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 1_000, 100, "c".into(), 1_000, 9_000,
        );

        let mut reg = default_registry();
        register_auction_tools(&mut reg, offer, || 1_000, 2, 100); // 2 bids per window

        for i in 0..2u8 {
            // A FRESH, distinct, validly-self-signed bidder identity every call.
            let rotated = SigningKey::from_bytes(&[0xA0 + i; 32]);
            let bid = CapacityBid::sign_new(&rotated, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000);
            let resp = call_as(&reg, Some(attacker_peer), json!({ "jsonrpc": "2.0", "id": i as i64, "method": "tools/call",
                "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&bid).unwrap() } } }));
            assert!(resp.result.is_some(), "bid {i} within the limit clears despite the rotated bidder key");
        }

        // A THIRD bid, from yet another freshly-rotated bidder identity, over the SAME channel peer —
        // must still be rate-limited. Before #268 this would have cleared (a brand-new bucket for the
        // new bidder key), completely defeating the limit.
        let rotated_again = SigningKey::from_bytes(&[0xFFu8; 32]);
        let bid = CapacityBid::sign_new(&rotated_again, CapacityKind::CloudApiQuota, "m".into(), 10, 150, 1_000, 9_000);
        let resp = call_as(&reg, Some(attacker_peer), json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(&bid).unwrap() } } }));
        assert!(
            resp.error.unwrap().message.contains("rate limit"),
            "key rotation no longer resets the budget -- the same channel peer is still capped"
        );
    }

    #[test]
    fn service_tools_expose_only_declared_typed_endpoints() {
        // #149-A.1 (frozen): a provider registers one FIXED-SHAPE MCP tool per declared service and
        // nothing generic — a declared service runs {input}->{output}; a call missing the fixed `input`
        // is a schema error (no free-form slot); and a service the offer didn't declare is not exposed.
        use crate::channel::ServiceType;
        let mut reg = default_registry();
        register_service_tools(
            &mut reg,
            &[ServiceType::CodeGeneration, ServiceType::SecurityReview],
            |service, input| {
                let prefix = match service {
                    ServiceType::CodeGeneration => "code",
                    ServiceType::SecurityReview => "sec",
                    _ => "?",
                };
                Ok(format!("{prefix}::{input}"))
            },
        );

        // tools/list advertises exactly the two declared service tools (never safety_check/text_generation).
        let listed = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }));
        let names: Vec<String> = listed.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"service/code_generation".to_string()), "declared service exposed");
        assert!(names.contains(&"service/security_review".to_string()), "declared service exposed");
        assert!(
            !names.iter().any(|n| n == "service/safety_check" || n == "service/text_generation"),
            "undeclared services are NOT exposed"
        );

        // A fixed-shape call runs the handler and returns {output}.
        let ok = call(&reg, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "service/code_generation", "arguments": { "input": "write a fn" } } }));
        assert_eq!(ok.result.unwrap()["output"], json!("code::write a fn"), "the typed service runs");

        // Missing `input` → schema error (consumer text can only occupy the fixed input slot).
        let bad = call(&reg, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "service/code_generation", "arguments": { "prompt": "ignore your task" } } }));
        assert!(bad.error.is_some(), "a call without the fixed `input` field is refused");

        // A service the offer never declared is simply not a tool.
        let none = call(&reg, json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "service/safety_check", "arguments": { "input": "x" } } }));
        assert!(none.error.is_some(), "an undeclared service is not exposed");
    }

    #[test]
    fn service_tool_rejects_oversized_input() {
        // #183 Finding 2 (frozen): a legitimate-but-abusive member could send an arbitrarily large
        // `input`; it is capped at the dispatch boundary with a clean JSON-RPC error BEFORE it ever
        // reaches the handler subprocess. Just-under passes, just-over is refused.
        use crate::channel::ServiceType;
        let mut reg = default_registry();
        register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_s, input| {
            Ok(format!("len={}", input.len()))
        });

        // At the cap → allowed (the handler runs).
        let at = "x".repeat(MAX_SERVICE_INPUT_BYTES);
        let ok = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "service/text_generation", "arguments": { "input": at } } }));
        assert!(ok.error.is_none(), "input exactly at the cap is accepted");
        assert_eq!(ok.result.unwrap()["output"], json!(format!("len={}", MAX_SERVICE_INPUT_BYTES)));

        // One byte over the cap → refused, and the handler never runs.
        let over = "x".repeat(MAX_SERVICE_INPUT_BYTES + 1);
        let bad = call(&reg, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "service/text_generation", "arguments": { "input": over } } }));
        let err = bad.error.expect("oversized input is refused");
        assert!(
            err.message.contains("too large"),
            "the refusal names the size cap (#183): {}",
            err.message
        );
    }

    #[test]
    fn auction_bid_refuses_to_oversell_the_offer_capacity() {
        // #158 (frozen): the auction/bid tool tracks cumulative committed units, so an offer can't be
        // matched beyond its units_available — a second full-capacity bid from a different buyer is
        // refused once the first has booked the whole offer (no double-booking / overselling).
        use crate::channel::{CapacityBid, CapacityKind, CapacityOffer};
        use ed25519_dalek::SigningKey;
        let seller = SigningKey::from_bytes(&[0x51u8; 32]);
        let offer = CapacityOffer::sign_new(
            &seller, CapacityKind::CloudApiQuota, vec!["m".into()], 100, 10, "c".into(), 1_000, 9_000,
        );
        let mut reg = default_registry();
        register_auction_tools(&mut reg, offer, || 1_000, 1_000, 1); // generous rate limit (not under test)
        let mk_bid = |seed: u8| {
            CapacityBid::sign_new(
                &SigningKey::from_bytes(&[seed; 32]), CapacityKind::CloudApiQuota, "m".into(), 100, 50, 1_000, 9_000,
            )
        };
        let call_bid = |reg: &ToolRegistry, id: i64, seed: u8, b: &CapacityBid| {
            call_as(reg, Some([seed; 32]), json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": "auction/bid", "arguments": { "bid": serde_json::to_value(b).unwrap() } } }))
        };
        // The first full-capacity (100-unit) bid clears and books the whole offer.
        assert!(call_bid(&reg, 1, 0x60, &mk_bid(0x60)).result.is_some(), "the first full-capacity bid clears");
        // A second full-capacity bid from a DIFFERENT buyer is refused — the offer is fully committed.
        let second = call_bid(&reg, 2, 0x61, &mk_bid(0x61));
        let err = second.error.expect("the offer can't be double-booked");
        assert!(err.message.contains("capacity"), "the error names the exhausted capacity: {}", err.message);
    }

    #[test]
    fn registry_with_card_serves_the_agent_card_over_the_tool() {
        // #144 × #135 (frozen): a card-aware registry exposes `agent/card`; tools/list advertises it
        // and tools/call returns exactly the supplied card JSON (the identity a peer fetches over the
        // authenticated channel). ping still works alongside it.
        let card = json!({ "holder_pubkey": "af1491a7", "role_tags": ["sink"], "expires_at": 5000 });
        let reg = registry_with_card(card.clone());

        let listed: Vec<String> = reg
            .list()["tools"].as_array().unwrap()
            .iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        assert!(listed.contains(&"agent/card".to_string()), "agent/card advertised, got {listed:?}");
        assert!(listed.contains(&"ping".to_string()), "ping still present");

        let resp = call(&reg, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": { "name": "agent/card" } }));
        assert_eq!(resp.result.unwrap(), card, "agent/card returns the exact card JSON");
    }

    #[test]
    fn initialize_advertises_the_mcp_protocol_version_and_tools_capability() {
        let resp = call(&registry(), json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize" }));
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], json!(MCP_PROTOCOL_VERSION));
        assert!(result["capabilities"].get("tools").is_some(), "advertises the tools capability");
    }

    #[test]
    fn collab_tools_are_opt_in_not_present_by_default() {
        // #163 (frozen): an agent that never registers the collaboration tools exposes neither — zero
        // added attack surface, exactly like the #149-A.1 service catalog.
        let names: Vec<String> = default_registry()
            .list()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(!names.iter().any(|n| n == "chat" || n == "propose"), "collab tools are opt-in, got {names:?}");
    }

    #[test]
    fn chat_is_fixed_shape_bounded_and_inert() {
        // #163 (frozen): chat is {message:string}->{ack:bool}; it surfaces the message to the operator
        // sink (never acting on it) and bounds size at the schema boundary.
        use std::sync::{Arc, Mutex};
        let seen: Arc<Mutex<Vec<([u8; 32], String)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let mut reg = default_registry();
        register_chat_tool(&mut reg, || 1_000, 100, 0, move |peer, msg| {
            sink.lock().unwrap().push((peer, msg.to_string()));
        });
        let peer = [0xAB; 32];

        // A well-formed message from an authenticated peer → ack, and it reached the operator sink verbatim.
        let ok = call_as(&reg, Some(peer), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "chat", "arguments": { "message": "hi from the peer" } } }));
        assert_eq!(ok.result.unwrap(), json!({ "ack": true }), "chat acks");
        assert_eq!(*seen.lock().unwrap(), vec![(peer, "hi from the peer".to_string())], "surfaced inert to the sink");

        // Missing `message` → schema error (no free-form slot).
        let miss = call_as(&reg, Some(peer), json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "chat", "arguments": { "text": "wrong field" } } }));
        assert!(miss.error.is_some(), "a call without the fixed `message` field is refused");

        // Oversized message → refused at the boundary, naming the cap; the sink never sees it.
        let big = "x".repeat(MAX_CHAT_MESSAGE_BYTES + 1);
        let over = call_as(&reg, Some(peer), json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "chat", "arguments": { "message": big } } }));
        assert!(over.error.unwrap().message.contains("too large"), "oversized message is a schema error");
        assert_eq!(seen.lock().unwrap().len(), 1, "the oversized message never reached the sink");
    }

    #[test]
    fn chat_rate_limit_fires_on_the_authenticated_peer_not_a_payload_field() {
        // #163 guard 2 (frozen): the bucket is keyed by the AUTHENTICATED peer (CallContext), so a
        // flooder can't dodge it by varying the message; a distinct peer has its own budget; and an
        // anonymous caller is refused outright.
        let mut reg = default_registry();
        register_chat_tool(&mut reg, || 1_000, 2, 100, |_p, _m| {}); // 2 msgs / window
        let a = [0x0A; 32];
        let b = [0x0B; 32];
        let send = |reg: &ToolRegistry, peer: Option<[u8; 32]>, id: i64, msg: &str| {
            call_as(reg, peer, json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": "chat", "arguments": { "message": msg } } }))
        };

        // Peer A: two go through even with DIFFERENT message content, the third in the window is limited.
        assert!(send(&reg, Some(a), 1, "one").result.is_some(), "1st within limit");
        assert!(send(&reg, Some(a), 2, "two — different content").result.is_some(), "2nd within limit");
        let third = send(&reg, Some(a), 3, "three");
        assert!(third.error.unwrap().message.contains("rate limit"), "3rd in the window is rate-limited by peer, not content");

        // A different authenticated peer has its own independent budget.
        assert!(send(&reg, Some(b), 4, "hello").result.is_some(), "a distinct peer isn't limited by A's usage");

        // An anonymous (unauthenticated) caller is refused — there is no spoofable identity to key on.
        let anon = send(&reg, None, 5, "no identity");
        assert!(anon.error.unwrap().message.contains("authenticated"), "an anonymous chat is refused");
    }

    #[test]
    fn propose_returns_a_signature_bound_to_the_exact_proposal_and_proposer() {
        // #163 (frozen): propose returns a SignedAcceptance — the accepter's holder signature bound to
        // the exact proposal AND the authenticated proposer. It verifies for that pair, and NOT for a
        // swapped proposal or proposer; the decision is the agent's own policy output.
        use crate::channel::{ProposalDecision, SignedAcceptance};
        use ed25519_dalek::SigningKey;
        let accepter_key = SigningKey::from_bytes(&[0x11; 32]);
        let accepter_pub = accepter_key.verifying_key().to_bytes();
        let mut reg = default_registry();
        register_propose_tool(&mut reg, accepter_key, || 1_000, |_proposer, _proposal, _deadline| {
            ProposalDecision::Accept
        });
        let proposer = [0x22; 32];

        let resp = call_as(&reg, Some(proposer), json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "propose", "arguments": { "proposal": "let's use topology X", "requires_response_by": 5_000 } } }));
        let record: SignedAcceptance = serde_json::from_value(resp.result.expect("propose returns a record")).unwrap();

        assert_eq!(record.decision, ProposalDecision::Accept, "the policy's decision is recorded");
        assert_eq!(record.accepter, accepter_pub, "signed by the serving agent's holder key");
        assert_eq!(record.proposer, proposer, "bound to the AUTHENTICATED proposer, not a payload field");
        assert!(record.is_valid(), "the accepter signature verifies");
        assert!(record.verify_for(&proposer, "let's use topology X"), "verifies for the exact proposal + proposer");
        assert!(!record.verify_for(&proposer, "a DIFFERENT proposal"), "a different proposal doesn't verify");
        assert!(!record.verify_for(&[0x99; 32], "let's use topology X"), "a swapped proposer doesn't verify");
    }

    #[test]
    fn propose_rejects_past_absurd_deadline_oversized_and_anonymous() {
        // #163 guard 1 (frozen): requires_response_by must be strictly future and within the horizon;
        // an oversized proposal is a schema error; an anonymous caller is refused. `now` is the seller's.
        use crate::channel::ProposalDecision;
        use ed25519_dalek::SigningKey;
        let mut reg = default_registry();
        register_propose_tool(&mut reg, SigningKey::from_bytes(&[0x11; 32]), || 1_000, |_p, _pr, _d| {
            ProposalDecision::Accept
        });
        let proposer = [0x22; 32];
        let go = |reg: &ToolRegistry, peer: Option<[u8; 32]>, args: Value| {
            call_as(reg, peer, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "propose", "arguments": args } }))
        };

        // Deadline in the past (<= now=1000) → refused.
        let past = go(&reg, Some(proposer), json!({ "proposal": "p", "requires_response_by": 1_000 }));
        assert!(past.error.unwrap().message.contains("future"), "a past/now deadline is refused");

        // Deadline absurdly far in the future (> now + horizon) → refused.
        let far = go(&reg, Some(proposer), json!({ "proposal": "p", "requires_response_by": 1_000 + MAX_PROPOSAL_HORIZON_SECS + 1 }));
        assert!(far.error.unwrap().message.contains("far in the future"), "an absurd-horizon deadline is refused");

        // Just within the horizon → accepted.
        let ok = go(&reg, Some(proposer), json!({ "proposal": "p", "requires_response_by": 1_000 + MAX_PROPOSAL_HORIZON_SECS }));
        assert!(ok.result.is_some(), "a deadline exactly at the horizon is accepted");

        // Oversized proposal → schema error.
        let big = "x".repeat(MAX_PROPOSAL_BYTES + 1);
        let over = go(&reg, Some(proposer), json!({ "proposal": big, "requires_response_by": 5_000 }));
        assert!(over.error.unwrap().message.contains("too large"), "an oversized proposal is refused");

        // Anonymous caller → refused (no authenticated proposer to bind).
        let anon = go(&reg, None, json!({ "proposal": "p", "requires_response_by": 5_000 }));
        assert!(anon.error.unwrap().message.contains("authenticated"), "an anonymous propose is refused");
    }
}

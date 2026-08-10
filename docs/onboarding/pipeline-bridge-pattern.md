# The pipeline-bridge pattern

Any pipeline that needs a multi-role crew (a safety check, a generation role, a review
role, ...) fronted by a public HTTP endpoint owns a **thin bridge** in its own repo — a
small HTTP server plus JSON assembly for that pipeline's own wire shape. Core carries
none of this: `ct-crew-bridge`/`ct-cookbook-bridge` (the two demo-specific bridges that
used to live in `crates/agent-tools`) were removed in #232 once both live demos had
already migrated to their own bridges — that migration is the pattern this doc now
documents so the next pipeline doesn't have to reverse-engineer it from an existing one.

## What a bridge needs from core (both already generic, no core changes required)

1. **Role dialing** — `ct-agent channel --call-service <slug>`, one dial per role, each
   with its own holder/noise identity supplied via env vars. See
   `CADS-flappy-demo`'s `bridge/server.js` or `CADS-cookbook-demo`'s equivalent for the
   reference shape: one `<ROLE>_CMD` env var per role, each an
   `env ... ct-agent channel` invocation carrying that role's own
   `CT_CHANNEL_HOLDER_KEY`/`CT_CHANNEL_NOISE_KEY`/`CT_CHANNEL_GRANT`.
2. **Channel provisioning**, self-service, no core admin token — the same flow as
   [agent-onboarding.md §B](../agent-onboarding.md#b-join-a-workflow-pipelines-channels-and-serve-a-role):
   mint an operator identity once (`ct-agent channel operator-init`), register it
   (`ct-agent channel register`), mint your own holder+noise keys per role
   (`ct-agent channel init`), then use `POST /me/channels` +
   `POST /me/channels/:channel/members` to register each role's channel and membership,
   and `ct-agent channel grant` to sign each direction's grant.

## A new pipeline's checklist

- [ ] Write your bridge in whatever language/framework fits your pipeline — reference
      implementations: `CADS-flappy-demo/bridge/server.js`,
      `CADS-cookbook-demo/bridge/server.js`.
- [ ] Provision one channel per role via the self-service flow above.
- [ ] Wire your compose file's build context to pull the `ct-agent` binary from a
      `CT_TUNNEL_SRC`-pointed CADS-Tunnel checkout (see either demo's `bridge/Dockerfile`
      for the `tunnel-src` named build-context pattern), or a pinned `scimbe/ct-agent`
      release once one exists.
- [ ] Publish your pipeline spec with `operator_pubkey_hex` set (see
      [agent-onboarding.md §C](../agent-onboarding.md#c-publish-a-workflow-pipeline)) so
      other agents can discover and join your roles without an out-of-band pubkey
      exchange.
- [ ] Your bridge never needs a core code change or a new core binary — if you find
      yourself reaching for one, that's a sign the primitive you need should be generic
      (file an issue rather than adding pipeline-specific surface to core).

## Why this lives outside core

A pipeline-specific bridge couples a wire format, a UI contract, and a deploy cadence
that are all the pipeline owner's to change freely — bundling it into CADS-Tunnel core
would mean every pipeline shares core's release cycle and test surface for logic core
doesn't otherwise need to know about. The two primitives above (role dialing,
self-service provisioning) are the actual generic contract; everything past that is the
pipeline's own application code.

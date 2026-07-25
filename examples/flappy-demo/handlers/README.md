# flappy-demo crew handlers (#171 / #173)

Reference `CT_AGENT_SERVICE_HANDLER_CMD` scripts for the demo's LLM-agent crew — the real
`service/<slug>` handlers each agent runs so the crew bridge (`POST /crew/build`) has something
live to call. Ported from central's #169 references and adapted to the exact JSON contracts the
bridge parses (`ct_common::crew` + `crew_build_over`).

| script | role / agent | `service/<slug>` | stdin → stdout |
|--------|--------------|------------------|----------------|
| `safety-check-handler.sh` | safety (any) | `safety_check` | prompt → `{"ok":bool,"reason":str}` |
| `physics-handler.sh` | 🕹️ physics / **source-2** | `text_generation` | prompt → `{gravity,flapPower,pipeGap,pipeSpeed}` |
| `art-handler.sh` | 🎨 art / **sink** | `text_generation` | prompt → `{theme,birdColor,birdEmoji,title}` |

## How an agent serves its role

On the agent host, run a channel-serving process that offers the service and points the handler at
these scripts (the `#173` sink/source-2 lane):

```bash
CT_CHANNEL_HOLDER_KEY=<agent holder key hex> \
CT_AGENT_OFFER_SERVICES=text_generation \
CT_AGENT_OFFER_KIND=cloud CT_AGENT_OFFER_MODELS=<model> \
CT_AGENT_OFFER_UNITS=100 CT_AGENT_OFFER_MIN_PRICE=1 CT_AGENT_OFFER_CURRENCY=ct-llm-token-chain \
CT_AGENT_SERVICE_HANDLER_CMD="$PWD/physics-handler.sh" \
CT_CHANNEL_SERVE=1 \
  ct-agent channel <join args…>          # source-2: physics-handler.sh; sink: art-handler.sh
```

The safety agent serves `safety_check` the same way (`CT_AGENT_OFFER_SERVICES` including
`safety_check`, `CT_AGENT_SERVICE_HANDLER_CMD=$PWD/safety-check-handler.sh`).

## The LLM call

Each handler shells to a **non-interactive LLM CLI**, isolated with **no tool access** (pure text
generation/classification — nothing to inject into). Set `CT_LLM_CMD` to your CLI (default
`claude`). The safety handler **fails closed** (rejects) on any LLM/parse failure; the physics/art
handlers fall back to sane defaults so a flaky LLM degrades gracefully (and the bridge itself fails
closed on a genuinely malformed fragment).

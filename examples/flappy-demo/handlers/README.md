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

On the agent host, run a channel-serving process that points the handler at these scripts (the
`#173` sink/source-2 lane):

```bash
CT_CHANNEL_HOLDER_KEY=<agent holder key hex> \
CT_AGENT_SERVICE_HANDLER_CMD="$PWD/physics-handler.sh" \
CT_AGENT_SERVICES=text_generation \
CT_CHANNEL_SERVE=1 \
  ct-agent channel <join args…>          # source-2: physics-handler.sh; sink: art-handler.sh
```

The safety agent serves `safety_check` the same way (`CT_AGENT_SERVICES=safety_check`,
`CT_AGENT_SERVICE_HANDLER_CMD=$PWD/safety-check-handler.sh`).

> **Use `CT_AGENT_SERVICES` — NOT `CT_AGENT_OFFER_SERVICES` — to register the served
> `service/<slug>` tools.** `CT_AGENT_OFFER_SERVICES` only feeds the #147 marketplace *offer*
> catalog; setting it **alone** (without a full `CT_AGENT_OFFER_KIND/MODELS/UNITS/MIN_PRICE/CURRENCY`
> offer) registers **zero** tools, so every call fails `unknown tool 'service/<slug>'` — the exact
> trap behind #203. To *also* advertise capacity in the marketplace, add the full `CT_AGENT_OFFER_*`
> block; then `CT_AGENT_SERVICES` (when set) is filtered to the offer's declared catalog (#167), and
> if `CT_AGENT_SERVICES` is unset the offer's catalog is used. `CT_AGENT_SERVICES` alone always works.

## The LLM call

Each handler shells to a **non-interactive LLM CLI**, isolated with **no tool access** (pure text
generation/classification — nothing to inject into). Set `CT_LLM_CMD` to your CLI (default
`claude`). The safety handler **fails closed** (rejects) on any LLM/parse failure; the physics/art
handlers fall back to sane defaults so a flaky LLM degrades gracefully (and the bridge itself fails
closed on a genuinely malformed fragment).

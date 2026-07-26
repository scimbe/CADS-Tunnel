# cookbook-demo crew handlers (#201)

Reference `CT_AGENT_SERVICE_HANDLER_CMD` scripts for the Cookbook demo's LLM-agent crew — the real
`service/<slug>` handlers each agent runs so `ct-cookbook-bridge` (`POST /cookbook/build`) has
something live to call. Same shape as the flappy-demo handlers, new (higher-stakes) domain.

| script | role / agent | bridge env | stdin → stdout |
|--------|--------------|------------|----------------|
| `safety-check-handler.sh` | safety (any) | `COOKBOOK_SAFETY_CMD` | prompt → `{"ok":bool,"reason":str}` |
| `ingredients-handler.sh` | 🥕 structure / **source-2** | `COOKBOOK_STRUCTURE_CMD` | `{prompt, image?}` → `{ingredients,steps,cookTime,difficulty,allergens}` |
| `presentation-handler.sh` | 🍽️ presentation / **sink** | `COOKBOOK_PRESENTATION_CMD` | `{prompt, structure}` → `{dishName,theme,garnish,moodDescription}` |
| `review-handler.sh` | 🛡️ review (any) | `COOKBOOK_REVIEW_CMD` | `{prompt, recipe}` → `{"ok":bool,"reason":str}` |

## Order + safety model

The bridge runs them **sequentially**: `safety → structure → presentation → review → built`.

- **structure** (source-2) is the one that gets the **photo**: the bytes travel over the Agent-Fabric
  channel as base64, and this handler decodes them to a **local temp file on source-2's own box**,
  then references that path in `claude -p` (which reads a local image when its path is mentioned).
  Requires `jq` + `base64`, and **Read** is left enabled (only for the image); write/exec/network
  tools are disabled.
- **presentation** (sink) names/themes the *actual* recipe, so it takes structure's output as context.
- **review** is the #201 machine-checkable layer: a holistic LLM review of the finished recipe
  (inedible/poisonous items, dietary-constraint contradictions, plausibility). It **fails closed** —
  any LLM/parse failure returns `{"ok":false}`, so an unreviewed recipe is never served.
- **structure fails soft** instead: if no ingredients can be recognized it returns a safe **fallback
  dish** rather than erroring (#201 error-handling addendum).

## How an agent serves its role

Same recipe as the flappy handlers, with the cookbook service env:

```bash
CT_AGENT_OFFER_SERVICES=text_generation \
CT_AGENT_SERVICE_HANDLER_CMD="$PWD/ingredients-handler.sh" \
CT_CHANNEL_SERVE=1 \
  ct-agent channel <join args…>          # source-2 = ingredients; sink = presentation
```

Point `CT_LLM_CMD` at your non-interactive LLM CLI (default `claude`). The safety + review agents
serve `safety_check`; structure + presentation serve `text_generation`.

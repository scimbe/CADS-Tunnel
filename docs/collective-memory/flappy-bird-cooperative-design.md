# Flappy Bird — cooperative design

Author: central

Tracking issue: `#159`. First real project to use [[README|this vault]] rather than GitHub
comments alone — a lightweight, low-stakes exercise testing multi-agent creative
collaboration (as opposed to the protocol-level debugging [[135-layer-4-collective-memory|
#133/#148/#154/#155/#156]] have all been about).

## Goal

A single self-contained `index.html` (HTML5 Canvas + vanilla JS, no build step, no external
deps) implementing a simple, playable Flappy Bird clone: bird physics (gravity + flap),
scrolling pipes with gaps, collision detection, score counter, game-over + restart.

## Design lenses (proposed in `#159`, not assigned — accept, swap, or redefine)

- [[source-2-mechanics-design]] — game-feel/mechanics: gravity curve, flap impulse, terminal
  velocity, difficulty pacing, collision fairness (hitbox vs. sprite).
- [[sink-ux-design]] — presentation/UX: visual style, score/UI placement, restart flow,
  optional juice (screen shake, particle burst).
- central — integration: reconcile both into one spec, implement, report back here and on
  `#159`.

## How to contribute here vs. on `#159`

Either works — GitHub is still the reliable medium (see [[135-layer-4-collective-memory]] for
why: no chat/message MCP tool exists on the Agent-Fabric channel yet, and neither source-2 nor
sink has a self-registered `AgentCard` in the `#144` directory). This vault is offered as an
**additional**, more structured option: edit your linked note directly (`git pull`, fill it
in, `git commit` + push) if you'd rather write a real design doc than a comment. Central will
read whichever lands — a GitHub comment on `#159`, a filled-in note here, or both.

## Status

2026-07-24: vault created, project note + stub notes seeded, invitation posted on `#159`.

2026-07-24 (later): both design contributions landed as `#159` comments (source-2:
mechanics/pacing/collision; sink: palette/UI/restart/juice, plus a self-signed `AgentCard` and
the `#161` registry-enrollment finding). Central synthesized both into `examples/flappy-bird/
index.html` (`4a47a11`), verified live via Playwright — not just read-checked — and found +
fixed two real bugs in the process (a `null`-vs-`undefined` pause guard blanking the whole
canvas, and a clipped score readout). **Done**: playable, tested, committed, pushed.

2026-11-15: the game was removed from the repository (`#908`); it was a collaboration exercise, not
part of CADS Tunnel. It stays reachable in the history at `4a47a11`.

2026-07-24 (discovery layer, spun off from this exercise): `#144`'s directory turned out to
need an M2M write path (`#161`, fixed) and — a false alarm corrected by the maintainer — I
briefly thought it also needed a non-`https` `card_url` variant for NAT'd agents (`#162`,
closed as unnecessary: the Browser-Plane hosting mechanism *is* the answer, already proven by
central's own card and `help.bunsenbrenner.org`). Central then provisioned real
`sink.agents.bunsenbrenner.org` / `source-2.agents.bunsenbrenner.org` hosting (reusing the
existing `*.agents.bunsenbrenner.org` wildcard cert) and registered both — `GET
/registry/agents` now returns three real, independently signature-verified agents. The `#159`
exercise ended up validating far more of the stack than just a game.

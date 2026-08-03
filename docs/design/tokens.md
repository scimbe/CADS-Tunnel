# Design tokens: the sign-in → account journey

Four separately-deployable surfaces render the path a user takes from
"sign in or create an account" through to managing that account — a Rust
binary (two of them) and a static Keycloak theme (the other two), with no
shared build step between them. Each hardcodes its own copy of the same
values. This file is the single documented source of truth to diff those
four copies against; it does not get imported by anything.

| Surface | File |
|---|---|
| Portal pre-login card | `crates/control-plane/src/portal.rs` (`PORTAL_HTML_HEAD`) |
| Portal dashboard chrome | `crates/control-plane/src/portal_api.rs` (`page()`) |
| Keycloak login form | `docker/deploy/keycloak/themes/ct-bunsenbrenner/login/resources/css/ct-login.css` |
| Keycloak account console | `docker/deploy/keycloak/themes/ct-bunsenbrenner/account/resources/css/ct-account.css` |

## Colors

```
--bg:            #0e1116
--panel/surface:  #161b22
--border:        #30363d
--border2:       #3d4551   (portal pre-login card only, provider-button hover)
--text:          #e6edf3
--muted:         #8b949e
--accent(2):     #5fb8ab   (teal -- links, nav, focus rings, secondary emphasis)
--accent2-hover: #7cc9bd
--primary:       #d98a4f   (warm orange -- the ONE primary-action button per screen)
--primary-hover: #e39a63
--primary-ink:   #20130a   (dark text on the orange button, never white)
```

**Provenance**: these are not invented for this journey — they're pulled
directly from the landing page's own established brand
(`https://bunsenbrenner.org/`: `--accent`/`--accent2` in its own stylesheet),
plus its serif display type (`ui-serif,Georgia,"Iowan Old Style","Palatino
Linotype",serif`, used here for every `h1`/`h2`) and its `pulse` live-indicator
keyframe (`0%,100%{opacity:1}50%{opacity:.35}`, `1.6s ease-in-out infinite`,
always paired with `prefers-reduced-motion`). An earlier pass (2026-08-03,
PR #337) unified these four surfaces to *each other* using generic
GitHub-dark blue/green, but never cross-checked them against the landing
page — so the result still didn't read as the same product as the site
the user actually lands on first. This pass corrects that.

**The rule**: teal is never a button background; orange is never a link
color, and orange buttons always use the dark `--primary-ink` text, never
white — matching the landing page's own button convention. One primary
(orange) button per screen; everything else that's clickable is teal.

## Motion

- Page/card entrance: `opacity 0→1` + `translateY(6px→0)`, `.32s ease-out`.
  Every one of the four surfaces uses this exact curve (`cardIn` in the two
  Rust-rendered pages, `ctCardIn` in the login theme, `ctAccountIn` in the
  account theme) — same name isn't possible across a Rust string literal and
  two independent CSS files, but the keyframe body must stay identical.
- List/row reveal: a light `nth-child` stagger (dashboard rows, pre-login
  provider buttons, account-console cards) — capped at a handful of steps so
  a long list doesn't end with a visibly-delayed tail.
- Live/connected indicator: a small dot using the landing page's own `pulse`
  keyframe — pulses only when actually live (a dead/idle tunnel has nothing
  to signal, so it stays static and muted). Replaces the raw 🟢/⚪ emoji the
  dashboard used before this pass.
- Primary buttons: a one-shot diagonal shine sweep on `:hover` (a single
  tasteful flourish on the one most-important click per screen, deliberately
  not applied to secondary/danger buttons), plus `background-color .15s ease`
  and `transform: scale(.97)` on `:active` for a tactile press.
- Always behind `@media (prefers-reduced-motion: reduce)`, disabling both
  `animation` and `transition` — every surface must keep this block.

## Why this file exists

Filed after live design feedback (2026-08-03) that the sign-in → account
journey felt "bolted together" (four surfaces had drifted, split colors
inconsistently, had little motion where it mattered). A follow-up round of
feedback the same day judged that first fix — internally consistent but
still generic — as falling well short of the landing page's own actual
design quality. If you're touching any of the four files above, diff its
`:root`/token block against this one first, and spot-check it against the
live landing page too, not just the other three files.

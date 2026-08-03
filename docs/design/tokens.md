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
--accent:        #58a6ff   (blue -- links, nav, focus rings, secondary emphasis)
--accent-hover:  #79c0ff
--primary:       #238636   (green -- the ONE primary-action button per screen)
--primary-hover: #2ea043
```

**The rule**: blue is never a button background; green is never a link
color. One primary (green) button per screen; everything else that's
clickable is blue. This was the one real inconsistency found across the
four surfaces (the Keycloak login and account primary buttons were blue
before this pass) — worth re-checking by eye whenever any of the four files
changes independently.

## Motion

- Page/card entrance: `opacity 0→1` + `translateY(6px→0)`, `.32s ease-out`.
  Every one of the four surfaces uses this exact curve now (`cardIn` in the
  two Rust-rendered pages, `ctCardIn` in the login theme, `ctAccountIn` in
  the account theme) — same name isn't possible across a Rust string literal
  and two independent CSS files, but the keyframe body must stay identical.
- Buttons: `background-color .15s ease`, plus `transform: scale(.97)` on
  `:active` for a tactile press.
- Always behind `@media (prefers-reduced-motion: reduce)`, disabling both
  `animation` and `transition` — every surface must keep this block.

## Why this file exists

Filed after live design feedback (2026-08-03) that the sign-in → account
journey felt "bolted together": the four surfaces had drifted (`#0b0e13` vs
`#0e1116`), split colors inconsistently (some screens blue-only, some
green-only, only the dashboard had both used correctly), and had the least
motion on the screen (the account console) that most needed to feel
considered. If you're touching any of the four files above, diff its
`:root`/token block against this one first.

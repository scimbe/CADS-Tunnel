---
name: coordinated-development-loop
description: The three-role (developer/agent/central) coordinated development loop for CADS-Tunnel — the per-cycle control loop, the report + verify contracts, and the delegated-agent contract. Synthesized from retrospective #115 round 1. Start this to reorganize the process at a better level; each role then aligns its own SKILL.md to its section here.
---

# Coordinated development loop (CADS-Tunnel)

Three roles coordinate **only through GitHub issues**; **only `developer` changes code**.
This skill is the shared process, distilled from retrospective #115 (round 1). Each role
owns the section named for it and should keep its own `.claude/skills/<role>/SKILL.md`
aligned to it.

## Per-cycle control loop (developer — every fire)
1. **Sweep** scimbe-authored open issues; re-derive the ladder: (A) fresh bug/report not
   fix-ready, lowest # → (B) security-review, priority:high first → (C) fresh feature not
   in-progress → (D) continue an in-progress item → (E) thesis. A **new** scimbe
   bug/report/security preempts feature work.
2. **Reconcile** the delivery roadmap against issue state (closed/relabeled/new comment =
   new input → update the plan; surface any needed decision on the issue).
3. **Pick ONE** bounded packet on the critical path.
4. **Size it:** finishable this cycle → land it directly. Too big → **delegate the split
   to an agent** (see delegated-agent contract) and finish what is directly finishable.
5. **Gate** in the hermetic Docker gate (`rust:1-slim`, `RUSTFLAGS=-D warnings`,
   persistent cargo cache, run in background) — 0 warnings, workspace green.
6. **Land:** `scripts/check-no-secrets.sh` → commit as scimbe (with the two footers) →
   `git push origin main` (never force-push, only main) → comment via `gh … -F -` heredoc.
7. **Relabel + handshake:** real fix → `fix-ready` (remove bug/report); feature slice →
   `in-progress`. Setting `fix-ready` is the **push signal** to the verifiers (below).
8. **Update slice-state** in `docs/planning/v1-first-task-packets.md` + the roadmap memory.

## Delegated-agent contract (developer)
- Delegate when a packet needs further splitting; use `isolation: worktree` when another
  tree-mutating agent is concurrently in flight.
- The agent **commits-or-reports-cleanly**: land the slice (commit+push+comment as its
  FINAL actions, then stop and report the commit hash) OR leave the tree untouched and
  report exactly what's done/undone — **never push half-broken work, never sit polling a
  monitor after pushing.**
- The developer **independently re-gates** delegated work before trusting it (agents have
  ended mid-gate without committing; verify git state + re-run the gate).

## Report contract (agent AND central — no dumps)
Every review report:
- **Leads with ONE** recommended drop-in, ranked #1, with its data-path / severity impact
  stated.
- Lists at most the **top-N confirmed** findings (each re-verified against source before
  filing).
- Puts everything else under an explicit **"defer — confirm first"** heading.
No multi-finding dumps; ranking is the floor, not the best case.

## Verify handshake — two explicit lanes (push, not poll)
Developer sets `fix-ready` when a slice lands (the push signal). Then:
- **agent lane — against source / frozen behavior:** re-read/gate the change against the
  source and the frozen tests; set `verified` on the issue, or comment a regression.
- **central lane — against the deployed binary/DB:** for **live-facing** changes only,
  prove it against the actually-deployed binary + DB (real HTTP, real crypto, real
  redeploy); unit-test-trust otherwise.
The lanes are **complementary by design, not by accident**: agent proves the code is
correct; central proves the deployment behaves. A slice states which lane(s) it needs.

## Standing hygiene
- **agent — blocked-probe caching:** cache a known-blocked external dependency (e.g. a
  filtered `:4435`/`:4436`) and re-check only when a commit or an explicit signal says
  exposure changed — not every cycle.
- **central — recipe-first:** trust an established recovery recipe before improvising
  against live infrastructure.
- **Local proof over operator-blocked proof:** prefer a self-contained docker-compose e2e
  (that agent can run against frozen behavior) so proof isn't gated on an operator step.

## Retrospective cadence
Every ~48h the developer rolls retrospective **#115**: each role posts one reflection
(what worked / what to do better / support needed / one process change) and reads +
responds to the others. On convergence ("no new comment" from all roles) the developer
synthesizes the round into an update of this skill and pings the maintainer to start it;
each role then re-aligns its own SKILL.md.

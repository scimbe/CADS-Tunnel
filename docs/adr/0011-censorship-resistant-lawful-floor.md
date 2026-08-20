# 0011. Censorship-resistant posture: terminate only at a Lawful Floor

Status: accepted (supersedes ADR-0008)

The product's ICP is censorship-resistance, so the operator commits to resisting discretionary, political, and third-party-pressure takedown. Its only enforcement action, **Termination**, is applied solely at the **Lawful Floor**: a narrow binding legal order in the operator's jurisdiction, or verified CSAM. The third-party abuse feeds that were the basis of the superseded ADR-0008 are dropped. CSAM is retained both as a moral floor and as a practical requirement for remaining bankable and hosted at all.

## Consequences

- No ingestion of or action on external abuse feeds; phishing/malware complaints without a binding order do not trigger Termination.
- Shared Edge-IP reputation risk is accepted and must be managed structurally (per-tenant IP diversity, upstream selection) rather than by content policing.
- Choice of incorporation jurisdiction and of upstream/hosting providers becomes load-bearing and must tolerate this posture (open branch, likely needs counsel).
- A published AUP documents the Lawful Floor and nothing broader.
- Responding to a genuine Lawful Floor order still requires *some* evidentiary basis — an optional, off-by-default, host-only connection-source audit log (`crates/edge/src/audit_log.rs`, #603) exists for exactly that: proving which real client originated a given relayed session, deliberately scoped to "thin metadata" (timestamp, source IP, transport, routing token/channel) with no request content, and with no network-reachable query surface — see the privacy policy §9 for the operator-facing description.

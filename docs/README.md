# docs/ — runbooks, consumer guides, active design docs

Operational documents and the design records that are still load-bearing. The root README is the
quickstart; root CONCEPT.md is the authoritative design + security model; root STATUS.md is the
per-subsystem verification table.

## Runbooks (operator)
- [INSTALL-RUNBOOK.md](INSTALL-RUNBOOK.md) — fresh install on a real host, step by step, with the
  known papercuts (`--force-squid`, SELinux labeling, firewalld) and the S6 enable/disable procedure.
- [UPDATE-RUNBOOK.md](UPDATE-RUNBOOK.md) — updating a deployed rig from a new pack (staging,
  verification, atomic swap, unit restarts).

## Consumer guides (mirrored into ../handout/, drift-tested)
- [AGENT-GUIDE.md](AGENT-GUIDE.md) — the complete `rigctl` verb reference for an unprivileged
  agent; kept code-true by tests/agent-guide.bats.
- [ORCHESTRATOR-GUIDE.md](ORCHESTRATOR-GUIDE.md) — the service-plane contract for a long-lived
  orchestrator consumer (service-class VMs, idempotency, snapshots/restore).

## Active design docs
- [CONCEPT-SERVICE-PLANE.md](CONCEPT-SERVICE-PLANE.md) — service plane for long-lived VMs
  (S0–S6): decisions, hard requirements, deferrals.
- [CONCEPT-S6-SECRETS-RESTORE.md](CONCEPT-S6-SECRETS-RESTORE.md) — the gated keep-secrets
  restore contract + the live-resolved identity semantics.
- [CONCEPT-BUILD-NET.md](CONCEPT-BUILD-NET.md) — appliance-network robustness for golden builds
  (implemented).
- [CONCEPT-NET-MODES.md](CONCEPT-NET-MODES.md) — per-run network modes (DR-6, design converged;
  implementation staged).
- [ISSUE-per-net-isolation.md](ISSUE-per-net-isolation.md) — the open DR-6 problem statement.

## Provenance
- [PROVENANCE.md](PROVENANCE.md) — the clean-room derivation audit + the license decision.

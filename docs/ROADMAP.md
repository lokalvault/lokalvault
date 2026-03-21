# LokalVault Roadmap

## Product Stages

- `Part 1` - CLI-first complete product
- `Part 1B` - developer-feel CLI pass
- `Part 2` - Tauri/React UI

## Major Completed Milestones

- `v0.0.1-poc`
- `v0.1.0-alpha.1`
- `v0.1.0-alpha.2`
- `v0.1.0-alpha.3`
- `v0.1.0-phase1a`
- `v0.1.1-cli`
- `v0.1.2-cli-ipc`
- `v0.1.3-audit`
- `v0.1.4-settings`
- `v0.1.5-phase1-complete`
- `v0.1.6-debt-cleared`
- `v0.1.7-dx`
- `v0.1.8-ai-safe`
- `v0.1.9-pre-phase1c-complete`
- `v0.1.10-docs-sync`
- `v0.1.11-cli-feel`
- `v0.1.12-run-lifecycle`
- `v0.2.0-phase1-hardened`
- `v0.2.1-backend-final`
- `v0.2.2-ui-contract-ready`
- `v0.2.3-ui-handoff-clean`
- `v0.2.4-ui-contract-ready-fixes`
- `v0.2.5-ui-contract-final`
- `v0.2.6-ui-audit-clean`

## Current Milestone - Backend Audit Stabilization + Part 2 Bootstrap

The backend/UI contract remains broadly frozen, but backend stabilization is still active while the audit backlog is burned down. The current work is focused on making the CLI/daemon paths trustworthy before further UI expansion:

- Phase 1 - share/claim regression cleanup
- Phase 2 - CLI/runtime correctness fixes
- Phase 3 - daemon IPC hardening with scoped approval tokens
- Phase 4 - test reliability and docs drift cleanup

Current bootstrap status:
- shared CLI entry now unblocks a thin Tauri wrapper from reusing the root crate
- root-owned Vite workflow now drives the `src-ui/` React app
- first desktop shell is read-only and only exposes sanitized status/project metadata

Next:
- finish the audit cleanup and validation pass
- expand `Part 2` UI flows on top of the stable backend/test baseline

## Deferred Work

- `lokalvault extend`
- `Part 2` UI work

# LokalVault Codebase Audit

Last updated: 2026-03-17

This document tracks the current known issues found during the repo-wide audit.
It is intended to drive implementation work, not just record findings.

## Fix Order

1. Share/claim regressions introduced by the new handoff bundle flow
2. CLI/runtime correctness bugs that can mislead users during normal usage
3. Daemon IPC hardening and token lifecycle fixes
4. Test reliability and docs drift cleanup

## Critical

### P0 — Same-UID daemon IPC is effectively unauthenticated

- `src/daemon.rs`
- Sensitive requests now require scoped single-use `action_token`s, and token
  minting now depends on a daemon-tracked approval request that is bound to the
  caller PID/UID, scope, and project.
- Impact: any local process running as the same user can still mint an action
  approval and then read or mutate the unlocked vault through the socket,
  because approval resolution is still same-UID IPC rather than a daemon-owned
  human-verification boundary.
- Status: `partially mitigated on current branch`
- Planned fix phase: `Phase 3`

## High

### P1 — Claim bypasses the daemon and can desync RAM vs disk

- `src/cli.rs`
- `cmd_claim` mutates the vault file directly even when the daemon is running.
- Impact: daemon-backed commands in the same unlocked session can miss claimed
  secrets until the vault is locked and unlocked again.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 1`

### P1 — Real run flow still has a hardcoded POC fallback

- `src/run_cmd.rs`
- `lokalvault run` can hit the POC path when `.lokalvault` exists but the daemon
  is not running.
- Impact: real projects can silently run with demo behavior.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 2`

### P1 — Two-phase token activation is bound to the CLI PID, not the child PID

- `src/run_cmd.rs`
- `src/daemon.rs`
- Impact: token lifecycle and child monitoring do not match the documented
  security model.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 3`

### P1 — macOS PID handling corrupts rate limiting and token monitoring

- `src/daemon.rs`
- Impact: PID `0` is used for lifecycle and rate-limit logic on macOS.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 3`

### P1 — Daemon-backed import/claim can hit the rate limiter mid-command

- `src/cli.rs`
- `src/daemon.rs`
- Status: `fixed on current branch`
- Daemon-backed import and claim now batch upserts into a single mutation
  request instead of per-key token+mutation request pairs.
- Planned fix phase: `Phase 3`

### P1 — The checked-in test suite is red and can hang in POC socket tests

- `src/daemon.rs`
- `src/run_cmd.rs`
- Impact: repo validation is not trustworthy.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 4`

### P1 — POC smoke test can silently skip when socket binding is unavailable

- `tests/poc_demo.rs`
- The POC regression test now avoids hanging in restricted environments, but it
  returns early when the daemon cannot bind its test socket.
- Impact: the smoke test can report success without actually exercising the
  `daemon-poc` end-to-end path.
- Planned fix phase: `Phase 4`

### P1 — `lokalvault dev` happy path is incorrect

- `src/cli.rs`
- `src/main.rs`
- Impact: documented flow can resolve to `lokalvault run -- true` and exit
  immediately instead of starting the app.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 2`

## Medium

### P2 — Claim silently drops duplicate keys

- `src/cli.rs`
- Impact: recipient can keep stale secrets without any warning.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 1`

### P2 — Share refreshes stale-secret access timestamps

- `src/cli.rs`
- `src/daemon.rs`
- Impact: share operations skew audit-derived stale-secret reporting.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 1`

### P2 — Password injection test seam is present in production code

- `src/cli.rs`
- Impact: in-process callers can preload password prompts through a global
  helper that should only exist in tests.
- Status: `narrowed to debug-only test env vars on current branch`
- Planned fix phase: `Phase 1`

### P2 — Stale socket cleanup is not wired into real control flow

- `src/ipc_client.rs`
- `src/cli.rs`
- Impact: socket path existence can diverge from daemon liveness.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 2`

### P2 — Audit log entries can be forged through IPC

- `src/daemon.rs`
- Impact: same-UID clients can write arbitrary audit history.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 3`

### P2 — Share/claim end-to-end tests do not model isolated sender/recipient vaults

- `tests/end_to_end.rs`
- The current handoff tests switch cwd between sender and recipient directories
  but still share one process-wide `LOKALVAULT_DATA_DIR`.
- Impact: the tests can pass without proving claim works against a truly separate
  recipient vault.
- Status: `fixed on current branch`
- Planned fix phase: `Phase 4`

## Low

### P3 — Share output overwrites existing files without confirmation

- `src/cli.rs`
- Status: `fixed on current branch`
- Planned fix phase: `Phase 1`

### P3 — CLI docs have duplicated export entries

- `docs/CLI.md`
- Status: `fixed on current branch`
- Planned fix phase: `Phase 4`

### P3 — Roadmap doc is stale relative to current backend work

- `docs/ROADMAP.md`
- Status: `fixed on current branch`
- Planned fix phase: `Phase 4`

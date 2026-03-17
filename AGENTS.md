# LokalVault - Agent Instructions

This file is for coding agents working inside `lokalvault`.
Follow the checked-in docs first, then the current codebase.

## Read First

Before making code changes, read these files in this order:

1. `docs/SPEC.md`
2. `docs/MODULE_MAP.md`
3. `docs/SECURITY_RULES.md`
4. `docs/ROADMAP.md`
5. `docs/CLI.md`

These docs are authoritative for architecture, ownership boundaries, security rules, roadmap intent, and CLI behavior.

## Repo Workflow

- Keep changes small and module-scoped.
- Update relevant docs after behavior or ownership changes.
- Write tests for every feature.
- Run validation before declaring work complete.
- Create clean milestone commits and tags for meaningful checkpoints.

## Source Of Truth For Ownership

Use `docs/MODULE_MAP.md` to decide where functions belong.

Important boundaries:
- `src/crypto.rs` is the only file where crypto primitives may be used.
- `src/vault_file.rs` owns vault structs and file persistence.
- `src/vault_ops.rs` owns CRUD and validation logic.
- `src/daemon.rs` owns socket serving and credential checks.
- `src/run_cmd.rs` owns process spawning and env injection.
- `src/main.rs` should remain an entrypoint, not a business-logic dump.

## Security Rules You Must Preserve

The hard rules are in `docs/SECURITY_RULES.md`.
If a requested change conflicts with them, choose the safest compliant implementation and call it out clearly.

## Build And Validation

Run from repo root: `/Users/mohneeru/Developer/lokalvault`

- Build: `cargo build`
- Check: `cargo check`
- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Test: `cargo test -- --nocapture`
- POC regression: `cargo test --test poc_demo -- --nocapture`

Recommended flow for shared or security-sensitive changes:
1. `cargo fmt`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test -- --nocapture`

## Repo-Specific Notes

- If the daemon is running, CLI CRUD mutations must go through daemon IPC.
- If the daemon is not running, CLI may mutate the vault file in offline mode.
- Do not introduce crypto outside `src/crypto.rs`.
- Do not log secret values, passwords, tokens, or clipboard contents.
- Do not simplify two-phase token registration.
- Do not add `daemon.lock`; the socket is the source of truth for daemon liveness.
- `LOKALVAULT_TEST_PASSWORDS` and `LOKALVAULT_TEST_PIN_APPROVAL` are debug/test-only seams.
  Do not expand them into runtime product behavior or document them as user-facing features.

## Deferred Work

- **Full error type unification (Phase 1C):** `vault_ops.rs` now returns `AppError` internally, but callers in `cli.rs` and `daemon.rs` convert back to `String` at module boundaries via `.map_err(|e| e.to_string())`. Phase 1C should propagate `AppError` end-to-end and eliminate the `Result<_, String>` return types from CLI and daemon functions.
- **Action-token approval proof:** sensitive daemon routes now require scoped single-use action tokens, but `register_action_token` still relies on same-UID trust. Phase 3 follow-up should bind token minting to a daemon-verifiable approval proof instead of a CLI-only prompt.
- **High-volume daemon mutations:** daemon-backed `import` and `claim` currently mint one action token per mutation request. Phase 3 follow-up should avoid tripping the daemon rate limiter on larger imports/bundles.
- **Handoff test isolation:** current share/claim end-to-end coverage is strong on behavior, but sender and recipient still share one process-wide data dir. Phase 4 follow-up should split those fixtures so the tests prove isolated vault handoff semantics.

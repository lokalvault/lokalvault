# LokalVault - Agent Instructions

This file is for coding agents working inside `lokalvault`.
Follow the checked-in docs first, then the current codebase.

## Read First

Before making code changes, read these files in this order:

1. `docs/SPEC.md`
2. `docs/MODULE_MAP.md`
3. `docs/SECURITY_RULES.md`

These docs are authoritative for architecture, ownership boundaries, and security rules.
If the code and docs disagree, assume the docs describe the intended direction and make the smallest safe change toward them unless the task explicitly says otherwise.

## Repo Instruction Files

- `AGENTS.md`: present
- `.cursorrules`: not present
- `.cursor/rules/`: not present
- `.github/copilot-instructions.md`: not present

If Cursor or Copilot instruction files are added later, treat them as additional repository guidance and keep this file aligned with them.

## Current Phase

The POC is complete and tagged `v0.0.1-poc`.
Current work is Phase 1, and Phase 1 is intentionally CLI-first.

POC completion is defined explicitly by one end-to-end demo only:

- `lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"`
- Expected output: `test-value-123`

If that exact demo does not work reliably, the POC is not complete, even if tests are green.
The UI is a later thin layer over the Rust core and CLI, not the source of truth.

### Phase 1 Order

- `Phase 1A` - `src/vault_ops.rs` -> `src/errors.rs` -> real `src/daemon.rs` -> real `src/run_cmd.rs`
- `Phase 1B` - `src/cli.rs` -> `src/audit_log.rs` -> `src/settings.rs`
- `Phase 1C` - Tauri + React UI

### Phase 1A Completion Bar

Phase 1A is complete only when all of the following are true:

- `src/vault_ops.rs` is stable and fully tested
- `src/errors.rs` is in place and used by new core work
- real `src/daemon.rs` has coherent vault-backed and token-aware behavior
- real `src/run_cmd.rs` uses correct phase1 -> spawn -> phase2 ordering
- terminal approval uses a non-deterministic code
- integration tests prove the token-aware run flow across modules

Do not declare Phase 1A complete while placeholder security logic still defines the real run path.

### Status Table

| Step | Module       | File              | Status      |
|------|--------------|-------------------|-------------|
| 1    | Crypto       | `src/crypto.rs`   | ✅ DONE     |
| 2    | Vault File   | `src/vault_file.rs` | ✅ DONE   |
| 3    | Daemon POC   | `src/daemon.rs`   | ✅ DONE     |
| 4    | Run POC      | `src/run_cmd.rs`  | ✅ DONE     |
| 5    | Vault Ops    | `src/vault_ops.rs` | ✅ DONE    |
| 6    | Integration Tests | `tests/`      | ✅ DONE     |
| 7    | Errors       | `src/errors.rs`   | ✅ DONE     |
| 8    | Daemon Real  | `src/daemon.rs`   | ✅ DONE     |
| 9    | Run Real     | `src/run_cmd.rs`  | ✅ DONE     |
| 10   | CLI          | `src/cli.rs`      | ✅ IPC-FIRST DONE |
| 11   | Audit Log    | `src/audit_log.rs` | ⬜ PENDING |
| 12   | Settings     | `src/settings.rs` | ⬜ PENDING  |
| 13   | Tauri Init   | `src-tauri/`      | ⬜ PHASE 1C |
| 14   | React UI     | `src/`            | ⬜ PHASE 1C |

Current next module from `docs/MODULE_MAP.md`:

- `src/audit_log.rs` - begin audit logging after closing out IPC-first CLI behavior

Do not jump ahead into later modules unless the user explicitly asks.
Build one module at a time and keep completed modules stable.

After completing each module, update both `AGENTS.md` and the relevant files under `docs/` to reflect the new status, behavior, commands, or ownership changes introduced by that module.
After those documentation updates, create proper git commits for the completed work and then respond to the user with what changed and the logical next instruction point.
Create clean commits for module milestones and other meaningful checkpoints; do not leave large security-sensitive work uncommitted.
Write tests for every feature and validate thoroughly before declaring a module complete.

### Daemon/CLI Sync Rule

Keep this invariant throughout Phase 1:

- If the daemon is running, CLI CRUD commands must mutate state through daemon IPC so RAM and disk stay in sync.
- If the daemon is not running, CLI may unlock the vault and mutate the vault file in offline mode.

Do not implement file-only CLI writes that bypass a live daemon.

## Source Of Truth For Ownership

Use `docs/MODULE_MAP.md` to decide where functions belong.

Important boundaries from the current docs:

- `src/crypto.rs` is the only file where crypto primitives may be used.
- `src/vault_file.rs` owns vault structs and file persistence.
- `src/vault_ops.rs` owns CRUD and validation logic.
- `src/daemon.rs` owns socket serving and credential checks.
- `src/run_cmd.rs` owns process spawning and env injection.
- `src/main.rs` should remain an entrypoint, not a business-logic dump.

If a function is not listed under a module in `docs/MODULE_MAP.md`, do not invent a new home for it casually.

## Security Rules You Must Preserve

The hard rules are in `docs/SECURITY_RULES.md`. Key ones to actively protect:

- Crypto logic stays in `src/crypto.rs` only.
- Never store or log the master password.
- Secret values should use `Zeroizing<>` where the spec requires it.
- Never reuse a nonce with the same key.
- Vault writes must stay atomic: temp file -> fsync -> rename.
- Never trust client-reported PID or UID; use kernel-provided peer credentials.
- Socket permissions must be `0600`.
- Token comparison must be constant-time.
- Best-effort hardening like `mlock` and core-dump disabling must never crash the app when unavailable.
- Audit logs must never contain secret values.
- The PIN code itself must never be sent to Rust; only approval boolean reaches backend logic.
- Two-phase token registration is mandatory; do not simplify it.

If a requested change conflicts with these rules, call it out clearly and choose the safest compliant implementation.

## Build Commands

Run from repo root: `/Users/mohneeru/Developer/lokalvault`

- Build: `cargo build`
- Check: `cargo check`
- Run binary: `cargo run`
- Run with backtrace: `RUST_BACKTRACE=1 cargo run`

## Formatting And Linting

- Format: `cargo fmt`
- Check formatting: `cargo fmt -- --check`
- Lint all targets: `cargo clippy --all-targets --all-features`
- Lint with warnings denied: `cargo clippy --all-targets --all-features -- -D warnings`

Use `cargo fmt` as the formatting source of truth.
Prefer fixing Clippy warnings in touched code, but do not do broad unrelated cleanup unless asked.

## Test Commands

- Run all tests: `cargo test`
- Show test output: `cargo test -- --nocapture`
- List tests: `cargo test -- --list`
- Run tests matching a substring: `cargo test vault_file`
- Run integration tests: `cargo test --test vault_roundtrip -- --nocapture`
- Run the official POC demo regression test: `cargo test --test poc_demo -- --nocapture`

Run a single exact test with:

- `cargo test crypto::tests::test_encrypt_decrypt_roundtrip -- --exact --nocapture`
- `cargo test crypto::tests::test_wrong_password_fails -- --exact --nocapture`
- `cargo test crypto::tests::test_tampered_ciphertext_fails -- --exact --nocapture`
- `cargo test vault_file::tests::test_write_and_read_vault -- --exact --nocapture`
- `cargo test vault_file::tests::test_wrong_password_on_read -- --exact --nocapture`
- `cargo test vault_file::tests::test_magic_bytes_present -- --exact --nocapture`

When debugging failures, prefer:

- `RUST_BACKTRACE=1 cargo test <full_test_name> -- --exact --nocapture`

## Recommended Validation Flow

For small changes:

1. `cargo fmt`
2. Run the most relevant single test
3. `cargo test`

For shared logic, security-sensitive code, or file-format changes:

1. `cargo fmt`
2. `cargo clippy --all-targets --all-features`
3. `cargo test -- --nocapture`

If you touch crypto, vault format, daemon IPC, or token flow, prefer full-suite validation even if a targeted test passes.

## Current Codebase Snapshot

The live codebase is smaller than the full spec.

- `src/main.rs`: clap CLI entrypoint for `daemon-poc` and `run`
- `src/crypto.rs`: salt/nonce generation, key derivation, encrypt/decrypt, unit tests
- `src/vault_file.rs`: vault structs, binary layout, read/write helpers, unit tests
- `src/daemon.rs`: POC Unix socket server, Linux SO_PEERCRED support, macOS LOCAL_PEERCRED/getpeereid UID checks, explicit parse/validate/route flow, request-level UID mismatch rejection, required-UID enforcement for `get_secret`, placeholder PID enforcement for Linux requests, explicit internal daemon error variants, structured JSON error responses, plus real daemon token/state groundwork and tests
- `src/run_cmd.rs`: POC process spawning with daemon request, required UID field, placeholder PID field, structured daemon error handling, plus real terminal PIN/config/token-aware helpers and tests
- `src/vault_ops.rs`: full CRUD and validation layer with unit tests
- `src/errors.rs`: shared application error enum with unit tests and minimal `vault_ops` integration
- `tests/`: integration scaffolding with `vault_roundtrip`, `poc_demo`, and `end_to_end` coverage placeholders
- `src/cli.rs`: Phase 1B CLI command surface with clap routing, IPC-first daemon access, offline fallback when no daemon is running, update/delete support, and unit/integration tests
- `src/ipc_client.rs`: per-user Unix socket IPC helpers for daemon discovery and request/response transport
- Planned modules in docs such as `src/settings.rs` and `src/audit_log.rs` are not yet implemented in this repository snapshot.
Do not pretend they exist.

## Rust Style Guidelines

Infer style from the codebase, then let `rustfmt` finalize it.

### Imports

- Prefer explicit imports over wildcard imports.
- Keep imports minimal and remove unused ones.
- When reorganizing a file, use a stable readable order: std, external crates, then crate-local imports.
- Preserve local consistency if only making a small edit.

### Naming

- Functions, modules, files, variables: `snake_case`
- Structs, enums, traits: `UpperCamelCase`
- Constants: `SCREAMING_SNAKE_CASE`
- Tests: descriptive `snake_case`, usually beginning with `test_`

### Types And APIs

- Prefer concrete types when they improve clarity and safety.
- Use fixed-size arrays for fixed-length crypto material like `[u8; 32]` and `[u8; 12]`.
- Borrow with `&str`, slices, and `&Path` where practical.
- Prefer `&Path` over `&PathBuf` for borrowed path parameters.
- Keep structs focused on domain data, not mixed responsibilities.

### Error Handling

- Current public fallible APIs commonly return `Result<_, String>`; follow that style unless a module introduces a documented shared error type.
- Use `?` for propagation.
- Convert low-level errors into clear messages with `map_err(|e| e.to_string())` or a more specific message.
- Use `unwrap()` and `expect()` mainly in tests or for invariants that truly cannot fail.
- Make corruption, tampering, wrong-password, and permission failures explicit in error text when possible.

### Comments

- Keep comments only where they add real value.
- Good comments explain file format, invariants, security reasoning, or platform differences.
- Do not narrate obvious Rust syntax.

### Testing

- Keep unit tests near the implementation in `#[cfg(test)]` modules.
- Put cross-module and end-to-end tests in the repo-root `tests/` directory.
- Test both happy paths and failure paths.
- For persistence logic, clean up temporary files.
- For crypto-sensitive code, include tampering and wrong-credential cases.

## Repo-Specific Implementation Notes

- The vault binary format currently used by code and module map is:
  - magic `LKVT`
  - version byte `0x01`
  - 32-byte salt
  - 12-byte nonce
  - ciphertext with AES-GCM auth tag appended inside ciphertext bytes
- `docs/SPEC.md` contains a broader future format discussion, but `docs/MODULE_MAP.md` matches the current implemented POC more closely for `src/vault_file.rs`.
- Favor `docs/MODULE_MAP.md` when deciding how to evolve the existing POC modules.
- `src/main.rs` is intentionally minimal right now; dead-code warnings may appear because the binary does little outside tests.

## What Agents Should Avoid

- Do not introduce crypto calls outside `src/crypto.rs`.
- Do not create `.env` files with real secret values.
- Do not log secrets, decrypted payloads, tokens, or passwords.
- Do not trust client-supplied PID/UID values.
- Do not weaken Argon2 or AES-GCM usage without an explicit documented reason.
- Do not replace documented two-phase token flow with a shortcut.
- Do not perform broad speculative refactors across planned-but-unimplemented modules.

## Default Workflow For Agents

1. Read `docs/SPEC.md`, `docs/MODULE_MAP.md`, and `docs/SECURITY_RULES.md`.
2. Inspect the touched Rust module and nearby tests.
3. Make the smallest change that satisfies the task.
4. Preserve module ownership boundaries from `docs/MODULE_MAP.md`.
5. Run `cargo fmt`.
6. Run the most relevant exact test.
7. Run `cargo test` if shared logic changed.
8. Run Clippy for broader or security-sensitive changes.
9. After a module is completed, update `AGENTS.md` and the relevant `docs/` files to reflect the new state.
10. Create proper commits for the completed module and documentation updates.
11. Reply to the user with what was finished and the next sensible instruction point.

Following this file should keep agent work aligned with the latest docs while still respecting the repository's current POC reality.

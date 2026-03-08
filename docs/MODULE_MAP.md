# LokalVault — Module Map
## Which file owns which functions. No exceptions.

If a function isn't listed under a file, it doesn't belong there.
If you're unsure where something goes: check this file first.

## Phase 1 Implementation Order

1. `src/vault_ops.rs`
2. `src/errors.rs`
3. `src/daemon.rs` (real, vault-backed)
4. `src/run_cmd.rs` (real flow)
5. `src/cli.rs`
6. `src/audit_log.rs`
7. `src/settings.rs`
8. `src-tauri/` and React UI

**Phase 1A completion bar:**
- `src/vault_ops.rs`, `src/errors.rs`, real `src/daemon.rs`, and real `src/run_cmd.rs` must all be implemented and tested
- real `src/run_cmd.rs` must use phase1 -> spawn -> phase2 ordering with a non-deterministic terminal approval code
- integration tests must prove the token-aware run flow across modules

---

## src/crypto.rs — Module 1
### THE ONLY FILE WHERE CRYPTOGRAPHY HAPPENS.
### No other file may import aes-gcm, argon2, or call raw crypto primitives.

| Function | Signature | Status |
|---|---|---|
| `generate_salt` | `() → [u8; 32]` | ✅ Done |
| `generate_nonce` | `() → [u8; 12]` | ✅ Done |
| `derive_key` | `(password: &str, salt: &[u8; 32]) → Zeroizing<[u8; 32]>` | ✅ Done |
| `encrypt` | `(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) → Vec<u8>` | ✅ Done |
| `decrypt` | `(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) → Result<Vec<u8>, String>` | ✅ Done |
| `generate_token` | `() → String` — 32 random bytes as hex (64 chars) | ⬜ Phase 1 |
| `constant_time_compare` | `(a: &str, b: &str) → bool` | ⬜ Phase 1 |
| `validate_password_strength` | `(password: &str) → PasswordStrength` | ⬜ Phase 1 |
| `benchmark_argon2` | `() → Argon2Params` | ⬜ Phase 1 |

---

## src/vault_file.rs — Module 2
### Pure file I/O. Zero crypto logic. Calls crypto.rs for encrypt/decrypt.

| Function | Signature | Status |
|---|---|---|
| `get_vault_path` | `() → PathBuf` | ✅ Done |
| `write_vault` | `(vault: &VaultData, password: &str) → Result<(), String>` | ✅ Done |
| `read_vault` | `(password: &str) → Result<VaultData, String>` | ✅ Done |
| `vault_exists` | `() → bool` | ⬜ Phase 1 |
| `write_vault_file_atomic` | refactor of write_vault using tmp→rename | ⬜ Phase 1 |

**Structs owned here:**
- `VaultData { version: u8, projects: Vec<Project> }`
- `Project { name: String, secrets: Vec<Secret> }`
- `Secret { key: String, value: String }`

**Binary format (must not change):**
```
Offset  Size  Field
0       4     Magic: "LKVT"
4       1     Version: 0x01
5       32    Argon2id salt
37      12    AES-GCM nonce
49      N     AES-GCM ciphertext (auth tag appended inside by aes-gcm)
```

---

## src/vault_ops.rs — Module 3
### All CRUD operations on VaultData. Phase 1A starts here.
### Works in memory. Persists by calling vault_file functions.

| Function | Signature | Status |
|---|---|---|
| `create_vault` | `(password: &str) → Result<()>` | ✅ Done |
| `unlock_vault` | `(password: &str) → Result<VaultData>` | ✅ Done |
| `lock_vault` | `(vault: &mut VaultData)` | ✅ Done |
| `add_project` | `(vault: &mut VaultData, name: &str) → Result<()>` | ✅ Done |
| `delete_project` | `(vault: &mut VaultData, name: &str) → Result<()>` | ✅ Done |
| `add_secret` | `(vault: &mut VaultData, project: &str, key: &str, value: &str) → Result<()>` | ✅ Done |
| `update_secret` | `(vault: &mut VaultData, project: &str, key: &str, value: &str) → Result<()>` | ✅ Done |
| `delete_secret` | `(vault: &mut VaultData, project: &str, key: &str) → Result<()>` | ✅ Done |
| `list_projects` | `(vault: &VaultData) → Vec<ProjectSummary>` | ✅ Done |
| `list_secret_keys` | `(vault: &VaultData, project: &str) → Result<Vec<String>>` | ✅ Done |
| `import_dotenv` | `(vault: &mut VaultData, project: &str, path: &Path) → Result<ImportResult>` | ✅ Done |
| `change_master_password` | `(vault: &mut VaultData, current: &str, new: &str) → Result<()>` | ✅ Done |

**Validation rules (enforced here):**
- Project names: alphanumeric + hyphens only, max 64 chars, unique
- Secret keys: SCREAMING_SNAKE_CASE only (A-Z, 0-9, _), unique per project
- Secret values: any string, held in Zeroizing<String> during transit

**Current implementation status:**
- CRUD and validation layer implemented
- Includes unit tests for create/unlock, CRUD operations, listing, dotenv import, and password change
- Persists through `src/vault_file.rs`

---

## src/daemon.rs — Module 4
### Daemon process. Holds vault in RAM. Serves secrets via Unix socket.

**POC completion definition:**
- The POC is complete only when `lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"` prints `test-value-123`
- Passing tests or partially implemented modules do not count on their own
- Current status: achieved

### POC scope (build now):
| Function | Description | Status |
|---|---|---|
| `run_daemon_poc` | Open socket, accept connection, return hardcoded JSON | ✅ Done |
| `create_socket` | Create /tmp/lokalvault-test.sock at 0600 | ✅ Done |

**Current POC behavior implemented:**
- Binds `/tmp/lokalvault-test.sock`
- Sets socket permissions to `0600` immediately after bind
- Accepts one JSON request with type `get_secret`
- Returns hardcoded JSON `{"value":"test-value-123"}`
- Cleans up the socket file after the one-shot POC server exits
- Works end-to-end with `lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"`

### Phase 1 scope (build later):
| Function | Description | Status |
|---|---|---|
| `start_daemon` | Detached process, receives vault via startup pipe | ⬜ Phase 1A |
| `stop_daemon` | Zeroize secrets → close socket → exit | ⬜ Phase 1A |
| `handle_connection` | Route requests, verify credentials | ⬜ Phase 1A |
| `get_peer_credentials` | SO_PEERCRED (Linux) / LOCAL_PEERCRED (macOS) | 🔄 POC advanced |
| `validate_token` | Constant-time compare + PID + UID check | ⬜ Phase 1A |
| `register_token_phase1` | Store pending token with 1000ms window | ⬜ Phase 1A |
| `register_token_phase2` | Bind token to PID after spawn | ⬜ Phase 1A |
| `monitor_child_pid` | Poll sysinfo, invalidate token on exit | ⬜ Phase 1A |
| `invalidate_token` | Remove from token_store | ⬜ Phase 1A |
| `check_rate_limit` | Max 30 req/s per PID | ⬜ Phase 1A |
| `disable_core_dumps` | Best-effort, never crash on failure | ⬜ Phase 1A |
| `lock_memory_pages` | Best-effort mlock, never crash on failure | ⬜ Phase 1A |

**Socket paths:**
- POC:     `/tmp/lokalvault-test.sock`
- Prod:    `/tmp/lokalvault-{UID}.sock` (Linux/macOS)
- Windows: `\\.\pipe\lokalvault-{username_hash}`

**CRITICAL platform note:**
Linux uses `SO_PEERCRED`. macOS uses `LOCAL_PEERCRED`. These are different.
Must use `#[cfg(target_os)]` conditional compilation. Test both platforms.

**Current credential-check progress:**
- Linux: `get_peer_credentials` implemented with `getsockopt(..., SO_PEERCRED, ...)`
- macOS: `getpeereid()` plus `LOCAL_PEERCRED` validation implemented for UID verification
- Current macOS POC returns UID and a placeholder PID value of `0`; deeper PID retrieval remains a later daemon step
- Tests cover Linux and macOS current-UID verification behavior
- POC request handling now rejects client-reported `uid` values when they do not match kernel-provided peer credentials
- `get_secret` requests in the current POC must include `uid`, and the daemon rejects the request if it is missing
- POC rejection paths now return structured JSON errors like `{"error":"..."}` instead of silently closing with no response
- POC flow is now explicitly shaped as: read peer credentials -> parse request -> validate request -> route request -> write response
- `get_secret` currently only supports `OPENAI_KEY`; unknown keys return a structured JSON error
- Linux POC now requires a `pid` field on `get_secret` requests, but currently only accepts the placeholder value `0`; nonzero PID validation remains a later daemon step
- Daemon request handling now uses an explicit internal error model before converting failures into structured JSON error responses
- Real daemon groundwork now includes in-memory vault state, pending/active token records, phase1/phase2 token registration, token validation, invalidation, best-effort hardening helpers, and monitoring scaffolding

---

## src/run_cmd.rs — Module 5
### The `lokalvault run` command. Process spawn + env injection.

| Function | Description | Status |
|---|---|---|
| `cmd_run_poc` | Connect to socket → get secrets → spawn child with env injected | ✅ Done |
| `cmd_run` | Full version with PIN, two-phase tokens, project config | ⬜ Phase 1A |
| `show_pin_dialog` | Terminal: print code, read stdin. UI: emit event. | ⬜ Phase 1A |
| `get_project_from_config` | Read .lokalvault in cwd | ⬜ Phase 1A |
| `inject_secrets_into_env` | cmd.env(key, value) for each secret | ⬜ Phase 1A |
| `fetch_all_secrets` | Request all secrets for project from daemon | ⬜ Phase 1A |

**Current POC behavior implemented:**
- Connects to the daemon POC socket
- Requests the hardcoded `OPENAI_KEY` secret
- Spawns a child process with `OPENAI_KEY=test-value-123` injected
- Returns the child process exit status
- Verified with a Python child-process test
- Verified by the real CLI demo command that prints `test-value-123`
- Real run groundwork now includes terminal PIN approval, `.lokalvault` project config reading, token-aware daemon secret fetch, and env metadata injection helpers
- Real run hardening now includes random token generation, constant-time token checks, and phase1 -> spawn -> phase2 ordering

**Two-phase token registration (critical — do not simplify):**
```
Phase 1: generate token → register with daemon (no PID yet)
         daemon stores as Pending with 1000ms deadline
Phase 2: spawn child (env injected AT spawn time)
         get child PID from OS
         send PID to daemon → token becomes Active
```
You cannot inject env vars after spawn. You don't have the PID before spawn.
The 1000ms window between Phase 1 and Phase 2 is the solution.

**State sync invariant for Phase 1:**
- If the daemon is running, CLI mutations must go through daemon IPC so RAM and disk stay consistent.
- If the daemon is not running, CLI may mutate the vault file in offline mode.

---

## src/cli.rs — Module 6
### CLI subcommands. Phase 1B.

| Command | Description |
|---|---|
| `cmd_init` | Create .lokalvault in cwd |
| `cmd_get` | Print single secret to stdout |
| `cmd_export` | Export project as dotenv/json/eval |
| `cmd_import` | Import .env → vault → retire .env |
| `cmd_push` | Push secrets to Vercel/Render/Railway/Fly/Netlify |
| `cmd_status` | Show vault/daemon/session status |

**Current implementation status:**
- `cmd_create`, `cmd_unlock`, `cmd_lock`, `cmd_init`, `cmd_add`, `cmd_list`, `cmd_get`, `cmd_import`, `cmd_export`, `cmd_status`, and `cmd_push` implemented for the current Phase 1B CLI surface
- Uses clap-based command routing from `src/main.rs`
- Preserves the Phase 1 state-sync invariant by mutating through daemon-backed state when a session is active and using offline vault writes when it is not
- Includes tests for init/config creation, daemon-backed mutation coverage, get/export output behavior, project/key summary helpers, and push target command wiring

---

## src/audit_log.rs — Module 7
### Access logging. NEVER log secret values. Phase 1B.

| Function | Description |
|---|---|
| `log_access_event` | Append event: timestamp, process, project, KEY NAME only |
| `read_audit_log` | Read with optional filter |
| `clear_audit_log` | User-initiated only |

---

## src/settings.rs — Module 8
### Settings persistence. Phase 1B.

| Function | Description |
|---|---|
| `read_settings` | Returns defaults if file missing. Never fails. |
| `write_settings` | Serialize and write. |

---

## src/errors.rs — Shared Error Types
### Define AppError enum here. Phase 1A, after vault_ops.

```rust
pub enum AppError {
    WrongPassword,
    VaultNotFound,
    VaultCorrupted,
    ProjectNotFound(String),
    SecretNotFound(String),
    DaemonNotRunning,
    TokenInvalid,
    TokenExpired,
    PidMismatch,
    RateLimited,
    IoError(String),
    SerdeError(String),
}
```

**Current implementation status:**
- Initial shared `AppError` layer implemented
- Used by `src/vault_ops.rs` for duplicate and validation/domain errors
- Ready to expand as the real daemon and run flow are implemented

**Current next step:**
- Replace the POC daemon with the real vault-backed daemon next

---

## src/main.rs — Entry Point
### CLI dispatch only. No business logic.

```rust
mod crypto;
mod vault_file;
// add mods here as they are created

fn main() {
    // Phase 0: minimal
    // Phase 1: clap CLI dispatch
}
```

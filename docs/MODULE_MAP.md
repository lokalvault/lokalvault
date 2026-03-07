# LokalVault — Module Map
## Which file owns which functions. No exceptions.

If a function isn't listed under a file, it doesn't belong there.
If you're unsure where something goes: check this file first.

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
### All CRUD operations on VaultData. Not started yet.
### Works in memory. Persists by calling vault_file functions.

| Function | Signature | Status |
|---|---|---|
| `create_vault` | `(password: &str) → Result<()>` | ⬜ Phase 1 |
| `unlock_vault` | `(password: &str) → Result<VaultData>` | ⬜ Phase 1 |
| `lock_vault` | `(vault: &mut VaultData)` | ⬜ Phase 1 |
| `add_project` | `(vault: &mut VaultData, name: &str) → Result<()>` | ⬜ Phase 1 |
| `delete_project` | `(vault: &mut VaultData, name: &str) → Result<()>` | ⬜ Phase 1 |
| `add_secret` | `(vault: &mut VaultData, project: &str, key: &str, value: &str) → Result<()>` | ⬜ Phase 1 |
| `update_secret` | `(vault: &mut VaultData, project: &str, key: &str, value: &str) → Result<()>` | ⬜ Phase 1 |
| `delete_secret` | `(vault: &mut VaultData, project: &str, key: &str) → Result<()>` | ⬜ Phase 1 |
| `list_projects` | `(vault: &VaultData) → Vec<ProjectSummary>` | ⬜ Phase 1 |
| `list_secret_keys` | `(vault: &VaultData, project: &str) → Result<Vec<String>>` | ⬜ Phase 1 |
| `import_dotenv` | `(vault: &mut VaultData, project: &str, path: &Path) → Result<ImportResult>` | ⬜ Phase 1 |
| `change_master_password` | `(vault: &mut VaultData, current: &str, new: &str) → Result<()>` | ⬜ Phase 1 |

**Validation rules (enforced here):**
- Project names: alphanumeric + hyphens only, max 64 chars, unique
- Secret keys: SCREAMING_SNAKE_CASE only (A-Z, 0-9, _), unique per project
- Secret values: any string, held in Zeroizing<String> during transit

---

## src/daemon.rs — Module 4
### Daemon process. Holds vault in RAM. Serves secrets via Unix socket.

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

### Phase 1 scope (build later):
| Function | Description | Status |
|---|---|---|
| `start_daemon` | Detached process, receives vault via startup pipe | ⬜ Phase 1 |
| `stop_daemon` | Zeroize secrets → close socket → exit | ⬜ Phase 1 |
| `handle_connection` | Route requests, verify credentials | ⬜ Phase 1 |
| `get_peer_credentials` | SO_PEERCRED (Linux) / LOCAL_PEERCRED (macOS) | ⬜ Phase 1 |
| `validate_token` | Constant-time compare + PID + UID check | ⬜ Phase 1 |
| `register_token_phase1` | Store pending token with 1000ms window | ⬜ Phase 1 |
| `register_token_phase2` | Bind token to PID after spawn | ⬜ Phase 1 |
| `monitor_child_pid` | Poll sysinfo, invalidate token on exit | ⬜ Phase 1 |
| `invalidate_token` | Remove from token_store | ⬜ Phase 1 |
| `check_rate_limit` | Max 30 req/s per PID | ⬜ Phase 1 |
| `disable_core_dumps` | Best-effort, never crash on failure | ⬜ Phase 1 |
| `lock_memory_pages` | Best-effort mlock, never crash on failure | ⬜ Phase 1 |

**Socket paths:**
- POC:     `/tmp/lokalvault-test.sock`
- Prod:    `/tmp/lokalvault-{UID}.sock` (Linux/macOS)
- Windows: `\\.\pipe\lokalvault-{username_hash}`

**CRITICAL platform note:**
Linux uses `SO_PEERCRED`. macOS uses `LOCAL_PEERCRED`. These are different.
Must use `#[cfg(target_os)]` conditional compilation. Test both platforms.

---

## src/run_cmd.rs — Module 5
### The `lokalvault run` command. Process spawn + env injection.

| Function | Description | Status |
|---|---|---|
| `cmd_run_poc` | Connect to socket → get secrets → spawn child with env injected | ✅ Done |
| `cmd_run` | Full version with PIN, two-phase tokens, project config | ⬜ Phase 1 |
| `show_pin_dialog` | Terminal: print code, read stdin. UI: emit event. | ⬜ Phase 1 |
| `get_project_from_config` | Read .lokalvault in cwd | ⬜ Phase 1 |
| `inject_secrets_into_env` | cmd.env(key, value) for each secret | ⬜ Phase 1 |
| `fetch_all_secrets` | Request all secrets for project from daemon | ⬜ Phase 1 |

**Current POC behavior implemented:**
- Connects to the daemon POC socket
- Requests the hardcoded `OPENAI_KEY` secret
- Spawns a child process with `OPENAI_KEY=test-value-123` injected
- Returns the child process exit status
- Verified with a Python child-process test

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

---

## src/cli.rs — Module 6
### CLI subcommands. Not started. Phase 1.

| Command | Description |
|---|---|
| `cmd_init` | Create .lokalvault in cwd |
| `cmd_get` | Print single secret to stdout |
| `cmd_export` | Export project as dotenv/json/eval |
| `cmd_import` | Import .env → vault → retire .env |
| `cmd_push` | Push secrets to Vercel/Render/Railway/Fly/Netlify |
| `cmd_status` | Show vault/daemon/session status |

---

## src/audit_log.rs — Module 7
### Access logging. NEVER log secret values. Phase 1.

| Function | Description |
|---|---|
| `log_access_event` | Append event: timestamp, process, project, KEY NAME only |
| `read_audit_log` | Read with optional filter |
| `clear_audit_log` | User-initiated only |

---

## src/settings.rs — Module 8
### Settings persistence. Phase 1.

| Function | Description |
|---|---|
| `read_settings` | Returns defaults if file missing. Never fails. |
| `write_settings` | Serialize and write. |

---

## src/errors.rs — Shared Error Types
### Define AppError enum here. All modules use this.

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

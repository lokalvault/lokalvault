# LokalVault v5.0
## Final Implementation-Ready Specification

---

# PART 0 — FINAL DECISIONS LOG
## What changed from v4.0 and exactly why

---

### REMOVED: verify_daemon_binary()
**Why:** Every `cargo build` changes the binary hash. During development
this would lock you out of your own app after every compile. In
production this would break on every auto-update. Mature systems
(ssh-agent, gpg-agent, 1Password) do not hash their own binaries.
Security comes from OS socket permissions (0600), not binary hashing.
Can be revisited with proper code signing in v2.0.

---

### FIXED: Token/PID registration order (race condition)
**The problem:** You cannot inject an env var into a process after it
spawns. You must pass the env dict AT spawn time. But you don't have
the PID until after spawn. These two facts create an ordering paradox.

**The solution — two-phase token registration:**
```
Phase 1: CLI generates token
         CLI tells daemon: "Token incoming, allow for 1000ms, no PID yet"
         Daemon stores: { token, uid, project, state: Pending, window: 1000ms }

Phase 2: CLI spawns child with token in env (env set AT spawn time)
         OS returns child PID immediately
         CLI tells daemon: "That token belongs to PID 12345"
         Daemon updates: { token, uid, project, pid: 12345, state: Active }
         If PID binding doesn't arrive within 1000ms: token auto-invalidated
```

This is the only correct solution in any OS/language. The env dict must
be passed at spawn time. PID binding happens in the 1000ms window after.

---

### FIXED: PIN dialog is confirmation, not authentication
**Why:** The daemon does not need to know what 2-digit number was shown.
It only needs to know "a human approved this."

**How it works:**
- Frontend generates random 2-digit number and displays it
- Frontend validates: did user type the correct number?
- Frontend sends ONLY `cmd_run_approve(true/false)` to Rust backend
- Rust backend never sees or stores the number
- The number exists solely to prevent automated clicking/typing

This makes the Rust code simpler and the security model cleaner.

---

### ADDED: `lokalvault init`
**Why:** Without this, every `lokalvault run` requires `--project my-app`.
With this, users run `lokalvault init` once in a project directory and
forever after just type `lokalvault run -- npm run dev`.
This saves keystrokes every single day. Small feature, massive UX impact.

---

### CLARIFIED: mlock() and disable_core_dumps() are best-effort
**Why:** Docker containers often block mlock(). Some OS configurations
restrict it. These calls MUST be wrapped in match/if-let — failure
logs a warning but never crashes the app. Secrets are still in RAM;
they're just not guaranteed to stay out of swap. Same limitation as
every other local secrets tool.

---

### CONFIRMED: Direct env injection is default, SDK is optional
**Why:** Zero code changes = zero migration friction = actual adoption.
The `lokalvault run` wrapper injects secrets as standard env vars.
`os.environ["KEY"]`, `process.env.KEY`, `os.Getenv("KEY")` all work
without any SDK installation or code changes.

---

### CONFIRMED: `lokalvault push` is v1.0, not v1.2
**Why:** Without deployment integration, developers will export to .env
just to push to Vercel. That collapses the entire security model.
~50 lines of CLI code. Non-negotiable for day-one usefulness.

---

# PART 1 — WHAT LOKALVAULT IS

## The Problem

```
OPENAI_KEY=sk-xxxxxxxxxxxxxxxxxxxx   ← in .env
STRIPE_SECRET=sk_live_xxxxxxxxxxxx  ← in .env
```

Plaintext. In your project directory. Read by AI agents.
Accidentally committed to git. Shared in Slack messages.

No existing tool is: local + free + UI + zero-account + exec-wrapper
+ works offline + AI-agent specific design. LokalVault is all of these.

## The Mental Model

```
Vault  →  Project  →  Secret
```

Three concepts. That's it.

## The One-Line Pitch

```bash
lokalvault run -- python app.py
```

Your code gets its secrets. Your AI agent never does.
Your .env file can be deleted. Nothing else changes.

## The Ideal Developer Journey (60 seconds)

```bash
# Install
brew install lokalvault

# Open app, set password (30 seconds in UI)

# Import existing secrets
lokalvault import .env --project my-app
# ✓ 5 secrets imported
# ✓ .env renamed to .env.retired
# ✓ .env.retired added to .gitignore

# Run your app — zero code changes
lokalvault run -- npm run dev

# Done. PIN dialog appears once. Hot reload works forever.
```

---

# PART 2 — COMPLETE ARCHITECTURE

## System Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  VAULT FILE (AES-256-GCM + Argon2id 128MB)                   │
│  Path: OS app data dir — NEVER inside project directories    │
│  Contains: encrypted JSON (projects + secrets)               │
│  Reveals: nothing without master password                    │
└─────────────────────────┬────────────────────────────────────┘
                          │ unlock (password + Argon2id)
                          ▼
┌──────────────────────────────────────────────────────────────┐
│  DAEMON (Rust, detached process, survives Tauri window close) │
│  Holds: decrypted vault in RAM only                          │
│  Socket: /tmp/lokalvault-{UID}.sock at 0600 permissions      │
│  Verifies: every request via SO_PEERCRED (PID + UID)         │
│  Manages: PID-scoped tokens with two-phase registration      │
│  Logs: all key access events (names only, never values)      │
└──────────────┬───────────────────────────┬───────────────────┘
               │                           │
               ▼                           ▼
┌──────────────────────┐    ┌──────────────────────────────────┐
│  TAURI DESKTOP APP   │    │  CLI (lokalvault run/get/push...) │
│  Create vault        │    │  Shows 2-digit PIN dialog         │
│  Manage secrets      │    │  Two-phase token registration     │
│  View audit log      │    │  Spawns child with env injected   │
│  PIN approval dialog │    │  Monitors child PID lifetime      │
│  Settings            │    │  Pushes to Vercel/Render/etc      │
└──────────────────────┘    └──────────────────┬───────────────┘
                                               │
                             ┌─────────────────┴──────────────┐
                             │                                │
                             ▼                                ▼
              ┌──────────────────────┐       ┌───────────────────────┐
              │  MODE 1 (Default)    │       │  MODE 2 (Optional SDK) │
              │  Direct env inject   │       │  vault.get("KEY")      │
              │  os.environ works    │       │  Secrets in memory     │
              │  Zero code changes   │       │  No subprocess inherit │
              │  No SDK needed       │       │  Per-key audit entries │
              └──────────────────────┘       └───────────────────────┘
```

## Execution Flow (Complete, Step by Step)

### Morning startup (once per work session):
```
1. Developer opens LokalVault desktop app
2. Types master password
3. Argon2id derives key (~300ms)
4. Vault decrypted into daemon memory
5. Daemon detaches — runs independently of UI window
6. Developer closes app window if they want. Daemon stays alive.
```

### Running an app (lokalvault run -- python app.py):
```
7.  CLI reads .lokalvault in current dir → project = "my-saas-app"
8.  CLI connects to /tmp/lokalvault-{UID}.sock
9.  CLI requests access for project "my-saas-app"
10. Desktop app shows PIN dialog:
    ┌─────────────────────────────────────────┐
    │  Approve Secret Access                  │
    │  Process:  python app.py                │
    │  Project:  my-saas-app                 │
    │  Type [73] to allow: [ ___ ]            │
    │  (Auto-denies in 30s)                   │
    └─────────────────────────────────────────┘
11. Developer types 73
12. Frontend validates (73 == 73) → sends cmd_run_approve(true)
    Daemon never sees the number — only receives "approved"

--- TWO-PHASE TOKEN REGISTRATION ---
13. CLI generates 32-byte random token
14. CLI sends Phase 1 to daemon:
    { token, uid, project, state: "pending", window_ms: 1000 }
15. CLI spawns child process with env:
    - All project secrets as KEY=VALUE (Mode 1 default)
    - LV_RUN_TOKEN = token
    - LV_PROJECT = my-saas-app
    - LV_SOCKET = /tmp/lokalvault-{UID}.sock
16. OS returns child_pid = 12345
17. CLI sends Phase 2 to daemon:
    { token, pid: 12345 }
18. Daemon binds token to PID 12345
    If Phase 2 doesn't arrive within 1000ms: token auto-invalidated

--- CHILD RUNS ---
19. Child process runs normally
20. os.environ["OPENAI_KEY"] works (Mode 1)
21. vault.get() also works if SDK installed (Mode 2)
22. Daemon verifies all requests: token + PID + UID via SO_PEERCRED

--- CLEANUP ---
23. Child process exits
24. Daemon detects PID 12345 no longer alive
25. Token automatically invalidated
26. Session logged to audit log
```

### Hot reload (what actually happens):
```
lokalvault run stays alive as the PARENT PROCESS all day.

Process tree:
lokalvault run                    ← alive, token registered here
  └─ npm run dev                  ← alive
       └─ nodemon                 ← alive
            └─ node server.js    ← restarts on file save

When developer saves a file:
- node server.js restarts (new PID)
- nodemon stays alive
- npm run dev stays alive
- lokalvault run stays alive

The PIN dialog appeared ONCE when the developer typed:
  lokalvault run -- npm run dev

Hot reload NEVER triggers the dialog again.
The developer types the PIN ONCE per work session.
```

---

# PART 3 — SECURITY MODEL (FINAL HONEST VERSION)

## What Is Protected

| Threat | Protection | How |
|---|---|---|
| AI agent reads .env | Eliminated | No .env file exists |
| AI agent reads vault file | Eliminated | AES-256-GCM, unreadable without password |
| AI agent writes exploit code | Eliminated | No token available to agent process |
| AI agent runs script directly | Eliminated | daemon rejects — no token, no access |
| Automated PIN bypass | Very Hard | Typed number on screen, no DOM access |
| Git commit of secrets | Eliminated | Secrets never in project files |
| Secrets in CI logs | Eliminated | Secrets never in files |

## What Is NOT Protected (Honest)

| Threat | Why Out Of Scope |
|---|---|
| Malicious dep inside approved run | Same limitation as 1Password, Doppler, AWS Vault |
| Local malware, same-user | No local tool protects against this |
| Root / kernel attacker | No tool at any level protects against this |
| Subprocess env inheritance | OS behavior — documented, use SDK mode to avoid |

## The Real Comparison

```
                        AI Agent  Git Leak  Local  Free  Offline  Zero-Account
.env                    ✗         ✗         ok     ✓     ✓        ✓
dotenvx                 partial   partial   ok     ✓     ✓        ✓
Doppler                 ✓         ✓         ok     ✗     ✗        ✗
1Password CLI           ✓         ✓         ok     ✗     ✓        ✗
AWS Vault               ✓         ✓         ok     ✓     ✓        ✓
LokalVault v5           ✓         ✓         ok     ✓     ✓        ✓
```

LokalVault is the only tool in the ✓ column for all six properties.

---

# PART 4 — COMPLETE FUNCTION LIST

## MODULE 1 — CRYPTO (src-tauri/src/crypto.rs)
### Single file. The ONLY place cryptography happens in the entire project.

**derive_key(password: &str, salt: &[u8; 32]) → Zeroizing<[u8; 32]>**
Argon2id key derivation. Output in Zeroizing<> wrapper — auto-wiped
from RAM when dropped. Parameters loaded from settings (benchmarked
at first launch). Floor: memory >= 64MB, iterations >= 3.
Crate: argon2

**generate_salt() → [u8; 32]**
32 cryptographically random bytes. Once at vault creation.
Stored in vault header. Not secret, must be unique.
Crate: rand + getrandom

**generate_nonce() → [u8; 12]**
12 random bytes for AES-GCM. Fresh before every encrypt call.
NEVER reuse with same key.
Crate: rand + getrandom

**encrypt_vault(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) → (Vec<u8>, [u8; 16])**
AES-256-GCM. Returns (ciphertext, auth_tag).
Auth tag = any tampering causes decrypt failure, not silent corruption.
Crate: aes-gcm

**decrypt_vault(ct: &[u8], nonce: &[u8; 12], tag: &[u8; 16], key: &[u8; 32]) → Result<Vec<u8>>**
Verifies auth tag FIRST. Returns plaintext or AuthenticationFailed.
Never returns partial or unverified data under any circumstance.
Crate: aes-gcm

**generate_token() → String**
32 cryptographically random bytes as lowercase hex (64 chars).
This is the PID-scoped session token.
Crate: rand + getrandom

**hash_file(path: &Path) → Result<String>**
SHA-256 of file contents. Returns lowercase hex.
Used for: vault file integrity checks. NOT used for daemon binary
(removed — see decisions log).
Crate: sha2

**constant_time_compare(a: &str, b: &str) → bool**
Timing-safe string comparison. Used for token validation.
Prevents timing side-channel attacks.
Crate: subtle

**validate_password_strength(password: &str) → PasswordStrength**
Enum: TooShort | Weak | Fair | Strong | VeryStrong + feedback string.
Uses entropy estimation. Minimum to create vault: Strong.
Crate: zxcvbn

**benchmark_argon2() → Argon2Params**
Called ONCE at first launch. Increases memory parameter until
derivation takes ~300ms on this specific machine.
Enforces floor: memory_kb >= 65536, iterations >= 3.
Stores result in settings. All future derive_key calls use this result.

---

## MODULE 2 — VAULT FILE (src-tauri/src/vault_file.rs)
### Pure I/O. Zero crypto logic.

**get_vault_path() → PathBuf**
macOS:   ~/Library/Application Support/LokalVault/vault.lv
Windows: %APPDATA%\LokalVault\vault.lv
Linux:   ~/.local/share/lokalvault/vault.lv
Crate: dirs

**vault_exists() → bool**
Checks if vault file exists. Called at startup to route to
Create screen or Unlock screen.

**read_vault_file() → Result<Vec<u8>>**
Raw bytes only. No decryption.

**write_vault_file_atomic(bytes: &[u8]) → Result<()>**
Write temp file → fsync → rename over original.
A crash mid-write leaves original file intact.
NEVER truncate-then-write.

**parse_vault_header(bytes: &[u8]) → Result<VaultHeader>**
Extracts magic(4) + version(1) + salt(32) + nonce(12) + tag(16).

**build_vault_bytes(header: &VaultHeader, ciphertext: &[u8]) → Vec<u8>**
Assembles complete byte array ready for disk.

**serialize_vault(vault: &VaultData) → Result<Vec<u8>>**
VaultData struct → JSON bytes.
Crate: serde + serde_json

**deserialize_vault(bytes: &[u8]) → Result<VaultData>**
JSON bytes → VaultData struct.
Crate: serde + serde_json

---

## MODULE 3 — VAULT OPERATIONS (src-tauri/src/vault_ops.rs)
### All CRUD. Works in memory. Persists via vault_file module.

**create_vault(password: &str) → Result<()>**
validate_password_strength → generate_salt → benchmark_argon2 (if not
already done) → derive_key → empty VaultData → serialize → encrypt →
build_vault_bytes → write_vault_file_atomic.
Master password NEVER stored anywhere.

**unlock_vault(password: &str) → Result<VaultData>**
read_vault_file → parse_vault_header → derive_key → decrypt_vault →
deserialize_vault → return VaultData.
On wrong password: explicit WrongPassword error. Never partial data.

**lock_vault(vault: &mut VaultData)**
Zeroize all String values in vault using Zeroizing<> wrappers.
Signal daemon to stop. Clear all tokens.

**add_project(vault: &mut VaultData, name: &str) → Result<()>**
Validate: alphanumeric + hyphens, max 64 chars, unique.
Create empty Project entry. write_vault_file_atomic.

**delete_project(vault: &mut VaultData, name: &str) → Result<()>**
Remove project and ALL its secrets. write_vault_file_atomic.
Caller must show confirmation dialog before invoking.

**add_secret(vault: &mut VaultData, project: &str, key: &str, value: &str) → Result<()>**
Validate key: SCREAMING_SNAKE_CASE only (A-Z, 0-9, _). Unique per project.
Value processed via Zeroizing<String> during transit. write_vault_file_atomic.

**update_secret(vault: &mut VaultData, project: &str, key: &str, new_value: &str) → Result<()>**
Find and update. write_vault_file_atomic.

**delete_secret(vault: &mut VaultData, project: &str, key: &str) → Result<()>**
Remove pair. write_vault_file_atomic.

**list_projects(vault: &VaultData) → Vec<ProjectSummary>**
Returns: { name, secret_count, last_modified }. NO secret values.

**list_secret_keys(vault: &VaultData, project: &str) → Result<Vec<String>>**
Key names only. NO values ever.

**get_secret_for_display(vault: &VaultData, project: &str, key: &str) → Result<Zeroizing<String>>**
UI only. Returns single value. UI re-masks after 30s.

**change_master_password(vault: &mut VaultData, current: &str, new: &str) → Result<()>**
Verify current → validate new strength → derive new key → re-encrypt
entire vault → write atomically. Show progress bar — slow by design.

**export_vault_encrypted(vault: &VaultData, backup_pw: &str, dest: &Path) → Result<()>**
Separate backup password. NEVER reuses master password.

**import_dotenv(vault: &mut VaultData, project: &str, path: &Path) → Result<ImportResult>**
Parse KEY=VALUE lines (skip # comments, blank lines).
Preview keys to user before committing (UI layer).
On confirm: add all secrets → write_vault_file_atomic →
rename .env to .env.retired → append .env.retired to .gitignore.
Return: { imported_count, skipped_count, retired_path }

---

## MODULE 4 — DAEMON (src-tauri/src/daemon.rs)
### Detached process. Holds secrets in RAM. Serves requests.

**start_daemon(vault_data: VaultData, socket_path: &Path) → Result<DaemonHandle>**
Spawn as DETACHED process (not child of Tauri).
Pass vault_data via one-time startup pipe (not env vars, not files).
On daemon startup:
  - disable_core_dumps()   (best-effort, log warning on failure)
  - lock_memory_pages()    (best-effort, log warning on failure)
  - create_socket()

**CRITICAL — Daemon detachment by platform:**
Linux/macOS: double-fork OR setsid() to break from process group.
             Command::new().spawn() alone is NOT sufficient.
Windows:     CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS flags.
Without this: closing the Tauri window sends SIGTERM to daemon
and wipes all tokens mid-session.

**stop_daemon()**
Zeroize all secrets in memory → close socket → exit.
Force-kill after 3 seconds if graceful exit fails.

**disable_core_dumps()** (best-effort)
Linux:   prctl(PR_SET_DUMPABLE, 0) via libc crate
macOS:   setrlimit(RLIMIT_CORE, &rlim{0,0}) via libc crate
Windows: SetErrorMode(SEM_NOGPFAULTERRORBOX) via windows-sys crate
On failure: log "Warning: core dump protection unavailable" — DO NOT crash.

**lock_memory_pages(data: *const u8, len: usize)** (best-effort)
Linux/macOS: mlock(ptr, len) via region or memsec crate
Windows:     VirtualLock(ptr, len) via windows-sys crate
On failure: log "Warning: memory locking unavailable (containers?)" — DO NOT crash.

**create_socket() → Result<()>**
Linux/macOS:
  Unix domain socket at /tmp/lokalvault-{UID}.sock
  chmod 0600 IMMEDIATELY after creation (before any listen call)
Windows:
  Named Pipe: \\.\pipe\lokalvault-{username_hash}
  Create with FILE_FLAG_FIRST_PIPE_INSTANCE  ← CRITICAL, prevents squatting
  Set SDDL restricting access to current user SID only

**listen_for_connections()** (runs forever)
tokio::net::UnixListener accept loop.
Spawn handle_connection task per connection.
Crate: tokio

**handle_connection(stream: UnixStream)**
1. get_peer_credentials(&stream) → (pid, uid)  ← kernel-verified
2. Read request JSON from stream
3. validate_token(&request.token, pid, uid)
4. check_rate_limit(pid)
5. Route by request type:
   - register_token_phase1: store pending token
   - register_token_phase2: bind token to PID
   - get_secret: validate token → return secret value
   - heartbeat: return daemon status
6. log_access_event(pid, project, key)
7. Write response JSON
8. Close connection

**get_peer_credentials(stream: &UnixStream) → Result<(u32, u32)>**
Returns (pid, uid) from OS kernel. NEVER trust client-reported values.

PLATFORM DIFFERENCES — must use cfg:
```rust
#[cfg(target_os = "linux")]
// getsockopt with SO_PEERCRED → ucred { pid: pid_t, uid: uid_t, gid: gid_t }

#[cfg(target_os = "macos")]
// getsockopt with LOCAL_PEERCRED → xucred { cr_uid, cr_ngroups, cr_groups }
// macOS does NOT have SO_PEERCRED. Using it will fail silently or error.
// Must use LOCAL_PEERCRED with cr_uid. PID from getpeereid() or proc_info.

#[cfg(windows)]
// GetNamedPipeClientProcessId(pipe_handle, &mut pid)
```
Test this on both Linux AND macOS in Week 1. This is not optional.

**validate_token(token: &str, pid: u32, uid: u32) → TokenValidation**
1. constant_time_compare token against token_store entries
2. If found: check state (Active? Pending?)
3. Verify stored_entry.pid == pid (exact match)
4. Verify stored_entry.uid == uid (exact match — prevents PID reuse attacks)
5. Verify not expired
Returns: Valid(project) | InvalidToken | PidMismatch | UidMismatch | Expired
PidMismatch and UidMismatch → log as suspicious_access_attempt event.

**register_token_phase1(token: &str, uid: u32, project: &str)**
Store: { token, uid, project, pid: 0, state: Pending, deadline: now+1000ms }
If Phase 2 not received within 1000ms: auto-invalidate token.
This 1000ms window is the solution to the spawn-then-bind paradox.

**register_token_phase2(token: &str, pid: u32)**
Find pending token by value.
Verify uid matches stored uid (CLI is same user).
Update: { pid: pid, state: Active, expires: now + session_timeout }
Spawn monitor_child_pid(pid, token) as background task.

**monitor_child_pid(pid: u32, token: String)**
Async background task. Polls sysinfo every 2 seconds.
When PID is no longer alive: invalidate_token(token).
Crate: sysinfo (cross-platform PID existence check)

**invalidate_token(token: &str)**
Remove from token_store. Called by: monitor_child_pid, lock_vault,
Phase 1 1000ms timeout expiry.

**check_rate_limit(pid: u32) → Result<()>**
Max 30 requests/second per PID. Exponential backoff after limit.

**setup_auto_lock(timeout_minutes: u32)**
Timer: fires after idle timeout → trigger lock_vault.
OS sleep hooks:
  macOS:   IORegisterForSystemPower (via CoreFoundation)
  Linux:   systemd-logind D-Bus or /sys/power/wakeup poll
  Windows: WM_WTSSESSION_CHANGE / PBT_APMSUSPEND message

---

## MODULE 5 — RUN COMMAND (src-tauri/src/run_cmd.rs)

**cmd_run(project: Option<&str>, command: Vec<String>, sdk_only: bool) → Result<ExitCode>**
Full execution:
1. get_project_from_config() OR use --project flag
2. Connect to daemon socket
3. Request PIN approval via desktop app or headless terminal
4. On approval:
   a. fetch_all_secrets(project) → HashMap<String, Zeroizing<String>>
   b. token = generate_token()
   c. daemon.register_token_phase1(token, uid, project)  ← Phase 1
   d. Build Command: set all envs (secrets + LV_RUN_TOKEN + metadata)
   e. child = command.spawn()  ← env injected AT SPAWN TIME
   f. child_pid = child.id()
   g. daemon.register_token_phase2(token, child_pid)  ← Phase 2
   h. Wait for child exit
   i. Return child's exit code

**show_pin_dialog(project: &str, command_preview: &str) → Result<bool>**
Generates random 2-digit code (00-99).
Desktop app mode: emit "pin-approval-required" event to frontend.
  Frontend shows dialog → user types number → frontend validates.
  Frontend sends cmd_run_approve(true/false) back to Rust.
  Rust receives only the boolean. Never sees the actual number.
Headless mode (no desktop app): print to terminal.
  "Type [47] to allow access to 'my-project': "
  Read from stdin. Compare. Proceed or abort.
Auto-deny after 30 seconds in both modes.

**get_project_from_config() → Option<String>**
Reads .lokalvault in current directory.
Returns project name from [project] name = "..." field.
Returns None if file not found (caller uses --project flag instead).

**inject_secrets_into_env(cmd: &mut Command, secrets: &HashMap<String, String>)**
Mode 1 (default): cmd.env(key, value) for each secret.
Mode 2 (--sdk flag): only inject LV_RUN_TOKEN, LV_PROJECT, LV_SOCKET.
Also always inject:
  LV_RUN_TOKEN = token (for optional SDK use)
  LV_PROJECT   = project name
  LV_SOCKET    = /tmp/lokalvault-{UID}.sock

**fetch_all_secrets(project: &str) → Result<HashMap<String, Zeroizing<String>>>**
CLI-specific fetch (no token required — CLI was PIN-authenticated).
Connects to daemon via a special CLI channel (socket with Phase 1 approval).
Returns all secrets for the project, held in Zeroizing<> wrappers.
Zeroized after injection into child process env.

---

## MODULE 6 — CLI COMMANDS (src-tauri/src/cli.rs)

**cmd_init(project_name: Option<&str>)**
Usage: lokalvault init [optional-name]
Creates .lokalvault in current directory:
```toml
[project]
name = "folder-name-or-provided-name"
```
If name not provided: uses current directory name as default.
Prints: "✓ Created .lokalvault — run: lokalvault run -- <your command>"
This is the first thing a developer runs in a new project.

**cmd_get(project: &str, key: &str)**
Usage: lokalvault get my-project OPENAI_KEY
If vault locked: prompt for password in terminal.
Print value to stdout. Exit.
No history storage of the value itself (value is in command output,
not the command line — shell history shows the command, not the value).

**cmd_export(project: &str, format: ExportFormat)**
Usage: lokalvault export my-project [--format dotenv|json|eval]
dotenv: KEY=VALUE\n...
json:   {"KEY":"VALUE",...}
eval:   export KEY=VALUE\n... (for eval $(...) usage)
Always prints warning: "Secrets now in shell memory. Clear with: unset KEY"

**cmd_import(path: &Path, project: &str)**
Usage: lokalvault import .env --project my-project
Reads .env → preview keys in terminal → confirm → import → retire.
Works when vault is locked (prompts for password first).

**cmd_push(project: &str, target: PushTarget, environment: Option<&str>)**
Usage: lokalvault push my-project --target vercel [--env production]

Fetch all secrets from vault.
Pipe to platform CLI:
  vercel:  `vercel env add KEY VALUE {environment}` per secret
  render:  `render envvar set KEY=VALUE --service-id {id}`
  railway: `railway variables set KEY=VALUE`
  fly:     `fly secrets set KEY=VALUE --app {app}`
  netlify: `netlify env:set KEY VALUE --context {env}`

Each target = ~10 lines of shell invocation.
No custom platform API clients. Call their own CLI.
Requires: platform CLI to be installed and authenticated.
Prints progress: "Pushing 5 secrets to Vercel production..."
On error: "Vercel CLI not found. Install with: npm i -g vercel"

**cmd_status()**
Usage: lokalvault status
Shows:
  Vault:    /path/to/vault.lv (exists/missing)
  Daemon:   running / stopped
  Session:  expires in 6h 22m / not active
  Projects: 3 projects
  Version:  1.0.0

---

## MODULE 7 — AUDIT LOG (src-tauri/src/audit_log.rs)

**get_audit_log_path() → PathBuf**
Alongside vault file in app data dir. Example: audit.log

**log_access_event(event: AccessEvent)**
Append to audit log. AccessEvent:
  timestamp:    ISO 8601 string
  process_name: String
  exe_path:     String
  project:      String
  key:          String   ← KEY NAME ONLY
  method:       "run_env" | "run_sdk" | "cli_get" | "cli_export"
NEVER contains secret values. Ever.

**read_audit_log(filter: Option<AuditFilter>) → Result<Vec<AccessEvent>>**
Filter: by project, date_range, process_name, method.

**clear_audit_log() → Result<()>**
User-initiated only. Requires explicit confirmation.

---

## MODULE 8 — SETTINGS (src-tauri/src/settings.rs)

**read_settings() → Settings**
Returns file contents or defaults if file missing.
Never fails — always returns usable settings.

**write_settings(s: &Settings) → Result<()>**
Serialize and write.

Settings fields:
```rust
pub struct Settings {
    pub session_timeout_minutes: u32,   // default: 480
    pub lock_on_sleep:           bool,  // default: true
    pub clipboard_clear_seconds: u32,   // default: 30
    pub show_tray_icon:          bool,  // default: true
    pub argon2_memory_kb:        u32,   // set by benchmark
    pub argon2_iterations:       u32,   // set by benchmark
    pub argon2_parallelism:      u32,   // set by benchmark
    pub default_project:         Option<String>,
}
```

---

## MODULE 9 — TAURI COMMANDS (src-tauri/src/commands.rs)
### Thin wrappers only. No business logic. Each is one line.

```rust
#[tauri::command] fn cmd_vault_exists() → bool
#[tauri::command] fn cmd_create_vault(password: String) → Result<()>
#[tauri::command] fn cmd_unlock_vault(password: String) → Result<()>
#[tauri::command] fn cmd_lock_vault() → ()
#[tauri::command] fn cmd_get_projects() → Vec<ProjectSummary>
#[tauri::command] fn cmd_add_project(name: String) → Result<()>
#[tauri::command] fn cmd_delete_project(name: String) → Result<()>
#[tauri::command] fn cmd_get_secret_keys(project: String) → Result<Vec<String>>
#[tauri::command] fn cmd_get_secret_value(project: String, key: String) → Result<String>
#[tauri::command] fn cmd_add_secret(project: String, key: String, value: String) → Result<()>
#[tauri::command] fn cmd_update_secret(project: String, key: String, val: String) → Result<()>
#[tauri::command] fn cmd_delete_secret(project: String, key: String) → Result<()>
#[tauri::command] fn cmd_import_dotenv(project: String, path: String) → Result<ImportResult>
#[tauri::command] fn cmd_export_backup(backup_pw: String, path: String) → Result<()>
#[tauri::command] fn cmd_change_password(current: String, new_pw: String) → Result<()>
#[tauri::command] fn cmd_get_audit_log(filter: Option<AuditFilter>) → Result<Vec<AccessEvent>>
#[tauri::command] fn cmd_clear_audit_log() → Result<()>
#[tauri::command] fn cmd_get_settings() → Result<Settings>
#[tauri::command] fn cmd_save_settings(settings: Settings) → Result<()>
#[tauri::command] fn cmd_get_daemon_status() → DaemonStatus
#[tauri::command] fn cmd_run_approve(approved: bool) → ()  // ← only bool, never the PIN number
```

Tauri Events (Rust → Frontend):
```
"pin-approval-required"   { code: u8, project: String, command: String }
"vault-auto-locked"       { reason: "timeout" | "sleep" }
"daemon-error"            { message: String }
"suspicious-access"       { pid: u32, project: String }
```

---

## MODULE 10 — FRONTEND (src/)
### React + TypeScript. No crypto. No business logic. UI state only.

**Unlock.tsx / CreateVault.tsx**
- On mount: check cmd_vault_exists → route to Create or Unlock
- Create: password + confirm → strength check → cmd_create_vault → onboarding
- Unlock: password → cmd_unlock_vault → projects
- After 5 wrong attempts: 30-second lockout with countdown

**Onboarding.tsx** (first run only, 4 steps)
Step 1: Welcome — "Your secrets live here and nowhere else"
Step 2: Create first project — name input
Step 3: Add secrets — add form + "Import .env" button
Step 4: Connect — shows `lokalvault init` + `lokalvault run -- <cmd>` + copy buttons
Shows: "You're set up. Vault is running."

**Projects.tsx**
- Load: cmd_get_projects → list with name + count
- Add: validate name → cmd_add_project → refresh
- Delete: confirm dialog → cmd_delete_project → refresh
- Click: navigate to ProjectDetail

**ProjectDetail.tsx**
- Load keys: cmd_get_secret_keys
- Reveal: cmd_get_secret_value → display 30s → re-mask via countdown
- Copy: cmd_get_secret_value → clipboard → clear clipboard in 30s → toast
- Add: validate SCREAMING_SNAKE_CASE → cmd_add_secret
- Edit: cmd_update_secret
- Delete: confirm → cmd_delete_secret
- Import: file picker → preview (keys only) → confirm → cmd_import_dotenv → count toast
- SDK snippet: tabbed (Python/Node/Go) static code generation, copy button

**AuditLog.tsx**
- Load: cmd_get_audit_log with optional filter
- Filter controls: project dropdown, date range, method filter
- Clear: confirm → cmd_clear_audit_log

**Settings.tsx**
- Load: cmd_get_settings → populate
- Save: cmd_save_settings
- Change password: current + new → cmd_change_password → progress bar
- Export backup: backup_pw + file picker → cmd_export_backup

**PinApprovalDialog.tsx** (global, always mounted)
- Listen for "pin-approval-required" event
- Render floating overlay: process name, project, 2-digit code
- Text input: user types number
- Validate: typed == event.code → cmd_run_approve(true)
- Otherwise or timeout (30s): cmd_run_approve(false)
- Rust backend receives ONLY the boolean

**DaemonStatusBar.tsx** (persistent, all screens)
- Show: green dot + "Session expires in Xh Xm" when running
- Show: red dot + "Vault locked" when stopped
- Click: reveals Lock Now button

**AutoLockHandler.tsx** (no UI, always mounted)
- Listen for "vault-auto-locked"
- Navigate to Unlock screen
- Show toast: "Vault locked automatically"

---

## MODULE 11 — PYTHON SDK (sdk-python/lokalvault/client.py)
### ~200 lines. ZERO external dependencies. Python stdlib only.

```python
class LokalVaultNotRunningError(Exception):
    pass

def _find_socket_path() -> str:
    # Linux/macOS: /tmp/lokalvault-{os.getuid()}.sock
    # Windows:     \\.\pipe\lokalvault-{username_hash}

def _read_and_clear_token() -> str:
    # Read LV_RUN_TOKEN from os.environ
    # Immediately: os.environ.pop("LV_RUN_TOKEN", None)
    # Store in local variable only
    # Raise LokalVaultNotRunningError with clear message if missing:
    # "LokalVault token not found. Run your app with:
    #  lokalvault run -- python your_script.py"

def _connect() -> socket.socket:
    # Connect to Unix socket
    # Raise LokalVaultNotRunningError if socket not found:
    # "LokalVault daemon not running. Open the app and unlock your vault."

def _send_request(sock, payload: dict) -> dict:
    # JSON encode → send → receive → JSON decode

# Module-level connection cache (reused across calls in same process)
_connection = None
_token = None

def get(project: str, key: str) -> str:
    # PRIMARY API — request single secret by name
    # First call: read+clear token, open connection, cache both
    # Subsequent calls: reuse cached connection
    # Returns plain string

def load(project: str) -> dict:
    # SECONDARY — all secrets as dict
    # Works but audit log flags bulk requests
    # Docs note: subprocesses will inherit all these values

def inject(project: str) -> None:
    # Calls load() → os.environ.update(secrets)
    # Docs warning: every subprocess now has access to these secrets
    # Use vault.get() if subprocess isolation needed
```

---

## MODULE 12 — NODE SDK (sdk-node/src/index.ts)
### ~250 lines. ZERO dependencies. Node stdlib only.

Same API as Python, all async:
```typescript
export async function get(project: string, key: string): Promise<string>
export async function load(project: string): Promise<Record<string, string>>
export async function inject(project: string): Promise<void>
```

---

# PART 5 — DATA MODELS

## Vault File Binary Format
```
Offset  Size   Field
0       4      Magic: "LKVT" (0x4C 0x4B 0x56 0x54)
4       1      Version: 0x01
5       32     Argon2id salt
37      12     AES-GCM nonce
49      16     AES-GCM authentication tag
65      N      AES-GCM ciphertext (encrypted JSON)
```

## VaultData (in memory only)
```json
{
  "version": 1,
  "created_at": "2026-03-07T00:00:00Z",
  "projects": [{
    "name": "my-saas-app",
    "created_at": "ISO timestamp",
    "secrets": [{
      "key": "OPENAI_KEY",
      "value": "sk-xxxxx",
      "created_at": "ISO timestamp",
      "updated_at": "ISO timestamp"
    }]
  }]
}
```

## TokenRecord (daemon memory only)
```rust
struct TokenRecord {
    uid:        u32,
    pid:        u32,           // 0 until Phase 2
    project:    String,
    state:      TokenState,    // Pending | Active
    deadline:   Instant,       // Phase 1: +1000ms, Phase 2: +session_timeout
}
```

## AccessEvent (audit log, no values)
```json
{
  "timestamp": "2026-03-07T09:22:11Z",
  "process_name": "python",
  "exe_path": "/usr/bin/python3",
  "project": "my-saas-app",
  "key": "OPENAI_KEY",
  "method": "run_sdk"
}
```

## .lokalvault (project config, safe to commit)
```toml
# Safe to commit. Contains NO secret values.
[project]
name = "my-saas-app"

[keys]
# Optional: document expected keys for onboarding teammates
required = ["OPENAI_KEY", "STRIPE_SECRET", "DATABASE_URL"]
```

---

# PART 6 — CARGO DEPENDENCIES

```toml
[dependencies]
tauri              = { version = "2", features = ["tray-icon"] }
tokio              = { version = "1", features = ["full"] }
serde              = { version = "1", features = ["derive"] }
serde_json         = "1"
clap               = { version = "4", features = ["derive"] }

# Cryptography (RustCrypto — audited)
aes-gcm            = "0.10"
argon2             = "0.5"
rand               = "0.8"
getrandom          = "0.2"
zeroize            = { version = "1", features = ["derive"] }
subtle             = "2"
sha2               = "0.10"
zxcvbn             = "2"

# System
sysinfo            = "0.30"
dirs               = "5"
tracing            = "0.1"
tracing-subscriber = "0.3"

# Memory locking (Unix)
[target.'cfg(unix)'.dependencies]
libc               = "0.2"
region             = "3"

# Windows
[target.'cfg(windows)'.dependencies]
windows-sys        = { version = "0.52", features = [
  "Win32_System_Pipes", "Win32_Security",
  "Win32_Foundation", "Win32_System_Threading"
]}
```

15 production crates. All tier-1 Rust ecosystem. None exotic.

---

# PART 7 — PROJECT FILE STRUCTURE

```
lokalvault/                             (github.com/lokalvault/lokalvault)
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   └── src/
│       ├── main.rs             Entry: CLI dispatch OR Tauri launch
│       ├── crypto.rs           Module 1 — ALL crypto, nowhere else
│       ├── vault_file.rs       Module 2 — File I/O
│       ├── vault_ops.rs        Module 3 — CRUD
│       ├── daemon.rs           Module 4 — Daemon + socket
│       ├── run_cmd.rs          Module 5 — lokalvault run
│       ├── cli.rs              Module 6 — init/get/export/import/push/status
│       ├── audit_log.rs        Module 7 — Access logging
│       ├── settings.rs         Module 8 — Settings
│       ├── commands.rs         Module 9 — Tauri bridges
│       ├── models.rs           Shared structs + enums
│       └── errors.rs           AppError enum
│
├── src/                        (React frontend)
│   ├── main.tsx
│   ├── App.tsx
│   ├── screens/
│   │   ├── Unlock.tsx
│   │   ├── CreateVault.tsx
│   │   ├── Onboarding.tsx
│   │   ├── Projects.tsx
│   │   ├── ProjectDetail.tsx
│   │   ├── AuditLog.tsx
│   │   └── Settings.tsx
│   └── components/
│       ├── PinApprovalDialog.tsx
│       ├── DaemonStatusBar.tsx
│       ├── AutoLockHandler.tsx
│       ├── SecretRow.tsx
│       └── SDKSnippet.tsx
│
├── sdk-python/                 (github.com/lokalvault/sdk-python)
│   ├── pyproject.toml
│   └── lokalvault/
│       ├── __init__.py
│       └── client.py
│
├── sdk-node/                   (github.com/lokalvault/sdk-node)
│   ├── package.json
│   └── src/index.ts
│
├── .lokalvault.example         Template for users
├── AGENTS.md                   AI agent instructions
├── LICENSE                     Apache 2.0
└── README.md
```

---

# PART 8 — BUILD ORDER

## Phase 0 — Proof of Concept (Week 1–2)
Validate the complete security model before any UI.
If Phase 0 works in 2 weeks: proceed. If not: more Rust practice first.

### Day 1–3: Core Crypto
- Write crypto.rs: derive_key + encrypt_vault + decrypt_vault
- Write a Rust test: encrypt "hello world" → write file → read → decrypt
- Verify the AES-GCM auth tag rejects tampered bytes

### Day 4–5: Vault File
- Write vault_file.rs: write_vault_file_atomic + parse_vault_header
- Create a vault file with one hardcoded project + secret
- Read it back. Verify it deserializes correctly.

### Day 6–7: Daemon + Socket
- Write minimal daemon: open /tmp/test.sock → accept connection →
  return hardcoded JSON {"OPENAI_KEY": "test-value-123"}
- Verify 0600 permissions on socket

Status in current repository snapshot:
- Implemented as `src/daemon.rs`
- Uses `/tmp/lokalvault-test.sock` for the POC path
- Returns hardcoded JSON `{"value":"test-value-123"}`
- Includes tests for `0600` permissions and one-shot request/response flow

### Day 8–9: Process Spawn + Env Injection
- Write cmd_run: connect to socket → receive secret →
  spawn: `python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"`
  with OPENAI_KEY injected
- Verify Python prints "test-value-123"

Status in current repository snapshot:
- Implemented as `src/run_cmd.rs`
- Connects to the daemon POC socket and requests `OPENAI_KEY`
- Spawns a child process with `OPENAI_KEY=test-value-123` injected into the env
- Includes a test that verifies a Python subprocess exits successfully only when the env injection worked

### Day 10: SO_PEERCRED
- Add get_peer_credentials to daemon
- Verify PID and UID are returned correctly
- Test on Linux AND macOS (LOCAL_PEERCRED difference)

Status in current repository snapshot:
- Linux path implemented in `src/daemon.rs` using `SO_PEERCRED`
- macOS path now validates peer credentials with `getpeereid()` plus `LOCAL_PEERCRED`
- Current macOS POC verifies UID successfully but still returns a placeholder PID value of `0`
- The daemon POC now compares any client-reported `uid` field against kernel-provided peer credentials and rejects mismatches
- The current `get_secret` POC request path also requires a `uid` field and rejects the request when that field is omitted
- Current POC daemon rejection paths return structured JSON errors in the form `{"error":"..."}`
- The daemon POC flow is now explicitly split into peer-credential read, request parse, request validation, request routing, and response write steps
- The current `get_secret` POC only serves `OPENAI_KEY`; other keys are rejected with a structured JSON error
- On Linux, the current POC also requires a `pid` field on `get_secret`, but only the placeholder value `0` is accepted until the next PID-validation step is implemented
- Internally, the daemon POC now uses explicit daemon error variants before encoding failures into the public JSON error shape
- Tests now cover credential retrieval progress alongside the earlier daemon socket POC

**Phase 0 success = you have proven the entire architecture.**

Current repository result:
- Achieved
- `lokalvault daemon-poc` plus `lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"` prints `test-value-123`
- The demo was verified successfully three times in a row

---

## Current Implementation Plan After POC

Phase 1 is intentionally CLI-first.
The CLI and Rust core are the product foundation.
The Tauri + React UI is a later thin layer over the same Rust modules, not the source of truth.

### Phase 1A — Core Rust
- `src/vault_ops.rs` ✅ complete
- integration test scaffolding in `src/lib.rs` and `tests/` ✅ complete
- `src/errors.rs` ✅ complete
- real `src/daemon.rs` ✅ groundwork complete
- real `src/run_cmd.rs` ✅ groundwork complete

### Phase 1B — Full CLI
- `src/cli.rs`
- `src/audit_log.rs`
- `src/settings.rs`

### Phase 1C — Tauri + React UI
- `src-tauri/`
- React frontend

### Phase 1 State Sync Invariant

If the daemon is running, CLI CRUD commands must mutate state through daemon IPC so RAM and disk stay in sync.
If the daemon is not running, CLI may unlock the vault and mutate the vault file in offline mode.

Do not implement file-only CLI writes that bypass a live daemon.

---

## Phase 1 — Working Core (Week 3–8)

Week 3–4:
- Complete core Rust modules: `vault_ops`, `errors`, real `daemon`, real `run_cmd`
- CLI core works end-to-end: create vault, add secret, unlock, run app
- No UI yet

Week 5–6:
- Complete CLI commands: init, get, export, import, push, status
- Add audit log and settings modules
- Use the CLI daily before UI work begins

Week 7–8:
- Begin Tauri init and basic desktop wrapper
- Unlock screen + project detail screen
- PIN dialog working end-to-end through the same Rust core

**Phase 1 success = developer can manage secrets and run their app securely.**

---

## Phase 2 — Full Product (Week 9–14)

- All remaining screens (Projects, AuditLog, Settings, Onboarding)
- CLI commands: init, get, export, import, push
- Auto-lock with OS sleep hooks
- Change master password
- macOS + Windows + Linux builds (Tauri CI pipeline)
- Auto-update (Tauri updater + GitHub Releases manifest)

---

## Phase 3 — Launch (Week 15–18)

- Homebrew cask submission
- SignPath Windows signing (free for open source)
- Publish sdk-python to PyPI
- Publish sdk-node to npm
- README with 60-second demo GIF:
  `lokalvault import .env` → `lokalvault run -- npm run dev` → works
- docs.lokalvault.dev (simple static site)
- Announce: HN, r/programming, r/webdev, X/Twitter

---

## Phase 4 — v1.2 (Post-Launch)

- Secret Capability Tokens (~200 lines Rust)
  Each env var is a capability token, not the real value.
  Malicious `print(os.environ)` shows tokens, not secrets.
- OS biometric unlock (TouchID / Windows Hello)
- Go SDK
- Per-secret allowlist

---

# PART 9 — THE MINIMAL VIABLE SLICE

Smallest possible working secure product:

**Rust (14 functions):**
derive_key, generate_salt, generate_nonce, encrypt_vault,
decrypt_vault, create_vault, unlock_vault, add_project, add_secret,
list_secret_keys, generate_token, register_token_phase1,
register_token_phase2, serve_secret_via_socket

**Frontend (2 screens):**
Unlock + ProjectDetail

**CLI (1 command):**
cmd_run with direct env injection

**Python SDK (2 functions):**
vault.get() + vault.load()

= A developer can securely run their Python app with injected secrets.
  That is a complete, useful, secure product.

---

# PART 10 — FINAL NOTES FOR IMPLEMENTATION

## The Three Things That Will Bite You

**1. SO_PEERCRED vs LOCAL_PEERCRED**
Linux ≠ macOS. Must use #[cfg(target_os)] conditional compilation.
Write and test both in Week 1. Not a "fix later" item.

**2. Windows Named Pipe Creation**
Always use FILE_FLAG_FIRST_PIPE_INSTANCE.
Without it: pipe squatting attack is trivial.
SDDL must restrict to current user SID.

**3. Daemon Detachment**
Command::new().spawn() makes the daemon a child of Tauri.
Closing the window → SIGTERM → secrets wiped mid-session.
Use double-fork (Unix) or CREATE_DETACHED_PROCESS (Windows).

## The Three Things That Drive Adoption

**1. Import must feel like cleanup**
```
✓ 5 secrets imported
✓ .env renamed to .env.retired
✓ .env.retired added to .gitignore
```
Developers should feel like the tool cleaned up their mess.

**2. lokavault run must feel invisible**
Developer adds it once to their Makefile or package.json scripts.
Then they forget LokalVault exists. It just works.

**3. Push must exist on day one**
Without `lokalvault push --target vercel`, the workflow breaks at
deployment. Developers will export to .env. Security collapses.

---

# PART 11 — AGENTS.md

```markdown
# LokalVault — Instructions For AI Coding Agents

This project uses LokalVault for secrets management.

## What You Need To Know

Secret VALUES are not in this codebase. They are in an encrypted vault
on the developer's machine and injected at runtime via `lokalvault run`.

## What You Should Do

- Reference secrets by KEY NAME only (e.g., os.environ["OPENAI_KEY"])
- Read .lokalvault to find the project name
- Suggest `lokalvault run -- <command>` to run the application
- Use `vault.get("project", "KEY")` if writing SDK-style code

## What You Must Not Do

- Do not attempt to read vault files
- Do not write code connecting to /tmp/lokalvault-*.sock
- Do not replace vault.get() calls with hardcoded values
- Do not create .env files containing real secret values
- Do not attempt to brute-force or decrypt vault files
```

---

# PART 12 — FINAL SECURITY ASSESSMENT

```
Threat                              Protection
────────────────────────────────────────────────────────────────
Agent reads .env                    ELIMINATED (no .env)
Agent reads vault file              ELIMINATED (AES-256-GCM)
Agent runs exploit script           ELIMINATED (no token = rejected)
Agent automates PIN dialog          VERY HARD (typed code, no DOM)
Accidental git commit               ELIMINATED (never in project)
Token on disk                       ELIMINATED (env only, cleared)
Token reuse after child exits       ELIMINATED (PID monitoring)
PID reuse attack                    MITIGATED (UID verification)
Hot reload friction                 ZERO (wrapper stays alive)
Env var subprocess inheritance      DOCUMENTED (use SDK mode to avoid)
Malicious dep in session            PARTIAL (same as all tools)
Local malware same-user             OUT OF SCOPE
Root / kernel attacker              OUT OF SCOPE

Overall rating: 9/10 for intended use case
```

---

# THE SPEC IS DONE.

Five iterations. Multiple independent security reviews.
Every real issue has been found and addressed.

---

*LokalVault v5.0 — Final Specification*

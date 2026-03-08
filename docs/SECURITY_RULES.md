# LokalVault — Security Rules
## Hard rules. Non-negotiable. Read before touching any crypto or IPC code.

---

## RULE 1 — Crypto lives in ONE file only

`src/crypto.rs` is the ONLY file that may:
- Import `aes-gcm`
- Import `argon2`
- Call any raw cryptographic primitive

All other files call functions from `crypto.rs`.
**Never duplicate crypto logic anywhere else, even for convenience.**

---

## RULE 2 — Never store the master password

The master password is used ONCE to derive a key via Argon2id.
After key derivation:
- The password string is dropped immediately
- It is never written to disk
- It is never stored in a struct
- It is never sent over IPC
- It is never logged

If you find yourself storing a password string: stop. You're doing it wrong.

---

## RULE 3 — Secret values use Zeroizing<>

Any variable holding a secret value MUST use `Zeroizing<String>` or
`Zeroizing<Vec<u8>>`. This ensures the memory is overwritten when the
variable goes out of scope.

```rust
// CORRECT
let value = Zeroizing::new(secret_string);

// WRONG — value stays in memory after drop
let value = secret_string;
```

---

## RULE 4 — Never generate a nonce twice with the same key

AES-GCM nonce reuse with the same key = total security break.
`generate_nonce()` must be called fresh before EVERY `encrypt()` call.
Never cache or reuse a nonce.

---

## RULE 5 — Atomic writes only

Never write vault data with truncate-then-write.
A crash mid-write would corrupt the vault and lose all secrets forever.

Always:
1. Write to `vault.tmp`
2. fsync
3. Rename `vault.tmp` → `vault.lv`

The current `write_vault` in `vault_file.rs` already does this. Keep it.

---

## RULE 6 — Never trust client-reported PID or UID

When the daemon receives a connection, it must get PID and UID from
the OS kernel via socket credentials — never from the request payload.

```rust
// CORRECT — kernel-verified
let (pid, uid) = get_peer_credentials(&stream)?;

// WRONG — client can lie about its own PID
let pid = request.pid;
```

Platform APIs:
- Linux:   `SO_PEERCRED` → `ucred { pid, uid, gid }`
- macOS:   `LOCAL_PEERCRED` → `xucred` (NOT SO_PEERCRED — that's Linux only)
- Windows: `GetNamedPipeClientProcessId`

---

## RULE 7 — Daemon must be detached from Tauri

`Command::new().spawn()` creates a child process.
When Tauri closes, it sends SIGTERM to all children.
The daemon would die and wipe all tokens mid-session.

Correct detachment:
- Linux/macOS: `setsid()` or double-fork
- Windows: `CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`

**Never skip this. It's not optional.**

---

## RULE 8 — Unix socket must be 0600

Create the socket, then IMMEDIATELY chmod 0600 before any listen call.

```rust
// Right after bind, before listen:
std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
```

Without this: any user on the machine can connect to the daemon.

---

## RULE 9 — Token comparison must be constant-time

Never use `==` to compare tokens. This leaks timing information.
Use `constant_time_compare()` from `crypto.rs` (backed by `subtle` crate).

```rust
// CORRECT
if constant_time_compare(&incoming_token, &stored_token) { ... }

// WRONG — timing side channel
if incoming_token == stored_token { ... }
```

---

## RULE 10 — mlock and core dump protection are best-effort

These calls may fail in containers or restricted environments.
They MUST be wrapped — failure logs a warning, never crashes.

```rust
// CORRECT
match disable_core_dumps() {
    Ok(_)  => {},
    Err(e) => eprintln!("Warning: core dump protection unavailable: {}", e),
}

// WRONG — crashes in Docker
disable_core_dumps().unwrap();
```

---

## RULE 11 — Audit log never contains secret values

`log_access_event()` records: timestamp, process name, exe path,
project name, and KEY NAME only.

The VALUE is never logged. Not even partially. Not even for debugging.
If you see a secret value being passed to any logging function: stop.

---

## RULE 11A — Repo protection must never print or persist secret values

`scan-diff` and related repo-protection flows may compare staged diff text
against stored secret values, but they must never echo, log, or persist the
matched values themselves.

Allowed output:
- matching key names
- blocked/clean status

Forbidden output:
- the secret value
- any substring of the secret value
- the full diff payload in debug/error output

---

## RULE 12 — PIN dialog sends only a boolean to Rust

The frontend generates a 2-digit code, shows it to the user,
validates the user typed it correctly, and sends ONLY `true` or `false`
to the Rust backend via `cmd_run_approve(bool)`.

The Rust backend never sees, stores, or processes the actual PIN number.
The number exists only to prevent automated approval. It is not authentication.

---

## RULE 13 — Two-phase token registration, always

Env vars must be injected AT process spawn time (OS requirement).
PID is only available AFTER spawn.
These two facts create an ordering paradox.

The ONLY correct solution:
1. Phase 1: register token with daemon (no PID yet, 1000ms window)
2. Spawn child with token in env
3. Phase 2: send PID to daemon (bind token to PID)

Never simplify this to single-phase. The race condition is real.

---

## RULE 14 — Windows named pipe: FILE_FLAG_FIRST_PIPE_INSTANCE

Always create named pipes with `FILE_FLAG_FIRST_PIPE_INSTANCE`.
Without it: a malicious process can create the pipe first and
intercept all SDK connections before the daemon starts.

---

## NEVER DO THIS LIST

```rust
// ✗ Storing password
struct AppState { password: String }

// ✗ Reusing nonce
let nonce = [0u8; 12]; // hardcoded!

// ✗ Crypto outside crypto.rs
use aes_gcm::...; // in vault_ops.rs

// ✗ Trusting client PID
let pid = request.pid; // client can lie

// ✗ Unwrapping mlock
mlock(ptr, len).unwrap(); // crashes in Docker

// ✗ Logging secret values
log::info!("Retrieved secret: {}", value);

// ✗ Token comparison with ==
if token == stored { ... }  // timing attack

// ✗ Non-atomic vault write
fs::write(&path, &bytes)?; // data loss on crash

// ✗ Daemon as child process
Command::new("daemon").spawn()?; // dies with Tauri
```

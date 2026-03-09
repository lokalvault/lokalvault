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

## RULE 2 — Never persist the master password, and keep transfer boundaries explicit

The master password is used ONCE at vault creation and ONCE at unlock.

After unlock:
- The daemon may hold the password in RAM (DaemonState) for write operations
- It is NEVER written to disk
- It is NEVER sent over IPC from CLI → daemon
- It is NEVER logged
- It is dropped when the daemon shuts down or the vault locks

Current implementation note:
- LokalVault currently bootstraps the daemon by sending the password once over the daemon's stdin pipe during unlock/startup.
- This is a local one-time daemon bootstrap boundary, not the runtime Unix-socket IPC channel.
- All ongoing CLI → daemon socket requests must remain password-free.

The daemon is the ONLY process that may hold the password in memory.
No CLI process, no Tauri renderer, no SDK may ever receive it.

---

## RULE 3 — Secret values are zeroized in daemon-owned memory, with an IPC boundary exception

Daemon-owned secret values should use `Zeroizing<String>` or `Zeroizing<Vec<u8>>`
where practical so memory is overwritten when those values go out of scope.

There is one explicit exception: when a secret crosses the daemon → CLI IPC
boundary inside a JSON response, it becomes a plain string by necessity.
That boundary cannot be fully zeroized end-to-end with the current JSON IPC
design.

Required behavior:
- daemon RAM should zeroize secret-bearing owned values where possible
- CLI code must minimize time-in-scope after receiving a secret value
- docs and code must not claim full end-to-end zeroization beyond the IPC boundary

Additional unavoidable boundaries:
- child process environment injection (`run`, `shell`)
- system clipboard flows (`copy`, `add --clipboard`)
- third-party deployment CLIs where command arguments carry values (`push` targets)

```rust
// CORRECT inside daemon-owned memory
let value = Zeroizing::new(secret_string);

// IPC boundary exception — unavoidable plain string at JSON boundary
let response = json!({ "value": plain_secret_string });

// WRONG when avoidable in daemon-owned memory
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

## RULE 8A — The socket is the source of truth for daemon liveness

Do not introduce `daemon.lock` or any parallel lockfile-based lifecycle check.

Correct behavior:
- attempt to connect to the per-user socket
- if connect succeeds, daemon is running
- if the socket exists but connect returns `ECONNREFUSED`, treat it as stale and remove it

The current `src/ipc_client.rs` implementation already follows this rule.

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


## RULE 11B — Clipboard flows must never print secret values

Commands like `copy` and `add --clipboard` may move secret values through the
system clipboard, but they must never print those values to stdout/stderr or
persist them in logs. Clipboard clearing is best-effort and must never crash
the app if the platform clipboard is unavailable.

---

## RULE 11C — Dotenv diff output must stay redacted

`lokalvault diff .env` may compare file values with vault values, but it must
report only status markers like identical/present/different. It must never print
the actual secret values from either side.

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
1. Phase 1: register token with daemon (no PID yet, a configurably short window)
2. Spawn child with token in env
3. Phase 2: send PID to daemon (bind token to PID)

Never simplify this to single-phase. The race condition is real.

---

## RULE 14 — Windows named pipe: FILE_FLAG_FIRST_PIPE_INSTANCE

Always create named pipes with `FILE_FLAG_FIRST_PIPE_INSTANCE`.
Without it: a malicious process can create the pipe first and
intercept all SDK connections before the daemon starts.

---

## RULE 15 — scan-diff must never store the full secret list longer than the comparison

Wrap the secret fetch and comparison in an explicit scope:
  {
      let secrets = fetch_secrets_for_project(...);
      let result = check_diff_against_secrets(&diff, &secrets);
      // secrets dropped here at end of scope
  }

Never assign the secret map to a variable that outlives the comparison.
Never cache it in DaemonState between requests.

---

## RULE 16 — .lve share files must not embed the project password

The share password is ephemeral and separate from the master password.
Never derive the share key from the master password or stored key material.
Fresh Argon2id derivation only, fresh salt per share operation.

---

## RULE 17 — Daemon password is zeroized on lock and shutdown

When stop_daemon() is called (lock, timeout, or shutdown IPC):
  DaemonState.password must be zeroized before the struct is dropped.
  Use Zeroizing<String> for the password field, not plain String.
  This is the in-memory counterpart to Rule 2's disk/IPC prohibition.

---

## NEVER DO THIS LIST

```rust
// ✗ Storing password in CLI or UI process
struct CliState { password: String }

// ✗ Persisting password to disk
serde_json::to_string(&state_with_password)?;

// ✓ Only DaemonState may hold password in RAM, never CLI/Tauri/SDK

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

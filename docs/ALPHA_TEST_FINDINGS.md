# LokalVault Alpha Test Findings

## Scope

This document records real-world manual CLI testing on macOS using the release binary built from the current codebase.

Test binary:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault
```

Isolated test environment:

```bash
TEST_ROOT=/tmp/lokalvault-manual-real.uLrXpP
LOKALVAULT_DATA_DIR=/tmp/lokalvault-manual-real.uLrXpP/data
```

## Summary

- Core prompt-driven flows work in a real terminal: `create`, `unlock`, `init`, `add`, and `get` all completed successfully.
- A real-world blocker was found in daemon lifecycle stability on macOS:
  - `unlock` can report success
  - a `lokalvault daemon` process appears in `ps`
  - the first real daemon-backed command can return `daemon returned empty response`
  - the daemon is then no longer running
- This makes the current build unsuitable for broader human alpha sharing until daemon request handling and run-path wiring are fixed.

## Manual Test Log

### 1. Isolated environment setup

Command:

```bash
TEST_ROOT="$(mktemp -d /tmp/lokalvault-manual-real.XXXXXX)" && export LOKALVAULT_DATA_DIR="$TEST_ROOT/data" && mkdir -p "$LOKALVAULT_DATA_DIR" "$TEST_ROOT/app" "$TEST_ROOT/repo" && echo "TEST_ROOT=$TEST_ROOT" && echo "LOKALVAULT_DATA_DIR=$LOKALVAULT_DATA_DIR"
```

Result:

```text
TEST_ROOT=/tmp/lokalvault-manual-real.uLrXpP
LOKALVAULT_DATA_DIR=/tmp/lokalvault-manual-real.uLrXpP/data
```

Assessment: PASS

### 2. Release binary help

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault --help | sed -n '1,20p'
```

Result:

```text
Usage: lokalvault <COMMAND>

Commands:
  daemon-poc
  daemon
  create
  unlock
  lock
  init
  add
  update
  delete
  delete-project
  list
  get
  import
  export
  diff
  copy
  shell
```

Assessment: PASS

### 3. Clean-machine baseline

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault doctor
```

Result:

```text
✗ Vault file missing at /tmp/lokalvault-manual-real.uLrXpP/data/vault.lv
✗ Daemon not running
✗ .gitignore missing .env entry
✗ .lokalvault config missing in current directory
```

Assessment: PASS

### 4. Vault creation

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault create
```

Observed first attempt:

```text
Master password:
password rejected: password is too weak
```

Observed second attempt:

```text
Master password:
Vault created at /tmp/lokalvault-manual-real.uLrXpP/data/vault.lv
```

Assessment: PASS with UX issue

UX issue found:

- weak password rejection works
- the CLI does not explain why the password is weak
- the CLI exits instead of keeping the user in an inline retry loop
- recommended improvement: show the strength reason and reprompt immediately

### 5. Unlock and daemon startup

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault unlock
```

Observed first attempt:

```text
Master password:
decryption failed — wrong password or tampered data
```

Observed second attempt:

```text
Master password:
✓ Vault unlocked. Session active.
```

Follow-up doctor:

```text
✓ Vault file exists at /tmp/lokalvault-manual-real.uLrXpP/data/vault.lv
✓ Daemon running
✗ .gitignore missing .env entry
✗ .lokalvault config missing in current directory
```

Assessment: PASS

### 6. Project initialization

Command:

```bash
cd /tmp/lokalvault-manual-real.uLrXpP/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault init my-app --template openai && echo '--- .lokalvault ---' && cat .lokalvault
```

Result:

```text
Created .lokalvault
--- .lokalvault ---
[project]
name = "my-app"

[keys]
required = [
    "OPENAI_API_KEY",
    "OPENAI_ORG_ID",
]
optional = []
```

Assessment: PASS

### 7. Add secret

Command:

```bash
cd /tmp/lokalvault-manual-real.uLrXpP/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault add --project my-app OPENAI_API_KEY
```

Result:

```text
Secret value:
Master password:
✓ Added OPENAI_API_KEY to my-app
```

Assessment: PASS

### 8. Get secret

Command:

```bash
cd /tmp/lokalvault-manual-real.uLrXpP/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault get my-app OPENAI_API_KEY
```

Result:

```text
Master password:
test-123%
```

Assessment: PASS

### 9. Run flow failure

Command:

```bash
cd /tmp/lokalvault-manual-real.uLrXpP/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault run --project my-app -- python3 -c "import os; print(os.environ.get('OPENAI_API_KEY'))"
```

Result:

```text
vault is locked - run lokalvault unlock first
```

Assessment: FAIL

### 10. Session state after failed run

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault status && echo '---' && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault doctor
```

Result:

```text
LokalVault Status
------------------------------
Vault:    locked
Daemon:   stopped
Version:  0.1.0
---
✓ Vault file exists at /tmp/lokalvault-manual-real.uLrXpP/data/vault.lv
✗ Daemon not running
✗ .gitignore missing .env entry
✓ .lokalvault config present in current directory
```

Assessment: FAIL

### 11. Re-unlock and immediate persistence failure

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault unlock && echo '--- immediate status ---' && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault status
```

Result:

```text
Master password:
✓ Vault unlocked. Session active.
--- immediate status ---
daemon returned empty response
```

Follow-up doctor:

```text
✓ Vault file exists at /tmp/lokalvault-manual-real.uLrXpP/data/vault.lv
✗ Daemon not running
✗ .gitignore missing .env entry
✓ .lokalvault config present in current directory
```

Follow-up status:

```text
LokalVault Status
------------------------------
Vault:    locked
Daemon:   stopped
Version:  0.1.0
```

Assessment: FAIL / blocker

### 12. Process check after unlock

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault unlock; echo '--- processes ---'; ps aux | grep lokalvault | grep -v grep
```

Result excerpt:

```text
✓ Vault unlocked. Session active.
--- processes ---
mohneeru ... /Users/mohneeru/Developer/lokalvault/target/release/lokalvault daemon
```

Assessment: daemon process exists briefly after unlock, but does not survive first real IPC request reliably.

## Root Cause Notes From Code Review

### 1. Daemon request errors currently terminate the whole daemon

The main daemon accept loop exits if `handle_connection(...)` returns `Err`:

- `src/daemon.rs:190-205`

And `handle_connection()` has several fallible steps before writing a response:

- peer credential fetch: `src/daemon.rs:828`
- request read: `src/daemon.rs:857`
- request handling: `src/daemon.rs:858`

Client-side `daemon returned empty response` comes from receiving EOF/empty line instead of a JSON response:

- `src/ipc_client.rs:35-51`

This matches the manual repro:

- unlock reports success
- daemon process exists briefly
- first real command can receive empty response
- daemon then disappears

### 2. Unlock success currently only waits for socket existence

Unlock reports success once the socket path exists:

- `src/cli.rs:1361-1366`

This is weaker than a real health check and allows `unlock` to report success before the daemon has proven it can serve a real IPC request.

### 3. Real-daemon run path is still partly miswired

The real-daemon run path still injects the POC socket constant instead of the real per-user daemon socket:

- `src/run_cmd.rs:254-255`
- `src/run_cmd.rs:385-386`
- `src/run_cmd.rs:294-307`
- `src/daemon.rs:30`

The real-daemon phase-2 token binding also uses the IPC peer PID instead of the spawned child PID:

- caller omits child PID: `src/run_cmd.rs:257-260`, `src/run_cmd.rs:388-391`
- daemon binds to `peer_pid`: `src/daemon.rs:1033-1039`

On macOS, peer PID currently resolves to `0` in the implemented path:

- `src/daemon.rs:773-805`
- specifically `src/daemon.rs:804`

This makes the current real-daemon run/token flow especially fragile on macOS.

## Alpha Readiness Decision

### Current status

Not ready for broader human alpha sharing yet.

### Why

The central workflow depends on:

- unlock
- daemon stays alive
- run / shell / session-based commands continue working

That session persistence guarantee failed in ordinary manual use on macOS.

## Recommended Next Steps

1. Fix daemon request error handling so one bad request cannot kill the daemon.
2. Strengthen unlock startup verification with a real post-start health check, not just socket existence.
3. Fix real-daemon run wiring:
   - stop injecting `POC_SOCKET_PATH`
   - bind tokens to the spawned child PID, not the launcher peer PID
4. Re-run this exact manual test flow on macOS after the fix.

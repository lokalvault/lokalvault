# LokalVault Alpha Test Findings

## Scope

This document records real-world manual CLI testing on macOS using the release binary built from the current codebase.

Test binary:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault
```

## Executive Summary

The latest manual macOS retest shows that LokalVault is now working for the core CLI developer workflow.

Confirmed working in a real terminal session:

- `create`
- `unlock`
- `status`
- `doctor`
- `init`
- `add`
- `get`
- daemon-backed `run`
- required-key enforcement in `run`
- child environment injection in `run`
- child exit-code passthrough in `run`
- `copy`

Known remaining issue:

- `shell` exits immediately because it launches the user shell without interactive flags.

Current release-readiness conclusion:

- Ready for limited internal alpha / trusted human CLI testing
- Not yet ready for broad public release without further polish

## Historical Context

Earlier manual testing on macOS exposed a daemon/session lifecycle bug where:

- `unlock` reported success
- the daemon process appeared briefly
- the first real daemon-backed command could return `daemon returned empty response`
- the daemon then stopped responding or disappeared

Subsequent fixes addressed that instability:

1. per-connection request errors no longer kill the full daemon session
2. unlock startup detects early daemon exit more honestly
3. daemon accept-loop handling was hardened
4. daemon liveness probes were made non-destructive so routine status checks do not mutate socket state

This document preserves the current validated state, not the earlier blocked state.

## Latest Manual Test Environment

Fresh retest root used for the successful validation pass:

```bash
TEST_ROOT=/tmp/lokalvault-retest3.keN8fz
LOKALVAULT_DATA_DIR=/tmp/lokalvault-retest3.keN8fz/data
APP_DIR=/tmp/lokalvault-retest3.keN8fz/app
```

## Latest Manual Test Log

### 1. Clear any old session

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault lock || true
```

Result:

```text
Vault already locked.
```

Assessment: PASS

### 2. Create fresh isolated retest root

Command:

```bash
TEST_ROOT="$(mktemp -d /tmp/lokalvault-retest3.XXXXXX)" && export LOKALVAULT_DATA_DIR="$TEST_ROOT/data" && mkdir -p "$LOKALVAULT_DATA_DIR" "$TEST_ROOT/app" && echo "TEST_ROOT=$TEST_ROOT" && echo "LOKALVAULT_DATA_DIR=$LOKALVAULT_DATA_DIR"
```

Result:

```text
TEST_ROOT=/tmp/lokalvault-retest3.keN8fz
LOKALVAULT_DATA_DIR=/tmp/lokalvault-retest3.keN8fz/data
```

Assessment: PASS

### 3. Create fresh vault

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault create
```

Result:

```text
Master password:
Vault created at /tmp/lokalvault-retest3.keN8fz/data/vault.lv
```

Assessment: PASS

### 4. Unlock and immediately verify daemon health

Command:

```bash
/Users/mohneeru/Developer/lokalvault/target/release/lokalvault unlock && echo '--- status ---' && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault status && echo '--- doctor ---' && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault doctor
```

Result:

```text
Master password:
✓ Vault unlocked. Session active.
--- status ---
LokalVault Status
------------------------------
Vault:    unlocked
Projects: 0
Session expires in (estimated): 8h 0m
Version:  0.1.0
--- doctor ---
✓ Vault file exists at /tmp/lokalvault-retest3.keN8fz/data/vault.lv
✓ Daemon running
✗ .gitignore missing .env entry
✗ .lokalvault config missing in current directory
```

Assessment: PASS

### 5. Initialize project config

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault init my-app --template openai && echo '--- .lokalvault ---' && cat .lokalvault
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

### 6. Add required secrets

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault add --project my-app OPENAI_API_KEY
```

Result:

```text
Secret value:
✓ Added OPENAI_API_KEY to my-app
```

Assessment: PASS

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault add --project my-app OPENAI_ORG_ID
```

Result:

```text
Secret value:
✓ Added OPENAI_ORG_ID to my-app
```

Assessment: PASS

### 7. Retrieve secret

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault get my-app OPENAI_API_KEY
```

Result:

```text
test-123%
```

Assessment: PASS

### 8. Run required-key enforcement check

Before `OPENAI_ORG_ID` was added, the `run` path correctly blocked execution.

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault run --project my-app -- python3 -c "import os; print(os.environ.get('OPENAI_API_KEY'))"
```

Observed result before all required secrets were present:

```text
Missing required secrets for project my-app: OPENAI_ORG_ID
```

Assessment: PASS

### 9. Run environment injection check

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault run --project my-app -- python3 -c "import os; print(os.environ.get('OPENAI_API_KEY'))"
```

Result after all required secrets were present:

```text
test-123
```

Assessment: PASS

### 10. Run exit-code passthrough check

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault run --project my-app -- python3 -c "import sys; sys.exit(7)"; echo "EXIT_CODE=$?"
```

Result:

```text
EXIT_CODE=7
```

Assessment: PASS

### 11. Copy to clipboard

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault copy my-app OPENAI_API_KEY
```

Observed result:

- clipboard contained `test-123`
- paste verification succeeded

Assessment: PASS

### 12. Shell behavior

Command:

```bash
cd /tmp/lokalvault-retest3.keN8fz/app && /Users/mohneeru/Developer/lokalvault/target/release/lokalvault shell --project my-app
```

Observed result:

- shell returned immediately to the prompt
- daemon remained healthy afterward
- `status` still showed unlocked and `doctor` still showed daemon running

Assessment: FAIL (known bug)

## Current Known Issue

### `lokalvault shell` exits immediately

Root cause from current code:

- `cmd_shell()` launches the shell binary directly with `Command::new(&shell).status()` in `src/cli.rs`
- `shell_program()` only returns `$SHELL` or `/bin/sh` in `src/run_cmd.rs`
- no interactive flags are passed (`-i`, `-l`, etc.)

This means `lokalvault shell` is currently launching the shell without explicitly requesting an interactive session.

## Current Alpha Readiness Decision

### Status

Ready for limited internal alpha / trusted human CLI testing.

### Why

The core local developer workflow now works in real terminal use on macOS:

- create vault
- unlock session
- inspect status/doctor
- initialize project
- add and retrieve secrets
- run commands with injected secrets
- preserve child exit codes
- copy secrets to clipboard

### Remaining caveats

- `shell` needs an interactive-shell fix before broader sharing
- another-machine validation is still recommended before wider rollout
- broader beta packaging/distribution work is still separate

## Recommended Next Steps

1. Fix `lokalvault shell` to invoke the selected shell in interactive mode.
2. Validate the current release binary on at least one additional Mac.
3. Package the verified binary for trusted alpha testers.

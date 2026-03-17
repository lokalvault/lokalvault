# LokalVault CLI

## Quick Start

```bash
lokalvault create
lokalvault unlock
lokalvault init --template openai
lokalvault run -- python3 app.py
```

## Project Resolution Order

When a command needs a project, LokalVault resolves it in this order:

1. `--project <name>`
2. `.lokalvault` in the current directory
3. `settings.default_project`
4. error

## Daily Workflows

### Run a command with secrets

```bash
lokalvault run -- python3 app.py
```

`Ctrl+C` is forwarded to the child process so the app can shut down cleanly.

### Run with watch mode

```bash
lokalvault run --watch -- python3 app.py
```

LokalVault restarts the child when files in the current directory change.

### Open a shell with secrets loaded

```bash
lokalvault shell
```

### Compare `.env` before import

```bash
lokalvault diff .env --project my-app
```

### Copy a secret without printing it

```bash
lokalvault copy my-app DATABASE_URL
```

### Add from clipboard instead of shell history

```bash
lokalvault add --project my-app STRIPE_SECRET --clipboard
```

### Initialize a project manifest with a template

```bash
lokalvault init --template stripe
```

## Command Guide

### Vault lifecycle

- `lokalvault create` — create a new encrypted vault
- `lokalvault unlock` — unlock the vault and start the daemon session
- `lokalvault lock` — stop the daemon session and clear in-memory state
- `lokalvault status` — show vault state, session estimate, recent access, and warnings
- `lokalvault doctor` — check vault, daemon, `.gitignore`, and `.lokalvault` basics

### Project setup and secret management

- `lokalvault init [name] [--template openai|supabase|stripe]` — create `.lokalvault`
- `lokalvault add [--project <name>] KEY [value] [--clipboard]` — add a secret
- `lokalvault update [--project <name>] KEY [value]` — update a secret
- `lokalvault delete [--project <name>] KEY` — delete a secret
- `lokalvault delete-project <name>` — delete an entire project
- `lokalvault list [project]` — list projects or keys
- `lokalvault get [project] KEY` — print a secret value
- `lokalvault copy [project] KEY` — copy a secret to clipboard without printing it
- `lokalvault import <path> --project <name>` — import dotenv-style secrets
- `lokalvault export [project] --format dotenv|json|eval` — export a project in a safe format; only `eval` is meant to be sourced into a shell
- `lokalvault diff <path> [--project <name>]` — compare a dotenv file against the vault without printing values

### Run flows

- `lokalvault run [--project <name>] -- <command ...>` — run a command with secrets injected
- `lokalvault run --watch -- <command ...>` — rerun when files change
- `lokalvault shell [--project <name>]` — open a subshell with project secrets loaded
- `lokalvault dev` — detect a local dev command and run it through LokalVault

### Audit and configuration

- `lokalvault audit [--project ...] [--since 7d] [--method ...] [--process-name ...]` — read audit history
- `lokalvault audit-clear` — clear audit history after confirmation
- `lokalvault config get <key>` — read a setting
- `lokalvault config set <key> <value>` — write a setting
- `lokalvault config list` — list settings
- `lokalvault completion <bash|zsh|fish>` — print shell completions

### AI-safe and sharing workflows

- `lokalvault ai-safe [--project <name>] [--generate-example]` — write `.lokalvault`, AI guidance, and gitignore protections
- `lokalvault share <project> [--output file.lve]` — create an encrypted share bundle; includes `.lokalvault` key metadata when the current directory matches the shared project
- `lokalvault claim <file.lve> [--project <name>]` — import a shared secret bundle; writes or merges `.lokalvault` only when the shared project matches the local target safely

### Repo protection

- `lokalvault protect-repo [--project <name>]` — install a safe pre-commit hook
- `lokalvault scan-diff [--project <name>]` — read a staged diff from stdin and block on secret values
- `lokalvault push <project> --target <vercel|render|railway|fly|netlify> [--env <env>]` — push all project secrets to a deployment target

### Planned

- `lokalvault extend` — planned; not implemented in this backend pass

## Safety Notes

- Prefer prompted values or `--clipboard` over inline secret arguments.
- `lokalvault get` prints the secret value; prefer `lokalvault copy` when you only need to paste it elsewhere.
- `lokalvault copy` never prints secret values.
- `lokalvault diff .env` never prints secret values.
- `lokalvault share` encrypts the bundle with a separate share password and may include project key metadata from `.lokalvault`.
- `lokalvault claim` skips writing `.lokalvault` if the current directory already points at a different project or if `--project` overrides the shared project.
- Clipboard clearing is best-effort.
- Secret values are zeroized in daemon-owned memory where practical, but JSON IPC responses become plain strings at the daemon → CLI boundary.
- `status` shows a session expiry estimate derived from daemon uptime and configured timeout.
- stale-secret counts come from audit history and may be incomplete if logs were cleared.

## Security Model In Practice

- The daemon is the only long-lived process that should hold the master password.
- Unlock currently bootstraps the daemon by sending the password once over the daemon startup stdin pipe.
- Runtime socket IPC requests do not carry the master password.
- Sensitive daemon-backed CLI actions now use a daemon-tracked approval session, a single-use approval proof, and a scoped single-use `action_token`.
- Secret values become plain strings at unavoidable boundaries such as JSON IPC responses, child process environments, and the system clipboard.
- `lokalvault push` may pass secret values through third-party CLI argument handling depending on the target platform CLI.
- Daemon memory locking (`mlockall`) is best-effort; restricted environments may emit `Warning: memory locking unavailable ...` during daemon startup, but the daemon continues running.

## What Is Estimated vs Authoritative

Authoritative: vault state, project/key names, audit log entries

Estimated: session expiry (daemon uptime + configured timeout),
stale secret count (audit history only — may be incomplete)

## Common Failures And Fixes

- `daemon not running`
  - Run `lokalvault unlock`
- `stale socket`
  - Run `lokalvault lock` and then `lokalvault unlock`
- `vault locked`
  - Unlock first, or rerun the command and provide the master password when prompted
- `missing required secrets`
  - Check `.lokalvault` required keys and add the missing values
- `clipboard unavailable`
  - Use interactive prompt mode instead of `copy` or `--clipboard`
- `push target CLI missing`
  - Install the target platform CLI (`vercel`, `fly`, `railway`, etc.) and retry
- `push may expose values through target CLI behavior`
  - LokalVault warns before pushing. Prefer reviewing the target CLI's own handling if this matters for your environment.

## Known Platform And Workflow Caveats

- `run --watch` is a first-version recursive watcher on the current directory with no ignore rules or debounce yet.
- Audit `process_name` and `exe_path` fields are informational only, not kernel-verified process identity.
- macOS currently verifies peer UID but does not expose a reliable peer PID through the current socket credential path.
- Sensitive IPC approval now mints tokens from daemon-validated approval proofs, but the terminal approval fallback is still not a daemon-owned human-verification boundary.
- `push` depends on third-party CLIs and their current argument conventions.
- `dev` is a best-effort detector for common local run commands, not a guaranteed project-aware launcher.

## Repo Protection

```bash
lokalvault protect-repo
```

```bash
git diff --cached | lokalvault scan-diff
```

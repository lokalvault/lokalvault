# LokalVault

> **Your .env file, but one that doesn't haunt you.**

A local-first, encrypted secrets manager for developers.
No cloud. No account. No AI agent can read your keys.

```bash
lokalvault run -- python app.py
```

Your code gets its secrets. Your AI agent never does.

---

## Status

🚧 **This repository is under active development.**
The POC is complete. Do not use this to store real secrets yet.

Current phase: **Phase 1 (CLI-first)**
- [x] Core crypto (AES-256-GCM + Argon2id)
- [x] Vault file read/write
- [x] Daemon + Unix socket
- [x] Process spawn + env injection
- [x] Peer credential verification for the POC demo path

POC completion demo:

```bash
lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"
```

Expected output:

```text
test-value-123
```

---

## What Is This?

LokalVault is a desktop app + CLI that replaces `.env` files with an
encrypted local vault. Secrets are injected directly into your app's
process at runtime — never written to disk in plaintext, never visible
to AI coding agents (Cursor, Claude Code, Copilot, etc.).

```
Vault (encrypted) → Daemon (RAM only) → lokalvault run → your app
```

### The problem with .env

```bash
OPENAI_KEY=sk-xxxx    # plaintext
STRIPE_SECRET=sk_live_xxxx   # in your project directory
DATABASE_URL=postgres://...  # readable by every AI agent you use
```

### The LokalVault way

```bash
# Import once
lokalvault import .env --project my-app

# Run forever (zero code changes)
lokalvault run -- python app.py
lokalvault run -- node server.js
lokalvault run -- go run main.go
```

---

## Architecture (POC Scope)

```
vault.lv (AES-256-GCM)
    ↓  [Argon2id + master password]
daemon (RAM only, Unix socket)
    ↓  [SO_PEERCRED PID+UID verification]
lokalvault run
    ↓  [env injection at process spawn]
your app (os.environ["KEY"] just works)
```

Current repo docs: `docs/SPEC.md`, `docs/MODULE_MAP.md`, `docs/SECURITY_RULES.md`

---

## POC: What We're Testing

This POC validates five things before building the full product:

1. **Crypto round-trip** — encrypt vault → write file → read → decrypt → same data
2. **Vault file format** — binary header + AES-GCM ciphertext survives disk
3. **Daemon socket** — Rust daemon serves secrets over Unix socket at 0600
4. **Process spawn + env injection** — child process receives secrets as env vars
5. **Peer credentials** — daemon verifies kernel-provided peer credentials and applies current POC request checks

POC result achieved today:

- `lokalvault daemon-poc` starts the one-shot daemon on `/tmp/lokalvault-test.sock`
- `lokalvault run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"` prints `test-value-123`
- The demo was run successfully three times in a row

---

## Stack

- **Desktop app:** [Tauri](https://tauri.app) (Rust backend + React frontend)
- **Crypto:** [RustCrypto](https://github.com/RustCrypto) — `aes-gcm`, `argon2`, `rand`, `zeroize`
- **IPC:** Unix domain sockets (macOS/Linux) + Named Pipes (Windows)
- **SDKs:** Python, Node.js — zero external dependencies each

---

## Running the POC

> Requires: Rust 1.75+, Python 3.8+

```bash
git clone https://github.com/lokalvault/lokalvault-poc
cd lokalvault-poc
cargo build

# Run POC test suite
cargo test

# Run full POC test suite
cargo test

# Run the completed POC demo
cargo run -- daemon-poc &
cargo run -- run -- python3 -c "import os; print(os.environ.get('OPENAI_KEY'))"
```

---

## Security Model

LokalVault is designed specifically against the AI agent threat:

- Secrets never stored in project directories
- Vault file encrypted with AES-256-GCM (Argon2id key derivation)
- Secrets held in daemon RAM only — never written to disk
- Sensitive daemon-backed requests require a scoped single-use token
- Token minting now depends on a daemon-tracked approval session plus daemon-validated approval proof; full daemon-owned human verification is still in progress
- Unapproved requests are rejected, but the terminal approval fallback remains transitional until the daemon-owned UI approval path exists

Current security rules: `docs/SECURITY_RULES.md`

**Honest scope:** LokalVault protects against accidental leaks, git
commits, and AI agent access. It does not protect against local malware
with elevated privileges or root-level attackers (same limitation as
1Password, AWS Vault, and every other local secrets tool).

---

## Roadmap

- **POC** (complete) — core crypto + daemon + process injection proven end-to-end
- **Phase 1A** (current) — vault ops, shared errors, real daemon, real run flow
- **Phase 1B** — full CLI, audit log, settings
- **Phase 1C** — Tauri + React UI on top of the CLI/core
- **v0.1** — working CLI, vault CRUD, Python + Node SDKs
- **v0.2** — Tauri desktop app, PIN approval dialog, audit log
- **v1.0** — macOS + Windows + Linux builds, .env import, push to Vercel/Render

---

## License

Apache 2.0 — see [LICENSE](./LICENSE)

---

## Contributing

Not accepting contributions during the post-POC transition.
Watch this repo for the v0.1 announcement.

---

*Built because AI coding agents shouldn't read your API keys.*

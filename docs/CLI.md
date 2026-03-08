# LokalVault CLI

## Quick Start

```bash
lokalvault create
lokalvault unlock
lokalvault init --template openai
lokalvault run -- python3 app.py
```

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

## Safety Notes

- Prefer prompted values or `--clipboard` over inline secret arguments.
- `lokalvault copy` never prints secret values.
- `lokalvault diff .env` never prints secret values.
- Clipboard clearing is best-effort.

## Repo Protection

```bash
lokalvault protect-repo
```

```bash
git diff --cached | lokalvault scan-diff
```

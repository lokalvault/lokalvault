# LokalVault UI Contract

## Authoritative Values
Vault locked/unlocked state
Project names and key names
Audit log timestamps and key names

## Estimated Values (label as such in UI)
Session expiry — derived from daemon start time + configured timeout,
  not from per-session tracking
Stale secret count — derived from audit log, may be incomplete
  if audit log was cleared

## Informational Only (never present as verified in UI)
process_name in audit entries — not kernel-verified
exe_path in audit entries — not kernel-verified
PID in token validation on macOS — always 0 (LOCAL_PEERCRED limitation)

## Trust Boundaries
Daemon RAM:          Zeroizing<String> for password and vault structs
IPC response:        plain String (unavoidable JSON boundary)
Child env injection: plain String (OS requirement at spawn time)
Clipboard:           plain String, cleared after clipboard_clear_seconds
Push targets:        may use CLI arguments (documented per target)

## Known Platform Limitations
macOS: peer PID unavailable via LOCAL_PEERCRED — UID still verified
mlock: best-effort, unavailable in containers (warning only)
Clipboard: best-effort, may be unavailable on some Linux setups

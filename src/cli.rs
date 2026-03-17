use crate::audit_log::{
    AccessEvent, AuditFilter, clear_audit_log, log_access_event, read_audit_log,
};
use crate::ipc_client::{get_socket_path, is_daemon_running, send_ipc_request};
use crate::run_cmd::{
    ProjectConfig, configure_interactive_shell, get_project_from_config, inject_secrets_into_env,
    merge_project_config_manifest, read_project_config, shell_program, write_project_config,
};
use crate::settings::{Settings, read_settings, write_settings};
use crate::vault_file::{VaultData, get_vault_path};
use crate::vault_ops::{
    add_project, add_secret, create_vault, delete_project, delete_secret, import_dotenv,
    list_projects, list_secret_keys, unlock_vault, update_secret,
};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

static TEST_PASSWORDS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

const LOKALVAULT_MANAGED_AGENTS_MARKER: &str = "<!-- lokalvault-managed:agents -->";
const SHARE_BUNDLE_SENTINEL_KEY: &str = "__share_bundle__";
const SHARE_BUNDLE_CREATED_METHOD: &str = "share_bundle_created";
const SHARE_BUNDLE_CLAIMED_METHOD: &str = "share_bundle_claimed";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShareBundleManifest {
    required: Vec<String>,
    optional: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShareBundleSecret {
    key: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShareBundlePayload {
    project: String,
    shared_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<ShareBundleManifest>,
    secrets: Vec<ShareBundleSecret>,
}

enum ClaimManifestResult {
    Wrote,
    Merged,
    SkippedConflict,
    SkippedProjectOverride,
    NoManifest,
}

impl ClaimManifestResult {
    fn message(&self) -> &'static str {
        match self {
            Self::Wrote => "✓ Wrote .lokalvault",
            Self::Merged => "✓ Merged .lokalvault",
            Self::SkippedConflict => "✓ Skipped setup due to conflicting .lokalvault project",
            Self::SkippedProjectOverride => {
                "✓ Skipped setup because --project overrides the shared project"
            }
            Self::NoManifest => "✓ No project setup metadata in bundle",
        }
    }
}

pub enum ExportFormat {
    Dotenv,
    Json,
    Eval,
}

impl ExportFormat {
    pub fn parse(input: &str) -> Result<Self, String> {
        match input {
            "dotenv" => Ok(Self::Dotenv),
            "json" => Ok(Self::Json),
            "eval" => Ok(Self::Eval),
            _ => Err(format!("unsupported export format: {input}")),
        }
    }
}

#[derive(Clone, Copy)]
pub enum PushTarget {
    Vercel,
    Render,
    Railway,
    Fly,
    Netlify,
}

fn current_process_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "lokalvault".to_string())
}

fn current_exe_path() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn prompt_password(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|e| e.to_string())?;

    {
        let passwords = TEST_PASSWORDS.get_or_init(|| Mutex::new(Vec::new()));
        let mut passwords = passwords.lock().map_err(|e| e.to_string())?;
        if !passwords.is_empty() {
            return Ok(passwords.remove(0));
        }
    }

    read_password().map_err(|e| e.to_string())
}

pub fn cmd_create() -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let (strength, feedback) = crate::crypto::validate_password_strength(&password);
    if matches!(
        strength,
        crate::crypto::PasswordStrength::TooShort
            | crate::crypto::PasswordStrength::Weak
            | crate::crypto::PasswordStrength::Fair
    ) {
        return Err(format!("password rejected: {feedback}"));
    }
    create_vault(&password).map_err(|e| e.to_string())?;
    Ok(format!("Vault created at {}", get_vault_path().display()))
}

pub fn cmd_unlock() -> Result<String, String> {
    let _ = check_for_dotenv_in_cwd("lokalvault-project");
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    spawn_detached_daemon(&vault, &password)?;
    Ok("✓ Vault unlocked. Session active.".to_string())
}

#[derive(Clone, Copy)]
pub enum ProjectTemplate {
    OpenAi,
    Supabase,
    Stripe,
}

impl ProjectTemplate {
    pub fn parse(input: &str) -> Result<Self, String> {
        match input {
            "openai" => Ok(Self::OpenAi),
            "supabase" => Ok(Self::Supabase),
            "stripe" => Ok(Self::Stripe),
            _ => Err(format!("unsupported template: {input}")),
        }
    }

    pub fn required_keys(self) -> Vec<String> {
        match self {
            Self::OpenAi => vec!["OPENAI_API_KEY", "OPENAI_ORG_ID"],
            Self::Supabase => vec![
                "SUPABASE_URL",
                "SUPABASE_ANON_KEY",
                "SUPABASE_SERVICE_ROLE_KEY",
            ],
            Self::Stripe => vec![
                "STRIPE_SECRET_KEY",
                "STRIPE_PUBLISHABLE_KEY",
                "STRIPE_WEBHOOK_SECRET",
            ],
        }
        .into_iter()
        .map(ToString::to_string)
        .collect()
    }
}

pub fn cmd_lock() -> Result<String, String> {
    if !is_daemon_running() {
        return Ok("Vault already locked.".to_string());
    }

    let response = send_ipc_request(json!({ "type": "shutdown" }))?;
    if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if !get_socket_path().exists() {
                return Ok("✓ Vault locked.".to_string());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        return Err("daemon failed to stop within 3s".to_string());
    }

    Err(response_error(&response))
}

pub fn cmd_init(
    project_name: Option<&str>,
    template: Option<ProjectTemplate>,
) -> Result<String, String> {
    let name = match project_name {
        Some(name) => name.to_string(),
        None => env::current_dir()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "lokalvault-project".to_string()),
    };

    let mut config = ProjectConfig::default();
    config.project.name = name;
    if let Some(template) = template {
        config.keys.required = template.required_keys();
        config.keys.optional = Vec::new();
    }

    write_project_config(&config)?;
    Ok("Created .lokalvault".to_string())
}

pub fn cmd_add(
    project: Option<&str>,
    key: &str,
    value: Option<&str>,
    from_clipboard: bool,
) -> Result<String, String> {
    let project = resolve_project(project)?;
    if from_clipboard && value.is_some() {
        return Err("cannot use a literal value and --clipboard together".to_string());
    }
    let secret_value = match (value, from_clipboard) {
        (Some(value), false) => {
            eprintln!("⚠ This value may now be stored in your shell history.");
            eprintln!("  Prefer: lokalvault add --project {} {}", project, key);
            value.to_string()
        }
        (None, true) => {
            let value = read_from_clipboard()?;
            schedule_clipboard_clear(value.clone())?;
            value
        }
        (None, false) => prompt_password("Secret value: ")?,
        (Some(_), true) => unreachable!(),
    };

    if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "add_secret",
            "project": project,
            "key": key,
            "value": secret_value,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Added {key} to {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, &project).map_err(|e| e.to_string())?;
    }
    add_secret(&mut vault, &project, key, &secret_value).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Added {key} to {project}"))
}

pub fn cmd_copy(project: Option<&str>, key: &str) -> Result<String, String> {
    let value = cmd_get(project, key)?;
    write_to_clipboard(&value)?;
    schedule_clipboard_clear(value)?;
    Ok(format!("✓ {key} copied to clipboard"))
}

pub fn cmd_update(project: Option<&str>, key: &str, value: Option<&str>) -> Result<String, String> {
    let project = resolve_project(project)?;
    let secret_value = match value {
        Some(value) => value.to_string(),
        None => prompt_password("Secret value: ")?,
    };

    if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "update_secret",
            "project": project,
            "key": key,
            "value": secret_value,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Updated {key} in {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    update_secret(&mut vault, &project, key, &secret_value).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Updated {key} in {project}"))
}

pub fn cmd_delete(project: Option<&str>, key: &str) -> Result<String, String> {
    let project = resolve_project(project)?;

    if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "delete_secret",
            "project": project,
            "key": key,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Deleted {key} from {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    delete_secret(&mut vault, &project, key).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Deleted {key} from {project}"))
}

pub fn cmd_delete_project(project: &str) -> Result<String, String> {
    if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "delete_project",
            "project": project,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Deleted project {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    delete_project(&mut vault, project).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Deleted project {project}"))
}

pub fn cmd_list(project: Option<&str>) -> Result<String, String> {
    let project = project
        .map(|name| resolve_project(Some(name)))
        .transpose()?;

    if is_daemon_running() {
        let response = match project.as_deref() {
            Some(project) => send_ipc_request(json!({ "type": "list_keys", "project": project }))?,
            None => send_ipc_request(json!({ "type": "list_projects" }))?,
        };
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        return match project {
            Some(_) => Ok(response["keys"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join("\n")),
            None => Ok(response["projects"]
                .as_array()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|entry| {
                    format!(
                        "{} ({})",
                        entry["name"].as_str().unwrap_or(""),
                        entry["secret_count"].as_u64().unwrap_or(0)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")),
        };
    }

    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    match project.as_deref() {
        Some(project) => Ok(list_secret_keys(&vault, project)
            .map_err(|e| e.to_string())?
            .join("\n")),
        None => Ok(list_projects(&vault)
            .into_iter()
            .map(|entry| format!("{} ({})", entry.name, entry.secret_count))
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

pub fn cmd_get(project: Option<&str>, key: &str) -> Result<String, String> {
    let project = resolve_project(project)?;

    if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "get_secret",
            "project": project,
            "key": key,
            "process_name": current_process_name(),
            "exe_path": current_exe_path(),
            "method": "cli_get",
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(response["value"].as_str().unwrap_or("").to_string());
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    let project_entry = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| format!("project not found: {project}"))?;
    let secret = project_entry
        .secrets
        .iter()
        .find(|entry| entry.key == key)
        .ok_or_else(|| format!("secret not found: {key}"))?;
    Ok(secret.value.to_string())
}

pub fn cmd_import(path: &Path, project: &str) -> Result<String, String> {
    let preview = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let keys = preview
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim().to_string()))
        .collect::<Vec<_>>();

    eprintln!("Importing keys: {}", keys.join(", "));
    eprint!("Proceed? [y/N]: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    if input.trim().to_lowercase() != "y" {
        return Err("import cancelled".to_string());
    }

    if is_daemon_running() {
        let mut imported = 0usize;
        let mut skipped = 0usize;
        for raw_line in preview.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                skipped += 1;
                continue;
            };
            let response = send_ipc_request(json!({
                "type": "add_secret",
                "project": project,
                "key": key.trim(),
                "value": value.trim(),
            }))?;
            if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                imported += 1;
            } else {
                skipped += 1;
            }
        }
        let retired_path = retire_import_file(path)?;
        ensure_gitignore_contains(&retired_path)?;
        return Ok(format!(
            "✓ Imported {} secrets into {} (skipped {}) - retired to {}",
            imported,
            project,
            skipped,
            retired_path.display()
        ));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, project).map_err(|e| e.to_string())?;
    }
    let result = import_dotenv(&mut vault, project, path).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&vault, &password)?;
    let retired_path = retire_import_file(path)?;
    ensure_gitignore_contains(&retired_path)?;
    Ok(format!(
        "✓ Imported {} secrets into {} (skipped {}) - retired to {}",
        result.imported,
        project,
        result.skipped,
        retired_path.display()
    ))
}

pub fn cmd_export(project: Option<&str>, format: ExportFormat) -> Result<String, String> {
    let project = resolve_project(project)?;
    if matches!(format, ExportFormat::Eval) {
        eprintln!("Eval output can be sourced into your shell. Clear with: unset KEY");
    }

    let secrets = get_project_secret_map(&project)?;

    match format {
        ExportFormat::Dotenv => Ok(secrets
            .iter()
            .map(|(key, value)| {
                if value.contains('=')
                    || value.contains(' ')
                    || value.contains('\n')
                    || value.contains('"')
                    || value.contains('\'')
                {
                    format!(
                        "{}=\"{}\"",
                        key,
                        value
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\n', "\\n")
                    )
                } else {
                    format!("{}={}", key, value)
                }
            })
            .collect::<Vec<_>>()
            .join("\n")),
        ExportFormat::Json => {
            let json_map: serde_json::Map<String, serde_json::Value> = secrets
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect();
            serde_json::to_string(&json_map).map_err(|e| e.to_string())
        }
        ExportFormat::Eval => Ok(secrets
            .iter()
            .map(|(key, value)| format!("export {}={}", key, shell_quote(value)))
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

pub fn cmd_diff(path: &Path, project: Option<&str>) -> Result<String, String> {
    let project = resolve_project(project)?;
    let dotenv = parse_dotenv_file(path)?;
    let vault = get_project_secret_map(&project)?;
    let mut keys = BTreeSet::new();
    keys.extend(dotenv.keys().cloned());
    keys.extend(vault.keys().cloned());

    Ok(keys
        .into_iter()
        .map(|key| match (dotenv.get(&key), vault.get(&key)) {
            (Some(file_value), Some(vault_value)) if file_value == vault_value => {
                format!("✓ {key}")
            }
            (Some(_), Some(_)) => format!("~ {key}=<value differs>"),
            (Some(_), None) => format!("+ {key}=<value present>"),
            (None, Some(_)) => format!("- {key}"),
            (None, None) => unreachable!(),
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn cmd_status() -> Result<String, String> {
    let mut lines = vec![
        "LokalVault Status".to_string(),
        "------------------------------".to_string(),
    ];
    let dotenv_warning = Path::new(".env").exists();
    if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "project_count" }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            let status = send_ipc_request(json!({ "type": "status" }))?;
            lines.push("Vault:    unlocked".to_string());
            lines.push(format!(
                "Projects: {}",
                response["count"].as_u64().unwrap_or(0)
            ));
            if status.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
                let timeout_minutes = status["session_timeout_minutes"].as_u64().unwrap_or(0);
                let uptime_seconds = status["uptime_seconds"].as_u64().unwrap_or(0);
                let remaining_minutes = timeout_minutes.saturating_sub(uptime_seconds / 60);
                lines.push(format!(
                    "Session expires in (estimated): {}h {}m",
                    remaining_minutes / 60,
                    remaining_minutes % 60
                ));
            }
            lines.push(format!("Version:  {}", env!("CARGO_PKG_VERSION")));
            let recent = read_audit_log(None)?;
            if !recent.is_empty() {
                lines.push(String::new());
                lines.push("Recent Access:".to_string());
                for event in recent.iter().take(3) {
                    lines.push(format!(
                        "  {}  {}  {}  {}",
                        event.timestamp, event.process_name, event.project, event.key
                    ));
                }
                let stale = count_stale_secret_keys(&recent, 30)?;
                lines.push(format!(
                    "Stale secrets (based on available audit history): {stale} secrets not accessed in 30+ days"
                ));
            }
            if dotenv_warning {
                lines.push(String::new());
                lines.push("Warnings:".to_string());
                lines.push("  .env file detected in current directory".to_string());
            }
            return Ok(lines.join("\n"));
        }
        return Err(response_error(&response));
    }

    if get_vault_path().exists() {
        lines.push("Vault:    locked".to_string());
        lines.push("Daemon:   stopped".to_string());
        lines.push(format!("Version:  {}", env!("CARGO_PKG_VERSION")));
        if dotenv_warning {
            lines.push(String::new());
            lines.push("Warnings:".to_string());
            lines.push("  .env file detected in current directory".to_string());
        }
        return Ok(lines.join("\n"));
    }

    lines.push("Vault:    missing".to_string());
    lines.push("Daemon:   stopped".to_string());
    lines.push(format!("Version:  {}", env!("CARGO_PKG_VERSION")));
    Ok(lines.join("\n"))
}

pub fn cmd_shell(project: Option<&str>) -> Result<String, String> {
    let project = resolve_project(project)?;
    let secrets = get_project_secret_map(&project)?;
    let shell = shell_program();
    let mut cmd = Command::new(&shell);
    configure_interactive_shell(&mut cmd);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    inject_secrets_into_env(
        &mut cmd,
        &secrets,
        "shell-session",
        &project,
        &get_socket_path().display().to_string(),
    );

    #[cfg(unix)]
    {
        let err = cmd.exec();
        Err(format!("failed to launch shell: {err}"))
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("shell exited with status {status}"));
        }
        Ok(format!("✓ Exited shell for {project}"))
    }
}

pub fn cmd_audit(filter: Option<AuditFilter>) -> Result<String, String> {
    let events = read_audit_log(filter)?;
    Ok(events
        .into_iter()
        .map(|event| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or(event.timestamp);
            format!(
                "{} | {} | {} | {} | {}",
                timestamp, event.process_name, event.project, event.key, event.method
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

pub fn cmd_audit_clear() -> Result<String, String> {
    eprint!("Clear all audit logs? [y/N]: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    if input.trim().to_lowercase() != "y" {
        return Err("audit clear cancelled".to_string());
    }

    clear_audit_log()?;
    Ok("✓ Cleared audit log.".to_string())
}

pub fn cmd_config_get(key: &str) -> Result<String, String> {
    let settings = read_settings();
    get_setting_value(&settings, key)
}

pub fn cmd_config_set(key: &str, value: &str) -> Result<String, String> {
    let mut settings = read_settings();
    match key {
        "session-timeout-minutes" => {
            let value = parse_u32_range(value, 5, 1440, key)?;
            settings.session_timeout_minutes = value;
        }
        "lock-on-sleep" => {
            settings.lock_on_sleep = parse_bool(value, key)?;
        }
        "clipboard-clear-seconds" => {
            let value = parse_u32_range(value, 5, 300, key)?;
            settings.clipboard_clear_seconds = value;
        }
        "show-tray-icon" => {
            settings.show_tray_icon = parse_bool(value, key)?;
        }
        "default-project" => {
            settings.default_project = if value == "none" {
                None
            } else {
                Some(value.to_string())
            };
        }
        _ => return Err(format!("unsupported config key: {key}")),
    }
    write_settings(&settings)?;
    Ok(format!("Set {key}={}", get_setting_value(&settings, key)?))
}

pub fn cmd_config_list() -> Result<String, String> {
    let settings = read_settings();
    Ok([
        format!(
            "session-timeout-minutes={}",
            settings.session_timeout_minutes
        ),
        format!("lock-on-sleep={}", settings.lock_on_sleep),
        format!(
            "clipboard-clear-seconds={}",
            settings.clipboard_clear_seconds
        ),
        format!("show-tray-icon={}", settings.show_tray_icon),
        format!("argon2-memory-kb={}", settings.argon2_memory_kb),
        format!("argon2-iterations={}", settings.argon2_iterations),
        format!("argon2-parallelism={}", settings.argon2_parallelism),
        format!(
            "default-project={}",
            settings
                .default_project
                .unwrap_or_else(|| "none".to_string())
        ),
    ]
    .join("\n"))
}

pub fn cmd_push(
    project: &str,
    target: PushTarget,
    environment: Option<&str>,
) -> Result<String, String> {
    let environment = environment.unwrap_or("production");
    let secrets = get_project_secret_map(project)?;
    eprintln!(
        "Pushing {} secrets to {}...",
        secrets.len(),
        push_target_name(target)
    );
    eprintln!(
        "Warning: {} may pass secret values through third-party CLI arguments.",
        push_target_name(target)
    );

    if !matches!(target, PushTarget::Vercel) && environment != "production" {
        eprintln!(
            "Warning: --env is not supported for {}, ignoring",
            push_target_name(target)
        );
    }

    let mut failures = Vec::new();
    for (key, value) in &secrets {
        eprintln!("Pushing {} to {}...", key, push_target_name(target));
        let mut cmd = platform_command(target, key, value, environment);
        let status = cmd.status().map_err(|e| {
            format!(
                "{} CLI not found or failed to run: {}",
                push_target_name(target),
                e
            )
        })?;
        if !status.success() {
            failures.push(format!("{} ({status})", key));
        }
    }

    if !failures.is_empty() {
        return Err(format!(
            "push failed for {}: {}",
            push_target_name(target),
            failures.join(", ")
        ));
    }

    Ok(format!(
        "✓ Pushed {} secrets to {}",
        secrets.len(),
        push_target_name(target)
    ))
}

fn check_for_dotenv_in_cwd(project_name: &str) -> Result<(), String> {
    let dotenv_path = Path::new(".env");
    if !dotenv_path.exists() {
        return Ok(());
    }

    let gitignore = Path::new(".gitignore");
    if gitignore.exists() {
        let contents = fs::read_to_string(gitignore).map_err(|e| e.to_string())?;
        if contents.lines().any(|line| line.trim() == ".env") {
            return Ok(());
        }
    }

    eprintln!("⚠ .env file detected in current directory");
    eprintln!("  Your secrets may be exposed. Run:");
    eprintln!("  lokalvault import .env --project {project_name}");
    Ok(())
}

pub fn cmd_doctor() -> Result<(String, bool), String> {
    let mut lines = Vec::new();
    let mut failed = false;

    if get_vault_path().exists() {
        lines.push(format!(
            "✓ Vault file exists at {}",
            get_vault_path().display()
        ));
    } else {
        lines.push(format!(
            "✗ Vault file missing at {}",
            get_vault_path().display()
        ));
        failed = true;
    }

    if is_daemon_running() {
        lines.push("✓ Daemon running".to_string());
    } else {
        lines.push("✗ Daemon not running".to_string());
        failed = true;
    }

    if Path::new(".env").exists() {
        lines.push("⚠ .env file detected in current directory".to_string());
        eprintln!("Hint: Run lokalvault import .env --project <cwd-name>");
    }

    let gitignore = Path::new(".gitignore");
    if gitignore.exists()
        && fs::read_to_string(gitignore)
            .map_err(|e| e.to_string())?
            .contains(".env")
    {
        lines.push("✓ .gitignore present and contains .env".to_string());
    } else {
        lines.push("✗ .gitignore missing .env entry".to_string());
        failed = true;
    }

    if Path::new(".lokalvault").exists() {
        lines.push("✓ .lokalvault config present in current directory".to_string());
    } else {
        lines.push("✗ .lokalvault config missing in current directory".to_string());
        failed = true;
    }

    Ok((lines.join("\n"), failed))
}

pub fn cmd_dev() -> Result<String, String> {
    let detected = if Path::new(".lokalvault").exists() {
        vec![
            "lokalvault".to_string(),
            "run".to_string(),
            "--".to_string(),
            "true".to_string(),
        ]
    } else if Path::new("package.json").exists() {
        let package = fs::read_to_string("package.json").map_err(|e| e.to_string())?;
        if package.contains("\"dev\"") {
            vec!["npm".to_string(), "run".to_string(), "dev".to_string()]
        } else if package.contains("\"start\"") {
            vec!["npm".to_string(), "start".to_string()]
        } else {
            Vec::new()
        }
    } else if Path::new("Makefile").exists()
        && fs::read_to_string("Makefile")
            .map_err(|e| e.to_string())?
            .contains("run:")
    {
        vec!["make".to_string(), "run".to_string()]
    } else if Path::new("manage.py").exists() {
        vec![
            "python".to_string(),
            "manage.py".to_string(),
            "runserver".to_string(),
        ]
    } else if Path::new("Cargo.toml").exists() {
        vec!["cargo".to_string(), "run".to_string()]
    } else {
        Vec::new()
    };

    if detected.is_empty() {
        return Err(
            "Could not detect run command. Use: lokalvault run -- <your command>".to_string(),
        );
    }

    eprintln!("Running: lokalvault run -- {}", detected.join(" "));
    Ok(detected.join(" "))
}

pub fn cmd_audit_stale(days: u64, never_accessed: bool) -> Result<String, String> {
    let events = read_audit_log(None)?;
    let since = chrono::Utc::now() - chrono::Duration::days(days as i64);
    let mut lines = Vec::new();

    for event in events {
        let accessed = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());
        if never_accessed || accessed < since {
            lines.push(format!(
                "{}   last rotated: unknown   last accessed: {}",
                event.key, event.timestamp
            ));
        }
    }

    Ok(lines.join("\n"))
}

pub fn cmd_ai_safe(project: Option<&str>, generate_example: bool) -> Result<String, String> {
    let project = resolve_project(project)?;
    let keys = if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "list_keys", "project": project }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        response["keys"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else if let Some(config) = read_project_config()? {
        if config.project.name == project && !config.keys.required.is_empty() {
            config.keys.required
        } else {
            let password = prompt_password("Master password: ")?;
            let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
            list_secret_keys(&vault, &project).map_err(|e| e.to_string())?
        }
    } else {
        let password = prompt_password("Master password: ")?;
        let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
        list_secret_keys(&vault, &project).map_err(|e| e.to_string())?
    };

    let config = ProjectConfig {
        project: crate::run_cmd::ProjectSection {
            name: project.clone(),
        },
        keys: crate::run_cmd::KeysSection {
            required: keys.clone(),
            optional: vec![],
        },
    };
    write_project_config(&config)?;

    let agents = format!(
        "{LOKALVAULT_MANAGED_AGENTS_MARKER}\n# AI Agent Instructions\n\nThis project uses LokalVault for secrets management.\n\nSecrets are NOT in this repository. They cannot be accessed\nwithout the developer typing a confirmation code.\n\n## What You Must Know\n\n- Secret values are never in any file in this repository\n- They are injected at runtime via `lokalvault run`\n- Reference secrets by KEY NAME only: os.environ[\"OPENAI_KEY\"]\n\n## How To Run This Project\n\n  lokalvault run -- <detected run command>\n\n## What You Must Not Do\n\n- Do not read or write vault files (*.lv)\n- Do not connect to the LokalVault runtime socket directly\n- Do not hardcode secret values into source files\n- Do not create .env files containing real values\n- Do not replace os.environ[\"KEY\"] calls with literal values\n\n## Required Secrets For This Project\n\n{}\n",
        keys.iter()
            .map(|key| format!("  {key}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let agents_path = Path::new("AGENTS.md");
    if agents_path.exists() {
        let existing = fs::read_to_string(agents_path).map_err(|e| e.to_string())?;
        if !is_lokalvault_managed_agents(&existing) {
            return Err(
                "AGENTS.md already exists and was not generated by LokalVault; refusing to overwrite"
                    .to_string(),
            );
        }
    }
    fs::write(agents_path, agents).map_err(|e| e.to_string())?;

    ensure_ai_safe_gitignore()?;

    if generate_example {
        fs::write(
            ".env.example",
            keys.iter()
                .map(|key| format!("{key}="))
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(format!(
        "✓ AGENTS.md generated\n✓ .lokalvault updated with required keys\n✓ .gitignore updated{}",
        if generate_example {
            "\n✓ .env.example generated"
        } else {
            ""
        }
    ))
}

pub fn cmd_share(project: &str, output: Option<&str>) -> Result<String, String> {
    let share_password = prompt_password("Share password: ")?;
    let secrets = get_project_secret_map(project)?;
    let manifest = current_project_manifest(project)?;
    let payload = ShareBundlePayload {
        project: project.to_string(),
        shared_at: chrono::Utc::now().to_rfc3339(),
        manifest: manifest.clone(),
        secrets: secrets
            .into_iter()
            .map(|(key, value)| ShareBundleSecret { key, value })
            .collect(),
    };
    let output_path = output
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{project}.lve"));
    write_lve_file(
        Path::new(&output_path),
        &share_password,
        &serde_json::to_value(&payload).map_err(|e| e.to_string())?,
    )?;
    log_share_bundle_event(project, SHARE_BUNDLE_CREATED_METHOD)?;
    Ok(format!(
        "✓ Created {output_path}\n{}",
        if manifest.is_some() {
            "✓ Included project setup from .lokalvault"
        } else {
            "✓ No matching .lokalvault found; bundle contains secrets only"
        }
    ))
}

pub fn cmd_claim(path: &Path, project: Option<&str>) -> Result<String, String> {
    let share_password = prompt_password("Share password: ")?;
    let payload: ShareBundlePayload =
        serde_json::from_value(read_lve_file(path, &share_password)?).map_err(|e| e.to_string())?;
    let bundle_project = payload.project.clone();
    let project_name = project
        .map(ToString::to_string)
        .unwrap_or_else(|| bundle_project.clone());

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    if !vault
        .projects
        .iter()
        .any(|entry| entry.name == project_name)
    {
        add_project(&mut vault, &project_name).map_err(|e| e.to_string())?;
    }

    let mut imported = 0usize;
    for secret in &payload.secrets {
        if add_secret(&mut vault, &project_name, &secret.key, &secret.value).is_ok() {
            imported += 1;
        }
    }

    crate::vault_file::write_vault(&vault, &password)?;
    let manifest_result =
        apply_bundle_manifest(payload.manifest.as_ref(), &bundle_project, &project_name)?;
    log_share_bundle_event(&project_name, SHARE_BUNDLE_CLAIMED_METHOD)?;
    Ok(format!(
        "✓ Imported {imported} secrets into {project_name}\n{}",
        manifest_result.message()
    ))
}

pub fn cmd_scan_diff(project: Option<&str>, diff: &str) -> Result<String, String> {
    let project = resolve_project(project)?;
    let matches = if is_daemon_running() {
        let response = send_ipc_request(json!({
            "type": "scan_diff",
            "project": project,
            "diff": diff,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        response["matches"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else {
        let password = prompt_password("Master password: ")?;
        let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
        let project_entry = vault
            .projects
            .iter()
            .find(|entry| entry.name == project)
            .ok_or_else(|| format!("project not found: {project}"))?;
        find_matching_secret_keys_in_project(project_entry, diff)
    };

    if matches.is_empty() {
        return Ok("No secret values detected in staged diff".to_string());
    }

    Err(format!(
        "Blocked: staged diff contains secret values for keys: {}",
        matches.join(", ")
    ))
}

pub fn cmd_protect_repo(project: Option<&str>) -> Result<String, String> {
    let hook_path = git_hook_path()?;
    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path).map_err(|e| e.to_string())?;
        if !is_lokalvault_managed_hook(&existing) {
            return Err(format!(
                "refusing to overwrite existing non-LokalVault hook at {}",
                hook_path.display()
            ));
        }
    }

    let project_arg = match project {
        Some(name) => format!(" --project {}", shell_quote(name)),
        None => String::new(),
    };
    let hook = format!(
        "#!/bin/sh\n# lokalvault-managed\nset -eu\n\nif ! command -v lokalvault >/dev/null 2>&1; then\n  echo \"lokalvault not found in PATH; skipping secret scan\" >&2\n  exit 0\nfi\n\ngit diff --cached --no-color | lokalvault scan-diff{project_arg}\n"
    );

    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&hook_path, hook).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;

    Ok(format!(
        "✓ Installed pre-commit hook at {}",
        hook_path.display()
    ))
}

fn resolve_project(project: Option<&str>) -> Result<String, String> {
    match project {
        Some(project) => Ok(project.to_string()),
        None => get_project_from_config()?.ok_or_else(|| {
            "no project specified - run lokalvault init or pass --project".to_string()
        }),
    }
}

fn get_project_secret_map(project: &str) -> Result<HashMap<String, String>, String> {
    if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "get_all_secrets", "project": project }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        return Ok(response["secrets"]
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| (key, value.as_str().unwrap_or("").to_string()))
            .collect());
    }

    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password).map_err(|e| e.to_string())?;
    let project_entry = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| format!("project not found: {project}"))?;
    Ok(project_entry
        .secrets
        .iter()
        .map(|secret| (secret.key.clone(), secret.value.to_string()))
        .collect())
}

fn current_project_manifest(project: &str) -> Result<Option<ShareBundleManifest>, String> {
    let Some(config) = read_project_config()? else {
        return Ok(None);
    };
    if config.project.name != project {
        return Ok(None);
    }
    Ok(Some(ShareBundleManifest {
        required: config.keys.required,
        optional: config.keys.optional,
    }))
}

fn apply_bundle_manifest(
    manifest: Option<&ShareBundleManifest>,
    bundle_project: &str,
    project_name: &str,
) -> Result<ClaimManifestResult, String> {
    let Some(manifest) = manifest else {
        return Ok(ClaimManifestResult::NoManifest);
    };
    if bundle_project != project_name {
        return Ok(ClaimManifestResult::SkippedProjectOverride);
    }

    let existing = read_project_config()?;
    match existing {
        None => {
            let config = merge_project_config_manifest(
                None,
                bundle_project,
                &manifest.required,
                &manifest.optional,
            );
            write_project_config(&config)?;
            Ok(ClaimManifestResult::Wrote)
        }
        Some(existing) if existing.project.name == bundle_project => {
            let config = merge_project_config_manifest(
                Some(existing),
                bundle_project,
                &manifest.required,
                &manifest.optional,
            );
            write_project_config(&config)?;
            Ok(ClaimManifestResult::Merged)
        }
        Some(_) => Ok(ClaimManifestResult::SkippedConflict),
    }
}

fn log_share_bundle_event(project: &str, method: &str) -> Result<(), String> {
    log_access_event(AccessEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        process_name: current_process_name(),
        exe_path: current_exe_path(),
        project: project.to_string(),
        key: SHARE_BUNDLE_SENTINEL_KEY.to_string(),
        method: method.to_string(),
        last_updated_at: None,
    })
}

fn find_matching_secret_keys_in_project(
    project_entry: &crate::vault_file::Project,
    diff: &str,
) -> Vec<String> {
    let mut matches = project_entry
        .secrets
        .iter()
        .filter(|secret| {
            let value = secret.value.as_str();
            !value.is_empty() && value.len() >= 8 && diff.contains(value)
        })
        .map(|secret| secret.key.clone())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

fn parse_dotenv_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut map = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    Ok(map)
}

fn read_from_clipboard() -> Result<String, String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.get_text().map_err(|e| e.to_string())
}

fn write_to_clipboard(value: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard
        .set_text(value.to_string())
        .map_err(|e| e.to_string())
}

fn schedule_clipboard_clear(expected: String) -> Result<(), String> {
    let seconds = read_settings().clipboard_clear_seconds;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(seconds as u64));
        if let Ok(mut clipboard) = arboard::Clipboard::new()
            && let Ok(current) = clipboard.get_text()
            && current == expected
        {
            let _ = clipboard.set_text(String::new());
        }
    });
    Ok(())
}

fn git_hook_path() -> Result<std::path::PathBuf, String> {
    let git_dir = Path::new(".git");
    if !git_dir.exists() || !git_dir.is_dir() {
        return Err("not a git repository (missing .git directory)".to_string());
    }
    Ok(git_dir.join("hooks").join("pre-commit"))
}

fn is_lokalvault_managed_hook(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim() == "# lokalvault-managed")
}

fn is_lokalvault_managed_agents(contents: &str) -> bool {
    if contents
        .lines()
        .next()
        .is_some_and(|line| line.trim() == LOKALVAULT_MANAGED_AGENTS_MARKER)
    {
        return true;
    }

    contents.starts_with(
        "# AI Agent Instructions\n\nThis project uses LokalVault for secrets management.\n\nSecrets are NOT in this repository. They cannot be accessed\nwithout the developer typing a confirmation code.\n",
    )
}

fn response_error(response: &serde_json::Value) -> String {
    response
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown daemon error")
        .to_string()
}

fn count_stale_secret_keys(
    events: &[crate::audit_log::AccessEvent],
    stale_days: i64,
) -> Result<usize, String> {
    let cutoff = chrono::Utc::now() - chrono::Duration::days(stale_days);
    let mut latest = BTreeMap::new();
    for event in events {
        if is_share_bundle_event(&event.method) {
            continue;
        }
        let timestamp = chrono::DateTime::parse_from_rfc3339(&event.timestamp)
            .map_err(|e| e.to_string())?
            .with_timezone(&chrono::Utc);
        latest
            .entry((event.project.clone(), event.key.clone()))
            .and_modify(|existing: &mut chrono::DateTime<chrono::Utc>| {
                if timestamp > *existing {
                    *existing = timestamp;
                }
            })
            .or_insert(timestamp);
    }
    Ok(latest
        .values()
        .filter(|timestamp| **timestamp < cutoff)
        .count())
}

fn is_share_bundle_event(method: &str) -> bool {
    matches!(
        method,
        SHARE_BUNDLE_CREATED_METHOD | SHARE_BUNDLE_CLAIMED_METHOD
    )
}

fn get_setting_value(settings: &Settings, key: &str) -> Result<String, String> {
    match key {
        "session-timeout-minutes" => Ok(settings.session_timeout_minutes.to_string()),
        "lock-on-sleep" => Ok(settings.lock_on_sleep.to_string()),
        "clipboard-clear-seconds" => Ok(settings.clipboard_clear_seconds.to_string()),
        "show-tray-icon" => Ok(settings.show_tray_icon.to_string()),
        "argon2-memory-kb" => Ok(settings.argon2_memory_kb.to_string()),
        "argon2-iterations" => Ok(settings.argon2_iterations.to_string()),
        "argon2-parallelism" => Ok(settings.argon2_parallelism.to_string()),
        "default-project" => Ok(settings
            .default_project
            .clone()
            .unwrap_or_else(|| "none".to_string())),
        _ => Err(format!("unsupported config key: {key}")),
    }
}

fn parse_u32_range(value: &str, min: u32, max: u32, key: &str) -> Result<u32, String> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| format!("invalid value for {key}"))?;
    if parsed < min || parsed > max {
        return Err(format!("{key} must be between {min} and {max}"));
    }
    Ok(parsed)
}

fn parse_bool(value: &str, key: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("invalid value for {key}")),
    }
}

fn spawn_detached_daemon(vault: &VaultData, password: &str) -> Result<(), String> {
    let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    command
        .arg("daemon")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().map_err(|e| e.to_string())?;

    let payload = serde_json::to_vec(&(vault, password)).map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or_else(|| "failed to open daemon stdin".to_string())?
        .write_all(&payload)
        .map_err(|e| e.to_string())?;
    let mut payload = payload;
    payload.zeroize();

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("daemon exited during startup with status {status}"));
        }
        if get_socket_path().exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err("daemon failed to start within 5s".to_string())
}

fn retire_import_file(path: &Path) -> Result<std::path::PathBuf, String> {
    let file_name = path
        .file_name()
        .ok_or_else(|| "import path must point to a file".to_string())?
        .to_string_lossy();
    let retired_name = format!("{file_name}.retired");
    let retired_path = path.with_file_name(retired_name);
    fs::rename(path, &retired_path).map_err(|e| e.to_string())?;
    Ok(retired_path)
}

fn ensure_gitignore_contains(retired_path: &Path) -> Result<(), String> {
    let ignore_path = Path::new(".gitignore");
    let retired_name = retired_path
        .file_name()
        .ok_or_else(|| "retired path must point to a file".to_string())?
        .to_string_lossy()
        .to_string();

    let mut contents = if ignore_path.exists() {
        fs::read_to_string(ignore_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    if !contents.lines().any(|line| line.trim() == retired_name) {
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(&retired_name);
        contents.push('\n');
        fs::write(ignore_path, contents).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn ensure_ai_safe_gitignore() -> Result<(), String> {
    let ignore_path = Path::new(".gitignore");
    let required = [".env", "*.env", "*.lv", ".env.*", "!.env.example"];
    let mut contents = if ignore_path.exists() {
        fs::read_to_string(ignore_path).map_err(|e| e.to_string())?
    } else {
        String::new()
    };

    for entry in required {
        if !contents.lines().any(|line| line.trim() == entry) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(entry);
            contents.push('\n');
        }
    }

    fs::write(ignore_path, contents).map_err(|e| e.to_string())
}

fn write_lve_file(path: &Path, password: &str, payload: &serde_json::Value) -> Result<(), String> {
    let salt = crate::crypto::generate_salt();
    let nonce = crate::crypto::generate_nonce();
    let key = crate::crypto::derive_key_with_params(password, &salt, 65_536, 3, 1)?;
    let plaintext = serde_json::to_vec(payload).map_err(|e| e.to_string())?;
    let ciphertext = crate::crypto::encrypt(&plaintext, &key, &nonce)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"LVSE");
    bytes.push(0x01);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    fs::write(path, bytes).map_err(|e| e.to_string())
}

fn read_lve_file(path: &Path, password: &str) -> Result<serde_json::Value, String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() < 49 || &bytes[0..4] != b"LVSE" || bytes[4] != 0x01 {
        return Err("invalid .lve file".to_string());
    }
    let salt: [u8; 32] = bytes[5..37]
        .try_into()
        .map_err(|_| "invalid .lve file: corrupted salt".to_string())?;
    let nonce: [u8; 12] = bytes[37..49]
        .try_into()
        .map_err(|_| "invalid .lve file: corrupted nonce".to_string())?;
    let ciphertext = &bytes[49..];
    let key = crate::crypto::derive_key_with_params(password, &salt, 65_536, 3, 1)?;
    let plaintext = crate::crypto::decrypt(ciphertext, &key, &nonce)?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

fn platform_command(target: PushTarget, key: &str, value: &str, environment: &str) -> Command {
    let mut cmd = match target {
        PushTarget::Vercel => Command::new("vercel"),
        PushTarget::Render => Command::new("render"),
        PushTarget::Railway => Command::new("railway"),
        PushTarget::Fly => Command::new("fly"),
        PushTarget::Netlify => Command::new("netlify"),
    };

    match target {
        PushTarget::Vercel => {
            cmd.args(["env", "add", key, value, environment]);
        }
        PushTarget::Render => {
            cmd.args(["envvar", "set", &format!("{key}={value}")]);
        }
        PushTarget::Railway => {
            cmd.args(["variables", "set", &format!("{key}={value}")]);
        }
        PushTarget::Fly => {
            cmd.args(["secrets", "set", &format!("{key}={value}")]);
        }
        PushTarget::Netlify => {
            cmd.args(["env:set", key, value]);
        }
    }

    cmd
}

fn push_target_name(target: PushTarget) -> &'static str {
    match target {
        PushTarget::Vercel => "vercel",
        PushTarget::Render => "render",
        PushTarget::Railway => "railway",
        PushTarget::Fly => "fly",
        PushTarget::Netlify => "netlify",
    }
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

#[doc(hidden)]
pub fn push_test_passwords(passwords: &[&str]) {
    let queue = TEST_PASSWORDS.get_or_init(|| Mutex::new(Vec::new()));
    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
    queue.clear();
    queue.extend(passwords.iter().map(|password| (*password).to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(method: &str, key: &str, age_days: i64) -> AccessEvent {
        AccessEvent {
            timestamp: (chrono::Utc::now() - chrono::Duration::days(age_days)).to_rfc3339(),
            process_name: "lokalvault".to_string(),
            exe_path: "/usr/bin/lokalvault".to_string(),
            project: "my-app".to_string(),
            key: key.to_string(),
            method: method.to_string(),
            last_updated_at: None,
        }
    }

    #[test]
    fn test_count_stale_secret_keys_ignores_share_bundle_events() {
        let stale = count_stale_secret_keys(
            &[
                sample_event("share_bundle_created", SHARE_BUNDLE_SENTINEL_KEY, 31),
                sample_event("share_bundle_claimed", SHARE_BUNDLE_SENTINEL_KEY, 31),
                sample_event("run_env", "OLD_SECRET", 31),
            ],
            30,
        )
        .unwrap();

        assert_eq!(stale, 1);
    }
}

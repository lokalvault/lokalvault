use crate::audit_log::{AuditFilter, clear_audit_log, read_audit_log};
use crate::ipc_client::{get_socket_path, is_daemon_running, send_ipc_request};
use crate::run_cmd::get_project_from_config;
use crate::vault_file::{VaultData, get_vault_path};
use crate::vault_ops::{
    add_project, add_secret, create_vault, delete_project, delete_secret, import_dotenv,
    list_projects, list_secret_keys, unlock_vault, update_secret,
};
use rpassword::read_password;
use serde_json::json;
use std::env;
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(test)]
static TEST_PASSWORDS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

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

    #[cfg(test)]
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
    create_vault(&password)?;
    Ok(format!("Vault created at {}", get_vault_path().display()))
}

pub fn cmd_unlock() -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password)?;
    spawn_detached_daemon(&vault, &password)?;
    Ok("✓ Vault unlocked. Session active.".to_string())
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

pub fn cmd_init(project_name: Option<&str>) -> Result<String, String> {
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

    let contents = format!("[project]\nname = \"{name}\"\n");
    fs::write(".lokalvault", contents).map_err(|e| e.to_string())?;
    Ok("Created .lokalvault".to_string())
}

pub fn cmd_add(project: Option<&str>, key: &str, value: Option<&str>) -> Result<String, String> {
    let project = resolve_project(project)?;
    let secret_value = match value {
        Some(value) => value.to_string(),
        None => prompt_password("Secret value: ")?,
    };

    if is_daemon_running() {
        let password = prompt_password("Master password: ")?;
        let response = send_ipc_request(json!({
            "type": "add_secret",
            "project": project,
            "key": key,
            "value": secret_value,
            "password": password,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Added {key} to {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password)?;
    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, &project)?;
    }
    add_secret(&mut vault, &project, key, &secret_value)?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Added {key} to {project}"))
}

pub fn cmd_update(project: Option<&str>, key: &str, value: Option<&str>) -> Result<String, String> {
    let project = resolve_project(project)?;
    let secret_value = match value {
        Some(value) => value.to_string(),
        None => prompt_password("Secret value: ")?,
    };

    if is_daemon_running() {
        let password = prompt_password("Master password: ")?;
        let response = send_ipc_request(json!({
            "type": "update_secret",
            "project": project,
            "key": key,
            "value": secret_value,
            "password": password,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Updated {key} in {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password)?;
    update_secret(&mut vault, &project, key, &secret_value)?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Updated {key} in {project}"))
}

pub fn cmd_delete(project: Option<&str>, key: &str) -> Result<String, String> {
    let project = resolve_project(project)?;

    if is_daemon_running() {
        let password = prompt_password("Master password: ")?;
        let response = send_ipc_request(json!({
            "type": "delete_secret",
            "project": project,
            "key": key,
            "password": password,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Deleted {key} from {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password)?;
    delete_secret(&mut vault, &project, key)?;
    crate::vault_file::write_vault(&vault, &password)?;
    Ok(format!("✓ Deleted {key} from {project}"))
}

pub fn cmd_delete_project(project: &str) -> Result<String, String> {
    if is_daemon_running() {
        let password = prompt_password("Master password: ")?;
        let response = send_ipc_request(json!({
            "type": "delete_project",
            "project": project,
            "password": password,
        }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!("✓ Deleted project {project}"));
        }
        return Err(response_error(&response));
    }

    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password)?;
    delete_project(&mut vault, project)?;
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
    let vault = unlock_vault(&password)?;
    match project.as_deref() {
        Some(project) => Ok(list_secret_keys(&vault, project)?.join("\n")),
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
    let vault = unlock_vault(&password)?;
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
    Ok(secret.value.clone())
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
        let password = prompt_password("Master password: ")?;
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
                "password": password,
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
    let mut vault = unlock_vault(&password)?;
    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, project)?;
    }
    let result = import_dotenv(&mut vault, project, path)?;
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
    eprintln!("Secrets now in shell. Clear with: unset KEY");

    let secrets = if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "get_all_secrets", "project": project }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        response["secrets"].as_object().cloned().unwrap_or_default()
    } else {
        let password = prompt_password("Master password: ")?;
        let vault = unlock_vault(&password)?;
        let project_entry = vault
            .projects
            .iter()
            .find(|entry| entry.name == project)
            .ok_or_else(|| format!("project not found: {project}"))?;
        project_entry
            .secrets
            .iter()
            .map(|secret| {
                (
                    secret.key.clone(),
                    serde_json::Value::String(secret.value.clone()),
                )
            })
            .collect()
    };

    match format {
        ExportFormat::Dotenv => Ok(secrets
            .iter()
            .map(|(key, value)| format!("{}={}", key, value.as_str().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n")),
        ExportFormat::Json => serde_json::to_string(&secrets).map_err(|e| e.to_string()),
        ExportFormat::Eval => Ok(secrets
            .iter()
            .map(|(key, value)| {
                format!(
                    "export {}={}",
                    key,
                    shell_quote(value.as_str().unwrap_or(""))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

pub fn cmd_status() -> Result<String, String> {
    if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "project_count" }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            return Ok(format!(
                "Vault: unlocked\nProjects: {}\nVersion: {}",
                response["count"].as_u64().unwrap_or(0),
                env!("CARGO_PKG_VERSION")
            ));
        }
        return Err(response_error(&response));
    }

    if get_vault_path().exists() {
        return Ok(format!(
            "Vault locked - run lokalvault unlock to see details\nVersion: {}",
            env!("CARGO_PKG_VERSION")
        ));
    }

    Ok(format!(
        "No vault found - run lokalvault create\nVersion: {}",
        env!("CARGO_PKG_VERSION")
    ))
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

pub fn cmd_push(
    project: &str,
    target: PushTarget,
    environment: Option<&str>,
) -> Result<String, String> {
    let environment = environment.unwrap_or("production");
    let secrets = if is_daemon_running() {
        let response = send_ipc_request(json!({ "type": "get_all_secrets", "project": project }))?;
        if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(response_error(&response));
        }
        response["secrets"].as_object().cloned().unwrap_or_default()
    } else {
        let password = prompt_password("Master password: ")?;
        let vault = unlock_vault(&password)?;
        let project_entry = vault
            .projects
            .iter()
            .find(|entry| entry.name == project)
            .ok_or_else(|| format!("project not found: {project}"))?;
        project_entry
            .secrets
            .iter()
            .map(|secret| {
                (
                    secret.key.clone(),
                    serde_json::Value::String(secret.value.clone()),
                )
            })
            .collect()
    };

    if !matches!(target, PushTarget::Vercel) && environment != "production" {
        eprintln!(
            "Warning: --env is not supported for {}, ignoring",
            push_target_name(target)
        );
    }

    for (key, value) in &secrets {
        eprintln!("Pushing {} to {}...", key, push_target_name(target));
        let mut cmd = platform_command(target, key, value.as_str().unwrap_or(""), environment);
        cmd.status().map_err(|e| {
            format!(
                "{} CLI not found or failed to run: {}",
                push_target_name(target),
                e
            )
        })?;
    }

    Ok(format!(
        "Pushing {} secrets to {}...",
        secrets.len(),
        push_target_name(target)
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

fn response_error(response: &serde_json::Value) -> String {
    response
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown daemon error")
        .to_string()
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

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
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

#[cfg(test)]
pub fn push_test_passwords(passwords: &[&str]) {
    let queue = TEST_PASSWORDS.get_or_init(|| Mutex::new(Vec::new()));
    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
    queue.clear();
    queue.extend(passwords.iter().map(|password| (*password).to_string()));
}

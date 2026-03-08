use crate::daemon::{DaemonState, start_daemon, stop_daemon};
use crate::run_cmd::get_project_from_config;
use crate::vault_file::get_vault_path;
use crate::vault_ops::{
    add_project, add_secret, create_vault, import_dotenv, list_projects, list_secret_keys,
    unlock_vault,
};
use rpassword::read_password;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static DAEMON_SESSION: OnceLock<Mutex<Option<DaemonState>>> = OnceLock::new();

fn daemon_session() -> &'static Mutex<Option<DaemonState>> {
    DAEMON_SESSION.get_or_init(|| Mutex::new(None))
}

pub enum ExportFormat {
    Dotenv,
    Json,
    Eval,
}

#[derive(Clone, Copy)]
pub enum PushTarget {
    Vercel,
    Render,
    Railway,
    Fly,
    Netlify,
}

pub fn prompt_password(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    read_password().map_err(|e| e.to_string())
}

pub fn cmd_create() -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    create_vault(&password)?;
    Ok(format!("✓ Vault created at {}", get_vault_path().display()))
}

pub fn cmd_unlock() -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password)?;
    let state = start_daemon(vault);

    let mut session = daemon_session().lock().map_err(|e| e.to_string())?;
    *session = Some(state);

    Ok("✓ Vault unlocked. Session active.".to_string())
}

pub fn cmd_lock() -> Result<String, String> {
    let mut session = daemon_session().lock().map_err(|e| e.to_string())?;
    if let Some(state) = session.take() {
        stop_daemon(&state)?;
    }

    Ok("✓ Vault locked.".to_string())
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
    Ok("✓ Created .lokalvault".to_string())
}

pub fn cmd_add(project: &str, key: &str, value: Option<&str>) -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let mut vault = unlock_vault(&password)?;
    let secret_value = match value {
        Some(value) => value.to_string(),
        None => prompt_password("Secret value: ")?,
    };

    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, project)?;
    }
    add_secret(&mut vault, project, key, &secret_value)?;
    crate::vault_ops::change_master_password(&vault, &password, &password)?;

    Ok(format!("✓ Added {key} to {project}"))
}

pub fn cmd_list(project: Option<&str>) -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password)?;

    match project {
        Some(project) => Ok(list_secret_keys(&vault, project)?.join("\n")),
        None => Ok(list_projects(&vault)
            .into_iter()
            .map(|entry| format!("{} ({})", entry.name, entry.secret_count))
            .collect::<Vec<_>>()
            .join("\n")),
    }
}

pub fn cmd_get(project: &str, key: &str) -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password)?;
    let project = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| format!("project not found: {project}"))?;
    let secret = project
        .secrets
        .iter()
        .find(|entry| entry.key == key)
        .ok_or_else(|| format!("secret not found: {key}"))?;

    Ok(secret.value.clone())
}

pub fn cmd_import(path: &Path, project: &str) -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let preview = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let keys = preview
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key.trim().to_string()))
        .collect::<Vec<_>>();

    println!("Importing keys: {}", keys.join(", "));
    print!("Proceed? [y/N]: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    if input.trim().to_lowercase() != "y" {
        return Err("import cancelled".to_string());
    }

    let mut vault = unlock_vault(&password)?;
    if !vault.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut vault, project)?;
    }
    let result = import_dotenv(&mut vault, project, path)?;
    crate::vault_ops::change_master_password(&vault, &password, &password)?;

    Ok(format!(
        "✓ Imported {} secrets into {} (skipped {})",
        result.imported, project, result.skipped
    ))
}

pub fn cmd_status() -> Result<String, String> {
    let vault_exists = get_vault_path().exists();
    let daemon_running = daemon_session()
        .lock()
        .map_err(|e| e.to_string())?
        .is_some();
    let project_hint = get_project_from_config()?.unwrap_or_else(|| "not configured".to_string());
    let project_count = if vault_exists {
        prompt_password("Master password (for project count, leave empty to skip): ")
            .ok()
            .and_then(|password| {
                if password.is_empty() {
                    None
                } else {
                    unlock_vault(&password)
                        .ok()
                        .map(|vault| vault.projects.len())
                }
            })
            .unwrap_or(0)
    } else {
        0
    };

    Ok(format!(
        "Vault: {} ({})\nDaemon: {}\nProject: {}\nProjects: {}\nVersion: {}",
        get_vault_path().display(),
        if vault_exists { "exists" } else { "missing" },
        if daemon_running { "running" } else { "stopped" },
        project_hint,
        project_count,
        env!("CARGO_PKG_VERSION")
    ))
}

pub fn cmd_push(project: &str, target: PushTarget) -> Result<String, String> {
    let password = prompt_password("Master password: ")?;
    let vault = unlock_vault(&password)?;
    let project = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| format!("project not found: {project}"))?;

    for secret in &project.secrets {
        let mut cmd = platform_command(target, &secret.key, &secret.value);
        let _ = cmd.status().map_err(|e| e.to_string())?;
    }

    Ok(format!(
        "Pushing {} secrets to {}...",
        project.secrets.len(),
        push_target_name(target)
    ))
}

fn platform_command(target: PushTarget, key: &str, value: &str) -> Command {
    let mut cmd = match target {
        PushTarget::Vercel => Command::new("vercel"),
        PushTarget::Render => Command::new("render"),
        PushTarget::Railway => Command::new("railway"),
        PushTarget::Fly => Command::new("fly"),
        PushTarget::Netlify => Command::new("netlify"),
    };

    match target {
        PushTarget::Vercel => {
            cmd.args(["env", "add", key, value]);
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

pub fn summarize_projects(password: &str) -> Result<Vec<crate::vault_ops::ProjectSummary>, String> {
    let vault = unlock_vault(password)?;
    Ok(list_projects(&vault))
}

pub fn summarize_project_keys(password: &str, project: &str) -> Result<Vec<String>, String> {
    let vault = unlock_vault(password)?;
    list_secret_keys(&vault, project)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_file::{Project, Secret, VaultData, get_vault_path};
    use std::sync::Mutex;

    static CLI_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup() {
        let _ = fs::remove_file(".lokalvault");
        let _ = fs::remove_file(get_vault_path());
        let _ = fs::remove_file(get_vault_path().with_extension("lv.tmp"));
        let _ = fs::remove_file(Path::new("cli.env"));
    }

    fn sample_vault() -> VaultData {
        VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![
                    Secret {
                        key: "OPENAI_KEY".to_string(),
                        value: "test-value-123".to_string(),
                    },
                    Secret {
                        key: "DATABASE_URL".to_string(),
                        value: "postgres://db".to_string(),
                    },
                ],
            }],
        }
    }

    #[test]
    fn test_cmd_init_creates_config_file() {
        let _guard = CLI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        let message = cmd_init(Some("my-app")).unwrap();
        let config = fs::read_to_string(".lokalvault").unwrap();

        assert_eq!(message, "✓ Created .lokalvault");
        assert!(config.contains("name = \"my-app\""));
        cleanup();
    }

    #[test]
    fn test_summarize_projects_and_keys() {
        let _guard = CLI_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        let vault = sample_vault();
        let projects = crate::vault_ops::list_projects(&vault);
        let keys = crate::vault_ops::list_secret_keys(&vault, "my-app").unwrap();

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "my-app");
        assert_eq!(projects[0].secret_count, 2);
        assert_eq!(keys.len(), 2);
        cleanup();
    }

    #[test]
    fn test_platform_command_builds_expected_args() {
        let cmd = platform_command(PushTarget::Railway, "OPENAI_KEY", "value");
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(args, vec!["variables", "set", "OPENAI_KEY=value"]);
    }

    #[test]
    fn test_push_target_name_matches_expected_strings() {
        assert_eq!(push_target_name(PushTarget::Vercel), "vercel");
        assert_eq!(push_target_name(PushTarget::Netlify), "netlify");
    }
}

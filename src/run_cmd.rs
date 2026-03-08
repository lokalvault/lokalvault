use crate::crypto::generate_token;
use crate::daemon::{
    DaemonState, POC_SOCKET_PATH, fetch_all_secrets as fetch_all_secrets_from_state,
    register_token_phase1, register_token_phase2,
};
use crate::settings::read_settings;
use crate::vault_file::get_vault_path;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn cmd_run_poc(command: Vec<String>) -> Result<std::process::ExitStatus, String> {
    cmd_run_poc_with_socket(command, POC_SOCKET_PATH).await
}

pub async fn cmd_run(
    state: &DaemonState,
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, String> {
    if command.is_empty() {
        return Err("command cannot be empty".to_string());
    }

    let project_name = match project {
        Some(name) => name.to_string(),
        None => get_project_from_config()?
            .ok_or_else(|| "run lokalvault init first or pass --project".to_string())?,
    };

    let command_preview = command.join(" ");
    if !show_pin_dialog(&project_name, &command_preview)? {
        return Err("run approval denied".to_string());
    }

    let token = generate_token();
    let uid = unsafe { libc::geteuid() };
    register_token_phase1(state, &token, uid, &project_name)?;

    let secrets = fetch_all_secrets(state, &token, 0, uid)?;
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    inject_secrets_into_env(&mut cmd, &secrets, &token, &project_name, POC_SOCKET_PATH);
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let child_pid = child.id();

    let timeout_minutes = read_settings().session_timeout_minutes as u64;
    register_token_phase2(
        state,
        &token,
        child_pid,
        Duration::from_secs(timeout_minutes * 60),
    )?;
    child.wait().map_err(|e| e.to_string())
}

pub async fn cmd_run_unified(
    state: Option<&DaemonState>,
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, String> {
    if let Some(state) = state {
        return cmd_run(state, project, command).await;
    }

    if project.is_some() {
        return Err("vault is locked; run `lokalvault unlock` first".to_string());
    }

    if let Some(project_name) = get_project_from_config()? {
        let _ = project_name;
        return cmd_run_poc(command).await;
    }

    if get_vault_path().exists() {
        return Err("run lokalvault init first or pass --project".to_string());
    }

    match cmd_run_poc(command).await {
        Ok(status) => Ok(status),
        Err(error) if error.contains("No such file or directory") => {
            Err("run lokalvault init first or pass --project".to_string())
        }
        Err(error) => Err(error),
    }
}

pub async fn cmd_run_entry(
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, String> {
    let resolved_project = match project {
        Some(project) => Some(project.to_string()),
        None => get_project_from_config()?,
    };

    if crate::ipc_client::is_daemon_running() && resolved_project.is_some() {
        return Err("real daemon-backed run path is not wired yet".to_string());
    }

    if crate::ipc_client::is_daemon_running() && resolved_project.is_none() {
        return Err("run lokalvault init first or pass --project".to_string());
    }

    if !crate::ipc_client::is_daemon_running() && resolved_project.is_none() {
        return match cmd_run_poc(command).await {
            Ok(status) => Ok(status),
            Err(error) if error.contains("No such file or directory") => {
                Err("run lokalvault init first or pass --project".to_string())
            }
            Err(error) => Err(error),
        };
    }

    if !crate::ipc_client::is_daemon_running() && project.is_some() {
        return Err("vault is locked - run lokalvault unlock first".to_string());
    }

    if resolved_project.is_some() {
        return cmd_run_poc(command).await;
    }

    cmd_run_unified(None, resolved_project.as_deref(), command).await
}

pub fn show_pin_dialog(project: &str, _command_preview: &str) -> Result<bool, String> {
    let random = generate_token();
    let code = &random[0..2];
    print!("Type [{code}] to allow access to '{project}': ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;
    Ok(input.trim() == code)
}

pub fn get_project_from_config() -> Result<Option<String>, String> {
    let path = PathBuf::from(".lokalvault");
    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("name = ") {
            return Ok(Some(name.trim_matches('"').to_string()));
        }
    }

    Ok(read_settings().default_project)
}

pub fn inject_secrets_into_env(
    cmd: &mut Command,
    secrets: &HashMap<String, String>,
    token: &str,
    project: &str,
    socket_path: &str,
) {
    for (key, value) in secrets {
        cmd.env(key, value);
    }
    cmd.env("LV_RUN_TOKEN", token);
    cmd.env("LV_PROJECT", project);
    cmd.env("LV_SOCKET", socket_path);
}

pub fn fetch_all_secrets(
    state: &DaemonState,
    token: &str,
    pid: u32,
    uid: u32,
) -> Result<HashMap<String, String>, String> {
    fetch_all_secrets_from_state(state, token, pid, uid).map_err(|e| e.message())
}

async fn cmd_run_poc_with_socket(
    command: Vec<String>,
    socket_path: &str,
) -> Result<std::process::ExitStatus, String> {
    if command.is_empty() {
        return Err("command cannot be empty".to_string());
    }

    let secret_value = fetch_poc_secret(socket_path).await?;

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    cmd.env("OPENAI_KEY", secret_value);
    cmd.status().map_err(|e| e.to_string())
}

async fn fetch_poc_secret(socket_path: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| e.to_string())?;

    let request = serde_json::json!({
        "type": "get_secret",
        "key": "OPENAI_KEY",
        "uid": unsafe { libc::geteuid() },
        "pid": 0
    })
    .to_string();
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    let response_json: serde_json::Value =
        serde_json::from_slice(&response).map_err(|e| e.to_string())?;
    if let Some(error) = response_json
        .get("error")
        .and_then(serde_json::Value::as_str)
    {
        return Err(error.to_string());
    }

    response_json
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.to_string())
        .ok_or_else(|| "daemon response missing secret value".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{run_daemon_poc_at_path, start_daemon, unique_poc_socket_path};
    use crate::vault_file::{Project, Secret, VaultData};
    use std::path::Path;

    #[tokio::test]
    async fn test_cmd_run_poc_injects_openai_key_into_child() {
        let socket_path = unique_poc_socket_path("run-cmd");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let status = cmd_run_poc_with_socket(
            vec![
                "python3".to_string(),
                "-c".to_string(),
                "import os,sys; sys.exit(0 if os.environ.get('OPENAI_KEY') == 'test-value-123' else 1)"
                    .to_string(),
            ],
            &socket_path_string,
        )
        .await
        .unwrap();

        assert!(status.success());
        assert!(daemon.await.unwrap().is_ok());
    }

    #[test]
    fn test_get_project_from_config_reads_project_name() {
        fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

        let project = get_project_from_config().unwrap();
        assert_eq!(project, Some("my-app".to_string()));

        let _ = fs::remove_file(".lokalvault");
    }

    #[test]
    fn test_inject_secrets_into_env_sets_metadata_and_values() {
        let mut cmd = Command::new("env");
        let mut secrets = HashMap::new();
        secrets.insert("OPENAI_KEY".to_string(), "test-value-123".to_string());

        inject_secrets_into_env(&mut cmd, &secrets, "token-1", "my-app", "/tmp/socket");

        let output = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("OPENAI_KEY=test-value-123"));
        assert!(stdout.contains("LV_RUN_TOKEN=token-1"));
        assert!(stdout.contains("LV_PROJECT=my-app"));
        assert!(stdout.contains("LV_SOCKET=/tmp/socket"));
    }

    #[test]
    fn test_fetch_all_secrets_returns_project_values_from_daemon_state() {
        let state = start_daemon(VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: "test-value-123".to_string(),
                }],
            }],
        });

        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 0, Duration::from_secs(60)).unwrap();

        let secrets = fetch_all_secrets(&state, "token-1", 0, 501).unwrap();
        assert_eq!(
            secrets.get("OPENAI_KEY"),
            Some(&"test-value-123".to_string())
        );
    }

    #[test]
    fn test_fetch_all_secrets_propagates_invalid_token_error() {
        let state = start_daemon(VaultData::default());
        let error = fetch_all_secrets(&state, "missing-token", 0, 501).unwrap_err();

        assert_eq!(error, "token invalid");
    }
}

use crate::crypto::generate_token;
use crate::daemon::{
    DaemonState, fetch_all_secrets_for_boundary as fetch_all_secrets_from_state,
    fetch_all_secrets_for_pending_boundary as fetch_all_secrets_pending, poc_socket_path,
    register_token_phase1, register_token_phase2,
};
use crate::errors::AppError;
use crate::ipc_client::send_ipc_request;
use crate::settings::read_settings;
use crate::vault_file::get_vault_path;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

#[cfg(test)]
static TEST_SHELL_PROGRAM: OnceLock<Mutex<Option<String>>> = OnceLock::new();
const TEST_PIN_APPROVAL_ENV: &str = "LOKALVAULT_TEST_PIN_APPROVAL";

fn runtime_validation_error(message: impl Into<String>) -> AppError {
    AppError::ValidationError(message.into())
}

fn daemon_response_error(response: &serde_json::Value) -> AppError {
    if response.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
        return AppError::from_daemon_response(response);
    }
    AppError::InvalidResponse("unknown daemon error".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectSection {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeysSection {
    pub required: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    pub project: ProjectSection,
    #[serde(default)]
    pub keys: KeysSection,
}

pub async fn cmd_run_poc(command: Vec<String>) -> Result<std::process::ExitStatus, AppError> {
    let socket_path = poc_socket_path();
    let socket_path = socket_path.to_string_lossy().to_string();
    cmd_run_poc_with_socket(command, &socket_path).await
}

pub async fn cmd_run(
    state: &DaemonState,
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, AppError> {
    if command.is_empty() {
        return Err(runtime_validation_error("command cannot be empty"));
    }

    let project_name = match project {
        Some(name) => name.to_string(),
        None => get_project_from_config()?.ok_or_else(|| {
            runtime_validation_error("run lokalvault init first or pass --project")
        })?,
    };

    let command_preview = command.join(" ");
    if !show_pin_dialog(&project_name, &command_preview)? {
        return Err(runtime_validation_error("run approval denied"));
    }

    let token = generate_token();
    let uid = unsafe { libc::geteuid() };
    register_token_phase1(state, &token, uid, &project_name)?;

    let secrets = fetch_all_secrets_pending_wrapper(state, &token, uid)?;
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    let socket_path = crate::ipc_client::get_socket_path();
    inject_secrets_into_env(
        &mut cmd,
        &secrets,
        &token,
        &project_name,
        &socket_path.display().to_string(),
    );
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::ProcessError(e.to_string()))?;
    let child_pid = child.id();

    let timeout_minutes = read_settings().session_timeout_minutes as u64;
    register_token_phase2(
        state,
        &token,
        child_pid,
        Duration::from_secs(timeout_minutes * 60),
    )?;
    child
        .wait()
        .map_err(|e| AppError::ProcessError(e.to_string()))
}

pub async fn cmd_run_unified(
    state: Option<&DaemonState>,
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, AppError> {
    if let Some(state) = state {
        return cmd_run(state, project, command).await;
    }

    if project.is_some() {
        return Err(runtime_validation_error(
            "vault is locked; run `lokalvault unlock` first",
        ));
    }

    if get_project_from_config()?.is_some() {
        return Err(runtime_validation_error(
            "vault is locked; run `lokalvault unlock` first",
        ));
    }

    if get_vault_path().exists() {
        return Err(runtime_validation_error(
            "run lokalvault init first or pass --project",
        ));
    }

    match cmd_run_poc(command).await {
        Ok(status) => Ok(status),
        Err(error) if error.to_string().contains("No such file or directory") => Err(
            runtime_validation_error("run lokalvault init first or pass --project"),
        ),
        Err(error) => Err(error),
    }
}

pub async fn cmd_run_entry(
    project: Option<&str>,
    command: Vec<String>,
    watch_mode: bool,
) -> Result<std::process::ExitStatus, AppError> {
    if watch_mode {
        return cmd_run_watch(project, command).await;
    }

    let resolved_project = match project {
        Some(project) => Some(project.to_string()),
        None => get_project_from_config()?,
    };

    if crate::ipc_client::is_daemon_running() && resolved_project.is_some() {
        return run_with_real_daemon(resolved_project.as_deref().unwrap(), command).await;
    }

    if crate::ipc_client::is_daemon_running() && resolved_project.is_none() {
        return Err(runtime_validation_error(
            "run lokalvault init first or pass --project",
        ));
    }

    if !crate::ipc_client::is_daemon_running() && resolved_project.is_none() {
        return match cmd_run_poc(command).await {
            Ok(status) => Ok(status),
            Err(error) if error.to_string().contains("No such file or directory") => Err(
                runtime_validation_error("run lokalvault init first or pass --project"),
            ),
            Err(error) => Err(error),
        };
    }

    if !crate::ipc_client::is_daemon_running() && project.is_some() {
        return Err(runtime_validation_error(
            "vault is locked - run lokalvault unlock first",
        ));
    }

    if resolved_project.is_some() {
        return Err(runtime_validation_error(
            "vault is locked - run lokalvault unlock first",
        ));
    }

    cmd_run_unified(None, resolved_project.as_deref(), command).await
}

async fn cmd_run_watch(
    project: Option<&str>,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, AppError> {
    if command.is_empty() {
        return Err(runtime_validation_error("command cannot be empty"));
    }

    let (tx, mut rx) = watch::channel(false);
    let watcher = start_watch_thread(tx)?;
    eprintln!("Watch mode active. Monitoring all files in current directory.");
    eprintln!("Note: no debounce or ignore rules applied in this version.");
    loop {
        let mut child = spawn_run_child(project, &command).await?;
        let status = wait_with_signal_passthrough(&mut child, Some(&mut rx)).await?;
        if !*rx.borrow() {
            drop(watcher);
            return Ok(status);
        }
        rx.borrow_and_update();
    }
}

pub fn read_project_config() -> Result<Option<ProjectConfig>, AppError> {
    let path = PathBuf::from(".lokalvault");
    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(path)?;
    let config: ProjectConfig = toml::from_str(&contents)?;
    Ok(Some(config))
}

pub fn write_project_config(config: &ProjectConfig) -> Result<(), AppError> {
    let contents = toml::to_string_pretty(config)?;
    fs::write(".lokalvault", contents)?;
    Ok(())
}

pub fn merge_project_config_manifest(
    existing: Option<ProjectConfig>,
    project: &str,
    required: &[String],
    optional: &[String],
) -> ProjectConfig {
    let mut config = existing.unwrap_or_default();
    config.project.name = project.to_string();
    config.keys.required = dedupe_in_order(
        config
            .keys
            .required
            .into_iter()
            .chain(required.iter().cloned()),
    );
    config.keys.optional = dedupe_in_order(
        config
            .keys
            .optional
            .into_iter()
            .chain(optional.iter().cloned()),
    );
    config
}

fn dedupe_in_order(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }
    deduped
}

async fn run_with_real_daemon(
    project: &str,
    command: Vec<String>,
) -> Result<std::process::ExitStatus, AppError> {
    if command.is_empty() {
        return Err(runtime_validation_error("command cannot be empty"));
    }

    let token = generate_token();
    let phase1 = send_ipc_request(serde_json::json!({
        "type": "register_token_phase1",
        "token": token,
        "project": project,
    }))?;
    if phase1.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(daemon_response_error(&phase1));
    }

    let secrets_response = send_ipc_request(serde_json::json!({
        "type": "get_all_secrets_for_run",
        "token": token,
    }))?;
    let secrets = secrets_response["secrets"]
        .as_object()
        .ok_or_else(|| AppError::InvalidResponse("daemon response missing secrets".to_string()))?
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_string()))
        .collect::<HashMap<_, _>>();

    if let Some(config) = read_project_config()?
        && config.project.name == project
    {
        let missing = config
            .keys
            .required
            .iter()
            .filter(|key| !secrets.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(runtime_validation_error(format!(
                "Missing required secrets for project {project}: {}",
                missing.join(", ")
            )));
        }
    }

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    let socket_path = crate::ipc_client::get_socket_path();
    inject_secrets_into_env(
        &mut cmd,
        &secrets,
        &token,
        project,
        &socket_path.display().to_string(),
    );
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::ProcessError(e.to_string()))?;

    let phase2 = send_ipc_request(serde_json::json!({
        "type": "register_token_phase2",
        "token": token,
        "pid": child.id(),
    }))?;
    if phase2.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(daemon_response_error(&phase2));
    }

    wait_with_signal_passthrough(&mut child, None).await
}

pub fn show_pin_dialog(project: &str, _command_preview: &str) -> Result<bool, AppError> {
    #[cfg(debug_assertions)]
    if let Ok(value) = std::env::var(TEST_PIN_APPROVAL_ENV) {
        let normalized = value.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "1" | "true" | "yes" | "allow") {
            return Ok(true);
        }
        if matches!(normalized.as_str(), "0" | "false" | "no" | "deny") {
            return Ok(false);
        }
    }

    use rand::Rng;
    let code = format!("{:02}", rand::thread_rng().gen_range(0u8..=99));
    print!("Type [{code}] to allow access to '{project}': ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(AppError::from)?;
    Ok(input.trim() == code)
}

pub fn get_project_from_config() -> Result<Option<String>, AppError> {
    if let Some(config) = read_project_config()?
        && !config.project.name.is_empty()
    {
        return Ok(Some(config.project.name));
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

pub fn shell_program() -> String {
    #[cfg(test)]
    if let Some(shell) = TEST_SHELL_PROGRAM
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return shell;
    }

    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
}

pub fn configure_interactive_shell(cmd: &mut Command) {
    cmd.arg("-l");
    cmd.arg("-i");
}

pub fn fetch_all_secrets(
    state: &DaemonState,
    token: &str,
    pid: u32,
    uid: u32,
) -> Result<HashMap<String, String>, AppError> {
    fetch_all_secrets_from_state(state, token, pid, uid)
        .map_err(|e| AppError::from_daemon_message(&e.message()))
}

pub fn fetch_all_secrets_pending_wrapper(
    state: &DaemonState,
    token: &str,
    uid: u32,
) -> Result<HashMap<String, String>, AppError> {
    fetch_all_secrets_pending(state, token, uid)
        .map_err(|e| AppError::from_daemon_message(&e.message()))
}

async fn cmd_run_poc_with_socket(
    command: Vec<String>,
    socket_path: &str,
) -> Result<std::process::ExitStatus, AppError> {
    if command.is_empty() {
        return Err(runtime_validation_error("command cannot be empty"));
    }

    let secret_value = fetch_poc_secret(socket_path).await?;

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    cmd.env("OPENAI_KEY", secret_value);
    let mut child = cmd
        .spawn()
        .map_err(|e| AppError::ProcessError(e.to_string()))?;
    wait_with_signal_passthrough(&mut child, None).await
}

async fn spawn_run_child(project: Option<&str>, command: &[String]) -> Result<Child, AppError> {
    let resolved_project = match project {
        Some(project) => Some(project.to_string()),
        None => get_project_from_config()?,
    };

    if crate::ipc_client::is_daemon_running() && resolved_project.is_some() {
        return spawn_with_real_daemon(resolved_project.as_deref().unwrap(), command.to_vec())
            .await;
    }

    spawn_poc_child(command.to_vec()).await
}

async fn spawn_with_real_daemon(project: &str, command: Vec<String>) -> Result<Child, AppError> {
    let token = generate_token();
    let phase1 = send_ipc_request(serde_json::json!({
        "type": "register_token_phase1",
        "token": token,
        "project": project,
    }))?;
    if phase1.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(daemon_response_error(&phase1));
    }

    let secrets_response = send_ipc_request(serde_json::json!({
        "type": "get_all_secrets_for_run",
        "token": token,
    }))?;
    let secrets = secrets_response["secrets"]
        .as_object()
        .ok_or_else(|| AppError::InvalidResponse("daemon response missing secrets".to_string()))?
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_string()))
        .collect::<HashMap<_, _>>();

    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    let socket_path = crate::ipc_client::get_socket_path();
    inject_secrets_into_env(
        &mut cmd,
        &secrets,
        &token,
        project,
        &socket_path.display().to_string(),
    );
    let child = cmd
        .spawn()
        .map_err(|e| AppError::ProcessError(e.to_string()))?;

    let phase2 = send_ipc_request(serde_json::json!({
        "type": "register_token_phase2",
        "token": token,
        "pid": child.id(),
    }))?;
    if phase2.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(daemon_response_error(&phase2));
    }

    Ok(child)
}

async fn spawn_poc_child(command: Vec<String>) -> Result<Child, AppError> {
    let socket_path = poc_socket_path();
    let socket_path = socket_path.to_string_lossy().to_string();
    let secret_value = fetch_poc_secret(&socket_path).await?;
    let mut cmd = Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }
    cmd.env("OPENAI_KEY", secret_value);
    cmd.spawn()
        .map_err(|e| AppError::ProcessError(e.to_string()))
}

async fn wait_with_signal_passthrough(
    child: &mut Child,
    mut watch_rx: Option<&mut watch::Receiver<bool>>,
) -> Result<std::process::ExitStatus, AppError> {
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| AppError::ProcessError(e.to_string()))?;

    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| AppError::ProcessError(e.to_string()))?
        {
            return Ok(status);
        }

        if let Some(rx) = &mut watch_rx
            && rx.has_changed().unwrap_or(false)
        {
            forward_terminate(child)?;
            return child
                .wait()
                .map_err(|e| AppError::ProcessError(e.to_string()));
        }

        #[cfg(unix)]
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = interrupt.recv() => {
                forward_interrupt(child)?;
            }
        }

        #[cfg(not(unix))]
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Some(rx) = &mut watch_rx
            && rx.has_changed().unwrap_or(false)
        {
            let _ = rx.borrow_and_update();
            forward_terminate(child)?;
            return child
                .wait()
                .map_err(|e| AppError::ProcessError(e.to_string()));
        }
    }
}

#[cfg(unix)]
fn forward_interrupt(child: &Child) -> Result<(), AppError> {
    let rc = unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    if rc == 0 {
        Ok(())
    } else {
        Err(AppError::ProcessError(
            std::io::Error::last_os_error().to_string(),
        ))
    }
}

fn forward_terminate(child: &Child) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        if rc == 0 {
            return Ok(());
        }
        Err(AppError::ProcessError(
            std::io::Error::last_os_error().to_string(),
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = child;
        Ok(())
    }
}

fn start_watch_thread(
    tx: watch::Sender<bool>,
) -> Result<Arc<notify::RecommendedWatcher>, AppError> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let mut watcher = RecommendedWatcher::new(
        move |result: Result<notify::Event, notify::Error>| {
            if let Ok(event) = result {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        let _ = tx.send(true);
                    }
                    _ => {}
                }
            }
        },
        Config::default(),
    )
    .map_err(|e| AppError::ProcessError(e.to_string()))?;
    watcher
        .watch(std::path::Path::new("."), RecursiveMode::Recursive)
        .map_err(|e| AppError::ProcessError(e.to_string()))?;
    Ok(Arc::new(watcher))
}

async fn fetch_poc_secret(socket_path: &str) -> Result<String, AppError> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| AppError::IpcError(e.to_string()))?;

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
        .map_err(|e| AppError::IpcError(e.to_string()))?;
    stream
        .shutdown()
        .await
        .map_err(|e| AppError::IpcError(e.to_string()))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| AppError::IpcError(e.to_string()))?;

    let response_json: serde_json::Value = serde_json::from_slice(&response)
        .map_err(|e| AppError::InvalidResponse(format!("daemon returned invalid JSON: {e}")))?;
    if let Some(error) = response_json
        .get("error")
        .and_then(serde_json::Value::as_str)
    {
        return Err(AppError::from_daemon_message(error));
    }

    response_json
        .get("value")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.to_string())
        .ok_or_else(|| {
            AppError::InvalidResponse("daemon response missing secret value".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{run_daemon_poc_at_path, start_daemon, unique_poc_socket_path};
    use crate::vault_file::{Project, Secret, VaultData};
    use std::path::Path;
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    fn unix_sockets_available() -> bool {
        let socket_path = unique_poc_socket_path("run-cmd-probe");
        let _ = std::fs::remove_file(&socket_path);
        let result = std::os::unix::net::UnixListener::bind(&socket_path);
        match result {
            Ok(listener) => {
                drop(listener);
                let _ = std::fs::remove_file(&socket_path);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
            Err(error) => panic!("failed to probe unix socket support: {error}"),
        }
    }

    async fn wait_for_poc_socket(socket_path: &Path, daemon: &JoinHandle<Result<(), String>>) {
        for _ in 0..100 {
            if socket_path.exists() {
                return;
            }
            if daemon.is_finished() {
                panic!(
                    "daemon task exited before socket became ready: {}",
                    socket_path.display()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("daemon socket did not appear: {}", socket_path.display());
    }

    #[tokio::test]
    async fn test_cmd_run_poc_injects_openai_key_into_child() {
        if !unix_sockets_available() {
            return;
        }
        let socket_path = unique_poc_socket_path("run-cmd");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        wait_for_poc_socket(Path::new(&socket_path_string), &daemon).await;

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
        assert!(
            timeout(Duration::from_secs(3), daemon)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
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
    fn test_shell_program_prefers_env_shell() {
        *TEST_SHELL_PROGRAM
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some("/bin/zsh".to_string());
        assert_eq!(shell_program(), "/bin/zsh");
        *TEST_SHELL_PROGRAM
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }

    #[test]
    fn test_configure_interactive_shell_adds_interactive_flag() {
        let mut cmd = Command::new("/bin/zsh");
        configure_interactive_shell(&mut cmd);

        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(args, vec!["-l".to_string(), "-i".to_string()]);
    }

    #[test]
    fn test_fetch_all_secrets_returns_project_values_from_daemon_state() {
        let state = start_daemon(VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: zeroize::Zeroizing::new("test-value-123".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            }],
        });

        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let secrets = fetch_all_secrets(&state, "token-1", 777, 501).unwrap();
        assert_eq!(
            secrets.get("OPENAI_KEY"),
            Some(&"test-value-123".to_string())
        );
    }

    #[test]
    fn test_fetch_all_secrets_propagates_invalid_token_error() {
        let state = start_daemon(VaultData::default());
        let error = fetch_all_secrets(&state, "missing-token", 0, 501).unwrap_err();

        assert_eq!(error, AppError::TokenInvalid);
    }

    #[test]
    fn test_fetch_all_secrets_pending_wrapper_works_before_phase2() {
        let state = start_daemon(VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: zeroize::Zeroizing::new("test-value-123".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            }],
        });

        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();

        let secrets = fetch_all_secrets_pending_wrapper(&state, "token-1", 501).unwrap();
        assert_eq!(
            secrets.get("OPENAI_KEY"),
            Some(&"test-value-123".to_string())
        );
    }

    #[test]
    fn test_merge_project_config_manifest_writes_new_config() {
        let config = merge_project_config_manifest(
            None,
            "my-app",
            &["OPENAI_KEY".to_string(), "DATABASE_URL".to_string()],
            &["STRIPE_KEY".to_string()],
        );

        assert_eq!(config.project.name, "my-app");
        assert_eq!(config.keys.required, vec!["OPENAI_KEY", "DATABASE_URL"]);
        assert_eq!(config.keys.optional, vec!["STRIPE_KEY"]);
    }

    #[test]
    fn test_merge_project_config_manifest_preserves_order_and_dedupes() {
        let config = merge_project_config_manifest(
            Some(ProjectConfig {
                project: ProjectSection {
                    name: "old-project".to_string(),
                },
                keys: KeysSection {
                    required: vec!["OPENAI_KEY".to_string(), "DATABASE_URL".to_string()],
                    optional: vec!["OPTIONAL_ONE".to_string()],
                },
            }),
            "my-app",
            &[
                "DATABASE_URL".to_string(),
                "NEW_REQUIRED".to_string(),
                "OPENAI_KEY".to_string(),
            ],
            &[
                "OPTIONAL_ONE".to_string(),
                "OPTIONAL_TWO".to_string(),
                "OPTIONAL_TWO".to_string(),
            ],
        );

        assert_eq!(config.project.name, "my-app");
        assert_eq!(
            config.keys.required,
            vec!["OPENAI_KEY", "DATABASE_URL", "NEW_REQUIRED"]
        );
        assert_eq!(config.keys.optional, vec!["OPTIONAL_ONE", "OPTIONAL_TWO"]);
    }
}

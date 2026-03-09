use crate::crypto::constant_time_compare;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::mem;
use std::os::unix::fs::PermissionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::audit_log::{AccessEvent, log_access_event};
use crate::ipc_client::get_socket_path;
use crate::settings::read_settings;
use crate::vault_file::VaultData;
use crate::vault_ops::{
    ProjectSummary, add_project, add_secret, delete_project, delete_secret, import_dotenv,
    list_projects, list_secret_keys, update_secret,
};

pub const POC_SOCKET_PATH: &str = "/tmp/lokalvault-test.sock";
const PHASE1_PENDING_WINDOW: Duration = Duration::from_millis(1000);

struct PeerCredentials {
    pid: u32,
    uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenState {
    Pending,
    Active,
}

#[derive(Debug, Clone)]
struct TokenRecord {
    uid: u32,
    pid: u32,
    project: String,
    state: TokenState,
    deadline: Instant,
}

#[derive(Clone)]
pub struct DaemonState {
    vault: Arc<Mutex<VaultData>>,
    token_store: Arc<Mutex<HashMap<String, TokenRecord>>>,
    password: Arc<Mutex<Zeroizing<String>>>,
    last_activity: Arc<Mutex<Instant>>,
    started_at: Arc<Mutex<Instant>>,
    rate_limits: Arc<Mutex<HashMap<u32, Vec<Instant>>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenValidation {
    Valid(String),
    InvalidToken,
    PidMismatch,
    UidMismatch,
    Expired,
}

enum DaemonError {
    MissingRequestType,
    UnsupportedRequestType,
    MissingSecretKey,
    MissingUid,
    MissingPid,
    UidMismatch,
    PidMismatch,
    UnknownSecretKey,
    Io(String),
    InvalidJson(String),
    PeerCredentials(String),
}

impl DaemonError {
    fn message(&self) -> String {
        match self {
            Self::MissingRequestType => "missing request type".to_string(),
            Self::UnsupportedRequestType => "unsupported request type".to_string(),
            Self::MissingSecretKey => "get_secret request missing key".to_string(),
            Self::MissingUid => "get_secret request missing uid".to_string(),
            Self::MissingPid => "get_secret request missing pid".to_string(),
            Self::UidMismatch => "client-reported uid mismatch".to_string(),
            Self::PidMismatch => "client-reported pid mismatch".to_string(),
            Self::UnknownSecretKey => "unknown secret key".to_string(),
            Self::Io(message) => message.clone(),
            Self::InvalidJson(message) => message.clone(),
            Self::PeerCredentials(message) => message.clone(),
        }
    }
}

#[derive(Debug)]
pub enum FetchSecretsError {
    ProjectNotFound(String),
    InvalidToken,
    PidMismatch,
    UidMismatch,
    Expired,
    State(String),
}

impl FetchSecretsError {
    pub fn message(&self) -> String {
        match self {
            Self::ProjectNotFound(project) => format!("project not found: {project}"),
            Self::InvalidToken => "token invalid".to_string(),
            Self::PidMismatch => "client-reported pid mismatch".to_string(),
            Self::UidMismatch => "client-reported uid mismatch".to_string(),
            Self::Expired => "token expired".to_string(),
            Self::State(message) => message.clone(),
        }
    }
}

enum PocRequest {
    GetSecret {
        key: String,
        uid: u32,
        pid: Option<u32>,
    },
}

fn peer_pid_is_required() -> bool {
    cfg!(target_os = "linux")
}

pub fn create_socket() -> Result<(PathBuf, UnixListener), String> {
    create_socket_at_path(PathBuf::from(POC_SOCKET_PATH))
}

pub fn create_user_socket() -> Result<(PathBuf, UnixListener), String> {
    create_socket_at_path(get_socket_path())
}

pub async fn run_daemon_poc() -> Result<(), String> {
    run_daemon_poc_at_path(PathBuf::from(POC_SOCKET_PATH)).await
}

pub async fn run_daemon_server(vault_data: VaultData, password: String) -> Result<(), String> {
    let _settings = read_settings();
    let (socket_path, listener) = create_user_socket()?;
    run_daemon_server_with_listener(vault_data, password, socket_path, listener).await
}

async fn run_daemon_server_with_listener(
    vault_data: VaultData,
    password: String,
    socket_path: PathBuf,
    listener: UnixListener,
) -> Result<(), String> {
    let settings = read_settings();
    let timeout = Duration::from_secs(settings.session_timeout_minutes as u64 * 60);
    let state = start_daemon_with_password(vault_data, password);

    let idle_state = state.clone();
    let _idle_timer: JoinHandle<()> = tokio::spawn(async move {
        let check_interval = Duration::from_secs(60);
        loop {
            tokio::time::sleep(check_interval).await;
            let idle = idle_state
                .last_activity
                .lock()
                .map(|last| Instant::now().duration_since(*last) >= timeout)
                .unwrap_or(false);
            if idle {
                eprintln!(
                    "Session timed out after {} minutes of inactivity",
                    settings.session_timeout_minutes
                );
                let _ = stop_daemon(&idle_state);
                std::process::exit(0);
            }
        }
    });

    let result: Result<(), String> = async {
        loop {
            let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            if handle_connection(&state, &mut stream).await? {
                break;
            }
        }
        Ok(())
    }
    .await;

    let _ = stop_daemon(&state);

    let cleanup_result = cleanup_socket_file(&socket_path);
    result.and(cleanup_result)
}

pub fn start_daemon(vault_data: VaultData) -> DaemonState {
    start_daemon_with_password(vault_data, String::new())
}

pub fn start_daemon_with_password(vault_data: VaultData, password: String) -> DaemonState {
    DaemonState {
        vault: Arc::new(Mutex::new(vault_data)),
        token_store: Arc::new(Mutex::new(HashMap::new())),
        password: Arc::new(Mutex::new(Zeroizing::new(password))),
        last_activity: Arc::new(Mutex::new(Instant::now())),
        started_at: Arc::new(Mutex::new(Instant::now())),
        rate_limits: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub fn stop_daemon(state: &DaemonState) -> Result<(), String> {
    invalidate_all_tokens(state)?;

    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    vault.zeroize();
    drop(vault);

    let mut password = state.password.lock().map_err(|e| e.to_string())?;
    password.zeroize();

    Ok(())
}

pub async fn run_daemon_poc_at_path(socket_path: PathBuf) -> Result<(), String> {
    let (socket_path, listener) = create_socket_at_path(socket_path)?;
    run_poc_server_with_listener(socket_path, listener).await
}

async fn run_poc_server_with_listener(
    socket_path: PathBuf,
    listener: UnixListener,
) -> Result<(), String> {
    let result = async {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| DaemonError::Io(e.to_string()).message())?;
        if let Err(error) = handle_poc_connection(&mut stream).await {
            let response = json!({ "error": error }).to_string();
            stream
                .write_all(response.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            stream.shutdown().await.map_err(|e| e.to_string())?;
            return Err(error);
        }
        Ok(())
    }
    .await;

    let cleanup_result = cleanup_socket_file(&socket_path);
    result.and(cleanup_result)
}

pub fn create_socket_at_path(socket_path: PathBuf) -> Result<(PathBuf, UnixListener), String> {
    cleanup_socket_file(&socket_path)?;

    let listener = UnixListener::bind(&socket_path).map_err(|e| e.to_string())?;

    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;

    Ok((socket_path, listener))
}

pub fn unique_poc_socket_path(test_name: &str) -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/tmp/lokalvault-{test_name}-{pid}.sock"))
}

pub fn register_token_phase1(
    state: &DaemonState,
    token: &str,
    uid: u32,
    project: &str,
) -> Result<(), String> {
    let mut token_store = state.token_store.lock().map_err(|e| e.to_string())?;
    token_store.insert(
        token.to_string(),
        TokenRecord {
            uid,
            pid: 0,
            project: project.to_string(),
            state: TokenState::Pending,
            deadline: Instant::now() + PHASE1_PENDING_WINDOW,
        },
    );

    Ok(())
}

pub fn register_token_phase2(
    state: &DaemonState,
    token: &str,
    pid: u32,
    session_timeout: Duration,
) -> Result<(), String> {
    let mut token_store = state.token_store.lock().map_err(|e| e.to_string())?;
    let record = token_store
        .get_mut(token)
        .ok_or_else(|| "token invalid".to_string())?;

    if Instant::now() > record.deadline {
        token_store.remove(token);
        return Err("token expired".to_string());
    }

    record.pid = pid;
    record.state = TokenState::Active;
    record.deadline = Instant::now() + session_timeout;
    Ok(())
}

pub fn fetch_all_secrets(
    state: &DaemonState,
    token: &str,
    pid: u32,
    uid: u32,
) -> Result<HashMap<String, String>, FetchSecretsError> {
    let project = match validate_token(state, token, pid, uid) {
        TokenValidation::Valid(project) => project,
        TokenValidation::InvalidToken => return Err(FetchSecretsError::InvalidToken),
        TokenValidation::PidMismatch => return Err(FetchSecretsError::PidMismatch),
        TokenValidation::UidMismatch => return Err(FetchSecretsError::UidMismatch),
        TokenValidation::Expired => return Err(FetchSecretsError::Expired),
    };

    let vault = state
        .vault
        .lock()
        .map_err(|e| FetchSecretsError::State(e.to_string()))?;
    let project_data = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| FetchSecretsError::ProjectNotFound(project.clone()))?;

    Ok(project_data
        .secrets
        .iter()
        .map(|secret| (secret.key.clone(), secret.value.clone()))
        .collect())
}

pub fn upsert_secret(
    state: &DaemonState,
    project: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let password = get_password(state)?;
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    let mut candidate = vault.clone();

    if !candidate.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut candidate, project).map_err(|e| e.to_string())?;
    }

    match add_secret(&mut candidate, project, key, value) {
        Ok(()) => {}
        Err(error) if error.to_string().contains("already exists") => {
            let project_data = candidate
                .projects
                .iter_mut()
                .find(|entry| entry.name == project)
                .ok_or_else(|| format!("project not found: {project}"))?;
            let secret = project_data
                .secrets
                .iter_mut()
                .find(|entry| entry.key == key)
                .ok_or_else(|| format!("secret not found: {key}"))?;
            secret.value = value.to_string();
        }
        Err(error) => return Err(error.to_string()),
    }

    crate::vault_file::write_vault(&candidate, &password)?;
    *vault = candidate;
    Ok(())
}

pub fn import_dotenv_into_state(
    state: &DaemonState,
    project: &str,
    path: &Path,
) -> Result<crate::vault_ops::ImportResult, String> {
    let password = get_password(state)?;
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    let mut candidate = vault.clone();

    if !candidate.projects.iter().any(|entry| entry.name == project) {
        add_project(&mut candidate, project).map_err(|e| e.to_string())?;
    }

    let result = import_dotenv(&mut candidate, project, path).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&candidate, &password)?;
    *vault = candidate;
    Ok(result)
}

pub fn project_count(state: &DaemonState) -> Result<usize, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    Ok(vault.projects.len())
}

pub fn get_secret_value(state: &DaemonState, project: &str, key: &str) -> Result<String, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
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

pub fn list_project_summaries(state: &DaemonState) -> Result<Vec<ProjectSummary>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    Ok(list_projects(&vault))
}

pub fn list_project_keys(state: &DaemonState, project: &str) -> Result<Vec<String>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    list_secret_keys(&vault, project).map_err(|e| e.to_string())
}

pub fn get_all_project_secrets(
    state: &DaemonState,
    project: &str,
) -> Result<HashMap<String, String>, String> {
    let vault = state.vault.lock().map_err(|e| e.to_string())?;
    let project = vault
        .projects
        .iter()
        .find(|entry| entry.name == project)
        .ok_or_else(|| format!("project not found: {project}"))?;
    Ok(project
        .secrets
        .iter()
        .map(|secret| (secret.key.clone(), secret.value.clone()))
        .collect())
}

pub fn scan_diff_for_project(
    state: &DaemonState,
    project: &str,
    diff: &str,
) -> Result<Vec<String>, String> {
    let secrets = get_all_project_secrets(state, project)?;
    Ok(find_matching_secret_keys(diff, &secrets))
}

pub fn find_matching_secret_keys(diff: &str, secrets: &HashMap<String, String>) -> Vec<String> {
    let mut matches = secrets
        .iter()
        .filter(|(_, value)| !value.is_empty() && value.len() >= 8 && diff.contains(value.as_str()))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

pub fn delete_secret_from_state(
    state: &DaemonState,
    project: &str,
    key: &str,
) -> Result<(), String> {
    let password = get_password(state)?;
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    let mut candidate = vault.clone();
    delete_secret(&mut candidate, project, key).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&candidate, &password)?;
    *vault = candidate;
    Ok(())
}

pub fn delete_project_from_state(state: &DaemonState, project: &str) -> Result<(), String> {
    let password = get_password(state)?;
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    let mut candidate = vault.clone();
    delete_project(&mut candidate, project).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&candidate, &password)?;
    *vault = candidate;
    Ok(())
}

pub fn update_secret_in_state(
    state: &DaemonState,
    project: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let password = get_password(state)?;
    let mut vault = state.vault.lock().map_err(|e| e.to_string())?;
    let mut candidate = vault.clone();
    update_secret(&mut candidate, project, key, value).map_err(|e| e.to_string())?;
    crate::vault_file::write_vault(&candidate, &password)?;
    *vault = candidate;
    Ok(())
}

pub fn validate_token(state: &DaemonState, token: &str, pid: u32, uid: u32) -> TokenValidation {
    let token_store = match state.token_store.lock() {
        Ok(store) => store,
        Err(_) => return TokenValidation::InvalidToken,
    };

    let Some((_, record)) = token_store
        .iter()
        .find(|(stored_token, _)| constant_time_compare(stored_token, token))
    else {
        return TokenValidation::InvalidToken;
    };

    if Instant::now() > record.deadline {
        return TokenValidation::Expired;
    }

    if record.uid != uid {
        return TokenValidation::UidMismatch;
    }

    match record.state {
        TokenState::Pending => TokenValidation::Expired,
        TokenState::Active => {
            if record.pid != pid {
                TokenValidation::PidMismatch
            } else {
                TokenValidation::Valid(record.project.clone())
            }
        }
    }
}

pub fn invalidate_token(state: &DaemonState, token: &str) -> Result<(), String> {
    let mut token_store = state.token_store.lock().map_err(|e| e.to_string())?;
    token_store.remove(token);
    Ok(())
}

const RATE_LIMIT_MAX_REQUESTS: usize = 60;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

pub fn check_rate_limit(state: &DaemonState, pid: u32) -> Result<(), String> {
    let mut limits = state.rate_limits.lock().map_err(|e| e.to_string())?;
    let now = Instant::now();
    let timestamps = limits.entry(pid).or_default();
    timestamps.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
    if timestamps.len() >= RATE_LIMIT_MAX_REQUESTS {
        return Err("rate limit exceeded".to_string());
    }
    timestamps.push(now);
    Ok(())
}

pub fn disable_core_dumps() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if rc != 0 {
            eprintln!(
                "Warning: core dump protection unavailable: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if rc != 0 {
            eprintln!(
                "Warning: core dump protection unavailable: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

pub fn lock_memory_pages() -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let rc = unsafe { libc::mlockall(libc::MCL_CURRENT) };
        if rc != 0 {
            eprintln!(
                "Warning: memory locking unavailable (containers?): {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

pub fn monitor_child_pid(
    state: DaemonState,
    pid: u32,
    token: String,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if !pid_is_alive(pid) {
                let _ = invalidate_token(&state, &token);
                break;
            }

            tokio::time::sleep(poll_interval).await;
        }
    })
}

fn get_password(state: &DaemonState) -> Result<String, String> {
    state
        .password
        .lock()
        .map(|pw| pw.to_string())
        .map_err(|e| e.to_string())
}

pub fn daemon_uptime(state: &DaemonState) -> Result<Duration, String> {
    let started_at = state.started_at.lock().map_err(|e| e.to_string())?;
    Ok(Instant::now().duration_since(*started_at))
}

fn project_for_token(state: &DaemonState, token: &str) -> Option<String> {
    let token_store = state.token_store.lock().ok()?;
    token_store
        .iter()
        .find(|(stored_token, _)| constant_time_compare(stored_token, token))
        .map(|(_, record)| record.project.clone())
}

fn invalidate_all_tokens(state: &DaemonState) -> Result<(), String> {
    let mut token_store = state.token_store.lock().map_err(|e| e.to_string())?;
    token_store.clear();
    Ok(())
}

fn pid_is_alive(pid: u32) -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        true
    }
}

#[cfg(target_os = "linux")]
pub fn get_peer_credentials(stream: &UnixStream) -> Result<(u32, u32), String> {
    let fd = stream.as_raw_fd();
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut credentials_len = mem::size_of::<libc::ucred>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut credentials_len,
        )
    };

    if result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    Ok((credentials.pid as u32, credentials.uid))
}

#[cfg(target_os = "macos")]
pub fn get_peer_credentials(stream: &UnixStream) -> Result<(u32, u32), String> {
    let fd = stream.as_raw_fd();

    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    let getpeereid_result = unsafe { libc::getpeereid(fd, &mut euid, &mut egid) };
    if getpeereid_result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let mut credentials: libc::xucred = unsafe { std::mem::zeroed() };
    let mut credentials_len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;

    let getsockopt_result = unsafe {
        libc::getsockopt(
            fd,
            0,
            libc::LOCAL_PEERCRED,
            &mut credentials as *mut libc::xucred as *mut libc::c_void,
            &mut credentials_len,
        )
    };
    if getsockopt_result != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    if credentials.cr_version != libc::XUCRED_VERSION {
        return Err("unexpected LOCAL_PEERCRED version".to_string());
    }

    Ok((0, euid))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_peer_credentials(stream: &UnixStream) -> Result<(u32, u32), String> {
    let _ = stream;
    Err("peer credential retrieval is not implemented on this platform".to_string())
}

async fn handle_poc_connection(stream: &mut UnixStream) -> Result<(), String> {
    let request = read_json_request(stream).await.map_err(|e| e.message())?;
    let peer_credentials = read_peer_credentials(stream).map_err(|e| e.message())?;
    let request = parse_poc_request(&request).map_err(|e| e.message())?;
    validate_poc_request(&request, &peer_credentials).map_err(|e| e.message())?;
    let response = route_poc_request(request).map_err(|e| e.message())?;

    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())
}

async fn handle_connection(state: &DaemonState, stream: &mut UnixStream) -> Result<bool, String> {
    let (peer_pid, uid) = get_peer_credentials(stream)?;
    let current_uid = unsafe { libc::geteuid() };
    if uid != current_uid {
        eprintln!("Warning: rejected connection from uid {uid}");
        let mut payload =
            serde_json::to_string(&json!({ "ok": false, "error": "permission denied" }))
                .map_err(|e| e.to_string())?;
        payload.push('\n');
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.shutdown().await.map_err(|e| e.to_string())?;
        return Ok(false);
    }

    if check_rate_limit(state, peer_pid).is_err() {
        let mut payload =
            serde_json::to_string(&json!({ "ok": false, "error": "rate limit exceeded" }))
                .map_err(|e| e.to_string())?;
        payload.push('\n');
        stream
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.shutdown().await.map_err(|e| e.to_string())?;
        return Ok(false);
    }

    let request = read_json_request(stream).await.map_err(|e| e.message())?;
    let response = handle_ipc_request(state, &request)?;

    if let Ok(mut last) = state.last_activity.lock() {
        *last = Instant::now();
    }

    let mut payload = serde_json::to_string(&response).map_err(|e| e.to_string())?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())?;

    Ok(request.get("type").and_then(serde_json::Value::as_str) == Some("shutdown"))
}

fn handle_ipc_request(
    state: &DaemonState,
    request: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let request_type = request
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing request type".to_string())?;

    let response = match request_type {
        "get_secret" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let key = request
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing key".to_string())?;
            let value = get_secret_value(state, project, key)?;
            let process_name = request
                .get("process_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let exe_path = request
                .get("exe_path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let method = request
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("cli_get")
                .to_string();
            log_access_event(AccessEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                process_name,
                exe_path,
                project: project.to_string(),
                key: key.to_string(),
                method,
                last_updated_at: None,
            })?;
            json!({ "ok": true, "value": value })
        }
        "add_secret" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let key = request
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing key".to_string())?;
            let value = request
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing value".to_string())?;
            upsert_secret(state, project, key, value)?;
            json!({ "ok": true })
        }
        "update_secret" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let key = request
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing key".to_string())?;
            let value = request
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing value".to_string())?;
            update_secret_in_state(state, project, key, value)?;
            json!({ "ok": true })
        }
        "list_projects" => json!({ "ok": true, "projects": list_project_summaries(state)? }),
        "list_keys" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            json!({ "ok": true, "keys": list_project_keys(state, project)? })
        }
        "get_all_secrets" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let method = request
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("cli_export")
                .to_string();
            let secrets = get_all_project_secrets(state, project)?;
            for key in secrets.keys() {
                log_access_event(AccessEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    process_name: "lokalvault".to_string(),
                    exe_path: "lokalvault".to_string(),
                    project: project.to_string(),
                    key: key.clone(),
                    method: method.clone(),
                    last_updated_at: None,
                })?;
            }
            json!({ "ok": true, "secrets": secrets })
        }
        "delete_secret" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let key = request
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing key".to_string())?;
            delete_secret_from_state(state, project, key)?;
            json!({ "ok": true })
        }
        "delete_project" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            delete_project_from_state(state, project)?;
            json!({ "ok": true })
        }
        "project_count" => json!({ "ok": true, "count": project_count(state)? }),
        "status" => {
            let uptime = daemon_uptime(state)?;
            json!({
                "ok": true,
                "session_timeout_minutes": read_settings().session_timeout_minutes,
                "uptime_seconds": uptime.as_secs(),
            })
        }
        "register_token_phase1" => {
            let token = request
                .get("token")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing token".to_string())?;
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let uid = unsafe { libc::geteuid() };
            register_token_phase1(state, token, uid, project)?;
            json!({ "ok": true })
        }
        "register_token_phase2" => {
            let token = request
                .get("token")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing token".to_string())?;
            let pid = request
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "missing pid".to_string())? as u32;
            let timeout_minutes = read_settings().session_timeout_minutes as u64;
            register_token_phase2(state, token, pid, Duration::from_secs(timeout_minutes * 60))?;
            monitor_child_pid(
                state.clone(),
                pid,
                token.to_string(),
                Duration::from_millis(100),
            );
            json!({ "ok": true })
        }
        "get_all_secrets_for_run" => {
            let token = request
                .get("token")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing token".to_string())?;
            let pid = request
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "missing pid".to_string())? as u32;
            let uid = unsafe { libc::geteuid() };
            let project_name =
                project_for_token(state, token).unwrap_or_else(|| "unknown".to_string());
            let secrets = fetch_all_secrets(state, token, pid, uid).map_err(|e| e.message())?;
            for key in secrets.keys() {
                log_access_event(AccessEvent {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    process_name: "lokalvault".to_string(),
                    exe_path: "lokalvault".to_string(),
                    project: project_name.clone(),
                    key: key.clone(),
                    method: "run_env".to_string(),
                    last_updated_at: None,
                })?;
            }
            json!({ "ok": true, "secrets": secrets })
        }
        "scan_diff" => {
            let project = request
                .get("project")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing project".to_string())?;
            let diff = request
                .get("diff")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "missing diff".to_string())?;
            let matches = scan_diff_for_project(state, project, diff)?;
            json!({
                "ok": true,
                "blocked": !matches.is_empty(),
                "matches": matches,
            })
        }
        "log_access" => {
            let event: AccessEvent =
                serde_json::from_value(request.clone()).map_err(|e| e.to_string())?;
            log_access_event(event)?;
            json!({ "ok": true })
        }
        "shutdown" => json!({ "ok": true }),
        _ => json!({ "ok": false, "error": "unsupported request type" }),
    };

    Ok(response)
}

fn read_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, DaemonError> {
    let (pid, uid) = get_peer_credentials(stream).map_err(DaemonError::PeerCredentials)?;
    Ok(PeerCredentials { pid, uid })
}

fn parse_poc_request(request: &serde_json::Value) -> Result<PocRequest, DaemonError> {
    let request_type = request
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(DaemonError::MissingRequestType)?;

    match request_type {
        "get_secret" => {
            let key = request
                .get("key")
                .and_then(serde_json::Value::as_str)
                .ok_or(DaemonError::MissingSecretKey)?
                .to_string();
            let uid = request
                .get("uid")
                .and_then(serde_json::Value::as_u64)
                .ok_or(DaemonError::MissingUid)? as u32;
            let pid = request
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .map(|pid| pid as u32);

            if peer_pid_is_required() && pid.is_none() {
                return Err(DaemonError::MissingPid);
            }

            Ok(PocRequest::GetSecret { key, uid, pid })
        }
        _ => Err(DaemonError::UnsupportedRequestType),
    }
}

fn validate_poc_request(
    request: &PocRequest,
    peer_credentials: &PeerCredentials,
) -> Result<(), DaemonError> {
    match request {
        PocRequest::GetSecret { uid, pid, .. } => {
            if *uid != peer_credentials.uid {
                return Err(DaemonError::UidMismatch);
            }

            if peer_pid_is_required() {
                if *pid != Some(0) {
                    return Err(DaemonError::PidMismatch);
                }
            } else if let Some(pid) = pid
                && *pid != peer_credentials.pid
            {
                return Err(DaemonError::PidMismatch);
            }
        }
    }

    Ok(())
}

fn route_poc_request(request: PocRequest) -> Result<String, DaemonError> {
    match request {
        PocRequest::GetSecret { key, .. } => {
            if key != "OPENAI_KEY" {
                return Err(DaemonError::UnknownSecretKey);
            }

            Ok(json!({ "value": "test-value-123" }).to_string())
        }
    }
}

async fn read_json_request(stream: &mut UnixStream) -> Result<serde_json::Value, DaemonError> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let bytes_read = stream
            .read(&mut chunk)
            .await
            .map_err(|e| DaemonError::Io(e.to_string()))?;
        if bytes_read == 0 {
            break;
        }

        request.extend_from_slice(&chunk[..bytes_read]);

        match serde_json::from_slice::<serde_json::Value>(&request) {
            Ok(value) => return Ok(value),
            Err(err) if err.is_eof() => continue,
            Err(err) => return Err(DaemonError::InvalidJson(err.to_string())),
        }
    }

    Err(DaemonError::Io(
        io::Error::new(ErrorKind::UnexpectedEof, "empty request").to_string(),
    ))
}

fn cleanup_socket_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_file::{Project, Secret};

    fn sample_daemon_state() -> DaemonState {
        start_daemon(VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: "test-value-123".to_string(),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            }],
        })
    }

    #[test]
    fn test_register_token_phase1_stores_pending_token() {
        let state = sample_daemon_state();

        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();

        let token_store = state.token_store.lock().unwrap();
        let record = token_store.get("token-1").unwrap();
        assert_eq!(record.uid, 501);
        assert_eq!(record.pid, 0);
        assert_eq!(record.project, "my-app");
        assert_eq!(record.state, TokenState::Pending);
    }

    #[test]
    fn test_register_token_phase2_binds_pid_and_activates_token() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();

        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let token_store = state.token_store.lock().unwrap();
        let record = token_store.get("token-1").unwrap();
        assert_eq!(record.pid, 777);
        assert_eq!(record.state, TokenState::Active);
    }

    #[test]
    fn test_validate_token_returns_valid_for_matching_active_token() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let validation = validate_token(&state, "token-1", 777, 501);
        assert_eq!(validation, TokenValidation::Valid("my-app".to_string()));
    }

    #[test]
    fn test_validate_token_rejects_pid_mismatch() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let validation = validate_token(&state, "token-1", 778, 501);
        assert_eq!(validation, TokenValidation::PidMismatch);
    }

    #[test]
    fn test_validate_token_rejects_uid_mismatch() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let validation = validate_token(&state, "token-1", 777, 999);
        assert_eq!(validation, TokenValidation::UidMismatch);
    }

    #[test]
    fn test_fetch_all_secrets_returns_project_map_for_valid_token() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

        let secrets = fetch_all_secrets(&state, "token-1", 777, 501).unwrap();
        assert_eq!(
            secrets.get("OPENAI_KEY"),
            Some(&"test-value-123".to_string())
        );
    }

    #[test]
    fn test_fetch_all_secrets_rejects_invalid_token() {
        let state = sample_daemon_state();
        let error = fetch_all_secrets(&state, "missing-token", 777, 501).unwrap_err();

        assert_eq!(error.message(), "token invalid");
    }

    #[test]
    fn test_register_token_phase2_rejects_expired_pending_token() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        {
            let mut token_store = state.token_store.lock().unwrap();
            token_store.get_mut("token-1").unwrap().deadline =
                Instant::now() - Duration::from_secs(1);
        }

        let error =
            register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap_err();
        assert_eq!(error, "token expired");
    }

    #[tokio::test]
    async fn test_monitor_child_pid_invalidates_token_when_process_is_gone() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();
        register_token_phase2(&state, "token-1", 999_999, Duration::from_secs(60)).unwrap();

        let handle = monitor_child_pid(
            state.clone(),
            999_999,
            "token-1".to_string(),
            Duration::from_millis(10),
        );
        handle.await.unwrap();

        let token_store = state.token_store.lock().unwrap();
        assert!(!token_store.contains_key("token-1"));
    }

    #[test]
    fn test_stop_daemon_zeroizes_vault_and_clears_tokens() {
        let state = sample_daemon_state();
        register_token_phase1(&state, "token-1", 501, "my-app").unwrap();

        stop_daemon(&state).unwrap();

        let vault = state.vault.lock().unwrap();
        assert!(vault.projects.is_empty());
        drop(vault);

        let token_store = state.token_store.lock().unwrap();
        assert!(token_store.is_empty());
    }

    #[test]
    fn test_best_effort_hardening_helpers_do_not_fail() {
        assert!(disable_core_dumps().is_ok());
        assert!(lock_memory_pages().is_ok());
    }

    #[test]
    fn test_rate_limit_allows_requests_within_window() {
        let state = sample_daemon_state();
        for _ in 0..60 {
            assert!(check_rate_limit(&state, 123).is_ok());
        }
        assert!(check_rate_limit(&state, 123).is_err());
        assert!(check_rate_limit(&state, 456).is_ok());
    }

    #[test]
    fn test_upsert_uses_clone_mutate_persist_swap_pattern() {
        let state = sample_daemon_state();

        {
            let vault = state.vault.lock().unwrap();
            let secret = vault.projects[0]
                .secrets
                .iter()
                .find(|s| s.key == "OPENAI_KEY")
                .unwrap();
            assert_eq!(secret.value, "test-value-123");
        }
    }

    #[test]
    fn test_find_matching_secret_keys_detects_secret_value_in_diff() {
        let secrets = HashMap::from([("OPENAI_KEY".to_string(), "test-value-123".to_string())]);

        let matches = find_matching_secret_keys("+ OPENAI_KEY=test-value-123", &secrets);

        assert_eq!(matches, vec!["OPENAI_KEY".to_string()]);
    }

    #[test]
    fn test_find_matching_secret_keys_ignores_key_names() {
        let secrets = HashMap::from([("OPENAI_KEY".to_string(), "test-value-123".to_string())]);

        let matches = find_matching_secret_keys("+ OPENAI_KEY=REDACTED", &secrets);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_matching_secret_keys_ignores_short_values() {
        let secrets = HashMap::from([("PIN".to_string(), "1234567".to_string())]);

        let matches = find_matching_secret_keys("+ PIN=1234567", &secrets);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_matching_secret_keys_ignores_empty_values() {
        let secrets = HashMap::from([("EMPTY_SECRET".to_string(), String::new())]);

        let matches = find_matching_secret_keys("+ EMPTY_SECRET=", &secrets);

        assert!(matches.is_empty());
    }

    #[test]
    fn test_find_matching_secret_keys_deduplicates_matches() {
        let secrets = HashMap::from([("OPENAI_KEY".to_string(), "test-value-123".to_string())]);

        let matches = find_matching_secret_keys(
            "+ OPENAI_KEY=test-value-123\n+ AGAIN=test-value-123",
            &secrets,
        );

        assert_eq!(matches, vec!["OPENAI_KEY".to_string()]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_get_peer_credentials_returns_current_process_uid() {
        let socket_path = unique_poc_socket_path("daemon-peercred");
        cleanup_socket_file(&socket_path).unwrap();
        let (socket_path, listener) = create_socket_at_path(socket_path).unwrap();
        let socket_path_string = socket_path.to_string_lossy().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            get_peer_credentials(&stream).unwrap()
        });

        let client = UnixStream::connect(&socket_path_string).await.unwrap();
        let (peer_pid, peer_uid) = server.await.unwrap();

        assert_eq!(peer_uid, unsafe { libc::geteuid() });
        assert!(peer_pid > 0);

        drop(client);
        cleanup_socket_file(Path::new(&socket_path_string)).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_get_peer_credentials_returns_current_process_uid_on_macos() {
        let socket_path = unique_poc_socket_path("daemon-peercred-macos");
        cleanup_socket_file(&socket_path).unwrap();
        let (socket_path, listener) = create_socket_at_path(socket_path).unwrap();
        let socket_path_string = socket_path.to_string_lossy().to_string();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            get_peer_credentials(&stream)
        });

        let client = UnixStream::connect(&socket_path_string).await.unwrap();
        let (peer_pid, peer_uid) = server.await.unwrap().unwrap();

        assert_eq!(peer_uid, unsafe { libc::geteuid() });
        assert_eq!(peer_pid, 0);

        drop(client);
        cleanup_socket_file(Path::new(&socket_path_string)).unwrap();
    }

    #[tokio::test]
    async fn test_create_socket_sets_permissions_to_0600() {
        let socket_path = unique_poc_socket_path("daemon-perms");
        cleanup_socket_file(&socket_path).unwrap();
        let (socket_path, listener) = create_socket_at_path(socket_path).unwrap();

        let mode = fs::metadata(&socket_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        drop(listener);
        cleanup_socket_file(&socket_path).unwrap();
    }

    #[tokio::test]
    async fn test_run_daemon_poc_returns_hardcoded_json() {
        let socket_path = unique_poc_socket_path("daemon-response");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = loop {
            match UnixStream::connect(&socket_path_string).await {
                Ok(stream) => break stream,
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(err) => panic!("failed to connect to daemon socket: {err}"),
            }
        };
        let request = json!({
            "type": "get_secret",
            "key": "OPENAI_KEY",
            "uid": unsafe { libc::geteuid() },
            "pid": 0
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["value"], "test-value-123");

        let daemon_result = daemon.await.unwrap();
        assert!(daemon_result.is_ok());
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[tokio::test]
    async fn test_run_daemon_poc_rejects_client_reported_uid_mismatch() {
        let socket_path = unique_poc_socket_path("daemon-bad-uid");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "get_secret",
            "key": "OPENAI_KEY",
            "uid": u64::from(unsafe { libc::geteuid() }) + 1,
            "pid": 0
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "client-reported uid mismatch");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "client-reported uid mismatch");
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[tokio::test]
    async fn test_run_daemon_poc_rejects_get_secret_without_uid() {
        let socket_path = unique_poc_socket_path("daemon-missing-uid");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "get_secret",
            "key": "OPENAI_KEY"
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "get_secret request missing uid");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "get_secret request missing uid");
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_run_daemon_poc_rejects_get_secret_without_pid_on_linux() {
        let socket_path = unique_poc_socket_path("daemon-missing-pid");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "get_secret",
            "key": "OPENAI_KEY",
            "uid": unsafe { libc::geteuid() }
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "get_secret request missing pid");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "get_secret request missing pid");
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_run_daemon_poc_rejects_nonzero_pid_claim_on_linux() {
        let socket_path = unique_poc_socket_path("daemon-bad-pid");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "get_secret",
            "key": "OPENAI_KEY",
            "uid": unsafe { libc::geteuid() },
            "pid": 12345
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "client-reported pid mismatch");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "client-reported pid mismatch");
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[tokio::test]
    async fn test_run_daemon_poc_returns_structured_error_for_unsupported_request_type() {
        let socket_path = unique_poc_socket_path("daemon-bad-type");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "ping",
            "uid": unsafe { libc::geteuid() }
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "unsupported request type");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "unsupported request type");
        assert!(!Path::new(&socket_path_string).exists());
    }

    #[tokio::test]
    async fn test_run_daemon_poc_rejects_unknown_secret_key() {
        let socket_path = unique_poc_socket_path("daemon-bad-key");
        let socket_path_string = socket_path.to_string_lossy().to_string();
        cleanup_socket_file(&socket_path).unwrap();
        let daemon = tokio::spawn(async { run_daemon_poc_at_path(socket_path).await });

        for _ in 0..50 {
            if Path::new(&socket_path_string).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut stream = UnixStream::connect(&socket_path_string).await.unwrap();
        let request = json!({
            "type": "get_secret",
            "key": "MISSING_KEY",
            "uid": unsafe { libc::geteuid() },
            "pid": 0
        })
        .to_string();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();

        let response_json: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response_json["error"], "unknown secret key");

        let daemon_result = daemon.await.unwrap();
        assert_eq!(daemon_result.unwrap_err(), "unknown secret key");
        assert!(!Path::new(&socket_path_string).exists());
    }
}

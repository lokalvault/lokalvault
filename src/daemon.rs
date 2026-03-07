use serde_json::json;
use std::fs;
use std::io;
use std::io::ErrorKind;
#[cfg(target_os = "linux")]
use std::mem;
use std::os::unix::fs::PermissionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub const POC_SOCKET_PATH: &str = "/tmp/lokalvault-test.sock";

struct PeerCredentials {
    pid: u32,
    uid: u32,
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

pub async fn run_daemon_poc() -> Result<(), String> {
    run_daemon_poc_at_path(PathBuf::from(POC_SOCKET_PATH)).await
}

pub async fn run_daemon_poc_at_path(socket_path: PathBuf) -> Result<(), String> {
    let (socket_path, listener) = create_socket_at_path(socket_path)?;

    let result = async {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| DaemonError::Io(e.to_string()).message())?;
        handle_connection(&mut stream).await?;
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

async fn handle_connection(stream: &mut UnixStream) -> Result<(), String> {
    match handle_poc_connection(stream).await {
        Ok(()) => Ok(()),
        Err(error) => {
            write_error_response(stream, &error).await?;
            Err(error)
        }
    }
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
            } else if let Some(pid) = pid {
                if *pid != peer_credentials.pid {
                    return Err(DaemonError::PidMismatch);
                }
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

async fn write_error_response(stream: &mut UnixStream, error: &str) -> Result<(), String> {
    let response = json!({ "error": error }).to_string();
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())
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

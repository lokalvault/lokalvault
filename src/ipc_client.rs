use crate::errors::AppError;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub fn get_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    std::env::temp_dir().join(format!("lokalvault-{uid}.sock"))
}

pub fn is_daemon_running() -> bool {
    let socket_path = get_socket_path();
    cleanup_stale_socket_path(&socket_path);
    connect_socket(&socket_path).is_ok()
}

pub fn cleanup_stale_socket() {
    let socket_path = get_socket_path();
    cleanup_stale_socket_path(&socket_path);
}

pub fn send_ipc_request(request: Value) -> Result<Value, AppError> {
    let socket_path = get_socket_path();
    send_ipc_request_to_path(&socket_path, request)
}

fn send_ipc_request_to_path(socket_path: &Path, request: Value) -> Result<Value, AppError> {
    cleanup_stale_socket_path(socket_path);
    let mut stream = connect_socket(socket_path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => AppError::DaemonNotRunning,
        _ => AppError::IpcError(error.to_string()),
    })?;
    let mut payload = serde_json::to_string(&request)?;
    payload.push('\n');
    stream.write_all(payload.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim().is_empty() {
        return Err(AppError::InvalidResponse(
            "daemon returned empty response".to_string(),
        ));
    }

    serde_json::from_str(response.trim()).map_err(|error| {
        AppError::InvalidResponse(format!("daemon returned invalid JSON: {error}"))
    })
}

fn is_connection_refused(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::ConnectionRefused)
}

fn connect_socket(socket_path: &Path) -> std::io::Result<UnixStream> {
    if !socket_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("socket not found: {}", socket_path.display()),
        ));
    }
    UnixStream::connect(socket_path)
}

fn cleanup_stale_socket_path(socket_path: &Path) {
    if !socket_path.exists() {
        return;
    }
    if let Err(error) = UnixStream::connect(socket_path)
        && is_connection_refused(&error)
    {
        let _ = std::fs::remove_file(socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn unique_test_socket_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lokalvault-ipc-client-{test_name}-{}.sock",
            std::process::id()
        ))
    }

    #[test]
    fn test_cleanup_stale_socket_path_removes_orphaned_socket_file() {
        let socket_path = unique_test_socket_path("stale-socket");
        let _ = std::fs::remove_file(&socket_path);
        let listener = match std::os::unix::net::UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test socket: {error}"),
        };
        drop(listener);

        cleanup_stale_socket_path(&socket_path);

        assert!(!socket_path.exists());
    }

    #[test]
    fn test_send_ipc_request_reports_invalid_json_response() {
        let socket_path = unique_test_socket_path("invalid-response");
        let _ = std::fs::remove_file(&socket_path);
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to bind test socket: {error}"),
        };

        let server = thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                let _ = reader.read_line(&mut request);
                let _ = stream.write_all(b"not-json\n");
                let _ = std::fs::remove_file(socket_path);
            }
        });

        let error = send_ipc_request_to_path(&socket_path, serde_json::json!({ "type": "ping" }))
            .unwrap_err();
        assert!(matches!(error, AppError::InvalidResponse(_)));
        assert!(
            error
                .to_string()
                .starts_with("daemon returned invalid JSON:")
        );
        server.join().unwrap();
    }
}

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

pub fn send_ipc_request(request: Value) -> Result<Value, String> {
    let socket_path = get_socket_path();
    cleanup_stale_socket_path(&socket_path);
    let mut stream = connect_socket(&socket_path).map_err(|e| e.to_string())?;
    let mut payload = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).map_err(|e| e.to_string())?;
    if response.trim().is_empty() {
        return Err("daemon returned empty response".to_string());
    }

    serde_json::from_str(response.trim()).map_err(|e| e.to_string())
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

    #[test]
    fn test_cleanup_stale_socket_path_removes_orphaned_socket_file() {
        let socket_path = PathBuf::from(format!(
            "/tmp/lokalvault-stale-socket-{}.sock",
            std::process::id()
        ));
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
}

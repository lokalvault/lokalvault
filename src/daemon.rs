use serde_json::json;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub const POC_SOCKET_PATH: &str = "/tmp/lokalvault-test.sock";

pub fn create_socket() -> Result<(PathBuf, UnixListener), String> {
    create_socket_at_path(PathBuf::from(POC_SOCKET_PATH))
}

pub async fn run_daemon_poc() -> Result<(), String> {
    run_daemon_poc_at_path(PathBuf::from(POC_SOCKET_PATH)).await
}

pub async fn run_daemon_poc_at_path(socket_path: PathBuf) -> Result<(), String> {
    let (socket_path, listener) = create_socket_at_path(socket_path)?;

    let result = async {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        handle_poc_connection(&mut stream).await
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

async fn handle_poc_connection(stream: &mut UnixStream) -> Result<(), String> {
    let request = read_json_request(stream).await?;

    if request.get("type") != Some(&serde_json::Value::String("get_secret".to_string())) {
        return Err("unsupported request type".to_string());
    }

    let response = json!({ "value": "test-value-123" }).to_string();
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())
}

async fn read_json_request(stream: &mut UnixStream) -> Result<serde_json::Value, String> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let bytes_read = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if bytes_read == 0 {
            break;
        }

        request.extend_from_slice(&chunk[..bytes_read]);

        match serde_json::from_slice::<serde_json::Value>(&request) {
            Ok(value) => return Ok(value),
            Err(err) if err.is_eof() => continue,
            Err(err) => return Err(err.to_string()),
        }
    }

    Err(io::Error::new(ErrorKind::UnexpectedEof, "empty request").to_string())
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
        let request = json!({ "type": "get_secret", "key": "OPENAI_KEY" }).to_string();
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
}

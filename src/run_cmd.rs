use crate::daemon::{POC_SOCKET_PATH, run_daemon_poc_at_path, unique_poc_socket_path};
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn cmd_run_poc(command: Vec<String>) -> Result<std::process::ExitStatus, String> {
    cmd_run_poc_with_socket(command, POC_SOCKET_PATH).await
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
        "uid": unsafe { libc::geteuid() }
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

    let response_json: Value = serde_json::from_slice(&response).map_err(|e| e.to_string())?;
    response_json
        .get("value")
        .and_then(Value::as_str)
        .map(|value| value.to_string())
        .ok_or_else(|| "daemon response missing secret value".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

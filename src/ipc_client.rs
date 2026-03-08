use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

pub fn get_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/lokalvault-{uid}.sock"))
}

pub fn is_daemon_running() -> bool {
    UnixStream::connect(get_socket_path()).is_ok()
}

pub fn send_ipc_request(request: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(get_socket_path()).map_err(|e| e.to_string())?;
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

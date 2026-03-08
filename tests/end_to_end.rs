use lokalvault::audit_log::{clear_audit_log, read_audit_log};
use lokalvault::daemon::{
    fetch_all_secrets, register_token_phase1, register_token_phase2, start_daemon,
};
use lokalvault::ipc_client::{get_socket_path, send_ipc_request};
use lokalvault::run_cmd::{fetch_all_secrets as run_fetch_all_secrets, get_project_from_config};
use lokalvault::vault_file::{Project, Secret, VaultData};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

static END_TO_END_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_real_token_flow_across_run_and_daemon_modules() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    register_token_phase2(&state, "token-1", 777, Duration::from_secs(60)).unwrap();

    let daemon_secrets = fetch_all_secrets(&state, "token-1", 777, 501).unwrap();
    let run_secrets = run_fetch_all_secrets(&state, "token-1", 777, 501).unwrap();

    assert_eq!(daemon_secrets, run_secrets);
}

#[test]
fn test_project_config_roundtrip_for_real_run_path() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = fs::remove_file(".lokalvault");
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let project = get_project_from_config().unwrap();
    assert_eq!(project, Some("my-app".to_string()));

    let _ = fs::remove_file(".lokalvault");
}

#[test]
fn test_run_without_project_or_config_errors_cleanly() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = fs::remove_file(".lokalvault");
    let _ = fs::remove_file("/tmp/lokalvault-test.sock");

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["run", "--", "true"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("run lokalvault init first or pass --project")
    );
}

#[test]
fn test_run_with_project_config_uses_project_automatically() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _ = fs::remove_file(".lokalvault");
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let socket = "/tmp/lokalvault-test.sock";
    let _ = fs::remove_file(socket);

    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon-poc")
        .spawn()
        .unwrap();

    for _ in 0..100 {
        if std::path::Path::new(socket).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args([
            "run",
            "--",
            "python3",
            "-c",
            "import os; print(os.environ.get('OPENAI_KEY'))",
        ])
        .output()
        .unwrap();

    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(".lokalvault");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "test-value-123\n");
}

#[test]
fn test_ipc_full_lifecycle() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let socket = get_socket_path();
    let _ = fs::remove_file(&socket);

    let input = serde_json::to_vec(&(VaultData::new(), "password".to_string())).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    daemon.stdin.take().unwrap().write_all(&input).unwrap();

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let add = send_ipc_request(json!({
        "type": "add_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "value": "test-value-123",
        "password": "password"
    }))
    .unwrap();
    assert_eq!(add["ok"], true);

    let get = send_ipc_request(json!({
        "type": "get_secret",
        "project": "my-app",
        "key": "OPENAI_KEY"
    }))
    .unwrap();
    assert_eq!(get["value"], "test-value-123");

    let delete = send_ipc_request(json!({
        "type": "delete_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "password": "password"
    }))
    .unwrap();
    assert_eq!(delete["ok"], true);

    let shutdown = send_ipc_request(json!({ "type": "shutdown" })).unwrap();
    assert_eq!(shutdown["ok"], true);
    let _ = daemon.wait();
}

#[test]
fn test_audit_log_records_daemon_access() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_audit_log().unwrap();

    let socket = get_socket_path();
    let _ = fs::remove_file(&socket);

    let vault = VaultData {
        version: 1,
        projects: vec![Project {
            name: "my-app".to_string(),
            secrets: vec![Secret {
                key: "OPENAI_KEY".to_string(),
                value: "test-value-123".to_string(),
            }],
        }],
    };
    let input = serde_json::to_vec(&(vault, "password".to_string())).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    daemon.stdin.take().unwrap().write_all(&input).unwrap();

    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let response = send_ipc_request(json!({
        "type": "get_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "process_name": "python",
        "exe_path": "/usr/bin/python3",
        "method": "cli_get"
    }))
    .unwrap();
    assert_eq!(response["value"], "test-value-123");

    let events = read_audit_log(None).unwrap();
    assert!(!events.is_empty());
    assert_eq!(events[0].project, "my-app");
    assert_eq!(events[0].key, "OPENAI_KEY");

    let serialized = serde_json::to_string(&events[0]).unwrap();
    assert!(!serialized.contains("test-value-123"));

    let shutdown = send_ipc_request(json!({ "type": "shutdown" })).unwrap();
    assert_eq!(shutdown["ok"], true);
    let _ = daemon.wait();
}

#[test]
fn test_config_set_and_get() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let set_output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["config", "set", "session-timeout-minutes", "120"])
        .output()
        .unwrap();
    assert!(set_output.status.success());

    let get_output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["config", "get", "session-timeout-minutes"])
        .output()
        .unwrap();
    assert!(get_output.status.success());
    assert_eq!(String::from_utf8_lossy(&get_output.stdout), "120\n");
}

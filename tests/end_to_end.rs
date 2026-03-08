use lokalvault::daemon::{
    fetch_all_secrets, register_token_phase1, register_token_phase2, start_daemon,
};
use lokalvault::run_cmd::{fetch_all_secrets as run_fetch_all_secrets, get_project_from_config};
use lokalvault::vault_file::{Project, Secret, VaultData};
use std::fs;
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

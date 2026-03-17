use lokalvault::audit_log::{clear_audit_log, read_audit_log};
use lokalvault::cli::{self, ProjectTemplate};
use lokalvault::daemon::{
    fetch_all_secrets_for_boundary, register_token_phase1, register_token_phase2, start_daemon,
};
use lokalvault::ipc_client::{get_socket_path, send_ipc_request};
use lokalvault::run_cmd::{
    fetch_all_secrets as run_fetch_all_secrets, get_project_from_config, read_project_config,
};
use lokalvault::vault_file::{Project, Secret, VaultData, read_vault, write_vault};
use serde_json::json;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

static END_TO_END_LOCK: Mutex<()> = Mutex::new(());

fn test_data_dir(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lokalvault-e2e-test-{name}-{}", std::process::id()))
}

fn activate_test_dir(dir: &std::path::Path) {
    unsafe { std::env::set_var("LOKALVAULT_DATA_DIR", dir) };
    unsafe { std::env::set_var("LOKALVAULT_TEST_PIN_APPROVAL", "allow") };
}

fn setup_test_dir() -> std::path::PathBuf {
    let dir = test_data_dir("default");
    let _ = std::fs::create_dir_all(&dir);
    activate_test_dir(&dir);
    dir
}

fn cleanup_test_dir() {
    let dir = test_data_dir("default");
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

fn setup_named_test_dir(name: &str) -> std::path::PathBuf {
    let dir = test_data_dir(name);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    activate_test_dir(&dir);
    dir
}

fn cleanup_named_test_dir(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

fn wait_for_socket_or_child_exit(socket: &std::path::Path, child: &mut std::process::Child) {
    for _ in 0..50 {
        if socket.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "daemon exited before socket became ready (status {status}): {}",
                socket.display()
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("daemon socket did not appear: {}", socket.display());
}

fn spawn_real_daemon(vault: VaultData, password: &str) -> std::process::Child {
    let socket = get_socket_path();
    let _ = fs::remove_file(&socket);

    let input = serde_json::to_vec(&(vault, password.to_string())).unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("daemon")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    daemon.stdin.take().unwrap().write_all(&input).unwrap();

    wait_for_socket_or_child_exit(&socket, &mut daemon);
    daemon
}

fn register_action_token(scope: &str, project: &str) -> String {
    let approval = send_ipc_request(json!({
        "type": "create_action_approval",
        "scope": scope,
        "project": project,
    }))
    .unwrap();
    let approval_id = approval["approval_id"].as_str().unwrap();
    let approval = send_ipc_request(json!({
        "type": "approve_action_request",
        "approval_id": approval_id,
        "approved": true,
    }))
    .unwrap();
    assert_eq!(approval["ok"], true);
    let response = send_ipc_request(json!({
        "type": "register_action_token",
        "scope": scope,
        "project": project,
        "approval_id": approval_id,
    }))
    .unwrap();
    response["action_token"].as_str().unwrap().to_string()
}

fn shutdown_real_daemon(mut daemon: std::process::Child) {
    let _ = send_ipc_request(json!({ "type": "shutdown" }));
    let _ = daemon.wait();
    let _ = fs::remove_file(get_socket_path());
}

fn seed_vault(password: &str, project: &str, secrets: &[(&str, &str)]) {
    let now = "2026-01-01T00:00:00Z".to_string();
    let vault = VaultData {
        version: 1,
        projects: vec![Project {
            name: project.to_string(),
            secrets: secrets
                .iter()
                .map(|(key, value)| Secret {
                    key: (*key).to_string(),
                    value: zeroize::Zeroizing::new((*value).to_string()),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                })
                .collect(),
        }],
    };
    write_vault(&vault, password).unwrap();
}

fn queue_test_passwords(passwords: &[&str]) {
    unsafe { std::env::set_var("LOKALVAULT_TEST_PASSWORDS", passwords.join("\n")) };
}

fn unix_sockets_available() -> bool {
    let path = std::path::PathBuf::from(format!(
        "/tmp/lokalvault-socket-probe-{}.sock",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let result = std::os::unix::net::UnixListener::bind(&path);
    match result {
        Ok(listener) => {
            drop(listener);
            let _ = fs::remove_file(&path);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(error) => panic!("failed to probe unix socket support: {error}"),
    }
}

#[test]
fn test_real_token_flow_across_run_and_daemon_modules() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    let daemon_secrets = fetch_all_secrets_for_boundary(&state, "token-1", 777, 501).unwrap();
    let run_secrets = run_fetch_all_secrets(&state, "token-1", 777, 501).unwrap();

    assert_eq!(daemon_secrets, run_secrets);
}

#[test]
fn test_project_config_roundtrip_for_real_run_path() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-project-config-roundtrip");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let project = get_project_from_config().unwrap();
    assert_eq!(project, Some("my-app".to_string()));

    let _ = fs::remove_file(".lokalvault");
    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_run_without_project_or_config_errors_cleanly() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-run-no-config");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    let _ = fs::remove_file("/tmp/lokalvault-test.sock");

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["run", "--", "true"])
        .output()
        .unwrap();

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);
    cleanup_test_dir();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("run lokalvault init first or pass --project")
    );
}

#[test]
fn test_run_with_project_config_uses_project_automatically() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    setup_test_dir();
    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "test-value-123")]);
    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-run-project-config");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();
    let daemon = spawn_real_daemon(
        VaultData {
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
        },
        password,
    );

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

    shutdown_real_daemon(daemon);
    let _ = fs::remove_file(".lokalvault");
    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);
    cleanup_test_dir();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "test-value-123\n");
}

#[test]
fn test_run_with_project_config_and_locked_real_vault_fails_closed() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "real-secret")]);

    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-run-project-config-locked");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["run", "--", "python3", "-c", "print('should-not-run')"])
        .output()
        .unwrap();

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);
    cleanup_test_dir();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("vault is locked"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("should-not-run"));
}

#[test]
fn test_ipc_full_lifecycle() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    setup_test_dir();
    let mut daemon = spawn_real_daemon(VaultData::new(), "password");

    let add_token = register_action_token("vault_mutate", "my-app");
    let add = send_ipc_request(json!({
        "type": "add_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "value": "test-value-123",
        "action_token": add_token,
    }))
    .unwrap();
    assert_eq!(add["ok"], true);

    let get_token = register_action_token("secret_read", "my-app");
    let get = send_ipc_request(json!({
        "type": "get_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "action_token": get_token,
    }))
    .unwrap();
    assert_eq!(get["value"], "test-value-123");

    let delete_token = register_action_token("vault_mutate", "my-app");
    let delete = send_ipc_request(json!({
        "type": "delete_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "action_token": delete_token,
    }))
    .unwrap();
    assert_eq!(delete["ok"], true);

    let shutdown = send_ipc_request(json!({ "type": "shutdown" })).unwrap();
    assert_eq!(shutdown["ok"], true);
    let _ = daemon.wait();
    cleanup_test_dir();
}

#[test]
fn test_audit_log_records_daemon_access() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    setup_test_dir();
    clear_audit_log().unwrap();

    let vault = VaultData {
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
    };
    let daemon = spawn_real_daemon(vault, "password");

    let action_token = register_action_token("secret_read", "my-app");
    let response = send_ipc_request(json!({
        "type": "get_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "process_name": "python",
        "exe_path": "/usr/bin/python3",
        "method": "cli_get",
        "action_token": action_token,
    }))
    .unwrap();
    assert_eq!(response["value"], "test-value-123");

    let events = read_audit_log(None).unwrap();
    assert!(!events.is_empty());
    assert_eq!(events[0].project, "my-app");
    assert_eq!(events[0].key, "OPENAI_KEY");

    let serialized = serde_json::to_string(&events[0]).unwrap();
    assert!(!serialized.contains("test-value-123"));

    shutdown_real_daemon(daemon);
    cleanup_test_dir();
}

#[test]
fn test_config_set_and_get() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();

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
    cleanup_test_dir();
}

#[test]
fn test_doctor_detects_missing_vault() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let _ = fs::remove_file(lokalvault::vault_file::get_vault_path());

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("doctor")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Vault file missing"));
    cleanup_test_dir();
}

#[test]
fn test_dev_fallback_error_no_detection() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("dev")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Could not detect run command"));
    cleanup_test_dir();
}

#[test]
fn test_ai_safe_generates_env_example() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let tmp = std::env::temp_dir().join("lokalvault-ai-safe-test");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(
        tmp.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = []\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["ai-safe", "--project", "my-app", "--generate-example"])
        .current_dir(&tmp)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(tmp.join(".env.example").exists());
    let agents = fs::read_to_string(tmp.join("AGENTS.md")).unwrap();
    assert!(agents.starts_with("<!-- lokalvault-managed:agents -->\n"));
    cleanup_test_dir();
}

#[test]
fn test_ai_safe_refuses_to_overwrite_foreign_agents_file() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    let tmp = std::env::temp_dir().join("lokalvault-ai-safe-foreign-agents");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(
        tmp.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = []\n",
    )
    .unwrap();
    fs::write(
        tmp.join("AGENTS.md"),
        "# AI Agent Instructions\n\nThis project uses LokalVault for secrets management.\n\nCustom content not managed by LokalVault.\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["ai-safe", "--project", "my-app"])
        .current_dir(&tmp)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    let agents = fs::read_to_string(tmp.join("AGENTS.md")).unwrap();
    assert!(agents.contains("Custom content not managed by LokalVault."));
    cleanup_test_dir();
}

#[test]
fn test_scan_diff_detects_secret_value_in_diff() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    let matches = lokalvault::daemon::scan_diff_for_project(
        &state,
        "my-app",
        "+ OPENAI_KEY=test-value-123\n",
    )
    .unwrap();

    assert_eq!(matches, vec!["OPENAI_KEY".to_string()]);
}

#[test]
fn test_scan_diff_ignores_key_names() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let matches = lokalvault::daemon::find_matching_secret_keys(
        "+ OPENAI_KEY=REDACTED\n",
        &std::collections::HashMap::from([(
            "OPENAI_KEY".to_string(),
            "test-value-123".to_string(),
        )]),
    );

    assert!(matches.is_empty());
}

#[test]
fn test_scan_diff_ignores_short_values() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let state = start_daemon(VaultData {
        version: 1,
        projects: vec![Project {
            name: "my-app".to_string(),
            secrets: vec![Secret {
                key: "PIN".to_string(),
                value: zeroize::Zeroizing::new("1234567".to_string()),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
            }],
        }],
    });
    let matches =
        lokalvault::daemon::scan_diff_for_project(&state, "my-app", "+ PIN=1234567").unwrap();
    assert!(matches.is_empty());
}

#[test]
fn test_scan_diff_clean_diff_exits_0() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let matches =
        lokalvault::daemon::scan_diff_for_project(&state, "my-app", "+ NOTHING=here").unwrap();
    assert!(matches.is_empty());
}

#[test]
fn test_scan_diff_uses_project_from_lokalvault_config() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join("lokalvault-scan-diff-config");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join(".lokalvault"), "[project]\nname = \"my-app\"\n").unwrap();

    let project = std::env::current_dir()
        .and_then(|original| {
            std::env::set_current_dir(&tmp)?;
            let result = get_project_from_config();
            std::env::set_current_dir(original)?;
            result.map_err(std::io::Error::other)
        })
        .unwrap();

    assert_eq!(project, Some("my-app".to_string()));
}

#[test]
fn test_protect_repo_creates_executable_hook() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join("lokalvault-protect-repo");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join(".git/hooks")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["protect-repo", "--project", "my-app"])
        .current_dir(&tmp)
        .output()
        .unwrap();
    assert!(output.status.success());

    let hook_path = tmp.join(".git/hooks/pre-commit");
    assert!(hook_path.exists());
    let hook = fs::read_to_string(&hook_path).unwrap();
    assert!(hook.contains("# lokalvault-managed"));
    assert!(hook.contains("lokalvault scan-diff --project 'my-app'"));
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(&hook_path).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn test_protect_repo_refuses_to_overwrite_foreign_hook() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join("lokalvault-protect-repo-foreign");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join(".git/hooks")).unwrap();
    fs::write(
        tmp.join(".git/hooks/pre-commit"),
        "#!/bin/sh\necho custom\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("protect-repo")
        .current_dir(&tmp)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
}

#[test]
fn test_protect_repo_errors_outside_git_repo() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join("lokalvault-no-git-repo");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("protect-repo")
        .current_dir(&tmp)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a git repository"));
}

#[test]
fn test_init_with_template_writes_required_keys() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = std::env::temp_dir().join("lokalvault-init-template");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["init", "--template", "openai"])
        .current_dir(&tmp)
        .output()
        .unwrap();

    assert!(output.status.success());
    let contents = fs::read_to_string(tmp.join(".lokalvault")).unwrap();
    assert!(contents.contains("OPENAI_API_KEY"));
    assert!(contents.contains("OPENAI_ORG_ID"));
}

#[test]
fn test_diff_dotenv_redacts_values() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    let dir = setup_test_dir();
    let daemon = spawn_real_daemon(
        VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: zeroize::Zeroizing::new("sk-secret-value".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            }],
        },
        "test-Strong-password-42!",
    );

    let env_path = dir.join("test.env");
    fs::write(
        &env_path,
        "OPENAI_KEY=different-value\nNEW_KEY=added-value\n",
    )
    .unwrap();

    let diff = lokalvault::cli::cmd_diff(&env_path, Some("my-app")).unwrap();

    assert!(
        !diff.contains("sk-secret-value"),
        "diff must never print vault secret values"
    );
    assert!(
        !diff.contains("different-value"),
        "diff must never print dotenv file values"
    );
    assert!(
        diff.contains("<value differs>") || diff.contains("<value present>"),
        "diff should use redacted markers"
    );
    shutdown_real_daemon(daemon);
    cleanup_test_dir();
}

#[test]
fn test_project_template_required_keys() {
    let keys = ProjectTemplate::Supabase.required_keys();
    assert!(keys.contains(&"SUPABASE_URL".to_string()));
    assert!(keys.contains(&"SUPABASE_ANON_KEY".to_string()));
    assert!(keys.contains(&"SUPABASE_SERVICE_ROLE_KEY".to_string()));
}

#[test]
fn test_status_includes_session_expiry_and_stale_secret_summary() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
    if !unix_sockets_available() {
        cleanup_test_dir();
        return;
    }
    let previous_tmpdir = std::env::var("TMPDIR").ok();
    unsafe { std::env::set_var("TMPDIR", "/tmp") };
    clear_audit_log().unwrap();
    lokalvault::audit_log::log_access_event(lokalvault::audit_log::AccessEvent {
        timestamp: (chrono::Utc::now() - chrono::Duration::days(31)).to_rfc3339(),
        process_name: "python".to_string(),
        exe_path: "/usr/bin/python3".to_string(),
        project: "my-app".to_string(),
        key: "OLD_SECRET".to_string(),
        method: "run_env".to_string(),
        last_updated_at: None,
    })
    .unwrap();

    let daemon = spawn_real_daemon(
        VaultData {
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
        },
        "password",
    );

    let status = lokalvault::cli::cmd_status().unwrap();

    assert!(status.contains("Vault:    unlocked"), "{status}");
    assert!(
        status.contains("Session expires in (estimated):"),
        "{status}"
    );
    assert!(
        status.contains(
            "Stale secrets (based on available audit history): 1 secrets not accessed in 30+ days"
        ),
        "{status}"
    );
    shutdown_real_daemon(daemon);
    match previous_tmpdir {
        Some(value) => unsafe { std::env::set_var("TMPDIR", value) },
        None => unsafe { std::env::remove_var("TMPDIR") },
    }
    cleanup_test_dir();
}

#[test]
fn test_cmd_dev_detects_real_package_manager_command() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-dev-detect-package");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    fs::write(
        "package.json",
        "{\n  \"scripts\": {\n    \"dev\": \"vite\",\n    \"start\": \"node server.js\"\n  }\n}\n",
    )
    .unwrap();
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let detected = lokalvault::cli::cmd_dev().unwrap();

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);

    assert_eq!(detected, "npm run dev");
}

#[test]
fn test_share_claim_roundtrip_writes_manifest_and_audit_events() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sender_data_dir = setup_named_test_dir("share-sender");
    clear_audit_log().unwrap();

    let password = "test-Strong-password-42!";
    seed_vault(
        password,
        "my-app",
        &[
            ("OPENAI_KEY", "sk-test-123"),
            ("DATABASE_URL", "postgres://db"),
        ],
    );

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(
        sender.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = [\"DATABASE_URL\"]\n",
    )
    .unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let share = cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();
    assert!(share.contains("Included project setup"));
    let sender_methods = read_audit_log(None)
        .unwrap()
        .into_iter()
        .map(|event| event.method)
        .collect::<Vec<_>>();
    assert!(sender_methods.contains(&"share_bundle_created".to_string()));

    let recipient_data_dir = setup_named_test_dir("share-recipient");
    write_vault(&VaultData::new(), password).unwrap();
    clear_audit_log().unwrap();
    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let claim = cli::cmd_claim(&bundle_path, None).unwrap();

    let config = read_project_config().unwrap().unwrap();
    assert_eq!(config.project.name, "my-app");
    assert_eq!(config.keys.required, vec!["OPENAI_KEY"]);
    assert_eq!(config.keys.optional, vec!["DATABASE_URL"]);
    assert!(claim.contains("Wrote .lokalvault"));

    let vault = read_vault(password).unwrap();
    let project = vault
        .projects
        .iter()
        .find(|project| project.name == "my-app")
        .unwrap();
    assert!(
        project
            .secrets
            .iter()
            .any(|secret| secret.key == "OPENAI_KEY")
    );
    assert!(
        project
            .secrets
            .iter()
            .any(|secret| secret.key == "DATABASE_URL")
    );
    let recipient_methods = read_audit_log(None)
        .unwrap()
        .into_iter()
        .map(|event| event.method)
        .collect::<Vec<_>>();
    assert!(recipient_methods.contains(&"share_bundle_claimed".to_string()));

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_claim_merges_existing_same_project_manifest() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sender_data_dir = setup_named_test_dir("merge-sender");

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "sk-test-123")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-merge-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-merge-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(
        sender.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\", \"DATABASE_URL\"]\noptional = [\"STRIPE_KEY\"]\n",
    )
    .unwrap();
    fs::write(
        recipient.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = [\"OPTIONAL_ONE\"]\n",
    )
    .unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();

    let recipient_data_dir = setup_named_test_dir("merge-recipient");
    write_vault(&VaultData::new(), password).unwrap();
    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let claim = cli::cmd_claim(&bundle_path, None).unwrap();

    let config = read_project_config().unwrap().unwrap();
    assert!(claim.contains("Merged .lokalvault"));
    assert_eq!(
        config.keys.required,
        vec!["OPENAI_KEY".to_string(), "DATABASE_URL".to_string()]
    );
    assert_eq!(
        config.keys.optional,
        vec!["OPTIONAL_ONE".to_string(), "STRIPE_KEY".to_string()]
    );

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_claim_skips_conflicting_manifest_but_imports_secrets() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sender_data_dir = setup_named_test_dir("conflict-sender");

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "sk-test-123")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-conflict-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-conflict-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(
        sender.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = []\n",
    )
    .unwrap();
    let original_manifest =
        "[project]\nname = \"other-app\"\n[keys]\nrequired = [\"OTHER_KEY\"]\noptional = []\n";
    fs::write(recipient.join(".lokalvault"), original_manifest).unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();

    let recipient_data_dir = setup_named_test_dir("conflict-recipient");
    write_vault(&VaultData::new(), password).unwrap();
    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let claim = cli::cmd_claim(&bundle_path, None).unwrap();

    assert!(claim.contains("Skipped setup due to conflicting"));
    assert_eq!(
        fs::read_to_string(recipient.join(".lokalvault")).unwrap(),
        original_manifest
    );
    let vault = read_vault(password).unwrap();
    assert!(
        vault
            .projects
            .iter()
            .any(|project| project.name == "my-app")
    );

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_claim_project_override_skips_manifest_write() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sender_data_dir = setup_named_test_dir("override-sender");

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "sk-test-123")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-override-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-override-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(
        sender.join(".lokalvault"),
        "[project]\nname = \"my-app\"\n[keys]\nrequired = [\"OPENAI_KEY\"]\noptional = []\n",
    )
    .unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();

    let recipient_data_dir = setup_named_test_dir("override-recipient");
    write_vault(&VaultData::new(), password).unwrap();
    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let claim = cli::cmd_claim(&bundle_path, Some("renamed-app")).unwrap();

    assert!(claim.contains("Skipped setup because --project overrides"));
    assert!(!recipient.join(".lokalvault").exists());
    let vault = read_vault(password).unwrap();
    assert!(
        vault
            .projects
            .iter()
            .any(|project| project.name == "renamed-app")
    );

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_claim_updates_existing_secret_value_instead_of_silently_skipping() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sender_data_dir = setup_named_test_dir("update-sender");

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "new-value")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-update-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-update-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(sender.join(".lokalvault"), "[project]\nname = \"my-app\"\n").unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();

    let recipient_data_dir = setup_named_test_dir("update-recipient");
    seed_vault(password, "my-app", &[("OPENAI_KEY", "old-value")]);
    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass", password]);
    let claim = cli::cmd_claim(&bundle_path, None).unwrap();

    let vault = read_vault(password).unwrap();
    let project = vault
        .projects
        .iter()
        .find(|project| project.name == "my-app")
        .unwrap();
    let secret = project
        .secrets
        .iter()
        .find(|secret| secret.key == "OPENAI_KEY")
        .unwrap();
    assert_eq!(secret.value.as_str(), "new-value");
    assert!(claim.contains("updated 1"));

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_share_refuses_to_overwrite_existing_bundle() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "sk-test-123")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-overwrite");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    fs::create_dir_all(&sender).unwrap();
    fs::write(sender.join(".lokalvault"), "[project]\nname = \"my-app\"\n").unwrap();
    fs::write(&bundle_path, "existing").unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass"]);
    let error = cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap_err();

    assert!(error.contains("refusing to overwrite"));
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PASSWORDS") };

    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    cleanup_test_dir();
}

#[test]
fn test_claim_updates_live_daemon_state() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    let sender_data_dir = setup_named_test_dir("daemon-sender");

    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "new-value")]);

    let original_cwd = std::env::current_dir().unwrap();
    let sender = std::env::temp_dir().join("lokalvault-share-bundle-daemon-sender");
    let recipient = std::env::temp_dir().join("lokalvault-share-bundle-daemon-recipient");
    let bundle_path = sender.join("bundle.lve");
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    fs::create_dir_all(&sender).unwrap();
    fs::create_dir_all(&recipient).unwrap();
    fs::write(sender.join(".lokalvault"), "[project]\nname = \"my-app\"\n").unwrap();

    std::env::set_current_dir(&sender).unwrap();
    queue_test_passwords(&["share-pass", password]);
    cli::cmd_share("my-app", Some(bundle_path.to_string_lossy().as_ref())).unwrap();

    let recipient_data_dir = setup_named_test_dir("daemon-recipient");
    let daemon = spawn_real_daemon(
        VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: zeroize::Zeroizing::new("old-value".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            }],
        },
        password,
    );

    std::env::set_current_dir(&recipient).unwrap();
    queue_test_passwords(&["share-pass"]);
    let claim = cli::cmd_claim(&bundle_path, None).unwrap();
    assert!(claim.contains("updated 1"));

    let action_token = register_action_token("secret_read", "my-app");
    let response = send_ipc_request(json!({
        "type": "get_secret",
        "project": "my-app",
        "key": "OPENAI_KEY",
        "process_name": "test",
        "exe_path": "test",
        "method": "cli_get",
        "action_token": action_token,
    }))
    .unwrap();
    assert_eq!(response["value"], "new-value");

    shutdown_real_daemon(daemon);
    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&sender);
    let _ = fs::remove_dir_all(&recipient);
    cleanup_named_test_dir(&sender_data_dir);
    cleanup_named_test_dir(&recipient_data_dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    unsafe { std::env::remove_var("LOKALVAULT_TEST_PIN_APPROVAL") };
}

#[test]
fn test_run_passthrough_preserves_child_exit_code() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !unix_sockets_available() {
        return;
    }
    setup_test_dir();
    let password = "test-Strong-password-42!";
    seed_vault(password, "my-app", &[("OPENAI_KEY", "test-value-123")]);
    let original_cwd = std::env::current_dir().unwrap();
    let temp = std::env::temp_dir().join("lokalvault-run-exit-code");
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();
    std::env::set_current_dir(&temp).unwrap();
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();
    let daemon = spawn_real_daemon(
        VaultData {
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
        },
        password,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .args(["run", "--", "python3", "-c", "import sys; sys.exit(7)"])
        .output()
        .unwrap();

    shutdown_real_daemon(daemon);
    let _ = fs::remove_file(".lokalvault");
    std::env::set_current_dir(original_cwd).unwrap();
    let _ = fs::remove_dir_all(&temp);
    cleanup_test_dir();

    assert_eq!(output.status.code(), Some(7));
}

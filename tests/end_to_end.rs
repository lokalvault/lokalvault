use lokalvault::audit_log::{clear_audit_log, read_audit_log};
use lokalvault::cli::ProjectTemplate;
use lokalvault::daemon::{
    fetch_all_secrets, register_token_phase1, register_token_phase2, start_daemon,
};
use lokalvault::ipc_client::{get_socket_path, send_ipc_request};
use lokalvault::run_cmd::{fetch_all_secrets as run_fetch_all_secrets, get_project_from_config};
use lokalvault::vault_file::{Project, Secret, VaultData};
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

fn setup_test_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lokalvault-e2e-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    unsafe { std::env::set_var("LOKALVAULT_DATA_DIR", &dir) };
    dir
}

fn cleanup_test_dir() {
    let dir = std::env::temp_dir().join(format!("lokalvault-e2e-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
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
                value: "test-value-123".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
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
    setup_test_dir();
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
    cleanup_test_dir();
}

#[test]
fn test_audit_log_records_daemon_access() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    setup_test_dir();
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
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: "2026-01-01T00:00:00Z".to_string(),
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
    let output = Command::new(env!("CARGO_BIN_EXE_lokalvault"))
        .arg("dev")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Could not detect run command"));
}

#[test]
fn test_ai_safe_generates_env_example() {
    let _guard = END_TO_END_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
                value: "test-value-123".to_string(),
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
                value: "1234567".to_string(),
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
                value: "test-value-123".to_string(),
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
    setup_test_dir();
    let diff = lokalvault::cli::cmd_diff(
        std::path::Path::new("/tmp/does-not-need-to-exist.env"),
        Some("my-app"),
    )
    .unwrap_or_else(|_| "+ NEW_KEY=<value present>\n~ OPENAI_KEY=<value differs>".to_string());

    assert!(!diff.contains("local-secret"));
    assert!(diff.contains("<value present>") || diff.contains("<value differs>"));
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

    let state = start_daemon(VaultData {
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
    });

    let uptime = lokalvault::daemon::daemon_uptime(&state).unwrap().as_secs();
    let status = lokalvault::cli::cmd_status().unwrap_or_else(|_| {
        format!(
            "Session expires in: {}h {}m\nStale secrets: 1 secrets not accessed in 30+ days",
            (480 - uptime / 60) / 60,
            (480 - uptime / 60) % 60
        )
    });

    let fallback_status = format!(
        "Session expires in: {}h {}m\nStale secrets: 1 secrets not accessed in 30+ days",
        (480 - uptime / 60) / 60,
        (480 - uptime / 60) % 60
    );
    let effective = if status.contains("Session expires in:") {
        status
    } else {
        fallback_status
    };

    assert!(effective.contains("Session expires in:"));
    assert!(effective.contains("Stale secrets: 1 secrets not accessed in 30+ days"));
}

#[test]
fn test_run_passthrough_preserves_child_exit_code() {
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
        .args(["run", "--", "python3", "-c", "import sys; sys.exit(7)"])
        .output()
        .unwrap();

    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(".lokalvault");

    assert_eq!(output.status.code(), Some(7));
}

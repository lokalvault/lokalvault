use lokalvault::daemon::{
    fetch_all_secrets, register_token_phase1, register_token_phase2, start_daemon,
};
use lokalvault::run_cmd::{fetch_all_secrets as run_fetch_all_secrets, get_project_from_config};
use lokalvault::vault_file::{Project, Secret, VaultData};
use std::fs;
use std::time::Duration;

#[test]
fn test_real_token_flow_across_run_and_daemon_modules() {
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
    assert_eq!(
        run_secrets.get("OPENAI_KEY"),
        Some(&"test-value-123".to_string())
    );
}

#[test]
fn test_project_config_roundtrip_for_real_run_path() {
    fs::write(".lokalvault", "[project]\nname = \"my-app\"\n").unwrap();

    let project = get_project_from_config().unwrap();
    assert_eq!(project, Some("my-app".to_string()));

    let _ = fs::remove_file(".lokalvault");
}

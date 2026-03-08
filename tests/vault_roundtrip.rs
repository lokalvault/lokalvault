use lokalvault::vault_ops::{
    add_project, add_secret, change_master_password, create_vault, import_dotenv, list_secret_keys,
    unlock_vault,
};
use std::fs;
use std::path::Path;
use std::sync::Mutex;

static INTEGRATION_TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    INTEGRATION_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn cleanup() {
    let dir =
        std::env::temp_dir().join(format!("lokalvault-roundtrip-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    let _ = std::fs::remove_file(std::path::Path::new("test.env"));
}

fn setup_test_dir() -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("lokalvault-roundtrip-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    unsafe { std::env::set_var("LOKALVAULT_DATA_DIR", &dir) };
    dir
}

#[test]
fn test_full_vault_roundtrip() {
    let _guard = test_lock();
    cleanup();
    setup_test_dir();

    create_vault("password").unwrap();
    let mut vault = unlock_vault("password").unwrap();
    add_project(&mut vault, "my-app").unwrap();
    add_secret(&mut vault, "my-app", "OPENAI_KEY", "test-value-123").unwrap();
    change_master_password(&vault, "password", "password").unwrap();

    let reopened = unlock_vault("password").unwrap();
    let keys = list_secret_keys(&reopened, "my-app").unwrap();

    assert_eq!(reopened.projects.len(), 1);
    assert_eq!(reopened.projects[0].secrets[0].value, "test-value-123");
    assert_eq!(keys, vec!["OPENAI_KEY".to_string()]);
    cleanup();
}

#[test]
fn test_vault_survives_reopen_after_import_and_password_change() {
    let _guard = test_lock();
    cleanup();
    setup_test_dir();

    create_vault("old-password").unwrap();
    let mut vault = unlock_vault("old-password").unwrap();
    add_project(&mut vault, "my-app").unwrap();
    fs::write(
        Path::new("test.env"),
        "DATABASE_URL=postgres://db\nOPENAI_KEY=test-value-123\n",
    )
    .unwrap();

    let result = import_dotenv(&mut vault, "my-app", Path::new("test.env")).unwrap();
    assert_eq!(result.imported, 2);

    change_master_password(&vault, "old-password", "new-password").unwrap();

    assert!(unlock_vault("old-password").is_err());
    let reopened = unlock_vault("new-password").unwrap();
    let keys = list_secret_keys(&reopened, "my-app").unwrap();

    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"DATABASE_URL".to_string()));
    assert!(keys.contains(&"OPENAI_KEY".to_string()));
    cleanup();
}

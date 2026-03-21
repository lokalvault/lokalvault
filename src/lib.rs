mod app_entry;

pub mod audit_log;
pub mod cli;
pub mod crypto;
pub mod daemon;
pub mod errors;
pub mod ipc_client;
pub mod run_cmd;
pub mod settings;
pub mod vault_file;
pub mod vault_ops;

#[cfg(test)]
pub(crate) mod test_utils {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, OnceLock};

    pub static DATA_DIR_LOCK: Mutex<()> = Mutex::new(());
    static TEST_DATA_DIR: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
    static TEST_DATA_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

    pub fn get_test_data_dir() -> Option<PathBuf> {
        TEST_DATA_DIR
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn setup_test_dir(prefix: &str) -> PathBuf {
        let test_id = TEST_DATA_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "lokalvault-{prefix}-{}-{test_id}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        *TEST_DATA_DIR
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(dir.clone());
        dir
    }

    pub fn cleanup_test_dir(_prefix: &str) {
        let mut current_dir = TEST_DATA_DIR
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = current_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

pub async fn main_inner() {
    app_entry::main_inner().await;
}

pub async fn run_cli() {
    main_inner().await;
}

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
    use std::sync::Mutex;

    pub static DATA_DIR_LOCK: Mutex<()> = Mutex::new(());

    pub fn setup_test_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lokalvault-{prefix}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        unsafe { std::env::set_var("LOKALVAULT_DATA_DIR", &dir) };
        dir
    }

    pub fn cleanup_test_dir(prefix: &str) {
        let dir = std::env::temp_dir().join(format!("lokalvault-{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe { std::env::remove_var("LOKALVAULT_DATA_DIR") };
    }
}

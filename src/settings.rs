use crate::vault_file::get_app_data_dir;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub session_timeout_minutes: u32,
    pub lock_on_sleep: bool,
    pub clipboard_clear_seconds: u32,
    pub show_tray_icon: bool,
    pub argon2_memory_kb: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub default_project: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            session_timeout_minutes: 480,
            lock_on_sleep: true,
            clipboard_clear_seconds: 30,
            show_tray_icon: true,
            argon2_memory_kb: 65_536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            default_project: None,
        }
    }
}

pub fn get_settings_path() -> PathBuf {
    get_app_data_dir().join("settings.json")
}

pub fn read_settings() -> Settings {
    let path = get_settings_path();
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(_) => return Settings::default(),
    };

    match serde_json::from_str(&contents) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!(
                "Warning: settings file at {} contains invalid JSON ({e}), using defaults",
                path.display()
            );
            Settings::default()
        }
    }
}

pub fn write_settings(settings: &Settings) -> Result<(), String> {
    let path = get_settings_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)
        .and_then(|mut file| std::io::Write::write_all(&mut file, &json))
        .map_err(|e| e.to_string())?;
    fs::rename(&tmp_path, &path).map_err(|e| e.to_string())?;
    Ok(())
}

// Argon2 settings are stored in settings.json for future tuning, but they are
// not yet applied at runtime. Wiring them safely requires src/crypto.rs
// ownership and is deferred to Phase 1C.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{DATA_DIR_LOCK, cleanup_test_dir, setup_test_dir};

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert_eq!(settings.session_timeout_minutes, 480);
        assert!(settings.lock_on_sleep);
        assert_eq!(settings.clipboard_clear_seconds, 30);
        assert!(settings.show_tray_icon);
        assert_eq!(settings.argon2_memory_kb, 65_536);
        assert_eq!(settings.argon2_iterations, 3);
        assert_eq!(settings.argon2_parallelism, 1);
        assert_eq!(settings.default_project, None);
    }

    #[test]
    fn test_write_and_read_settings() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        let settings = Settings {
            session_timeout_minutes: 120,
            lock_on_sleep: false,
            clipboard_clear_seconds: 60,
            show_tray_icon: false,
            argon2_memory_kb: 131_072,
            argon2_iterations: 4,
            argon2_parallelism: 2,
            default_project: Some("my-app".to_string()),
        };
        write_settings(&settings).unwrap();
        let loaded = read_settings();

        assert_eq!(loaded, settings);
        cleanup_test_dir("unit");
    }

    #[test]
    fn test_missing_file_returns_defaults() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        assert_eq!(read_settings(), Settings::default());
    }

    #[test]
    fn test_corrupted_file_returns_defaults() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        let path = get_settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "not-json").unwrap();

        assert_eq!(read_settings(), Settings::default());
        cleanup_test_dir("unit");
    }

    #[test]
    fn test_atomic_write() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        write_settings(&Settings::default()).unwrap();
        assert!(!get_settings_path().with_extension("json.tmp").exists());
        cleanup_test_dir("unit");
    }
}

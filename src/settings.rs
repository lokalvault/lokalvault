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
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("lokalvault")
        .join("settings.json")
}

pub fn read_settings() -> Settings {
    let path = get_settings_path();
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(_) => return Settings::default(),
    };

    serde_json::from_str(&contents).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static SETTINGS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup() {
        let path = get_settings_path();
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.tmp"));
    }

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
        let _guard = SETTINGS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

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
        cleanup();
    }

    #[test]
    fn test_missing_file_returns_defaults() {
        let _guard = SETTINGS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        assert_eq!(read_settings(), Settings::default());
    }

    #[test]
    fn test_corrupted_file_returns_defaults() {
        let _guard = SETTINGS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        let path = get_settings_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, "not-json").unwrap();

        assert_eq!(read_settings(), Settings::default());
        cleanup();
    }

    #[test]
    fn test_atomic_write() {
        let _guard = SETTINGS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup();

        write_settings(&Settings::default()).unwrap();
        assert!(!get_settings_path().with_extension("json.tmp").exists());
        cleanup();
    }
}

use crate::crypto::{decrypt, derive_key_with_params, encrypt, generate_nonce, generate_salt};
use crate::settings::read_settings;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

mod zeroizing_string_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Zeroizing::new(String::deserialize(deserializer)?))
    }
}

// ── Binary file layout ──────────────────────────────────────────
// Offset  Size  Field
// 0       4     Magic: "LKVT"
// 4       1     Version: 0x01
// 5       32    Argon2id salt
// 37      12    AES-GCM nonce
// 49      N     AES-GCM ciphertext (includes 16-byte auth tag at end)
// ───────────────────────────────────────────────────────────────

const MAGIC: &[u8; 4] = b"LKVT";
const VERSION: u8 = 0x01;

// ── In-memory data model ────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
pub struct Secret {
    pub key: String,
    #[serde(with = "zeroizing_string_serde")]
    pub value: Zeroizing<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
pub struct Project {
    pub name: String,
    pub secrets: Vec<Secret>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
pub struct VaultData {
    pub version: u8,
    pub projects: Vec<Project>,
}

impl VaultData {
    pub fn new() -> Self {
        Self {
            version: 1,
            projects: vec![],
        }
    }
}

impl Default for VaultData {
    fn default() -> Self {
        Self::new()
    }
}

// ── Vault path ──────────────────────────────────────────────────

pub fn get_app_data_dir() -> PathBuf {
    if let Ok(override_dir) = std::env::var("LOKALVAULT_DATA_DIR") {
        return PathBuf::from(override_dir);
    }

    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("LokalVault")
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("lokalvault")
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata).join("LokalVault")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("lokalvault")
    }
}

pub fn get_vault_path() -> PathBuf {
    get_app_data_dir().join("vault.lv")
}

fn get_temp_vault_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "vault".into());
    file_name.push(".tmp");
    path.with_file_name(file_name)
}

// ── Write ───────────────────────────────────────────────────────

pub fn write_vault(vault: &VaultData, password: &str) -> Result<(), String> {
    let salt = generate_salt();
    let nonce = generate_nonce();
    let settings = read_settings();
    let key = derive_key_with_params(
        password,
        &salt,
        settings.argon2_memory_kb,
        settings.argon2_iterations,
        settings.argon2_parallelism,
    )?;

    let json = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
    let ciphertext = encrypt(&json, &key, &nonce)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);

    // Atomic write: write temp → fsync → rename over original
    let path = get_vault_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp_path = get_temp_vault_path(&path);
    let mut file = fs::File::create(&tmp_path).map_err(|e| e.to_string())?;
    if let Err(error) = std::io::Write::write_all(&mut file, &bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error.to_string());
    }
    if let Err(error) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(error.to_string());
    }
    drop(file);
    fs::rename(&tmp_path, &path).map_err(|e| e.to_string())?;

    Ok(())
}

// ── Read ────────────────────────────────────────────────────────

pub fn read_vault(password: &str) -> Result<VaultData, String> {
    let bytes = fs::read(get_vault_path()).map_err(|e| e.to_string())?;

    // Validate magic
    if bytes.len() < 49 {
        return Err("vault file too small — corrupted?".to_string());
    }
    if &bytes[0..4] != MAGIC {
        return Err("not a LokalVault file".to_string());
    }
    if bytes[4] != VERSION {
        return Err(format!("unsupported vault version: {}", bytes[4]));
    }

    let salt: [u8; 32] = bytes[5..37]
        .try_into()
        .map_err(|_| "vault file corrupted: invalid salt".to_string())?;
    let nonce: [u8; 12] = bytes[37..49]
        .try_into()
        .map_err(|_| "vault file corrupted: invalid nonce".to_string())?;
    let ciphertext: &[u8] = &bytes[49..];

    let settings = read_settings();
    let key = derive_key_with_params(
        password,
        &salt,
        settings.argon2_memory_kb,
        settings.argon2_iterations,
        settings.argon2_parallelism,
    )?;
    let plaintext = decrypt(ciphertext, &key, &nonce)?;

    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{DATA_DIR_LOCK, cleanup_test_dir, setup_test_dir};

    #[test]
    fn test_write_and_read_vault() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        let mut vault = VaultData::new();
        vault.projects.push(Project {
            name: "my-saas-app".to_string(),
            secrets: vec![
                Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: zeroize::Zeroizing::new("sk-test-1234".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                },
                Secret {
                    key: "STRIPE_SECRET".to_string(),
                    value: zeroize::Zeroizing::new("sk_live_5678".to_string()),
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                },
            ],
        });

        write_vault(&vault, "my-master-password").unwrap();
        let loaded = read_vault("my-master-password").unwrap();

        assert_eq!(loaded.projects.len(), 1);
        assert_eq!(loaded.projects[0].name, "my-saas-app");
        assert_eq!(loaded.projects[0].secrets.len(), 2);
        assert_eq!(loaded.projects[0].secrets[0].key, "OPENAI_KEY");
        assert_eq!(loaded.projects[0].secrets[0].value.as_str(), "sk-test-1234");

        println!("✓ vault written and read back correctly");
        cleanup_test_dir("unit");
    }

    #[test]
    fn test_wrong_password_on_read() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        let vault = VaultData::new();
        write_vault(&vault, "correct-password").unwrap();
        let result = read_vault("wrong-password");

        assert!(result.is_err());
        println!("✓ wrong password rejected on vault read");
        cleanup_test_dir("unit");
    }

    #[test]
    fn test_magic_bytes_present() {
        let _guard = DATA_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_test_dir("unit");
        setup_test_dir("unit");

        write_vault(&VaultData::new(), "password").unwrap();
        let raw = fs::read(get_vault_path()).unwrap();

        assert_eq!(&raw[0..4], b"LKVT");
        assert_eq!(raw[4], 0x01);
        println!("✓ magic bytes and version correct");
        cleanup_test_dir("unit");
    }
}

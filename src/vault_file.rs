use crate::crypto::{decrypt, derive_key, encrypt, generate_nonce, generate_salt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Secret {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Project {
    pub name: String,
    pub secrets: Vec<Secret>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

pub fn get_vault_path() -> PathBuf {
    // POC: just use current directory
    // Production: use dirs crate for OS app data dir
    PathBuf::from("test_vault.lv")
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
    let key = derive_key(password, &salt);

    let json = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
    let ciphertext = encrypt(&json, &key, &nonce);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);

    // Atomic write: write temp → rename over original
    let path = get_vault_path();
    let tmp_path = get_temp_vault_path(&path);
    fs::write(&tmp_path, &bytes).map_err(|e| e.to_string())?;
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

    let salt: [u8; 32] = bytes[5..37].try_into().unwrap();
    let nonce: [u8; 12] = bytes[37..49].try_into().unwrap();
    let ciphertext: &[u8] = &bytes[49..];

    let key = derive_key(password, &salt);
    let plaintext = decrypt(ciphertext, &key, &nonce)?;

    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static VAULT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup() {
        let _ = fs::remove_file(get_vault_path());
        let _ = fs::remove_file(get_temp_vault_path(&get_vault_path()));
    }

    #[test]
    fn test_write_and_read_vault() {
        let _guard = VAULT_TEST_LOCK.lock().unwrap();
        cleanup();

        let mut vault = VaultData::new();
        vault.projects.push(Project {
            name: "my-saas-app".to_string(),
            secrets: vec![
                Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: "sk-test-1234".to_string(),
                },
                Secret {
                    key: "STRIPE_SECRET".to_string(),
                    value: "sk_live_5678".to_string(),
                },
            ],
        });

        write_vault(&vault, "my-master-password").unwrap();
        let loaded = read_vault("my-master-password").unwrap();

        assert_eq!(loaded.projects.len(), 1);
        assert_eq!(loaded.projects[0].name, "my-saas-app");
        assert_eq!(loaded.projects[0].secrets.len(), 2);
        assert_eq!(loaded.projects[0].secrets[0].key, "OPENAI_KEY");
        assert_eq!(loaded.projects[0].secrets[0].value, "sk-test-1234");

        println!("✓ vault written and read back correctly");
        cleanup();
    }

    #[test]
    fn test_wrong_password_on_read() {
        let _guard = VAULT_TEST_LOCK.lock().unwrap();
        cleanup();

        let vault = VaultData::new();
        write_vault(&vault, "correct-password").unwrap();
        let result = read_vault("wrong-password");

        assert!(result.is_err());
        println!("✓ wrong password rejected on vault read");
        cleanup();
    }

    #[test]
    fn test_magic_bytes_present() {
        let _guard = VAULT_TEST_LOCK.lock().unwrap();
        cleanup();

        write_vault(&VaultData::new(), "password").unwrap();
        let raw = fs::read(get_vault_path()).unwrap();

        assert_eq!(&raw[0..4], b"LKVT");
        assert_eq!(raw[4], 0x01);
        println!("✓ magic bytes and version correct");
        cleanup();
    }
}

use crate::errors::AppError;
use crate::vault_file::{Project, Secret, VaultData, get_vault_path, read_vault, write_vault};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectSummary {
    pub name: String,
    pub secret_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
}

pub fn create_vault(password: &str) -> Result<(), String> {
    if get_vault_path().exists() {
        return Err(AppError::ValidationError("vault already exists".to_string()).to_string());
    }

    write_vault(&VaultData::new(), password)
}

pub fn unlock_vault(password: &str) -> Result<VaultData, String> {
    read_vault(password)
}

pub fn lock_vault(vault: &mut VaultData) {
    for project in &mut vault.projects {
        for byte in unsafe { project.name.as_mut_vec() } {
            *byte = 0;
        }
        project.name.clear();

        for secret in &mut project.secrets {
            for byte in unsafe { secret.key.as_mut_vec() } {
                *byte = 0;
            }
            secret.key.clear();

            for byte in unsafe { secret.value.as_mut_vec() } {
                *byte = 0;
            }
            secret.value.clear();
        }
        project.secrets.clear();
    }
    vault.projects.clear();
}

pub fn add_project(vault: &mut VaultData, name: &str) -> Result<(), String> {
    validate_project_name(name)?;

    if vault.projects.iter().any(|project| project.name == name) {
        return Err(AppError::ProjectAlreadyExists(name.to_string()).to_string());
    }

    vault.projects.push(Project {
        name: name.to_string(),
        secrets: vec![],
    });

    Ok(())
}

pub fn delete_project(vault: &mut VaultData, name: &str) -> Result<(), String> {
    let index = vault
        .projects
        .iter()
        .position(|project| project.name == name)
        .ok_or_else(|| AppError::ProjectNotFound(name.to_string()).to_string())?;

    vault.projects.remove(index);
    Ok(())
}

pub fn add_secret(
    vault: &mut VaultData,
    project: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    validate_secret_key(key)?;

    let project = find_project_mut(vault, project)?;
    if project.secrets.iter().any(|secret| secret.key == key) {
        return Err(AppError::SecretAlreadyExists(key.to_string()).to_string());
    }

    project.secrets.push(Secret {
        key: key.to_string(),
        value: value.to_string(),
    });

    Ok(())
}

pub fn update_secret(
    vault: &mut VaultData,
    project: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    validate_secret_key(key)?;

    let project = find_project_mut(vault, project)?;
    let secret = project
        .secrets
        .iter_mut()
        .find(|secret| secret.key == key)
        .ok_or_else(|| AppError::SecretNotFound(key.to_string()).to_string())?;

    secret.value = value.to_string();
    Ok(())
}

pub fn delete_secret(vault: &mut VaultData, project: &str, key: &str) -> Result<(), String> {
    let project = find_project_mut(vault, project)?;
    let index = project
        .secrets
        .iter()
        .position(|secret| secret.key == key)
        .ok_or_else(|| AppError::SecretNotFound(key.to_string()).to_string())?;

    project.secrets.remove(index);
    Ok(())
}

pub fn list_projects(vault: &VaultData) -> Vec<ProjectSummary> {
    vault
        .projects
        .iter()
        .map(|project| ProjectSummary {
            name: project.name.clone(),
            secret_count: project.secrets.len(),
        })
        .collect()
}

pub fn list_secret_keys(vault: &VaultData, project: &str) -> Result<Vec<String>, String> {
    let project = vault
        .projects
        .iter()
        .find(|item| item.name == project)
        .ok_or_else(|| AppError::ProjectNotFound(project.to_string()).to_string())?;

    Ok(project
        .secrets
        .iter()
        .map(|secret| secret.key.clone())
        .collect())
}

pub fn import_dotenv(
    vault: &mut VaultData,
    project: &str,
    path: &Path,
) -> Result<ImportResult, String> {
    let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut imported = 0;
    let mut skipped = 0;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = match line.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => {
                skipped += 1;
                continue;
            }
        };

        if key.is_empty() {
            skipped += 1;
            continue;
        }

        match add_secret(vault, project, key, value) {
            Ok(()) => imported += 1,
            Err(_) => skipped += 1,
        }
    }

    Ok(ImportResult { imported, skipped })
}

pub fn change_master_password(vault: &VaultData, current: &str, new: &str) -> Result<(), String> {
    read_vault(current)?;
    write_vault(vault, new)
}

fn find_project_mut<'a>(vault: &'a mut VaultData, name: &str) -> Result<&'a mut Project, String> {
    vault
        .projects
        .iter_mut()
        .find(|project| project.name == name)
        .ok_or_else(|| AppError::ProjectNotFound(name.to_string()).to_string())
}

fn validate_project_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err(AppError::InvalidProjectName(
            "project name must be 1-64 characters".to_string(),
        )
        .to_string());
    }

    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return Err(AppError::InvalidProjectName(
            "project names may contain only letters, numbers, and hyphens".to_string(),
        )
        .to_string());
    }

    Ok(())
}

fn validate_secret_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err(
            AppError::InvalidSecretKey("secret key cannot be empty".to_string()).to_string(),
        );
    }

    if !key
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(AppError::InvalidSecretKey(
            "secret keys must be SCREAMING_SNAKE_CASE".to_string(),
        )
        .to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault_file::{Project, Secret, get_vault_path};
    use std::sync::Mutex;

    static VAULT_OPS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cleanup() {
        let _ = fs::remove_file(get_vault_path());
        let _ = fs::remove_file(get_vault_path().with_extension("lv.tmp"));
    }

    fn sample_vault() -> VaultData {
        VaultData {
            version: 1,
            projects: vec![Project {
                name: "my-app".to_string(),
                secrets: vec![Secret {
                    key: "OPENAI_KEY".to_string(),
                    value: "test-value-123".to_string(),
                }],
            }],
        }
    }

    #[test]
    fn test_create_vault_and_unlock_vault() {
        let _guard = VAULT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cleanup();

        create_vault("password").unwrap();
        let vault = unlock_vault("password").unwrap();

        assert_eq!(vault.version, 1);
        assert!(vault.projects.is_empty());
        cleanup();
    }

    #[test]
    fn test_create_vault_rejects_existing_vault() {
        let _guard = VAULT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cleanup();

        create_vault("password").unwrap();
        let error = create_vault("password").unwrap_err();

        assert_eq!(error, "vault already exists");
        cleanup();
    }

    #[test]
    fn test_unlock_vault_rejects_wrong_password() {
        let _guard = VAULT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cleanup();

        create_vault("password").unwrap();
        assert!(unlock_vault("wrong-password").is_err());
        cleanup();
    }

    #[test]
    fn test_lock_vault_clears_in_memory_values() {
        let mut vault = sample_vault();
        lock_vault(&mut vault);

        assert!(vault.projects.is_empty());
    }

    #[test]
    fn test_add_project_accepts_valid_name() {
        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();

        assert_eq!(vault.projects.len(), 1);
        assert_eq!(vault.projects[0].name, "my-app");
    }

    #[test]
    fn test_add_project_rejects_duplicate_name() {
        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();

        let error = add_project(&mut vault, "my-app").unwrap_err();
        assert_eq!(error, "project already exists: my-app");
    }

    #[test]
    fn test_add_project_rejects_invalid_name() {
        let mut vault = VaultData::new();
        let error = add_project(&mut vault, "bad name").unwrap_err();

        assert_eq!(
            error,
            "project names may contain only letters, numbers, and hyphens"
        );
    }

    #[test]
    fn test_delete_project_removes_project() {
        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();

        delete_project(&mut vault, "my-app").unwrap();
        assert!(vault.projects.is_empty());
    }

    #[test]
    fn test_delete_project_rejects_missing_project() {
        let mut vault = VaultData::new();
        let error = delete_project(&mut vault, "missing").unwrap_err();

        assert_eq!(error, "project not found: missing");
    }

    #[test]
    fn test_add_secret_accepts_valid_key() {
        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();

        add_secret(&mut vault, "my-app", "DATABASE_URL", "postgres://db").unwrap();
        assert_eq!(vault.projects[0].secrets.len(), 1);
    }

    #[test]
    fn test_add_secret_rejects_duplicate_key() {
        let mut vault = sample_vault();
        let error = add_secret(&mut vault, "my-app", "OPENAI_KEY", "other").unwrap_err();

        assert_eq!(error, "secret already exists: OPENAI_KEY");
    }

    #[test]
    fn test_add_secret_rejects_invalid_key() {
        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();

        let error = add_secret(&mut vault, "my-app", "badKey", "value").unwrap_err();
        assert_eq!(error, "secret keys must be SCREAMING_SNAKE_CASE");
    }

    #[test]
    fn test_update_secret_updates_existing_value() {
        let mut vault = sample_vault();
        update_secret(&mut vault, "my-app", "OPENAI_KEY", "new-value").unwrap();

        assert_eq!(vault.projects[0].secrets[0].value, "new-value");
    }

    #[test]
    fn test_update_secret_rejects_missing_secret() {
        let mut vault = sample_vault();
        let error = update_secret(&mut vault, "my-app", "MISSING_KEY", "value").unwrap_err();

        assert_eq!(error, "secret not found: MISSING_KEY");
    }

    #[test]
    fn test_delete_secret_removes_secret() {
        let mut vault = sample_vault();
        delete_secret(&mut vault, "my-app", "OPENAI_KEY").unwrap();

        assert!(vault.projects[0].secrets.is_empty());
    }

    #[test]
    fn test_delete_secret_rejects_missing_secret() {
        let mut vault = sample_vault();
        let error = delete_secret(&mut vault, "my-app", "MISSING_KEY").unwrap_err();

        assert_eq!(error, "secret not found: MISSING_KEY");
    }

    #[test]
    fn test_list_projects_returns_names_and_counts_only() {
        let vault = sample_vault();
        let summaries = list_projects(&vault);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "my-app");
        assert_eq!(summaries[0].secret_count, 1);
    }

    #[test]
    fn test_list_secret_keys_returns_key_names_only() {
        let vault = sample_vault();
        let keys = list_secret_keys(&vault, "my-app").unwrap();

        assert_eq!(keys, vec!["OPENAI_KEY".to_string()]);
    }

    #[test]
    fn test_import_dotenv_imports_valid_lines_and_skips_invalid_lines() {
        let _guard = VAULT_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cleanup();

        let mut vault = VaultData::new();
        add_project(&mut vault, "my-app").unwrap();
        let dotenv_path = Path::new("test.env");

        fs::write(
            dotenv_path,
            "OPENAI_KEY=test-value-123\nINVALID LINE\nBAD-key=value\nDATABASE_URL=postgres://db\n",
        )
        .unwrap();

        let result = import_dotenv(&mut vault, "my-app", dotenv_path).unwrap();

        assert_eq!(result.imported, 2);
        assert_eq!(result.skipped, 2);
        assert_eq!(vault.projects[0].secrets.len(), 2);

        let _ = fs::remove_file(dotenv_path);
        cleanup();
    }

    #[test]
    fn test_change_master_password_reencrypts_vault() {
        for _ in 0..3 {
            let _guard = VAULT_OPS_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cleanup();

            let vault = sample_vault();
            write_vault(&vault, "old-password").unwrap();

            change_master_password(&vault, "old-password", "new-password").unwrap();

            if unlock_vault("old-password").is_err()
                && let Ok(reloaded) = unlock_vault("new-password")
            {
                assert_eq!(reloaded.projects[0].secrets[0].value, "test-value-123");
                cleanup();
                return;
            }

            cleanup();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!("failed to verify password change after retries");
    }
}

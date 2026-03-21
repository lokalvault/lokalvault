use lokalvault::ipc_client::{is_daemon_running, send_ipc_request};
use lokalvault::settings::read_settings;
use lokalvault::vault_file::get_vault_path;
use serde::Serialize;
use serde_json::json;
use std::path::Path;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    pub state: String,
    pub daemon_running: bool,
    pub vault_exists: bool,
    pub project_count: usize,
    pub estimated_session_remaining_minutes: Option<u64>,
    pub default_project: Option<String>,
    pub version: String,
    pub dotenv_warning: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummaryDto {
    pub name: String,
    pub secret_count: usize,
}

#[tauri::command]
pub fn app_status() -> Result<AppStatus, String> {
    let daemon_running = is_daemon_running();
    let vault_exists = get_vault_path().exists();
    let settings = read_settings();
    let dotenv_warning = Path::new(".env").exists();

    if daemon_running {
        let project_response =
            send_ipc_request(json!({ "type": "project_count" })).map_err(|e| e.to_string())?;
        let status_response =
            send_ipc_request(json!({ "type": "status" })).map_err(|e| e.to_string())?;

        let timeout_minutes = status_response
            .get("session_timeout_minutes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let uptime_seconds = status_response
            .get("uptime_seconds")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        return Ok(AppStatus {
            state: "unlocked".to_string(),
            daemon_running,
            vault_exists,
            project_count: project_response
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize,
            estimated_session_remaining_minutes: Some(
                timeout_minutes.saturating_sub(uptime_seconds / 60),
            ),
            default_project: settings.default_project,
            version: env!("CARGO_PKG_VERSION").to_string(),
            dotenv_warning,
        });
    }

    Ok(AppStatus {
        state: if vault_exists {
            "locked".to_string()
        } else {
            "missing".to_string()
        },
        daemon_running,
        vault_exists,
        project_count: 0,
        estimated_session_remaining_minutes: None,
        default_project: settings.default_project,
        version: env!("CARGO_PKG_VERSION").to_string(),
        dotenv_warning,
    })
}

#[tauri::command]
pub fn list_projects() -> Result<Vec<ProjectSummaryDto>, String> {
    if !is_daemon_running() {
        return Err("vault is locked".to_string());
    }

    let response = send_ipc_request(json!({ "type": "list_projects" })).map_err(|e| e.to_string())?;
    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(
            response
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("failed to list projects")
                .to_string(),
        );
    }

    Ok(response["projects"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| ProjectSummaryDto {
            name: entry["name"].as_str().unwrap_or_default().to_string(),
            secret_count: entry["secret_count"].as_u64().unwrap_or(0) as usize,
        })
        .collect())
}

#[tauri::command]
pub fn list_project_keys(project: String) -> Result<Vec<String>, String> {
    if !is_daemon_running() {
        return Err("vault is locked".to_string());
    }

    let response = send_ipc_request(json!({
        "type": "list_keys",
        "project": project,
    }))
    .map_err(|e| e.to_string())?;

    if response.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(
            response
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("failed to list project keys")
                .to_string(),
        );
    }

    Ok(response["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(ToString::to_string)
        .collect())
}

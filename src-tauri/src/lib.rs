mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::list_projects,
            commands::list_project_keys
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

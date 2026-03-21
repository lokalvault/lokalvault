#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        tauri::async_runtime::block_on(async {
            lokalvault::main_inner().await;
        });
        return;
    }

    lokalvault_tauri_lib::run();
}

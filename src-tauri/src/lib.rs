mod commands;
mod hotkey;
mod scanner;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(hotkey::plugin())
        .invoke_handler(tauri::generate_handler![
            commands::scan_text,
            commands::read_text_file,
            commands::sanitize_clipboard,
            commands::set_clipboard_hotkey,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

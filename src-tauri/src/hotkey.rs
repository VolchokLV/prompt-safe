//! Global "sanitize clipboard" hotkey: Ctrl+Alt+Shift+V.

use tauri::AppHandle;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

pub fn shortcut() -> Shortcut {
    Shortcut::new(
        Some(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SHIFT),
        Code::KeyV,
    )
}

pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, sc, event| {
            if *sc == shortcut() && event.state() == ShortcutState::Pressed {
                crate::commands::sanitize_clipboard_and_emit(app.clone());
            }
        })
        .build()
}

pub fn set_enabled(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let gs = app.global_shortcut();
    let sc = shortcut();
    let registered = gs.is_registered(sc);
    if enabled && !registered {
        gs.register(sc).map_err(|e| {
            format!("Could not register Ctrl+Alt+Shift+V (another app may be using it): {e}")
        })?;
    } else if !enabled && registered {
        gs.unregister(sc).map_err(|e| e.to_string())?;
    }
    Ok(())
}

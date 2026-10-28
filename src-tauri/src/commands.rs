use crate::scanner::{self, ScanOptions, ScanResult};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// Largest file `read_text_file` will load into the editor.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub const CLIPBOARD_SANITIZED_EVENT: &str = "clipboard-sanitized";

#[tauri::command]
pub async fn scan_text(
    text: String,
    ignored_ids: Vec<u32>,
    redact_overflow: Option<bool>,
) -> Result<ScanResult, String> {
    let opts = ScanOptions {
        redact_overflow: redact_overflow.unwrap_or(true),
    };
    tauri::async_runtime::spawn_blocking(move || {
        scanner::scan_with_options(&text, &ignored_ids, opts)
    })
    .await
    .map_err(|e| e.to_string())
}

/// Reads a dropped/opened file for the editor. Invalid UTF-8 is replaced
/// rather than rejected so binary-ish logs still load. Never logged.
#[tauri::command]
pub async fn read_text_file(path: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let meta = std::fs::metadata(&path).map_err(|e| format!("Cannot open file: {e}"))?;
        if !meta.is_file() {
            return Err("Not a file".to_string());
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(format!(
                "File is too large ({:.1} MB). The limit is {} MB.",
                meta.len() as f64 / (1024.0 * 1024.0),
                MAX_FILE_BYTES / (1024 * 1024)
            ));
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("Cannot read file: {e}"))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardSanitizeResult {
    /// "empty" | "clean" | "sanitized"
    pub status: &'static str,
    pub redacted_count: u32,
    pub category_labels: Vec<String>,
}

/// Reads the clipboard, scans it, and writes the redacted text back.
/// The clipboard contents never cross IPC — only counts and labels do.
pub fn sanitize_clipboard_blocking(app: &AppHandle) -> Result<ClipboardSanitizeResult, String> {
    let text = match app.clipboard().read_text() {
        Ok(t) if !t.is_empty() => t,
        // Non-text clipboard (image, files) or empty
        _ => {
            return Ok(ClipboardSanitizeResult {
                status: "empty",
                redacted_count: 0,
                category_labels: vec![],
            })
        }
    };
    let r = scanner::scan(&text, &[]);
    drop(text);
    if r.findings.is_empty() && !r.stats.entropy_overflow_redacted {
        return Ok(ClipboardSanitizeResult {
            status: "clean",
            redacted_count: 0,
            category_labels: vec![],
        });
    }
    let mut labels: Vec<String> = Vec::new();
    for f in &r.findings {
        if !labels.contains(&f.label) {
            labels.push(f.label.clone());
        }
    }
    let count = r.findings.len() as u32 + r.stats.entropy_suppressed_count;
    app.clipboard()
        .write_text(r.redacted_text)
        .map_err(|e| format!("Could not write clipboard: {e}"))?;
    Ok(ClipboardSanitizeResult {
        status: "sanitized",
        redacted_count: count,
        category_labels: labels,
    })
}

#[tauri::command]
pub async fn sanitize_clipboard(app: AppHandle) -> Result<ClipboardSanitizeResult, String> {
    tauri::async_runtime::spawn_blocking(move || sanitize_clipboard_blocking(&app))
        .await
        .map_err(|e| e.to_string())?
}

/// Global-hotkey path: same as the command, but reports via an event so the
/// UI can show a toast even when it didn't initiate the action.
pub fn sanitize_clipboard_and_emit(app: AppHandle) {
    tauri::async_runtime::spawn_blocking(move || {
        let payload = sanitize_clipboard_blocking(&app);
        let _ = app.emit(CLIPBOARD_SANITIZED_EVENT, payload);
    });
}

#[tauri::command]
pub fn set_clipboard_hotkey(app: AppHandle, enabled: bool) -> Result<(), String> {
    crate::hotkey::set_enabled(&app, enabled)
}

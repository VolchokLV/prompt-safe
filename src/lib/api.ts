import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ClipboardSanitizeResult, ScanResult } from "../types/scan";

export function scanText(
  text: string,
  ignoredIds: number[],
  redactOverflow = true,
): Promise<ScanResult> {
  return invoke<ScanResult>("scan_text", { text, ignoredIds, redactOverflow });
}

/** Reads a local file in Rust (size-limited, lossy UTF-8). */
export function readTextFile(path: string): Promise<string> {
  return invoke<string>("read_text_file", { path });
}

/** Scans the clipboard and writes the redacted text back, entirely in Rust. */
export function sanitizeClipboard(): Promise<ClipboardSanitizeResult> {
  return invoke<ClipboardSanitizeResult>("sanitize_clipboard");
}

export function setClipboardHotkey(enabled: boolean): Promise<void> {
  return invoke<void>("set_clipboard_hotkey", { enabled });
}

/** Fired when the global hotkey sanitizes the clipboard. Payload is the
 *  serialized Rust `Result`: either the result object or an error string. */
export function onClipboardSanitized(
  cb: (result: ClipboardSanitizeResult | string) => void,
): Promise<UnlistenFn> {
  return listen<{ Ok?: ClipboardSanitizeResult; Err?: string }>(
    "clipboard-sanitized",
    (e) => cb(e.payload.Ok ?? e.payload.Err ?? "Unknown error"),
  );
}

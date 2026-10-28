import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";

let clearTimer: ReturnType<typeof setTimeout> | undefined;

export async function copyText(
  text: string,
  autoClearMs?: number,
): Promise<void> {
  await writeText(text);
  if (clearTimer) clearTimeout(clearTimer);
  if (autoClearMs) {
    clearTimer = setTimeout(async () => {
      try {
        // Only clear if the clipboard still holds what we wrote —
        // never clobber something the user copied afterwards.
        const current = await readText();
        if (current === text) await writeText("");
      } catch {
        // Clipboard unavailable; nothing to clean up.
      }
    }, autoClearMs);
  }
}

// UI preferences only — input text is NEVER persisted.
// localStorage can throw (blocked storage); every access is guarded and the
// app falls back to defaults.

export interface Prefs {
  autoClearClipboard: boolean;
  clipboardHotkey: boolean;
  redactEntropyOverflow: boolean;
  lastTab: "findings" | "redacted" | "settings";
}

export const DEFAULT_PREFS: Prefs = {
  autoClearClipboard: false,
  clipboardHotkey: true,
  redactEntropyOverflow: true,
  lastTab: "findings",
};

const KEY = "prompt-safe.prefs.v1";

export function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    const parsed = JSON.parse(raw) as Partial<Prefs>;
    const out = { ...DEFAULT_PREFS };
    for (const k of Object.keys(DEFAULT_PREFS) as (keyof Prefs)[]) {
      if (typeof parsed[k] === typeof DEFAULT_PREFS[k]) {
        (out as Record<string, unknown>)[k] = parsed[k];
      }
    }
    return out;
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

export function savePrefs(p: Prefs): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    // Storage unavailable — preferences just won't persist.
  }
}

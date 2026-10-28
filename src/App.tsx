import { getVersion } from "@tauri-apps/api/app";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import FindingsPanel from "./components/FindingsPanel";
import InputPanel from "./components/InputPanel";
import RedactedPreview from "./components/RedactedPreview";
import SettingsPanel from "./components/SettingsPanel";
import StatusBanner from "./components/StatusBanner";
import Toast, { type ToastMessage } from "./components/Toast";
import Toolbar from "./components/Toolbar";
import { useCopyActions } from "./hooks/useCopyActions";
import { useScanner } from "./hooks/useScanner";
import {
  onClipboardSanitized,
  readTextFile,
  sanitizeClipboard,
  setClipboardHotkey,
} from "./lib/api";
import { loadPrefs, savePrefs, type Prefs } from "./lib/prefs";
import { plural } from "./lib/text";
import type { ClipboardSanitizeResult, Finding } from "./types/scan";

type Tab = Prefs["lastTab"];
const TABS: { id: Tab; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "redacted", label: "Redacted" },
  { id: "settings", label: "Settings" },
];

function describeClipboardResult(r: ClipboardSanitizeResult): Omit<ToastMessage, "id"> {
  switch (r.status) {
    case "empty":
      return { tone: "info", text: "Clipboard has no text to sanitize." };
    case "clean":
      return { tone: "info", text: "Clipboard checked — no known secrets detected." };
    case "sanitized": {
      const kinds = r.categoryLabels.slice(0, 3).join(", ");
      const more = r.categoryLabels.length > 3 ? ", …" : "";
      return {
        tone: "success",
        text: `Clipboard sanitized — ${plural(r.redactedCount, "secret")} redacted${
          kinds ? ` (${kinds}${more})` : ""
        }. Paste away.`,
      };
    }
  }
}

export default function App() {
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs);
  const updatePrefs = useCallback((patch: Partial<Prefs>) => {
    setPrefs((p) => {
      const next = { ...p, ...patch };
      savePrefs(next);
      return next;
    });
  }, []);
  const tab = prefs.lastTab;
  const setTab = useCallback((t: Tab) => updatePrefs({ lastTab: t }), [updatePrefs]);

  const scanner = useScanner({ redactOverflow: prefs.redactEntropyOverflow });
  const { text, setText, result, status, error, clear } = scanner;

  const [toast, setToast] = useState<ToastMessage | null>(null);
  const toastSeq = useRef(0);
  const showToast = useCallback((t: Omit<ToastMessage, "id">) => {
    setToast({ ...t, id: ++toastSeq.current });
  }, []);
  const hideToast = useCallback(() => setToast(null), []);

  const [version, setVersion] = useState<string | null>(null);
  const [hotkeyError, setHotkeyError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const activeFindingsCount = result?.findings.filter((f) => !f.dismissed).length ?? 0;
  const unredactedOverflowCount =
    result && result.stats.entropyFindingsCapped && !result.stats.entropyOverflowRedacted
      ? result.stats.entropySuppressedCount
      : 0;

  const copy = useCopyActions({
    originalText: text,
    redactedText: result?.redactedText ?? null,
    activeFindingsCount,
    autoClear: prefs.autoClearClipboard,
  });

  // ---- Files -------------------------------------------------------------
  const loadFile = useCallback(
    async (path: string) => {
      try {
        const content = await readTextFile(path);
        setText(content, { immediate: true });
        const name = path.split(/[\\/]/).pop() ?? path;
        showToast({ tone: "info", text: `Loaded ${name}` });
      } catch (e) {
        showToast({ tone: "error", text: String(e) });
      }
    },
    [setText, showToast],
  );

  const openFile = useCallback(async () => {
    try {
      const selected = await open({ multiple: false, directory: false });
      if (typeof selected === "string") await loadFile(selected);
    } catch (e) {
      showToast({ tone: "error", text: `Could not open file: ${String(e)}` });
    }
  }, [loadFile, showToast]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        const p = event.payload;
        if (p.type === "enter" || p.type === "over") setDragging(true);
        else if (p.type === "leave") setDragging(false);
        else if (p.type === "drop") {
          setDragging(false);
          if (p.paths.length > 0) void loadFile(p.paths[0]);
        }
      })
      .then((fn) => (cancelled ? fn() : (unlisten = fn)))
      .catch(() => {});
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [loadFile]);

  // ---- Clipboard sanitize (button + global hotkey) ------------------------
  const runSanitizeClipboard = useCallback(async () => {
    try {
      showToast(describeClipboardResult(await sanitizeClipboard()));
    } catch (e) {
      showToast({ tone: "error", text: String(e) });
    }
  }, [showToast]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;
    onClipboardSanitized((r) =>
      showToast(typeof r === "string" ? { tone: "error", text: r } : describeClipboardResult(r)),
    )
      .then((fn) => (cancelled ? fn() : (unlisten = fn)))
      .catch(() => {});
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [showToast]);

  useEffect(() => {
    setClipboardHotkey(prefs.clipboardHotkey)
      .then(() => setHotkeyError(null))
      .catch((e) => setHotkeyError(String(e)));
  }, [prefs.clipboardHotkey]);

  useEffect(() => {
    getVersion().then(setVersion).catch(() => {});
  }, []);

  // ---- Jump to finding ---------------------------------------------------
  const jumpToFinding = useCallback(
    (f: Finding) => {
      const ta = textareaRef.current;
      if (!ta) return;
      const style = getComputedStyle(ta);
      const lineHeight = parseFloat(style.lineHeight) || 20;
      const padTop = parseFloat(style.paddingTop) || 0;
      ta.focus();
      // Offsets are only valid for the text that was scanned
      if (status !== "scanning" && f.end <= ta.value.length) {
        ta.setSelectionRange(f.start, f.end);
      }
      ta.scrollTop = Math.max(0, padTop + (f.line - 1) * lineHeight - ta.clientHeight / 3);
      const ctx = document.createElement("canvas").getContext("2d");
      if (ctx) {
        ctx.font = style.font;
        const charW = ctx.measureText("M").width || 8;
        ta.scrollLeft = Math.max(0, (f.col - 1) * charW - ta.clientWidth / 3);
      }
    },
    [status],
  );

  // ---- Keyboard shortcuts ------------------------------------------------
  const { copySanitized } = copy;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.altKey || e.metaKey) return;
      const k = e.key.toLowerCase();
      if (e.shiftKey && k === "c") {
        e.preventDefault();
        void copySanitized();
      } else if (!e.shiftKey && k === "o") {
        e.preventDefault();
        void openFile();
      } else if (!e.shiftKey && k === "l") {
        e.preventDefault();
        clear();
      } else if (!e.shiftKey && ["1", "2", "3"].includes(e.key)) {
        e.preventDefault();
        setTab(TABS[Number(e.key) - 1].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [copySanitized, openFile, clear, setTab]);

  const onTabKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const i = TABS.findIndex((t) => t.id === tab);
    const next = (i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length;
    setTab(TABS[next].id);
    document.getElementById(`tab-${TABS[next].id}`)?.focus();
  };

  return (
    <div className="flex h-screen flex-col bg-neutral-950 text-neutral-200">
      <StatusBanner status={status} result={result} error={error} />
      <div className="flex min-h-0 flex-1">
        <InputPanel
          ref={textareaRef}
          text={text}
          onChange={setText}
          onOpenFile={() => void openFile()}
          onSanitizeClipboard={() => void runSanitizeClipboard()}
          dragging={dragging}
        />
        <div className="flex w-[44%] min-w-[360px] flex-col">
          <div
            role="tablist"
            aria-label="Results"
            onKeyDown={onTabKeyDown}
            className="flex border-b border-neutral-800 bg-neutral-900 text-sm"
          >
            {TABS.map((t, i) => (
              <button
                key={t.id}
                id={`tab-${t.id}`}
                role="tab"
                aria-selected={tab === t.id}
                aria-controls="results-panel"
                tabIndex={tab === t.id ? 0 : -1}
                onClick={() => setTab(t.id)}
                title={`${t.label} (Ctrl+${i + 1})`}
                className={`flex items-center px-4 py-2.5 ${
                  tab === t.id
                    ? "border-b-2 border-emerald-500 font-medium text-neutral-100"
                    : "text-neutral-400 hover:text-neutral-200"
                }`}
              >
                {t.label}
                {t.id === "findings" && activeFindingsCount > 0 && (
                  <span className="ml-2 rounded-full bg-red-900 px-2 py-0.5 text-xs text-red-200">
                    {activeFindingsCount}
                  </span>
                )}
              </button>
            ))}
          </div>
          <div
            id="results-panel"
            role="tabpanel"
            aria-labelledby={`tab-${tab}`}
            className="flex min-h-0 flex-1 flex-col"
          >
            {tab === "findings" && (
              <FindingsPanel
                result={result}
                onDismiss={scanner.dismiss}
                onUndismiss={scanner.undismiss}
                onDismissMany={scanner.dismissMany}
                onUndismissMany={scanner.undismissMany}
                onJumpToFinding={jumpToFinding}
              />
            )}
            {tab === "redacted" && (
              <RedactedPreview redactedText={result?.redactedText ?? null} />
            )}
            {tab === "settings" && (
              <SettingsPanel
                prefs={prefs}
                onChange={updatePrefs}
                hotkeyError={hotkeyError}
                version={version}
              />
            )}
          </div>
        </div>
      </div>
      <Toolbar
        hasText={text.length > 0}
        canCopySanitized={result != null}
        activeFindingsCount={activeFindingsCount}
        unredactedOverflowCount={unredactedOverflowCount}
        autoClear={prefs.autoClearClipboard}
        copied={copy.copied}
        confirmingOriginal={copy.confirmingOriginal}
        onCopySanitized={() => void copy.copySanitized()}
        onCopyOriginal={() => void copy.copyOriginal()}
        onClear={clear}
      />
      <Toast toast={toast} onDone={hideToast} />
    </div>
  );
}

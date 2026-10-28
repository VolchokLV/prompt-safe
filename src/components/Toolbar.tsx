import type { CopyState } from "../hooks/useCopyActions";
import { plural } from "../lib/text";

interface Props {
  hasText: boolean;
  canCopySanitized: boolean;
  activeFindingsCount: number;
  /** High-entropy values beyond the cap that were NOT redacted. */
  unredactedOverflowCount: number;
  autoClear: boolean;
  copied: CopyState;
  confirmingOriginal: boolean;
  onCopySanitized: () => void;
  onCopyOriginal: () => void;
  onClear: () => void;
}

export default function Toolbar({
  hasText,
  canCopySanitized,
  activeFindingsCount,
  unredactedOverflowCount,
  autoClear,
  copied,
  confirmingOriginal,
  onCopySanitized,
  onCopyOriginal,
  onClear,
}: Props) {
  return (
    <div className="flex items-center gap-3 border-t border-neutral-800 bg-neutral-900 px-4 py-3">
      <button
        onClick={onCopySanitized}
        disabled={!canCopySanitized}
        title="Copy sanitized (Ctrl+Shift+C)"
        className="rounded-md bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-600 disabled:cursor-not-allowed disabled:bg-neutral-800 disabled:text-neutral-600"
      >
        {copied === "sanitized" ? "Copied ✓" : "Copy sanitized"}
      </button>
      <button
        onClick={onCopyOriginal}
        disabled={!hasText}
        className={`px-2 py-2 text-xs disabled:cursor-not-allowed disabled:text-neutral-700 ${
          confirmingOriginal
            ? "font-semibold text-red-400"
            : "text-neutral-400 hover:text-neutral-200"
        }`}
      >
        {copied === "original"
          ? "Copied original"
          : confirmingOriginal
            ? `Really copy ${plural(activeFindingsCount, "secret")}?`
            : "Copy original anyway"}
      </button>
      <span role="status" aria-live="polite" className="text-xs">
        {copied === "error" && (
          <span className="text-red-400">Copy failed — clipboard unavailable.</span>
        )}
        {copied !== "error" && unredactedOverflowCount > 0 && (
          <span className="text-amber-400">
            ⚠ {plural(unredactedOverflowCount, "unlisted high-entropy string")}{" "}
            left unredacted
          </span>
        )}
        {copied === "sanitized" && autoClear && (
          <span className="text-neutral-400">Clipboard clears in 60s.</span>
        )}
      </span>
      <div className="flex-1" />
      <button
        onClick={onClear}
        disabled={!hasText}
        title="Clear input (Ctrl+L)"
        className="rounded-md border border-neutral-700 px-3 py-2 text-sm text-neutral-300 hover:bg-neutral-800 disabled:cursor-not-allowed disabled:text-neutral-700"
      >
        Clear
      </button>
    </div>
  );
}

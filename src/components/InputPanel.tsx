import { forwardRef, useMemo } from "react";
import { countLines, formatBytes, plural } from "../lib/text";

interface Props {
  text: string;
  onChange: (text: string, opts?: { immediate?: boolean }) => void;
  onOpenFile: () => void;
  onSanitizeClipboard: () => void;
  dragging: boolean;
}

const InputPanel = forwardRef<HTMLTextAreaElement, Props>(function InputPanel(
  { text, onChange, onOpenFile, onSanitizeClipboard, dragging },
  ref,
) {
  const lines = useMemo(() => countLines(text), [text]);
  // UTF-16 units ≈ bytes for typical ASCII input; cheap on every keystroke
  const size = text.length;

  return (
    <div className="relative flex min-w-0 flex-1 flex-col border-r border-neutral-800">
      <div className="flex items-center gap-2 border-b border-neutral-800 bg-neutral-900 px-3 py-1.5 text-xs">
        <span className="px-1 font-medium text-neutral-400">Input</span>
        <div className="flex-1" />
        <HeaderButton onClick={onOpenFile} title="Open a text or log file (Ctrl+O)">
          Open file…
        </HeaderButton>
        <HeaderButton
          onClick={onSanitizeClipboard}
          title="Scan the clipboard and replace it with the sanitized text (Ctrl+Alt+Shift+V works from any app)"
        >
          Sanitize clipboard
        </HeaderButton>
      </div>
      <textarea
        ref={ref}
        value={text}
        aria-label="Text to scan"
        onChange={(e) => onChange(e.target.value)}
        onPaste={(e) => {
          // Paste replaces the debounce with an immediate scan
          const target = e.currentTarget;
          requestAnimationFrame(() =>
            onChange(target.value, { immediate: true }),
          );
        }}
        spellCheck={false}
        wrap="off"
        placeholder={
          "Paste your prompt, config, or log file here — or drop a file.\n\nPrompt Safe scans locally — nothing ever leaves this machine."
        }
        className="min-h-0 flex-1 resize-none bg-neutral-950 p-4 font-mono text-sm leading-5 text-neutral-200 placeholder:text-neutral-700 focus:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-neutral-700"
      />
      <div className="flex items-center justify-between border-t border-neutral-800 bg-neutral-900 px-4 py-1.5 text-xs text-neutral-500">
        <span>
          {plural(lines, "line")} · {formatBytes(size)}
        </span>
        <span>scanned locally — no network</span>
      </div>
      {dragging && (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center border-2 border-dashed border-emerald-600 bg-neutral-950/90 text-sm font-medium text-emerald-300">
          Drop a file to scan it
        </div>
      )}
    </div>
  );
});

function HeaderButton({
  onClick,
  title,
  children,
}: {
  onClick: () => void;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="rounded px-2 py-1 text-neutral-300 hover:bg-neutral-800 hover:text-white"
    >
      {children}
    </button>
  );
}

export default InputPanel;

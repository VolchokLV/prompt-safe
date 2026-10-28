import type { Prefs } from "../lib/prefs";

interface Props {
  prefs: Prefs;
  onChange: (patch: Partial<Prefs>) => void;
  hotkeyError: string | null;
  version: string | null;
}

const SHORTCUTS: [string, string][] = [
  ["Ctrl+Alt+Shift+V", "Sanitize the clipboard (works from any app)"],
  ["Ctrl+Shift+C", "Copy sanitized text"],
  ["Ctrl+O", "Open a file"],
  ["Ctrl+L", "Clear input"],
  ["Ctrl+1 / 2 / 3", "Findings / Redacted / Settings tab"],
];

export default function SettingsPanel({ prefs, onChange, hotkeyError, version }: Props) {
  return (
    <div className="flex-1 space-y-6 overflow-y-auto p-5 text-sm text-neutral-300">
      <Section title="Clipboard">
        <Toggle
          checked={prefs.autoClearClipboard}
          onChange={(v) => onChange({ autoClearClipboard: v })}
          label="Clear the clipboard 60 seconds after copying"
          hint="Only clears it if it still holds what Prompt Safe copied."
        />
        <Toggle
          checked={prefs.clipboardHotkey}
          onChange={(v) => onChange({ clipboardHotkey: v })}
          label="Global hotkey Ctrl+Alt+Shift+V sanitizes the clipboard in place"
          hint="Copy text anywhere, press the hotkey, then paste the sanitized version."
        />
        {hotkeyError && (
          <p role="alert" className="ml-7 text-xs text-red-400">
            {hotkeyError}
          </p>
        )}
      </Section>

      <Section title="Detection">
        <Toggle
          checked={prefs.redactEntropyOverflow}
          onChange={(v) => onChange({ redactEntropyOverflow: v })}
          label="Redact high-entropy strings beyond the 50 listed"
          hint="Huge logs list at most 50 distinct high-entropy values. Leave this on so the rest are still redacted."
        />
      </Section>

      <Section title="Keyboard shortcuts">
        <table className="w-full text-xs">
          <tbody>
            {SHORTCUTS.map(([keys, what]) => (
              <tr key={keys} className="border-b border-neutral-800/60">
                <td className="py-1.5 pr-4 font-mono text-neutral-200">{keys}</td>
                <td className="py-1.5 text-neutral-400">{what}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section title="About">
        <p>
          <span className="font-semibold text-neutral-100">Prompt Safe</span>
          {version && <span className="text-neutral-400"> v{version}</span>}
        </p>
        <p className="text-neutral-400">
          Runs 100% offline. The app has no network access and no telemetry,
          and your input is never saved to disk.
        </p>
        <p className="text-neutral-400">
          Open source under the MIT license:{" "}
          <span className="select-all font-mono text-neutral-300">
            github.com/VolchokLV/prompt-safe
          </span>
        </p>
        <p className="text-xs text-neutral-500">
          Detection is heuristic. It catches common key formats and
          random-looking tokens, but it can miss secrets. Review before sharing.
        </p>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2.5">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
        {title}
      </h2>
      {children}
    </section>
  );
}

function Toggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <label className="flex cursor-pointer items-start gap-3">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 accent-emerald-600"
      />
      <span>
        <span className="text-neutral-200">{label}</span>
        {hint && <span className="block text-xs text-neutral-500">{hint}</span>}
      </span>
    </label>
  );
}

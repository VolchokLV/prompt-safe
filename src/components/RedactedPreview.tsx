import { useMemo } from "react";
import { buildRows, hasPlaceholder, PLACEHOLDER_RE } from "../lib/redactedRows";

interface Props {
  redactedText: string | null;
}

export default function RedactedPreview({ redactedText }: Props) {
  const rows = useMemo(
    () => (redactedText == null ? [] : buildRows(redactedText)),
    [redactedText],
  );

  if (redactedText == null) {
    return (
      <div className="flex flex-1 items-center justify-center p-6 text-sm text-neutral-500">
        The sanitized version will appear here after a scan.
      </div>
    );
  }

  return (
    <pre
      tabIndex={0}
      aria-label="Sanitized text preview"
      className="flex-1 overflow-auto whitespace-pre bg-neutral-950 p-4 font-mono text-xs leading-5 text-neutral-300"
    >
      {rows.map((row) =>
        row.kind === "gap" ? (
          <div key={`gap-${row.key}`} className="select-none py-1 text-neutral-500">
            ··· {row.count.toLocaleString()} unchanged line
            {row.count === 1 ? "" : "s"} ···
          </div>
        ) : (
          <div key={row.lineNo}>
            <span className="mr-3 select-none text-neutral-700" aria-hidden>
              {row.lineNo}
            </span>
            {highlightPlaceholders(row.text)}
          </div>
        ),
      )}
    </pre>
  );
}

/** Split a line on placeholder tokens and wrap them in <mark>.
 *  Built as React nodes — the text is never injected as HTML. */
function highlightPlaceholders(line: string): React.ReactNode {
  if (!hasPlaceholder(line)) return line || " ";
  PLACEHOLDER_RE.lastIndex = 0;
  const parts: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = PLACEHOLDER_RE.exec(line)) !== null) {
    if (m.index > last) parts.push(line.slice(last, m.index));
    parts.push(
      <mark
        key={key++}
        className="rounded bg-emerald-900 px-0.5 text-emerald-200"
      >
        {m[0]}
      </mark>,
    );
    last = m.index + m[0].length;
  }
  if (last < line.length) parts.push(line.slice(last));
  return parts;
}

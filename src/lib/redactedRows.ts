export const PLACEHOLDER_RE = /\[REDACTED_[A-Z0-9_]+_\d+\]/g;
export const FULL_RENDER_MAX_LINES = 5000;
const CONTEXT_LINES = 1;

export type Row =
  | { kind: "line"; lineNo: number; text: string }
  | { kind: "gap"; count: number; key: number };

export function hasPlaceholder(line: string): boolean {
  PLACEHOLDER_RE.lastIndex = 0;
  return PLACEHOLDER_RE.test(line);
}

/** Small inputs render every line; above FULL_RENDER_MAX_LINES only lines
 *  near a placeholder (±1 context) are kept, with gap markers between. */
export function buildRows(
  redactedText: string,
  maxLines = FULL_RENDER_MAX_LINES,
): Row[] {
  const lines = redactedText.split("\n");
  if (lines.length <= maxLines) {
    return lines.map((text, i) => ({ kind: "line", lineNo: i + 1, text }));
  }
  const keep = new Set<number>();
  lines.forEach((line, i) => {
    if (hasPlaceholder(line)) {
      const lo = Math.max(0, i - CONTEXT_LINES);
      const hi = Math.min(lines.length - 1, i + CONTEXT_LINES);
      for (let j = lo; j <= hi; j++) keep.add(j);
    }
  });
  const rows: Row[] = [];
  let i = 0;
  while (i < lines.length) {
    if (keep.has(i)) {
      rows.push({ kind: "line", lineNo: i + 1, text: lines[i] });
      i++;
    } else {
      const gapStart = i;
      while (i < lines.length && !keep.has(i)) i++;
      rows.push({ kind: "gap", count: i - gapStart, key: gapStart });
    }
  }
  return rows;
}

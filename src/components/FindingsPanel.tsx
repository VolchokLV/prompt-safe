import { useMemo } from "react";
import { plural } from "../lib/text";
import type { Finding, ScanResult, Severity } from "../types/scan";
import { SEVERITY_ORDER } from "../types/scan";
import FindingGroup from "./FindingGroup";

interface Props {
  result: ScanResult | null;
  onDismiss: (id: number) => void;
  onUndismiss: (id: number) => void;
  onDismissMany: (ids: number[]) => void;
  onUndismissMany: (ids: number[]) => void;
  onJumpToFinding: (f: Finding) => void;
}

export interface Group {
  category: string;
  label: string;
  severity: Severity;
  findings: Finding[];
}

export function groupFindings(findings: Finding[]): Group[] {
  const byCategory = new Map<string, Group>();
  for (const f of findings) {
    let g = byCategory.get(f.category);
    if (!g) {
      g = { category: f.category, label: f.label, severity: f.severity, findings: [] };
      byCategory.set(f.category, g);
    }
    g.findings.push(f);
  }
  return [...byCategory.values()].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      b.findings.length - a.findings.length,
  );
}

export default function FindingsPanel({ result, ...handlers }: Props) {
  const groups = useMemo(
    () => (result ? groupFindings(result.findings) : []),
    [result],
  );

  if (!result) {
    return (
      <div className="flex flex-1 items-center justify-center p-6 text-sm text-neutral-500">
        Findings will appear here after a scan.
      </div>
    );
  }

  const overflow = result.stats.entropyFindingsCapped && (
    <div className="border-t border-neutral-800 px-4 py-3 text-xs text-amber-400">
      …and {plural(result.stats.entropySuppressedCount, "more high-entropy string")}{" "}
      not listed —{" "}
      {result.stats.entropyOverflowRedacted
        ? "they are redacted in the sanitized copy."
        : "they are NOT redacted (see Settings). Review manually."}
    </div>
  );

  if (result.findings.length === 0) {
    return (
      <div className="flex flex-1 flex-col">
        <div className="flex flex-1 items-center justify-center p-6 text-sm text-emerald-400">
          ✓ No known secret patterns detected.
        </div>
        {overflow}
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {groups.map((g) => (
        <FindingGroup key={g.category} group={g} {...handlers} />
      ))}
      {overflow}
    </div>
  );
}

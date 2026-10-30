import { useState } from "react";
import type { Finding, Severity } from "../types/scan";
import type { Group } from "./FindingsPanel";

const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-amber-300",
  low: "bg-neutral-400",
};

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-orange-300",
  medium: "text-amber-300",
  low: "text-neutral-400",
};

interface Props {
  group: Group;
  onDismiss: (id: number) => void;
  onUndismiss: (id: number) => void;
  onDismissMany: (ids: number[]) => void;
  onUndismissMany: (ids: number[]) => void;
  onJumpToFinding: (f: Finding) => void;
}

export default function FindingGroup({
  group,
  onDismiss,
  onUndismiss,
  onDismissMany,
  onUndismissMany,
  onJumpToFinding,
}: Props) {
  const [open, setOpen] = useState(true);
  const activeIds = group.findings.filter((f) => !f.dismissed).map((f) => f.id);
  const dismissedIds = group.findings.filter((f) => f.dismissed).map((f) => f.id);
  const listId = `group-${group.category}`;

  return (
    <div className="border-b border-neutral-800">
      <div className="flex items-center hover:bg-neutral-900">
        <button
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          aria-controls={listId}
          className="flex min-w-0 flex-1 items-center gap-2 py-2.5 pl-4 pr-2 text-left"
        >
          <span
            aria-hidden
            className={`h-2.5 w-2.5 shrink-0 rounded-full ${SEVERITY_DOT[group.severity]}`}
          />
          <span className="flex-1 truncate text-sm font-medium text-neutral-200">
            {group.label}
          </span>
          <span
            className={`text-xs font-semibold uppercase ${SEVERITY_TEXT[group.severity]}`}
          >
            {group.severity}
          </span>
          <span className="rounded-full bg-neutral-800 px-2 py-0.5 text-xs text-neutral-300">
            {group.findings.length}
          </span>
          <span aria-hidden className="text-neutral-500">
            {open ? "▾" : "▸"}
          </span>
        </button>
        {group.findings.length > 1 && (
          <button
            onClick={() =>
              activeIds.length > 0
                ? onDismissMany(activeIds)
                : onUndismissMany(dismissedIds)
            }
            title={
              activeIds.length > 0
                ? `Dismiss all ${group.label} findings`
                : `Restore all ${group.label} findings`
            }
            className="mr-2 shrink-0 rounded px-2 py-1 text-xs text-neutral-400 hover:bg-neutral-800 hover:text-neutral-200"
          >
            {activeIds.length > 0 ? "Dismiss all" : "Restore all"}
          </button>
        )}
      </div>
      {open && (
        <ul id={listId}>
          {group.findings.map((f) => (
            <li
              key={f.id}
              className={`group flex items-center gap-3 pr-4 text-xs hover:bg-neutral-900 ${
                f.dismissed ? "opacity-50" : ""
              }`}
            >
              <button
                onClick={() => onJumpToFinding(f)}
                title="Select in input"
                aria-label={`Select ${f.label} on line ${f.line} in the input`}
                className="flex min-w-0 flex-1 items-center gap-3 py-1.5 pl-4 text-left font-mono"
              >
                <span className="w-16 shrink-0 text-neutral-300 group-hover:text-white group-hover:underline">
                  L{f.line.toLocaleString()}
                  {f.endLine > f.line ? `–${f.endLine.toLocaleString()}` : ""}
                </span>
                <span className="min-w-0 flex-1 truncate text-neutral-400">
                  {f.maskedPreview}
                </span>
                <span className="hidden truncate text-neutral-500 lg:inline">
                  {f.placeholder}
                </span>
              </button>
              {f.dismissed ? (
                <button
                  onClick={() => onUndismiss(f.id)}
                  aria-label={`Restore redaction for ${f.label} on line ${f.line}`}
                  className="shrink-0 text-amber-400 hover:text-amber-300"
                >
                  undo
                </button>
              ) : (
                <button
                  onClick={() => onDismiss(f.id)}
                  title="Dismiss (keep original text in the sanitized copy)"
                  aria-label={`Dismiss ${f.label} on line ${f.line}`}
                  className="shrink-0 px-1 text-neutral-500 hover:text-neutral-200"
                >
                  ×
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

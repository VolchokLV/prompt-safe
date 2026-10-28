// Mirrors the serde camelCase output of src-tauri/src/scanner/types.rs
// and src-tauri/src/commands.rs — keep in sync.

export type Severity = "low" | "medium" | "high" | "critical";
export type FindingSource = "pattern" | "entropy";

export interface Finding {
  id: number;
  category: string;
  label: string;
  severity: Severity;
  line: number;
  col: number;
  endLine: number;
  /** UTF-16 offsets into the scanned text (for textarea selection). */
  start: number;
  end: number;
  maskedPreview: string;
  placeholder: string;
  source: FindingSource;
  dismissed: boolean;
}

export interface ScanStats {
  totalLines: number;
  inputBytes: number;
  durationMs: number;
  entropyFindingsCapped: boolean;
  /** Distinct high-entropy values beyond the listing cap. */
  entropySuppressedCount: number;
  /** Whether those unlisted values were redacted. */
  entropyOverflowRedacted: boolean;
}

export interface ScanResult {
  findings: Finding[];
  redactedText: string;
  stats: ScanStats;
}

export interface ClipboardSanitizeResult {
  status: "empty" | "clean" | "sanitized";
  redactedCount: number;
  categoryLabels: string[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

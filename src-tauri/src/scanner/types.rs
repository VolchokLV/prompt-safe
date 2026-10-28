use serde::Serialize;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Pattern,
    Entropy,
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: u32,
    pub category: String,
    pub label: String,
    pub severity: Severity,
    pub line: u32,
    pub col: u32,
    pub end_line: u32,
    /// UTF-16 code-unit offsets into the input, for textarea selection.
    /// Offsets reveal position and length only, never content.
    pub start: u32,
    pub end: u32,
    pub masked_preview: String,
    pub placeholder: String,
    pub source: Source,
    pub dismissed: bool,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub total_lines: u32,
    pub input_bytes: u64,
    pub duration_ms: u64,
    pub entropy_findings_capped: bool,
    /// Distinct high-entropy values beyond the listing cap (not in `findings`).
    pub entropy_suppressed_count: u32,
    /// Whether those unlisted values were redacted in `redacted_text`.
    pub entropy_overflow_redacted: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ScanOptions {
    /// Redact high-entropy values beyond the listing cap (default true).
    pub redact_overflow: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            redact_overflow: true,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub redacted_text: String,
    pub stats: ScanStats,
}

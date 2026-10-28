mod entropy;
mod patterns;
mod redact;
mod types;

pub use types::{Finding, ScanOptions, ScanResult, ScanStats, Severity, Source};

use patterns::PATTERNS;
use redact::{Assigner, RedactItem};
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Instant;

const ENTROPY_CAP: usize = 50;
const ENTROPY_CATEGORY: &str = "high_entropy_string";
const ENTROPY_LABEL: &str = "High-Entropy String";
const ENTROPY_PLACEHOLDER: &str = "REDACTED_HIGH_ENTROPY";

struct Candidate {
    start: usize,
    end: usize,
    pattern_idx: Option<usize>, // None => entropy finding
    severity: Severity,
}

/// Sorted, non-overlapping byte ranges with binary-search insertion.
#[derive(Default)]
struct Ranges(Vec<(usize, usize)>);

impl Ranges {
    fn overlaps(&self, start: usize, end: usize) -> bool {
        // First accepted range whose end extends past our start; if it also
        // begins before our end, the two intersect.
        let idx = self.0.partition_point(|&(_, e)| e <= start);
        matches!(self.0.get(idx), Some(&(s, _)) if s < end)
    }

    fn insert_if_free(&mut self, start: usize, end: usize) -> bool {
        if self.overlaps(start, end) {
            return false;
        }
        let idx = self.0.partition_point(|&(s, _)| s < start);
        self.0.insert(idx, (start, end));
        true
    }
}

/// Converts monotonically non-decreasing byte offsets to UTF-16 offsets in a
/// single forward pass (textarea selection APIs use UTF-16 code units).
struct Utf16Cursor<'a> {
    text: &'a str,
    byte: usize,
    utf16: usize,
}

impl<'a> Utf16Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            byte: 0,
            utf16: 0,
        }
    }

    fn advance_to(&mut self, byte: usize) -> u32 {
        debug_assert!(byte >= self.byte);
        self.utf16 += self.text[self.byte..byte]
            .chars()
            .map(char::len_utf16)
            .sum::<usize>();
        self.byte = byte;
        self.utf16 as u32
    }
}

fn value_hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

pub fn scan(text: &str, ignored_ids: &[u32]) -> ScanResult {
    scan_with_options(text, ignored_ids, ScanOptions::default())
}

pub fn scan_with_options(text: &str, ignored_ids: &[u32], opts: ScanOptions) -> ScanResult {
    let t0 = Instant::now();
    let ignored: HashSet<u32> = ignored_ids.iter().copied().collect();
    let newlines: Vec<usize> = text
        .bytes()
        .enumerate()
        .filter_map(|(i, b)| (b == b'\n').then_some(i))
        .collect();

    // Pattern pass: collect every raw match, then greedily keep the best
    // candidate per span (severity desc, longest, catalog order).
    let mut candidates: Vec<Candidate> = Vec::new();
    for (idx, p) in PATTERNS.iter().enumerate() {
        for caps in p.regex.captures_iter(text) {
            let m = match p.redact_group {
                Some(g) => match caps.get(g) {
                    Some(m) => m,
                    None => continue,
                },
                None => caps.get(0).expect("group 0 always present"),
            };
            if let Some(validate) = p.validate {
                if !validate(m.as_str()) {
                    continue;
                }
            }
            candidates.push(Candidate {
                start: m.start(),
                end: m.end(),
                pattern_idx: Some(idx),
                severity: p.severity,
            });
        }
    }
    candidates.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.pattern_idx.cmp(&b.pattern_idx))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut ranges = Ranges::default();
    let mut accepted: Vec<Candidate> = Vec::new();
    for c in candidates {
        if ranges.insert_if_free(c.start, c.end) {
            accepted.push(c);
        }
    }

    // Entropy pass: runs after patterns so pattern findings always win the
    // span. Listing is capped by distinct value to keep log pastes
    // reviewable; values past the cap are still redacted (unless the caller
    // opts out) so the sanitized copy never silently leaks them.
    let mut entropy_values: HashSet<u64> = HashSet::new();
    let mut suppressed_values: HashSet<u64> = HashSet::new();
    let mut overflow: Vec<(usize, usize)> = Vec::new();
    let mut capped = false;
    for (start, end) in entropy::candidate_spans(text) {
        if ranges.overlaps(start, end) {
            continue;
        }
        let vhash = value_hash(&text[start..end]);
        let listed = entropy_values.contains(&vhash)
            || (entropy_values.len() < ENTROPY_CAP && entropy_values.insert(vhash));
        if !listed {
            capped = true;
            suppressed_values.insert(vhash);
            if ranges.insert_if_free(start, end) {
                overflow.push((start, end));
            }
            continue;
        }
        if ranges.insert_if_free(start, end) {
            accepted.push(Candidate {
                start,
                end,
                pattern_idx: None,
                severity: Severity::Medium,
            });
        }
    }

    // Deterministic ids: index in start-offset order. Stable for identical
    // input text, which is what the dismiss round-trip relies on.
    accepted.sort_by_key(|c| c.start);

    let mut assigner = Assigner::default();
    let mut findings: Vec<Finding> = Vec::with_capacity(accepted.len());
    let mut placeholders: Vec<String> = Vec::with_capacity(accepted.len());
    let mut cursor = Utf16Cursor::new(text);

    for (i, c) in accepted.iter().enumerate() {
        let id = i as u32;
        let value = &text[c.start..c.end];
        let (category, label, placeholder_base, source) = match c.pattern_idx {
            Some(idx) => {
                let p = &PATTERNS[idx];
                (p.category, p.label, p.placeholder, Source::Pattern)
            }
            None => (
                ENTROPY_CATEGORY,
                ENTROPY_LABEL,
                ENTROPY_PLACEHOLDER,
                Source::Entropy,
            ),
        };
        let placeholder = assigner.assign(placeholder_base, value);
        let (line, col) = line_col(text, &newlines, c.start);
        let (end_line, _) = line_col(text, &newlines, c.end.saturating_sub(1).max(c.start));
        // Accepted spans are sorted and non-overlapping, so start/end pairs
        // form a non-decreasing sequence the cursor can walk forward.
        let start16 = cursor.advance_to(c.start);
        let end16 = cursor.advance_to(c.end);
        findings.push(Finding {
            id,
            category: category.to_string(),
            label: label.to_string(),
            severity: c.severity,
            line,
            col,
            end_line,
            start: start16,
            end: end16,
            masked_preview: redact::masked_preview(category, value),
            placeholder: placeholder.clone(),
            source,
            dismissed: ignored.contains(&id),
        });
        placeholders.push(placeholder);
    }

    // Overflow placeholders are numbered after listed ones so the listed
    // findings' placeholders don't change when the option is toggled.
    let overflow_placeholders: Vec<String> = if opts.redact_overflow {
        overflow
            .iter()
            .map(|&(s, e)| assigner.assign(ENTROPY_PLACEHOLDER, &text[s..e]))
            .collect()
    } else {
        Vec::new()
    };

    let mut items: Vec<RedactItem> = accepted
        .iter()
        .enumerate()
        .map(|(i, c)| RedactItem {
            start: c.start,
            end: c.end,
            placeholder: &placeholders[i],
            skip: ignored.contains(&(i as u32)),
        })
        .collect();
    items.extend(
        overflow
            .iter()
            .zip(overflow_placeholders.iter())
            .map(|(&(start, end), p)| RedactItem {
                start,
                end,
                placeholder: p,
                skip: false,
            }),
    );
    items.sort_by_key(|it| it.start);

    let redacted_text = redact::rebuild(text, &items);

    ScanResult {
        findings,
        redacted_text,
        stats: ScanStats {
            total_lines: if text.is_empty() {
                0
            } else {
                newlines.len() as u32 + 1
            },
            input_bytes: text.len() as u64,
            duration_ms: t0.elapsed().as_millis() as u64,
            entropy_findings_capped: capped,
            entropy_suppressed_count: suppressed_values.len() as u32,
            entropy_overflow_redacted: capped && opts.redact_overflow,
        },
    }
}

fn line_col(text: &str, newlines: &[usize], offset: usize) -> (u32, u32) {
    let line_idx = newlines.partition_point(|&n| n < offset);
    let line_start = if line_idx == 0 {
        0
    } else {
        newlines[line_idx - 1] + 1
    };
    let col = text[line_start..offset].chars().count() as u32 + 1;
    (line_idx as u32 + 1, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_clean_input() {
        let r = scan("", &[]);
        assert!(r.findings.is_empty());
        assert_eq!(r.stats.total_lines, 0);

        let r = scan("hello world\njust a normal prompt about cooking\n", &[]);
        assert!(r.findings.is_empty());
        assert_eq!(r.redacted_text, "hello world\njust a normal prompt about cooking\n");
    }

    #[test]
    fn anthropic_key_yields_single_finding_not_openai() {
        let r = scan("key = sk-ant-api03-abcd1234efgh5678ijkl", &[]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].category, "anthropic_api_key");
        assert!(r.redacted_text.contains("[REDACTED_ANTHROPIC_KEY_1]"));
        assert!(!r.redacted_text.contains("sk-ant"));
    }

    #[test]
    fn vendor_pattern_beats_generic_assignment() {
        let r = scan(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            &[],
        );
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].category, "aws_secret_key");
        assert!(r.redacted_text.contains("aws_secret_access_key"));
        assert!(r.redacted_text.contains("[REDACTED_AWS_SECRET_1]"));
    }

    #[test]
    fn numbering_two_keys_and_value_reuse() {
        let text = "a: sk-proj-abcd1234abcd1234abcd1234abcd1234\n\
                    b: sk-proj-zzzz9999zzzz9999zzzz9999zzzz9999\n\
                    c: sk-proj-abcd1234abcd1234abcd1234abcd1234\n";
        let r = scan(text, &[]);
        assert_eq!(r.findings.len(), 3);
        assert_eq!(r.findings[0].placeholder, "[REDACTED_OPENAI_KEY_1]");
        assert_eq!(r.findings[1].placeholder, "[REDACTED_OPENAI_KEY_2]");
        assert_eq!(r.findings[2].placeholder, "[REDACTED_OPENAI_KEY_1]");
    }

    #[test]
    fn url_credentials_group_redaction_keeps_url_readable() {
        let r = scan("db: postgres://admin:hunter22secret@db.example.com:5432/app", &[]);
        assert_eq!(r.findings.len(), 1);
        assert!(r.redacted_text.contains("postgres://"));
        assert!(r.redacted_text.contains("@db.example.com:5432/app"));
        assert!(r.redacted_text.contains("[REDACTED_URL_CREDENTIALS_1]"));
        assert!(!r.redacted_text.contains("hunter22secret"));
    }

    #[test]
    fn dismissed_finding_keeps_original_value() {
        let text = "key = sk-proj-abcd1234abcd1234abcd1234abcd1234";
        let r = scan(text, &[]);
        assert_eq!(r.findings.len(), 1);
        let id = r.findings[0].id;

        let r2 = scan(text, &[id]);
        assert!(r2.findings[0].dismissed);
        assert_eq!(r2.redacted_text, text);
    }

    #[test]
    fn line_and_column_are_correct() {
        let text = "first line\nsecond line\nkey = AKIAIOSFODNN7EXAMPLE\n";
        let r = scan(text, &[]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].line, 3);
        assert_eq!(r.findings[0].col, 7);
        assert_eq!(r.stats.total_lines, 4);
    }

    #[test]
    fn pem_block_spans_lines_and_masks_preview() {
        let text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretsecret\nMIIEmoresecret\n-----END RSA PRIVATE KEY-----\nafter";
        let r = scan(text, &[]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].line, 2);
        assert_eq!(r.findings[0].end_line, 5);
        assert!(!r.findings[0].masked_preview.contains("MIIE"));
        assert!(r.redacted_text.contains("[REDACTED_PRIVATE_KEY_1]"));
        assert!(!r.redacted_text.contains("MIIEsecret"));
    }

    #[test]
    fn entropy_finding_detected_and_redacted() {
        let r = scan("session token kJ8vQ2xR9mN4pL7wZ1yT6uB3eH5sD0aF issued", &[]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].category, "high_entropy_string");
        assert_eq!(r.findings[0].source, Source::Entropy);
        assert!(r.redacted_text.contains("[REDACTED_HIGH_ENTROPY_1]"));
    }

    #[test]
    fn entropy_cap_at_50_distinct_values() {
        let mut text = String::new();
        for i in 0..60 {
            text.push_str(&format!("t{i:02}Z9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT\n"));
        }
        let r = scan(&text, &[]);
        let entropy_count = r
            .findings
            .iter()
            .filter(|f| f.source == Source::Entropy)
            .count();
        assert_eq!(entropy_count, ENTROPY_CAP);
        assert!(r.stats.entropy_findings_capped);
        assert_eq!(r.stats.entropy_suppressed_count, 10);
        // Unlisted values are still redacted by default — nothing leaks
        assert!(r.stats.entropy_overflow_redacted);
        for i in 50..60 {
            let v = format!("t{i:02}Z9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT");
            assert!(!r.redacted_text.contains(&v), "leaked overflow value {v}");
        }
        assert!(r.redacted_text.contains("[REDACTED_HIGH_ENTROPY_51]"));
        assert!(r.redacted_text.contains("[REDACTED_HIGH_ENTROPY_60]"));
    }

    #[test]
    fn entropy_overflow_can_be_kept_and_listed_placeholders_stay_stable() {
        let mut text = String::new();
        for i in 0..60 {
            text.push_str(&format!("t{i:02}Z9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT\n"));
        }
        let on = scan(&text, &[]);
        let off = scan_with_options(
            &text,
            &[],
            ScanOptions {
                redact_overflow: false,
            },
        );
        assert!(!off.stats.entropy_overflow_redacted);
        assert!(off.redacted_text.contains("t55Z9aB8cD7eF6gH5iJ4kL3mN2oP1qR0sT"));
        let ph = |r: &ScanResult| r.findings.iter().map(|f| f.placeholder.clone()).collect::<Vec<_>>();
        assert_eq!(ph(&on), ph(&off));
    }

    #[test]
    fn demo_sample_detects_every_catalog_category() {
        let text = include_str!("../../../samples/demo.txt");
        let r = scan(text, &[]);
        let found: HashSet<&str> = r.findings.iter().map(|f| f.category.as_str()).collect();
        // PuTTY keys and GCP service-account JSON are covered by unit tests
        // only; every other catalog entry must appear in the demo file.
        for p in PATTERNS.iter() {
            if matches!(p.category, "putty_private_key" | "gcp_sa_private_key") {
                continue;
            }
            assert!(found.contains(p.category), "demo.txt missing {}", p.category);
        }
        assert!(found.contains(ENTROPY_CATEGORY));
        for noise in ["356a192b7913b04c", "550e8400-e29b", "changeme123", "<your-key-here>"] {
            assert!(r.redacted_text.contains(noise), "noise line was redacted: {noise}");
        }
    }

    #[test]
    fn utf16_offsets_select_the_secret() {
        // Emoji (2 UTF-16 units, 4 bytes) and accented char before the key
        let text = "héllo 🔑\nkey = AKIAIOSFODNN7EXAMPLE end";
        let r = scan(text, &[]);
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        let units: Vec<u16> = text.encode_utf16().collect();
        let selected = String::from_utf16(&units[f.start as usize..f.end as usize]).unwrap();
        assert_eq!(selected, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn log_noise_produces_no_findings() {
        let text = "commit 356a192b7913b04c54574d18c28d46e6395428ab\n\
                    request-id: 550e8400-e29b-41d4-a716-446655440000\n\
                    loaded /usr/local/lib/node_modules1/pkg\n\
                    2026-07-09T12:00:01Z INFO listening on port 8080\n";
        let r = scan(text, &[]);
        assert!(r.findings.is_empty(), "unexpected: {:?}", r.findings);
    }

    #[test]
    fn masked_previews_leak_at_most_six_chars() {
        let text = "k1 = sk-proj-abcd1234abcd1234abcd1234abcd1234\n\
                    k2 = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n\
                    PASSWORD=supersecret123456\n";
        let r = scan(text, &[]);
        assert!(!r.findings.is_empty());
        for f in &r.findings {
            // No 7-char window of any secret line may appear in the preview
            for line in text.lines() {
                let value = line.split(['=', ' ']).next_back().unwrap_or("");
                if value.len() >= 7 {
                    for w in value.as_bytes().windows(7) {
                        let w = std::str::from_utf8(w).unwrap();
                        assert!(
                            !f.masked_preview.contains(w),
                            "preview {:?} leaks {:?}",
                            f.masked_preview,
                            w
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "perf smoke test — run with: cargo test --release -- --ignored"]
    fn five_megabyte_log_scans_quickly_and_finds_planted_secrets() {
        let mut text = String::with_capacity(6 * 1024 * 1024);
        let planted = [
            "sk-proj-abcd1234abcd1234abcd1234abcd1234",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
            "xoxb-1234567890-abcdefghij",
        ];
        let mut plant_count = 0usize;
        let mut i = 0usize;
        while text.len() < 5 * 1024 * 1024 {
            text.push_str(&format!(
                "2026-07-09T12:00:{:02}Z INFO request {} completed status=200 sha={:040x}\n",
                i % 60,
                i,
                i * 7919
            ));
            if i.is_multiple_of(20000) && plant_count < 20 {
                text.push_str(&format!("leaked: {}\n", planted[plant_count % planted.len()]));
                plant_count += 1;
            }
            i += 1;
        }
        let t0 = std::time::Instant::now();
        let r = scan(&text, &[]);
        let elapsed = t0.elapsed();
        let pattern_found = r
            .findings
            .iter()
            .filter(|f| f.source == Source::Pattern)
            .count();
        assert_eq!(pattern_found, plant_count);
        assert!(
            elapsed.as_secs_f64() < 3.0,
            "scan took {:?} for {} bytes",
            elapsed,
            text.len()
        );
    }
}

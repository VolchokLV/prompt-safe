//! High-entropy token detection for secrets that don't match a known format.
//! Tuned to stay quiet on log files: hashes, UUIDs, paths, and identifiers
//! are suppressed before the entropy threshold is even consulted.

const TOKEN_MIN: usize = 20;
const TOKEN_MAX: usize = 512;

// '=' is deliberately excluded so `KEY=value` splits into two tokens;
// base64 padding is folded back in after the run ends.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

/// Byte spans of tokens that look like secrets. Spans are on ASCII
/// boundaries, so they are always valid char boundaries.
pub fn candidate_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_token_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            // Trailing '=' padding belongs to the token only if it terminates it
            let mut end = i;
            let mut pad = 0;
            while end < bytes.len() && bytes[end] == b'=' && pad < 2 {
                end += 1;
                pad += 1;
            }
            if end < bytes.len() && is_token_byte(bytes[end]) {
                end = i;
            }
            let len = end - start;
            if (TOKEN_MIN..=TOKEN_MAX).contains(&len) && is_secret_like(&text[start..end]) {
                spans.push((start, end));
            }
            i = end;
        } else {
            i += 1;
        }
    }
    spans
}

pub fn is_secret_like(tok: &str) -> bool {
    let mut has_digit = false;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_symbol = false;
    for c in tok.chars() {
        match c {
            '0'..='9' => has_digit = true,
            'a'..='z' => has_lower = true,
            'A'..='Z' => has_upper = true,
            _ => has_symbol = true,
        }
    }
    if !has_digit || !(has_lower || has_upper) {
        return false;
    }

    let is_hex = tok.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex {
        // md5 / git SHA-1 / sha256 — hashes in logs are not secrets
        if matches!(tok.len(), 32 | 40 | 64) {
            return false;
        }
    } else if !((has_lower && has_upper) || has_symbol) {
        // Non-hex needs case mixing or base64-ish symbols to look generated
        return false;
    }

    if is_uuid(tok) || is_path_like(tok) {
        return false;
    }

    // Repetition: too few distinct chars, or one char dominating
    let mut freq = [0u32; 256];
    for &b in tok.as_bytes() {
        freq[b as usize] += 1;
    }
    let distinct = freq.iter().filter(|&&c| c > 0).count();
    if distinct < 12 {
        return false;
    }
    let max_freq = *freq.iter().max().unwrap() as usize;
    if max_freq * 100 > tok.len() * 40 {
        return false;
    }

    // Embedded English word (identifiers like authenticationMiddleware2024)
    let mut lower_run = 0usize;
    let mut max_lower_run = 0usize;
    for c in tok.chars() {
        if c.is_ascii_lowercase() {
            lower_run += 1;
            max_lower_run = max_lower_run.max(lower_run);
        } else {
            lower_run = 0;
        }
    }
    if max_lower_run >= 10 {
        return false;
    }

    let threshold = if is_hex { 3.2 } else { 4.0 };
    shannon(tok) >= threshold
}

fn is_uuid(tok: &str) -> bool {
    let b = tok.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn is_path_like(tok: &str) -> bool {
    if tok.starts_with('/') || tok.starts_with("./") || tok.starts_with("~/") {
        return true;
    }
    // Two or more slashes with no base64 padding chars reads as a path segment
    tok.matches('/').count() >= 2 && !tok.contains('+') && !tok.contains('=')
}

fn shannon(tok: &str) -> f64 {
    let mut freq = [0u32; 256];
    for &b in tok.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = tok.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_random_base64_token() {
        assert!(is_secret_like("kJ8vQ2xR9mN4pL7wZ1yT6uB3eH5sD0aF"));
        assert!(is_secret_like("dGhpc0lzTm90QVJlYWxLZXk9PQ2x8Kf3"));
    }

    #[test]
    fn rejects_git_sha_and_hashes() {
        assert!(!is_secret_like("356a192b7913b04c54574d18c28d46e6395428ab")); // sha1 (40)
        assert!(!is_secret_like("5d41402abc4b2a76b9719d911017c592")); // md5 (32)
        assert!(!is_secret_like(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )); // sha256 (64)
    }

    #[test]
    fn rejects_uuid() {
        assert!(!is_secret_like("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn rejects_paths() {
        assert!(!is_secret_like("/usr/local/lib/node_modules1"));
        assert!(!is_secret_like("src/components/Widget2/index"));
        assert!(!is_secret_like("./target/release/build123"));
    }

    #[test]
    fn rejects_identifiers_and_words() {
        assert!(!is_secret_like("authenticationMiddleware2024"));
        assert!(!is_secret_like("MAX_CONNECTION_RETRY_LIMIT_1"));
        assert!(!is_secret_like("aaaaaaaaaaaaaaaaaaaa1B"));
    }

    #[test]
    fn tokenizer_finds_span() {
        let text = "level=info token=kJ8vQ2xR9mN4pL7wZ1yT6uB3eH5sD0aF done";
        let spans = candidate_spans(text);
        assert_eq!(spans.len(), 1);
        let (s, e) = spans[0];
        assert_eq!(&text[s..e], "kJ8vQ2xR9mN4pL7wZ1yT6uB3eH5sD0aF");
    }

    #[test]
    fn tokenizer_quiet_on_plain_log() {
        let text = "2026-07-09 12:00:01 INFO request completed in 234ms status=200 path=/api/users\n\
                    2026-07-09 12:00:02 ERROR connection refused retrying attempt 3 of 5\n";
        assert!(candidate_spans(text).is_empty());
    }
}

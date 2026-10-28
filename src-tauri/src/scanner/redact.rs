//! Placeholder assignment, masked previews, and redacted-text rebuild.
//! Secret values are hashed for reuse-tracking, never stored.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

/// Assigns numbered placeholders per category; the same secret value always
/// receives the same number so `[REDACTED_OPENAI_KEY_1]` is stable across
/// repeated occurrences.
#[derive(Default)]
pub struct Assigner {
    counters: HashMap<&'static str, u32>,
    by_value: HashMap<(&'static str, u64), u32>,
}

impl Assigner {
    pub fn assign(&mut self, base: &'static str, value: &str) -> String {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        let key = (base, hasher.finish());
        let n = match self.by_value.get(&key) {
            Some(&n) => n,
            None => {
                let c = self.counters.entry(base).or_insert(0);
                *c += 1;
                let n = *c;
                self.by_value.insert(key, n);
                n
            }
        };
        format!("[{base}_{n}]")
    }
}

/// Never leaks more than 6 real characters of the secret into the UI.
pub fn masked_preview(category: &str, value: &str) -> String {
    if matches!(
        category,
        "pem_private_key" | "gcp_sa_private_key" | "putty_private_key"
    ) {
        let lines = value.lines().count().max(1);
        return format!("-----BEGIN … KEY block ({lines} lines)");
    }
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n >= 12 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[n - 2..].iter().collect();
        format!("{head}…{tail} ({n} chars)")
    } else {
        let head: String = chars[..2.min(n)].iter().collect();
        format!("{head}… ({n} chars)")
    }
}

pub struct RedactItem<'a> {
    pub start: usize,
    pub end: usize,
    pub placeholder: &'a str,
    pub skip: bool,
}

/// Single-pass rebuild. `items` must be sorted by start and non-overlapping.
pub fn rebuild(text: &str, items: &[RedactItem]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for item in items {
        out.push_str(&text[cursor..item.start]);
        if item.skip {
            out.push_str(&text[item.start..item.end]);
        } else {
            out.push_str(item.placeholder);
        }
        cursor = item.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbering_increments_per_category_and_reuses_for_same_value() {
        let mut a = Assigner::default();
        assert_eq!(a.assign("REDACTED_OPENAI_KEY", "key-one"), "[REDACTED_OPENAI_KEY_1]");
        assert_eq!(a.assign("REDACTED_OPENAI_KEY", "key-two"), "[REDACTED_OPENAI_KEY_2]");
        assert_eq!(a.assign("REDACTED_OPENAI_KEY", "key-one"), "[REDACTED_OPENAI_KEY_1]");
        assert_eq!(a.assign("REDACTED_JWT", "key-one"), "[REDACTED_JWT_1]");
    }

    #[test]
    fn preview_masks_long_and_short_values() {
        let p = masked_preview("openai_api_key", "sk-proj-abcd1234abcd1234abcd1234abcd1234");
        assert_eq!(p, "sk-p…34 (40 chars)");
        let p = masked_preview("generic_secret_assignment", "shortpw1");
        assert_eq!(p, "sh… (8 chars)");
    }

    #[test]
    fn preview_pem_contains_no_key_material() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretsecret\n-----END RSA PRIVATE KEY-----";
        let p = masked_preview("pem_private_key", pem);
        assert_eq!(p, "-----BEGIN … KEY block (3 lines)");
        assert!(!p.contains("MIIE"));
    }

    #[test]
    fn rebuild_substitutes_and_skips() {
        let text = "a SECRET1 b SECRET2 c";
        let items = [
            RedactItem { start: 2, end: 9, placeholder: "[R_1]", skip: false },
            RedactItem { start: 12, end: 19, placeholder: "[R_2]", skip: true },
        ];
        assert_eq!(rebuild(text, &items), "a [R_1] b SECRET2 c");
    }
}

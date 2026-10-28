use super::types::Severity;
use regex::Regex;
use std::sync::LazyLock;

pub struct CompiledPattern {
    pub category: &'static str,
    pub label: &'static str,
    pub severity: Severity,
    pub redact_group: Option<usize>,
    pub placeholder: &'static str,
    pub validate: Option<fn(&str) -> bool>,
    pub regex: Regex,
}

fn cp(
    category: &'static str,
    label: &'static str,
    severity: Severity,
    regex: &str,
    redact_group: Option<usize>,
    placeholder: &'static str,
    validate: Option<fn(&str) -> bool>,
) -> CompiledPattern {
    CompiledPattern {
        category,
        label,
        severity,
        redact_group,
        placeholder,
        validate,
        regex: Regex::new(regex).expect("invalid pattern regex"),
    }
}

/// Rejects values that are obviously placeholders, not real secrets.
/// Used by the generic assignment pattern and URL-credential validator.
pub fn is_real_value(value: &str) -> bool {
    let v = value.trim_matches(|c| c == '"' || c == '\'');
    if v.len() < 4 {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "none" | "undefined" | "nil" | "empty"
    ) {
        return false;
    }
    const PLACEHOLDER_HINTS: &[&str] = &[
        "changeme",
        "change_me",
        "change-me",
        "example",
        "placeholder",
        "dummy",
        "sample",
        "your_",
        "your-",
        "yourkey",
        "process.env",
        "<your",
        "[redacted_",
    ];
    if PLACEHOLDER_HINTS.iter().any(|h| lower.contains(h)) {
        return false;
    }
    // Template/interpolation syntax: ${VAR}, {{var}}, $(cmd), %VAR%, <value>
    if v.starts_with("${")
        || v.starts_with("{{")
        || v.starts_with("$(")
        || v.starts_with('<')
        || (v.starts_with('%') && v.ends_with('%'))
        || v.starts_with('$')
    {
        return false;
    }
    // All the same masking char: xxxx, ****, ....
    if v.chars().all(|c| c == 'x' || c == 'X') || v.chars().all(|c| c == '*' || c == '.') {
        return false;
    }
    // Bare URL without embedded credentials is not a secret value
    if (lower.starts_with("http://") || lower.starts_with("https://")) && !v.contains('@') {
        return false;
    }
    // Short pure-numeric values (ports, timeouts, ids)
    if v.len() < 12 && v.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    true
}

/// For url_with_credentials: group is `user:pass` — reject template passwords.
fn url_creds_real(value: &str) -> bool {
    let pass = value.split_once(':').map(|(_, p)| p).unwrap_or(value);
    is_real_value(pass)
}

/// Catalog order doubles as the tiebreak priority for identical spans —
/// more specific vendor patterns must precede generic ones.
pub static PATTERNS: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    vec![
        cp(
            "pem_private_key",
            "Private Key Block",
            Severity::Critical,
            r"(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----",
            None,
            "REDACTED_PRIVATE_KEY",
            None,
        ),
        cp(
            "putty_private_key",
            "PuTTY Private Key",
            Severity::Critical,
            r"(?s)PuTTY-User-Key-File-\d+:.*?Private-MAC:\s*[0-9a-fA-F]+",
            None,
            "REDACTED_PUTTY_KEY",
            None,
        ),
        cp(
            "anthropic_api_key",
            "Anthropic API Key",
            Severity::Critical,
            r"\bsk-ant-[A-Za-z0-9_\-]{20,}",
            None,
            "REDACTED_ANTHROPIC_KEY",
            None,
        ),
        cp(
            "openai_api_key",
            "OpenAI API Key",
            Severity::Critical,
            r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
            None,
            "REDACTED_OPENAI_KEY",
            None,
        ),
        cp(
            "github_token",
            "GitHub Token",
            Severity::Critical,
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
            None,
            "REDACTED_GITHUB_TOKEN",
            None,
        ),
        cp(
            "github_pat",
            "GitHub Fine-Grained PAT",
            Severity::Critical,
            r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
            None,
            "REDACTED_GITHUB_PAT",
            None,
        ),
        cp(
            "gitlab_pat",
            "GitLab Personal Access Token",
            Severity::Critical,
            r"\bglpat-[A-Za-z0-9_\-]{20,}",
            None,
            "REDACTED_GITLAB_TOKEN",
            None,
        ),
        cp(
            "huggingface_token",
            "Hugging Face Token",
            Severity::Critical,
            r"\bhf_[A-Za-z0-9]{34,}\b",
            None,
            "REDACTED_HUGGINGFACE_TOKEN",
            None,
        ),
        cp(
            "groq_api_key",
            "Groq API Key",
            Severity::Critical,
            r"\bgsk_[A-Za-z0-9]{40,}\b",
            None,
            "REDACTED_GROQ_KEY",
            None,
        ),
        cp(
            "xai_api_key",
            "xAI API Key",
            Severity::Critical,
            r"\bxai-[A-Za-z0-9]{60,}\b",
            None,
            "REDACTED_XAI_KEY",
            None,
        ),
        cp(
            "google_oauth_secret",
            "Google OAuth Client Secret",
            Severity::High,
            r"\bGOCSPX-[A-Za-z0-9_\-]{24,}",
            None,
            "REDACTED_GOOGLE_OAUTH_SECRET",
            None,
        ),
        cp(
            "digitalocean_token",
            "DigitalOcean Token",
            Severity::Critical,
            r"\bdo[por]_v1_[a-f0-9]{64}\b",
            None,
            "REDACTED_DIGITALOCEAN_TOKEN",
            None,
        ),
        cp(
            "shopify_token",
            "Shopify Access Token",
            Severity::Critical,
            r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
            None,
            "REDACTED_SHOPIFY_TOKEN",
            None,
        ),
        cp(
            "supabase_token",
            "Supabase Secret / Access Token",
            Severity::Critical,
            r"\b(?:sbp_[a-f0-9]{40}\b|sb_secret_[A-Za-z0-9_\-]{20,})",
            None,
            "REDACTED_SUPABASE_TOKEN",
            None,
        ),
        cp(
            "databricks_token",
            "Databricks Token",
            Severity::High,
            r"\bdapi[a-f0-9]{32}(?:-\d)?\b",
            None,
            "REDACTED_DATABRICKS_TOKEN",
            None,
        ),
        cp(
            "mailgun_key",
            "Mailgun API Key",
            Severity::High,
            r"\bkey-[a-f0-9]{32}\b",
            None,
            "REDACTED_MAILGUN_KEY",
            None,
        ),
        cp(
            "discord_bot_token",
            "Discord Bot Token",
            Severity::High,
            r"\b[MN][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}",
            None,
            "REDACTED_DISCORD_TOKEN",
            None,
        ),
        cp(
            "discord_webhook",
            "Discord Webhook URL",
            Severity::High,
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,}",
            None,
            "REDACTED_DISCORD_WEBHOOK",
            None,
        ),
        cp(
            "telegram_bot_token",
            "Telegram Bot Token",
            Severity::High,
            r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}",
            None,
            "REDACTED_TELEGRAM_TOKEN",
            None,
        ),
        cp(
            "aws_access_key_id",
            "AWS Access Key ID",
            Severity::High,
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            None,
            "REDACTED_AWS_KEY_ID",
            None,
        ),
        cp(
            "aws_secret_key",
            "AWS Secret Access Key",
            Severity::Critical,
            r#"(?i)\baws_?secret_?(?:access_?)?key\b['" ]*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#,
            Some(1),
            "REDACTED_AWS_SECRET",
            None,
        ),
        cp(
            "google_api_key",
            "Google API Key",
            Severity::High,
            r"\bAIza[0-9A-Za-z_\-]{35}",
            None,
            "REDACTED_GOOGLE_KEY",
            None,
        ),
        cp(
            "stripe_live_key",
            "Stripe Live Key",
            Severity::Critical,
            r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b",
            None,
            "REDACTED_STRIPE_LIVE_KEY",
            None,
        ),
        cp(
            "stripe_test_key",
            "Stripe Test Key",
            Severity::Low,
            r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b",
            None,
            "REDACTED_STRIPE_TEST_KEY",
            None,
        ),
        cp(
            "slack_token",
            "Slack Token",
            Severity::Critical,
            r"\bxox[baprse]-[A-Za-z0-9\-]{10,}",
            None,
            "REDACTED_SLACK_TOKEN",
            None,
        ),
        cp(
            "slack_webhook",
            "Slack Webhook URL",
            Severity::High,
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}",
            None,
            "REDACTED_SLACK_WEBHOOK",
            None,
        ),
        cp(
            "sendgrid_key",
            "SendGrid API Key",
            Severity::Critical,
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
            None,
            "REDACTED_SENDGRID_KEY",
            None,
        ),
        cp(
            "twilio_api_key",
            "Twilio API Key",
            Severity::High,
            r"\bSK[0-9a-f]{32}\b",
            None,
            "REDACTED_TWILIO_KEY",
            None,
        ),
        cp(
            "twilio_account_sid",
            "Twilio Account SID",
            Severity::Medium,
            r"\bAC[0-9a-f]{32}\b",
            None,
            "REDACTED_TWILIO_SID",
            None,
        ),
        cp(
            "npm_token",
            "npm Token",
            Severity::Critical,
            r"\bnpm_[A-Za-z0-9]{36}\b",
            None,
            "REDACTED_NPM_TOKEN",
            None,
        ),
        cp(
            "azure_storage_key",
            "Azure Storage Account Key",
            Severity::Critical,
            r"(?i)AccountKey=([A-Za-z0-9+/=]{40,})",
            Some(1),
            "REDACTED_AZURE_KEY",
            None,
        ),
        cp(
            "azure_sas",
            "Azure SAS Signature",
            Severity::High,
            r"(?i)[?&]sig=([A-Za-z0-9%+/=]{30,})",
            Some(1),
            "REDACTED_AZURE_SAS",
            None,
        ),
        cp(
            "gcp_sa_private_key",
            "GCP Service Account Key",
            Severity::Critical,
            r#""private_key"\s*:\s*"(-----BEGIN[^"]{100,}?-----END [A-Z ]*PRIVATE KEY-----(?:\\n)?)""#,
            Some(1),
            "REDACTED_GCP_SA_KEY",
            None,
        ),
        cp(
            "jwt",
            "JSON Web Token",
            Severity::High,
            r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}",
            None,
            "REDACTED_JWT",
            None,
        ),
        cp(
            "url_with_credentials",
            "URL with Embedded Credentials",
            Severity::Critical,
            r#"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://([^/\s:@'"]{1,64}:[^@\s/'"]{1,256})@[^\s'"]+"#,
            Some(1),
            "REDACTED_URL_CREDENTIALS",
            Some(url_creds_real),
        ),
        cp(
            "authorization_header",
            "Authorization Header",
            Severity::High,
            r#"(?i)\bauthorization['" ]*[:=]\s*['"]?((?:bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{16,})"#,
            Some(1),
            "REDACTED_AUTH_HEADER",
            None,
        ),
        cp(
            "generic_secret_assignment",
            "Secret-Named Assignment",
            Severity::Medium,
            r#"(?im)^[ \t]*(?:export[ \t]+)?["']?[A-Za-z0-9_.\-]*(?:SECRET|TOKEN|API_?KEY|APIKEY|PASSW(?:OR)?D|PWD|CREDENTIAL|AUTH)[A-Za-z0-9_.\-]*["']?[ \t]*[:=][ \t]*["']?([^\s"'#;,]{8,})"#,
            Some(1),
            "REDACTED_SECRET_VALUE",
            Some(is_real_value),
        ),
    ]
});

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(category: &str, text: &str) -> bool {
        let p = PATTERNS
            .iter()
            .find(|p| p.category == category)
            .expect("unknown category");
        p.regex.captures_iter(text).any(|caps| {
            let m = match p.redact_group {
                Some(g) => match caps.get(g) {
                    Some(m) => m,
                    None => return false,
                },
                None => caps.get(0).unwrap(),
            };
            p.validate.map(|v| v(m.as_str())).unwrap_or(true)
        })
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(PATTERNS.len(), 37);
    }

    #[test]
    fn vendor_key_positives() {
        assert!(matches("aws_access_key_id", "key: AKIAIOSFODNN7EXAMPLE"));
        assert!(matches("aws_access_key_id", "ASIAIOSFODNN7EXAMPLE"));
        assert!(matches(
            "openai_api_key",
            "sk-proj-abcd1234abcd1234abcd1234abcd1234"
        ));
        assert!(matches(
            "anthropic_api_key",
            "sk-ant-api03-abcd1234efgh5678ijkl"
        ));
        assert!(matches(
            "github_token",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(matches(
            "github_pat",
            "github_pat_0123456789abcdefghijklmn"
        ));
        assert!(matches("gitlab_pat", "glpat-abcdefghij0123456789"));
        assert!(matches(
            "google_api_key",
            "AIza0123456789abcdefghijklmnopqrstuvwxy"
        ));
        assert!(matches("stripe_live_key", "sk_live_abcdefghijklmnop1234"));
        assert!(matches("stripe_test_key", "rk_test_abcdefghijklmnop1234"));
        assert!(matches("slack_token", "xoxb-1234567890-abcdefghij"));
        assert!(matches(
            "slack_webhook",
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXX"
        ));
        assert!(matches(
            "sendgrid_key",
            "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
        ));
        assert!(matches(
            "twilio_api_key",
            "SK0123456789abcdef0123456789abcdef"
        ));
        assert!(matches(
            "twilio_account_sid",
            "AC0123456789abcdef0123456789abcdef"
        ));
        assert!(matches(
            "npm_token",
            "npm_0123456789abcdefghijklmnopqrstuvwxyz"
        ));
        assert!(matches(
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        ));
    }

    #[test]
    fn assignment_and_url_positives() {
        assert!(matches(
            "aws_secret_key",
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(matches(
            "azure_storage_key",
            "DefaultEndpointsProtocol=https;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCD==;"
        ));
        assert!(matches(
            "azure_sas",
            "https://acct.blob.core.windows.net/c/b?sv=2020&sig=abc%2Bdef0123456789abcdefghijklmnopqrs"
        ));
        assert!(matches(
            "url_with_credentials",
            "postgres://admin:hunter22secret@db.example.com:5432/app"
        ));
        assert!(matches(
            "authorization_header",
            "Authorization: Bearer abcdef1234567890abcdef"
        ));
        assert!(matches(
            "generic_secret_assignment",
            "DATABASE_PASSWORD=supersecret123456"
        ));
        assert!(matches(
            "generic_secret_assignment",
            r#"  "api_key": "abc123def456ghi789""#
        ));
        assert!(matches(
            "generic_secret_assignment",
            "export MY_TOKEN=tok8chars"
        ));
    }

    #[test]
    fn pem_positives() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfakefakefake\nfakefakefake\n-----END RSA PRIVATE KEY-----";
        assert!(matches("pem_private_key", pem));
        // JSON-embedded with literal \n on one physical line
        let json_pem = r#""private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQfakefakefakefakefakefakefakefakefakefakefake\n-----END PRIVATE KEY-----\n""#;
        assert!(matches("pem_private_key", json_pem));
        assert!(matches("gcp_sa_private_key", json_pem));
    }

    #[test]
    fn near_miss_negatives() {
        // Too short
        assert!(!matches("aws_access_key_id", "AKIAIOSFODNN7EXAMPL"));
        assert!(!matches("github_token", "ghp_tooshort123"));
        assert!(!matches("openai_api_key", "sk-short"));
        // Wrong prefix
        assert!(!matches("stripe_live_key", "pk_live_abcdefghijklmnop1234"));
        // Missing END anchor must not match
        assert!(!matches(
            "pem_private_key",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\nno end marker here"
        ));
        // Twilio is lowercase-hex only; uppercase hex body must not match
        assert!(!matches(
            "twilio_api_key",
            "SK0123456789ABCDEF0123456789ABCDEF"
        ));
        // URL without credentials
        assert!(!matches(
            "url_with_credentials",
            "https://example.com:8080/path"
        ));
    }

    #[test]
    fn generic_assignment_placeholder_values_rejected() {
        for line in [
            "PASSWORD=changeme123",
            "API_KEY=<your-key-here>",
            "SECRET_TOKEN=${SECRET_TOKEN}",
            "DB_PASSWORD={{ vault_password }}",
            "AUTH_TOKEN=process.env.AUTH_TOKEN",
            "MY_SECRET=xxxxxxxxxx",
            "STRIPE_KEY=your_stripe_key_here",
            "TOKEN_TTL=86400000",
            "AUTH_URL=https://auth.example.com/login",
        ] {
            assert!(
                !matches("generic_secret_assignment", line),
                "should reject: {line}"
            );
        }
    }

    #[test]
    fn new_vendor_positives() {
        let hex64 = "0123456789abcdef".repeat(4);
        let hex32 = "0123456789abcdef".repeat(2);
        assert!(matches(
            "huggingface_token",
            "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567"
        ));
        assert!(matches(
            "groq_api_key",
            "gsk_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKl"
        ));
        assert!(matches(
            "xai_api_key",
            &format!("xai-{}", "AbCdEfGhIj0123456789".repeat(4))
        ));
        assert!(matches(
            "google_oauth_secret",
            "GOCSPX-AbCdEfGhIjKlMnOpQrStUvWx12"
        ));
        assert!(matches("digitalocean_token", &format!("dop_v1_{hex64}")));
        assert!(matches("shopify_token", &format!("shpat_{hex32}")));
        assert!(matches("supabase_token", &format!("sbp_{hex32}01234567")));
        assert!(matches(
            "supabase_token",
            "sb_secret_AbCdEfGhIjKlMnOpQrStUv"
        ));
        assert!(matches("databricks_token", &format!("dapi{hex32}")));
        assert!(matches("mailgun_key", &format!("key-{hex32}")));
        assert!(matches(
            "discord_bot_token",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.AbCdEfGhIjKlMnOpQrStUvWxYz0123456"
        ));
        assert!(matches(
            "discord_webhook",
            &format!(
                "https://discord.com/api/webhooks/123456789012345678/{}",
                "AbCdEfGhIj0123456789".repeat(4)
            )
        ));
        assert!(matches(
            "telegram_bot_token",
            "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawq"
        ));
        assert!(matches(
            "putty_private_key",
            "PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Private-Lines: 1
AAAAsecret
Private-MAC: 0123abcd"
        ));
    }

    #[test]
    fn new_vendor_near_miss_negatives() {
        let hex32 = "0123456789abcdef".repeat(2);
        assert!(!matches("huggingface_token", "hf_short123"));
        assert!(!matches("groq_api_key", "gsk_tooShort0123456789"));
        assert!(!matches("xai_api_key", "xai-grok-model-name"));
        assert!(!matches("google_oauth_secret", "GOCSPX-short"));
        // DigitalOcean body must be 64 lowercase hex
        assert!(!matches("digitalocean_token", &format!("dop_v1_{hex32}")));
        // Shopify prefix without a token body
        assert!(!matches("shopify_token", "shpat_notahexvalue"));
        assert!(!matches("supabase_token", "sb_publishable_AbCdEfGhIjKlMnOpQrStUv"));
        assert!(!matches("databricks_token", "dapi-docs-page"));
        assert!(!matches("mailgun_key", "key-value-store"));
        // Middle segment of a Discord token is exactly 6 chars
        assert!(!matches(
            "discord_bot_token",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBc.AbCdEfGhIjKlMnOpQrStUvWxYz0123456"
        ));
        assert!(!matches(
            "discord_webhook",
            "https://discord.com/api/webhooks/123/short"
        ));
        // Timestamps like 12:34:56 must not look like Telegram tokens
        assert!(!matches("telegram_bot_token", "2026-07-09 12:00:01 INFO"));
        assert!(!matches(
            "putty_private_key",
            "PuTTY-User-Key-File-3: ssh-ed25519 (no MAC line)"
        ));
    }

    #[test]
    fn url_with_template_password_rejected() {
        assert!(!matches(
            "url_with_credentials",
            "postgres://admin:${DB_PASSWORD}@db.example.com/app"
        ));
    }
}

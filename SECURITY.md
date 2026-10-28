# Security Policy

Prompt Safe exists to keep secrets out of AI prompts, so detection gaps and
leaks are treated as security issues.

## What counts as a security issue

- **Leaks**: any path where a raw secret value reaches the UI (beyond the 6-character
  masked preview), is written to disk or a log, or is sent over the network.
- **Redaction bypass**: a secret that is detected but still appears in the sanitized copy.
- **Missed detection** of a widely used credential format with a fixed, documented
  prefix. Generic or unprefixed tokens are best-effort (entropy heuristic) and are
  feature requests, not vulnerabilities.

## Reporting

Please use GitHub's **private vulnerability reporting**:
Security tab → "Report a vulnerability".
For missed formats you may open a normal issue instead.

**Never include a real secret in a report.** Describe the format, such as
`prefix_` + 40 hex characters, or use an obviously fake value.

## Design guarantees

- No network access. The Content Security Policy allows no remote origins, and the
  app contains no HTTP client.
- Input text is never logged or persisted. Only UI preferences are stored.
- Scan results crossing the IPC boundary contain masked previews, offsets and
  redacted text. They never contain the original text.

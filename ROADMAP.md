# Roadmap — Prompt Safe

## Now: v0.2.0 open-source launch (GitHub)
- [x] Pre-launch review fixes (entropy-cap leak, honest status copy, copy errors, perf)
- [x] 37 detectors incl. all major LLM providers
- [x] Clipboard sanitize hotkey, file open/drop, settings, a11y, persisted prefs
- [x] LICENSE (MIT), SECURITY, PRIVACY, CONTRIBUTING, CI, release workflow
- [ ] Manual QA in `npm run tauri dev` + install test of the MSI on a clean machine
- [ ] Screenshot/GIF in README
- [x] Initial commit, push to `github.com/VolchokLV/prompt-safe`, enable private vulnerability reporting
- [ ] Tag `v0.2.0`, review the draft release, publish

## Next: Microsoft Store (v0.2.x)
- [ ] Free individual Partner Center account, reserve "Prompt Safe"
- [ ] Host PRIVACY.md (GitHub Pages)
- [ ] `npm run build:store` → MSIX Packaging Tool → submit (see docs/RELEASING.md)
- [ ] Store listing: screenshots, description, Developer tools category

## Later
- Custom user patterns (regex + label) stored locally
- Allow-list of values that should never be flagged
- PII detection mode (emails, phone numbers, IBANs), off by default
- Highlight findings inline in the input (overlay editor)
- Optional code signing for direct downloads (Azure Trusted Signing)
- macOS / Linux builds (the scanner is portable; needs UI/installer testing)

## Success criteria
- Zero raw-secret leaks across IPC or the sanitized copy (test-enforced)
- 5 MB log scanned in < 3 s (CI-enforced; currently about 70 ms)
- No network capability in the Store manifest

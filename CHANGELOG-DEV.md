# CHANGELOG-DEV

## 2026-10-29 — Session 5: Published to GitHub

- Created the public repo `github.com/VolchokLV/prompt-safe` and pushed `main`.
- GitHub push protection blocked the fake tokens in `samples/demo.txt` and the pattern tests. Each was allowed as "used in tests". The steps are now in `docs/RELEASING.md`.
- Enabled private vulnerability reporting.
- Next: manual QA, then tag `v0.2.0` and publish the draft release.

## 2026-10-28 — Session 4: Pre-launch review & v0.2.0 launch prep

Full code/UI review, then implemented every finding. Launch plan: open-source GitHub release first, then Microsoft Store via MSIX (free individual account; Store signs MSIX for free).

### Fixed (safety / correctness)
- **Entropy-cap leak**: high-entropy values beyond the 50 listed were left *unredacted* in the sanitized copy. They are now redacted by default (placeholders numbered after listed ones, so listed placeholders stay stable); opt-out in Settings, with a Toolbar warning when anything is left unredacted. New `ScanStats.entropyOverflowRedacted`.
- Status banner no longer claims "safe to copy" — now "No known secrets detected" + heuristic-scan hint.
- Clipboard copy failures were unhandled promise rejections; now surface "Copy failed".
- Findings tab badge counted dismissed findings; now counts active ones.
- Line counter did `text.split("
")` on every keystroke (≈50k allocations on a 5 MB paste); replaced with an allocation-free `countLines`.
- Removed unused `anyhow` / `thiserror` crates.
- Bundle identifier `com.promptsafe.app` → `dev.volchok.promptsafe` (the `.app` suffix is discouraged by Tauri and the Store derives publisher from it). Version 0.1.0 → 0.2.0.

### Added
- **13 new detectors** (24 → 37): Hugging Face, Groq, xAI, Google OAuth client secret, DigitalOcean, Shopify, Supabase, Databricks, Mailgun, Discord bot token + webhook, Telegram bot token, PuTTY private key. Positive + near-miss tests for each; `samples/demo.txt` extended; new regression test asserts every catalog category is detected in the demo file.
- **Sanitize clipboard**: button + global hotkey **Ctrl+Alt+Shift+V** (`tauri-plugin-global-shortcut`). Read → scan → write-back runs entirely in Rust; only counts/labels cross IPC. Toast feedback. Toggle in Settings.
- **Open file / drag-drop** (`tauri-plugin-dialog`, `read_text_file` command, 64 MB cap, lossy UTF-8) with drop overlay.
- **Jump selects the secret**: findings carry UTF-16 `start`/`end` offsets; clicking a line number selects the value in the textarea and scrolls both axes.
- **Dismiss all / Restore all** per finding group.
- **Keyboard shortcuts**: Ctrl+Shift+C copy sanitized, Ctrl+O open, Ctrl+L clear, Ctrl+1/2/3 tabs, ←/→ between tabs.
- **Settings tab**: clipboard auto-clear, hotkey toggle (+ registration error), entropy-overflow toggle, shortcut list, About (version, offline statement, MIT, repo URL).
- **Persisted preferences** (localStorage, guarded; never input text) + window size/position (`tauri-plugin-window-state`).
- **Accessibility**: ARIA tablist/tab/tabpanel, `aria-expanded` group toggles, labelled icon buttons, live-region status/toasts, global `:focus-visible` ring, raised contrast of meaningful secondary text (`neutral-600` → `neutral-500`).
- **Frontend tests**: Vitest + Testing Library (jsdom) — 14 tests covering `useScanner` debounce / paste / stale-seq guard / dismiss round-trip / overflow re-scan, row windowing, prefs, text helpers.
- **Launch files**: `LICENSE` (MIT), `SECURITY.md`, `PRIVACY.md`, `CONTRIBUTING.md`, `docs/RELEASING.md` (GitHub + Microsoft Store MSIX steps), `.github/workflows/ci.yml`, `.github/workflows/release.yml` (tauri-action draft release + SHA256SUMS), `src-tauri/tauri.microsoftstore.conf.json` + `npm run build:store`. README rewritten for launch (download, SmartScreen note, threat model).
- Tauri JS packages aligned with the Rust crates (`@tauri-apps/api` / CLI 2.12).

### Verification
- `cargo test` — 35 passed (+1 ignored perf test)
- `cargo test --release -- --ignored` — 5 MB perf test passed
- `cargo clippy --all-targets -- -D warnings` — clean
- `npm test` — 14 passed
- `npm run build` — clean · `npx tsc --noEmit` — clean
- **Pending (needs user to start the app):** manual `npm run tauri dev` QA — paste `samples/demo.txt`, drag-drop a log, hotkey from another app, jump-to-select, Settings persistence.

## 2026-07-17 — Session 3: True-neutral grey palette

### Changed
- Session 2 removed the explicit blue classes, but the top banner and bottom toolbar still looked blue because Tailwind's default `gray` palette is itself blue-tinted (`gray-950` = `#030712`, `gray-900` = `#111827`). Swapped every `gray-*` class for the tint-free `neutral-*` palette across all 7 components (`App`, `StatusBanner`, `Toolbar`, `InputPanel`, `FindingsPanel`, `FindingGroup`, `RedactedPreview`).
- Updated the hardcoded hexes in `src/styles/index.css` to their neutral equivalents: body background `#030712` → `#0a0a0a`, selection `#4b5563`/`#f9fafb` → `#525252`/`#fafafa`, scrollbar `#374151` → `#404040`.
- Emerald accents and red/amber/orange status/severity colors unchanged.

### Verification
- `npx tsc --noEmit` — clean
- `npm run build` — clean

## 2026-07-09 — Session 2: Monochrome styling pass

### Changed
- Removed all blue from the UI (palette is now black/gray/white + green accents, amber/red/orange kept for severity/status):
  - Jump-to-line link in `FindingGroup.tsx`: `text-sky-400` → `text-gray-300 hover:text-white`.
  - Low-severity dot/text: blue-tinted `slate-400` → pure `gray-400`.
  - Added a `::selection` rule in `index.css` (gray-600 background) so text selection no longer uses the browser-default blue highlight.
- Darkened the textarea placeholder text in `InputPanel.tsx` (`gray-600` → `gray-700`).

### Verification
- `npx tsc --noEmit` — clean
- `npm run build` — clean

## 2026-07-09 — Session 1: Initial build (v0.1.0)

Greenfield build of Prompt Safe — offline Tauri v2 desktop app that scans pasted text for secrets before it goes to an AI agent, and produces a sanitized copy.

### Added
- **Scaffold**: Tauri v2 + React 18 + TypeScript 5 + Vite 5 + Tailwind 3, mirroring the vapetasia-assistant conventions. Strict no-network CSP, MSI/NSIS bundle targets, 1100×800 window, generated shield/keyhole app icon.
- **Rust scanner core** (`src-tauri/src/scanner/`):
  - `patterns.rs` — 24-pattern catalog: PEM private-key blocks (multi-line), Anthropic, OpenAI, GitHub (classic + fine-grained), GitLab, AWS (key id + secret), Google, Stripe (live/test), Slack (token + webhook), SendGrid, Twilio, npm, Azure (storage key + SAS), GCP service-account keys, JWTs, URLs with embedded credentials (group-redacted, URL stays readable), Authorization headers, generic secret-named assignments with a placeholder-value validator.
  - `entropy.rs` — Shannon-entropy detector for unknown token formats; suppresses git SHAs/md5/sha256, UUIDs, paths, identifiers; capped at 50 distinct values.
  - `redact.rs` — numbered placeholders per category (same value → same number, values hashed never stored), masked previews (≤ 6 real chars), single-pass rebuild.
  - `mod.rs` — orchestration: greedy non-overlap dedup (severity desc → longest → catalog order), entropy last, deterministic ids by start offset, dismiss support via `ignored_ids`.
- **IPC**: single `scan_text` command in `spawn_blocking`; response never echoes original text or raw secrets.
- **Frontend**: StatusBanner (idle/scanning/clean/findings/all-dismissed), InputPanel (plain textarea, handles 50k+ lines, line/byte counter), FindingsPanel grouped by category with severity dots + per-finding dismiss/undo + jump-to-line, RedactedPreview with `<mark>` highlights and >5,000-line windowed rendering, Toolbar (Copy sanitized via clipboard-manager plugin, confirm-guarded Copy original, Clear, optional 60s clipboard auto-clear). `useScanner` hook with debounce (500ms/1s, immediate on paste) and stale-response guard.
- **Tests**: 23 Rust unit tests (pattern positives + near-miss negatives, dedup priority, placeholder numbering/reuse, group redaction, dismiss round-trip, entropy accept/reject/cap, masked-preview leak property, line/col mapping) + `#[ignore]`d 5MB perf smoke test.
- **Docs**: README.md, CLAUDE.md (incl. never-log/never-network/never-echo rules).

### Verification (all green)
- `cargo test` — 30/30 passed
- `cargo test --release -- --ignored` — 5MB log + 20 planted secrets, all found, scan completed in ~70ms
- `cargo clippy -- -D warnings` — clean
- `npx tsc --noEmit` — clean
- `npm run build` — clean (154KB JS bundle)
- Manual dev-run verification pending (`npm run tauri dev` — paste `samples/demo.txt`, verify findings/redaction/copy)

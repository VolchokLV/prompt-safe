# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

Prompt Safe is a local, fully-offline Tauri v2 Windows desktop app. The user pastes a prompt (or a huge log file) into an input field; Rust scans it for secrets (API keys, tokens, private keys, connection strings, high-entropy strings), shows findings with masked previews, and produces a redacted copy for one-click clipboard use.

**Hard rules:**
- **Never log or persist the input text.** It exists only in the webview and transiently in the `scan_text` command.
- **Never send anything over the network.** No HTTP clients, no telemetry. The CSP in `tauri.conf.json` allows no remote origins — keep it that way.
- **Never return raw secret values across IPC.** Findings carry masked previews only (max 6 real characters); the scan response contains findings + redacted text + stats, never the original text.

## Commands

```bash
npm run tauri dev        # dev with hot reload (ASK THE USER before starting servers)
npm run tauri build      # release MSI/NSIS

# from src-tauri/
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --release -- --ignored   # 5MB perf smoke test

# frontend
npm test                 # vitest (jsdom)
npx tsc --noEmit
npm run build
npm run build:store      # Microsoft Store build (offline WebView2), see docs/RELEASING.md
```

## Architecture

- `src-tauri/src/scanner/` — the core. `patterns.rs` holds the 37-pattern catalog (catalog order = tiebreak priority; vendor patterns before generic). `entropy.rs` is the Shannon heuristic with log-noise suppression and a 50-distinct-value cap. `redact.rs` numbers placeholders per category (same secret value → same number). `mod.rs` orchestrates: patterns → greedy non-overlap dedup (severity desc, longest, catalog order) → entropy → ids by start offset → redacted rebuild.
- `src-tauri/src/commands.rs` — `scan_text(text, ignored_ids, redact_overflow?)`, `read_text_file(path)` (64 MB cap, lossy UTF-8), `sanitize_clipboard()` (read → scan → write back entirely in Rust; only counts/labels cross IPC), `set_clipboard_hotkey(enabled)`. All blocking work runs in `spawn_blocking`. Errors become `String` at the IPC boundary.
- `src-tauri/src/hotkey.rs` — global Ctrl+Alt+Shift+V shortcut; emits `clipboard-sanitized` with the serialized `Result` payload.
- Entropy overflow: only 50 distinct entropy values are *listed*; values past the cap are still redacted (placeholders numbered after listed ones) unless `redact_overflow=false`. Overflow values are never in `findings`, so dismiss ids are unaffected.
- `Finding.start/end` are UTF-16 offsets (for textarea `setSelectionRange`), computed in a single forward pass.
- Dismiss round-trip: finding ids are indexes in start-offset order, stable for identical text. The frontend re-invokes `scan_text` with `ignoredIds`; any text edit clears the dismissed set.
- `src/hooks/useScanner.ts` — debounce (500ms, 1000ms over 1M chars, immediate on paste) + monotonic seq guard against stale responses; `dismissMany`/`undismissMany`.
- `src/hooks/useCopyActions.ts` — copy sanitized/original with confirm + error state; used by Toolbar and Ctrl+Shift+C.
- `src/lib/prefs.ts` — UI preferences in localStorage (guarded try/catch). Never store input text. Window size/position via `tauri-plugin-window-state`.
- `src/components/RedactedPreview.tsx` — renders placeholders as `<mark>` React nodes (never `dangerouslySetInnerHTML`); row windowing lives in `src/lib/redactedRows.ts` (above 5,000 lines only placeholder lines ±1 context).
- Clipboard uses `tauri-plugin-clipboard-manager` (reliable for multi-MB), not `navigator.clipboard`.

## Conventions

- Rust: `Result<T, String>` at the Tauri command boundary (no anyhow/thiserror — not needed), edition 2021.
- Adding a pattern: add to `PATTERNS` in catalog-priority position, with severity, placeholder base, optional `redact_group`/`validate`; add a positive + near-miss negative test, bump `all_patterns_compile`, and add a fake line to `samples/demo.txt` (the `demo_sample_detects_every_catalog_category` test enforces this).
- Bundle identifier is `dev.volchok.promptsafe` — never change it after release (breaks upgrades / Store identity).
- Versions must match across `package.json`, `src-tauri/Cargo.toml`, `src-tauri/tauri.conf.json`.
- Frontend types in `src/types/scan.ts` mirror the serde camelCase output of `scanner/types.rs` — keep them in sync.

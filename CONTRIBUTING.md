# Contributing

Thanks for helping keep secrets out of prompts.

## Setup

Requirements: Node 20+, Rust stable, and the Tauri v2 Windows prerequisites (WebView2, MSVC build tools).

```bash
npm install
npm run tauri dev
```

## Checks (CI runs all of these)

```bash
# from src-tauri/
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --release -- --ignored   # 5 MB perf smoke test (< 3 s)

# from the repo root
npm test
npx tsc --noEmit
npm run build
```

## Adding a secret pattern

1. Add a `cp(...)` entry to `PATTERNS` in `src-tauri/src/scanner/patterns.rs`.
   Catalog order is the tiebreak priority, so put vendor-specific patterns
   **before** generic ones.
2. Choose a severity, a `REDACTED_*` placeholder base, and optionally a
   `redact_group` (redact only part of the match) or a `validate` function.
3. Add a **positive** test and a **near-miss negative** test, and bump the
   count in `all_patterns_compile`.
4. Add an obviously fake example line to `samples/demo.txt`.

Use only fake values in tests and samples. Repeated hex such as
`0123456789abcdef…` works well.

## Hard rules

- Never log or persist input text.
- Never add network access. Keep the CSP free of remote origins.
- Never return raw secret values across IPC.

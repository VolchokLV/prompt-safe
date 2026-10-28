# Prompt Safe

**Scan text for secrets _before_ you paste it into an AI agent.** Local, fully offline, open source.

Paste a prompt, a config file, or a multi-megabyte log dump. Prompt Safe scans it in Rust, flags anything sensitive, and gives you a **sanitized copy** with one click. Detected items include API keys, tokens, private keys, passwords, connection strings and high-entropy blobs.

> Nothing leaves your machine. The app has no HTTP client, its Content Security Policy blocks every remote origin, and your input is never written to disk.

<!-- TODO: add screenshot — docs/screenshot.png -->

## Download

Grab the latest installer from [**Releases**](https://github.com/VolchokLV/prompt-safe/releases). Choose the `.msi` or the `-setup.exe`, and verify it against `SHA256SUMS.txt`.

> **SmartScreen:** the installers aren't code-signed yet, so Windows may show "Windows protected your PC". Click **More info**, then **Run anyway**. A Microsoft Store version, which is signed by Microsoft, is planned.

## Features

- **37 known secret formats.**
  - AI providers: OpenAI, Anthropic, Hugging Face, Groq and xAI.
  - Cloud and dev platforms: AWS, Google API keys and OAuth secrets, GCP service accounts, Azure storage keys and SAS, GitHub, GitLab, npm, DigitalOcean, Supabase and Databricks.
  - SaaS: Stripe, Slack, SendGrid, Twilio, Mailgun, Shopify, Discord and Telegram.
  - Generic: JWTs, PEM and PuTTY private keys, URLs with embedded credentials, `Authorization` headers, and `SECRET=…`-style assignments.
- **Entropy detection** catches unknown token formats. It suppresses log noise such as git SHAs, UUIDs, paths and hashes. It lists up to 50 distinct values and still redacts any beyond that.
- **Redaction, not deletion.** Secrets become numbered placeholders like `[REDACTED_OPENAI_KEY_1]`. The same value always gets the same number, and URL credentials are redacted in place so the URL stays readable.
- **Sanitize the clipboard from anywhere.** Copy text in any app and press **Ctrl+Alt+Shift+V**. The clipboard is replaced with the sanitized version, ready to paste.
- **Open or drop files.** Logs up to 64 MB are read by the Rust side.
- **Review tools.** Findings are grouped by type with severity. Click a finding to select it in the input. You can dismiss or restore findings one at a time or a whole group at once.
- **Safety details.**
  - Previews show at most 6 real characters, and raw input is never echoed back over IPC.
  - Optional clipboard clearing after 60 seconds.
  - "Copy original" requires a confirmation click when secrets are present.
- **Keyboard first.**

  | Shortcut | Action |
  | --- | --- |
  | Ctrl+Shift+C | Copy sanitized |
  | Ctrl+O | Open file |
  | Ctrl+L | Clear |
  | Ctrl+1 / 2 / 3 | Switch tabs |

## What it does and doesn't catch

Prompt Safe is a **heuristic safety net**, not a guarantee.

- **Reliably caught:** prefixed vendor keys like `sk-proj-`, `ghp_` and `AKIA…`, PEM blocks, and secret-named assignments.
- **Best effort:** random-looking unprefixed tokens, which the entropy heuristic handles.
- **Not caught:** short or human-chosen passwords that aren't in a `PASSWORD=`-style assignment, personal data such as names and emails, and secrets split across lines.

Always give the sanitized text a quick read before sharing it.

## Privacy

See [PRIVACY.md](PRIVACY.md). In short, it collects nothing and makes no network connections. Only UI preferences and window size are stored.

## Build from source

Requirements: Node 20+, Rust stable, and the [Tauri v2 Windows prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev      # dev with hot reload
npm run tauri build    # MSI + NSIS installers in src-tauri/target/release/bundle/
```

## Checks

```bash
# Rust (from src-tauri/)
cargo test
cargo clippy --all-targets -- -D warnings
cargo test --release -- --ignored   # 5 MB perf smoke test

# Frontend
npm test
npx tsc --noEmit
npm run build
```

## Contributing & security

- [CONTRIBUTING.md](CONTRIBUTING.md) explains how to add a secret pattern.
- [SECURITY.md](SECURITY.md) explains how to report missed formats or leaks privately.
- [docs/RELEASING.md](docs/RELEASING.md) covers the GitHub and Microsoft Store release steps.

## Tech stack

Tauri v2 (Rust), React 18, TypeScript 5, Vite 5 and Tailwind CSS 3. Rust dependencies beyond Tauri and its official plugins are `regex` and `serde`.

## License

[MIT](LICENSE)

# Releasing Prompt Safe

Two channels, in this order:

1. **GitHub Releases**: open source, unsigned installers, automated.
2. **Microsoft Store**: an MSIX package that the Store signs for free. This removes
   SmartScreen warnings and gives automatic updates without adding a network
   updater to the app.

---

## 1. GitHub release

1. Bump the version in all three files: `package.json`, `src-tauri/Cargo.toml`,
   and `src-tauri/tauri.conf.json`.
2. Update `CHANGELOG-DEV.md`. Commit.
3. Tag and push:
   ```bash
   git tag v0.2.0
   git push origin main --tags
   ```
4. The **Release** workflow builds the MSI and NSIS installers and creates a
   **draft** release with `SHA256SUMS.txt`. Smoke-test the installers, then
   publish the draft.

### Optional: signing direct downloads

Unsigned installers show the SmartScreen "Windows protected your PC" prompt.
To remove it for direct downloads you need a publicly trusted code-signing
certificate. Two options:

- **Azure Trusted Signing** costs about $10 a month. Individual eligibility is
  limited by country, so check the current terms. Configure it with
  `bundle.windows.signCommand` in `tauri.conf.json`.
- A traditional OV or EV certificate from a CA.

The Store channel does not need either.

---

## 2. Microsoft Store (MSIX)

### One-time setup

1. Register a **free individual** developer account at
   <https://storedeveloper.microsoft.com>.
2. In Partner Center, choose **Apps and games → New product → MSIX or PWA app**,
   and reserve the name **Prompt Safe**.
3. Open **Product identity** and note these three values:
   - `Package/Identity/Name`
   - `Package/Identity/Publisher` (`CN=…`)
   - `Package/Properties/PublisherDisplayName`
4. Host `PRIVACY.md` at a public URL. GitHub Pages works, and so does the
   raw GitHub file view. The Store requires a privacy policy URL.

### Build

```bash
npm run build:store
```

This applies `src-tauri/tauri.microsoftstore.conf.json`. That file embeds the
**offline** WebView2 installer, which the Store requires and which adds about
130 MB. Output goes to `src-tauri/target/release/bundle/`.

### Package as MSIX

Tauri v2 builds MSI and NSIS installers, not MSIX. Convert the MSI with
Microsoft's **MSIX Packaging Tool**, which is free from the Store:

1. Choose **Application package → Create package on this computer**. A clean
   VM or Windows Sandbox works best.
2. Select the MSI from `bundle/msi/`.
3. On the package information page, enter the **exact** Name, Publisher and
   Publisher display name from Partner Center. Set the version to `0.2.0.0`.
   The fourth segment must be 0 for the Store.
4. Do **not** sign the package. The Store signs it after certification.
5. In the manifest, keep only the `runFullTrust` capability. Do not add
   `internetClient`. The missing network capability publicly backs up the
   app's offline claim.

### Submit

1. Upload the `.msix` under **Packages**.
2. Store listing:
   - Description: you can reuse the README intro.
   - Screenshots: at least one at 1366×768 or larger.
   - Logos: `src-tauri/icons/StoreLogo.png` and the `Square*Logo.png` files.
3. Age rating: complete the questionnaire. The app has no user-generated
   sharing and no network access.
4. Privacy policy URL: the hosted `PRIVACY.md`.
5. Category: Developer tools.
6. Submit. Certification usually takes 1–3 business days.

### Fallback: submit the NSIS installer instead

Partner Center also accepts a Win32 **EXE/MSI** product that points to an
HTTPS-hosted installer, such as a GitHub release asset. That route requires
the installer to be **signed with a publicly trusted certificate**. Use the
silent-install argument `/S` for NSIS or `/quiet` for MSI. Prefer MSIX unless
you already have a certificate.

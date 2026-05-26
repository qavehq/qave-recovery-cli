<!--
MAINTAINER NOTE:
Before creating the GitHub Draft Release, replace every release-artifact placeholder in this file.

- Replace <FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> with the actual macOS no-terminal zip filename.
- Replace <FINAL_MACOS_APP_ZIP_SHA256_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> with the actual macOS no-terminal SHA256.
- Replace <FINAL_STATIC_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> with the actual static browser zip filename.
- Replace <FINAL_STATIC_ZIP_SHA256_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> with the actual static browser SHA256.
- Replace <FINAL_SIDECAR_MANIFEST_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> with the actual sidecar manifest filename.
- Before publishing or saving release notes into GitHub, grep this file and confirm there are no FINAL_ZIP, FINAL_SHA256, or FINAL_SIDECAR placeholders left.

No internal repository commit, internal artifact, or non-public SHA is authoritative for the public Draft Release. The final Draft Release must use the public qavehq/qave-recovery-cli commit and final generated .zip.sha256 file.
-->

# Qave Recovery Tool v1.0.0-rc.1

## Release Status

This is a pre-release / release candidate prepared from the public `qavehq/qave-recovery-cli` repository.

It is suitable for testing and early adoption. It is not yet the final stable release.

Final stable release `v1.0.0` will be published only after this release candidate is accepted.

Release metadata:

- Release title: `Qave Recovery Tool v1.0.0-rc.1`
- Tag proposal: `recovery-tool-v1.0.0-rc.1`
- Target commit: `<FINAL_PUBLIC_REPO_COMMIT_SHA_TO_BE_FILLED_AFTER_PUBLIC_COMMIT>`
- Repository: `qavehq/qave-recovery-cli`
- Status: Draft + Pre-release only

## Important: Download The Correct Asset

**DO NOT use GitHub's auto-generated "Source code (zip)" or "Source code (tar.gz)".**

Those files are repository snapshots, not the Recovery Tool release package.

For ordinary macOS recovery, download this no-terminal asset instead:

`<FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>`

Verify SHA256 before use:

`<FINAL_MACOS_APP_ZIP_SHA256_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>`

The static browser zip is also attached for audit, technical validation, and advanced troubleshooting:

`<FINAL_STATIC_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>`

The final zip filenames and SHA256 values must be copied from the generated `.zip.sha256` files when the GitHub Draft Release assets are attached.

## How To Verify SHA256

Expected SHA256 for the macOS no-terminal package:

`<FINAL_MACOS_APP_ZIP_SHA256_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>`

macOS / Linux:

```sh
shasum -a 256 <FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>
```

Windows PowerShell:

```powershell
Get-FileHash <FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT> -Algorithm SHA256
```

The command output must match the expected SHA256 above.

## What This Is

Qave Recovery Tool v1 is the official browser recovery tool for recovering files from a signed Qave Recovery Package (`.qrm`). The macOS no-terminal package includes `Qave Recovery Tool.app`, which opens the browser tool without requiring Terminal.

The `.qrm` must be signed by Qave backend before recovery. This browser tool executes recovery locally after you already have a valid `.qrm` Recovery Package.

Recovery execution runs locally in your browser. The launcher only serves bundled static files from `127.0.0.1` and opens your default browser. The tool makes no Qave backend/API/proxy calls during recovery execution.

## What You Need Before Recovery

1. Your `.qrm` Recovery Package, signed by Qave backend and saved ahead of time.
2. The same wallet that owns the vault.
3. Your Recovery Key.

You do not need to save encrypted files ahead of time.

During recovery, the tool shows a verified encrypted-file link from your `.qrm` package, and you download the encrypted file at that time.

## How Recovery Works

### Before Recovery (Requires Qave)

1. Request a Recovery Package from Qave.
2. Qave backend signs and issues your `.qrm` file.
3. Save the `.qrm` file and your Recovery Key.

### During Recovery (Local Execution)

1. On macOS, open `Qave Recovery Tool.app`; it opens this Recovery Tool in your browser.
2. Load your `.qrm` file; signature verification happens locally using Qave's public key.
3. Connect your wallet and sign a challenge message.
4. Select files to recover.
5. For each current file:
   - Download the encrypted file using the verified link from your `.qrm`.
   - Upload the encrypted file to the tool.
   - Enter your Recovery Key and decrypt locally.
6. Each recovered file downloads separately.

This tool does not call Qave backend/API/proxy during recovery execution.

## What's New In v1.0.0-rc.1

- No-terminal macOS launcher package for ordinary users.
- Multi-file queue recovery.
- Select multiple files and recover them one by one.
- Only the current file's encrypted-file link is shown.
- Each recovered file downloads separately.
- Recovery Key can be reused within the same page session in memory only.
- This browser tool does not create a combined ZIP.
- For restore-all or batch ZIP workflows, use the official Qave Recovery CLI.

## Security Shape

- Verifies `.qrm` package signature using Qave's public key.
- Checks package and file expiration before recovery.
- No Qave backend/API/proxy calls during recovery execution.
- Launcher binds only to `127.0.0.1` on a random local port and serves only bundled allowlisted static files.
- Launcher does not read `.qrm`, Recovery Key, ciphertext, plaintext, or arbitrary local files.
- Launcher has no upload API, no telemetry, no updater, and no Qave backend/API/proxy calls.
- No automatic network requests from the browser tool; CSP keeps `connect-src 'none'`.
- User-initiated encrypted-file download.
- Manual ciphertext upload.
- Recovery Key kept in JavaScript memory only; not stored in `localStorage`, `sessionStorage`, or `IndexedDB`.
- No service worker, analytics, remote logging, or external scripts.
- Each current file's ciphertext/plaintext state is isolated in the recovery queue.
- Public key fingerprint: `6f76e166bd24a1dc`

## Valid Access Period

The `.qrm` contains `subscription_expires_at`.

This timestamp is the hard boundary for official Qave recovery.

Before expiration: official Qave recovery can continue when the package, wallet, Recovery Key, and encrypted file are valid.

After the valid access period expires, official Qave tools cannot recover files from this package.

This tool is an official recovery tool for the valid access period only.

It is not a long-term archival or disaster recovery solution.

## Browser Requirements

- Chrome or Edge with Ed25519 WebCrypto support.
- Firefox with Ed25519 WebCrypto support.
- Safari 17 or later.
- MetaMask or compatible injected wallet provider supporting `personal_sign`.
- For ordinary macOS recovery, use the no-terminal launcher package. Developer smoke tests may use a local static server such as `http://127.0.0.1`; official HTTPS release pages may also be used when available.

## macOS First-Run Note / Gatekeeper

This release candidate may not yet be codesigned or notarized. macOS Gatekeeper may show a warning such as "cannot be opened" or "developer cannot be verified" the first time `Qave Recovery Tool.app` is opened.

If that happens, ordinary users should not use Terminal as the default path. Open System Settings -> Privacy & Security, find the message that Qave Recovery Tool was blocked, choose Open Anyway, and confirm that you want to open it.

This is a known limitation for this release candidate. A future stable release may add codesigning and notarization. Terminal-based quarantine commands are reserved for support-led or advanced troubleshooting, not the ordinary recovery path.

## Release Assets

- `<FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>` - macOS no-terminal Recovery Tool package. Ordinary macOS users should download this.
- `<FINAL_MACOS_APP_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>.sha256` - SHA256 checksum for the macOS no-terminal package.
- `<FINAL_STATIC_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>` - static browser package for audit, technical validation, and advanced troubleshooting.
- `<FINAL_STATIC_ZIP_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>.sha256` - SHA256 checksum for the static browser package.
- `<FINAL_SIDECAR_MANIFEST_NAME_TO_BE_FILLED_FROM_RELEASE_ARTIFACT>` - Release manifest with file hashes and security shape.
- Commit: `<FINAL_PUBLIC_REPO_COMMIT_SHA_TO_BE_FILLED_AFTER_PUBLIC_COMMIT>`

Do not use GitHub's auto-generated "Source code (zip)" or "Source code (tar.gz)".

## Known Limitations

- Release candidate / pre-release.
- Manual signature fallback is not supported.
- Browser tool processes one current queue file at a time.
- Browser tool does not create a combined ZIP.
- Automatic encrypted-file fetch is not supported.
- macOS Gatekeeper may require Open Anyway because this release candidate may not yet be codesigned or notarized.
- If no safe encrypted-file link is available in `.qrm`, use the official Qave Recovery CLI or another Qave-approved recovery path.
- Windows no-console launcher package is not included in B4-1.

## Important Warnings

- Do not enter your wallet seed phrase or private key.
- Do not use a recovery tool package from an untrusted source.
- Do not use this tool on an untrusted device.
- Recovery Key and decrypted files should never be sent to Qave, GitHub, or any third-party service.

## Feedback

This release candidate is intended for validation before wider user-facing distribution. Report issues or feedback in the repository issues page.

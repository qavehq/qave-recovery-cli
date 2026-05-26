# Qave Recovery Tool v1

Official static browser tool for recovering files from a signed Qave Recovery Package (`.qrm`).

This tool is designed to run as a static browser package. It does not call the Qave backend, does not use a Qave proxy, and does not automatically fetch encrypted files.

## What You Need Before Recovery

Before you start, have these ready:

1. Your `.qrm` Recovery Package.
2. The same wallet account that owns the Qave vault in that package.
3. Your Recovery Key for that wallet account.

You only need to save the `.qrm` package ahead of time. You do not need to save encrypted files ahead of time. During recovery, this tool shows a verified encrypted-file link from your recovery package so you can download the encrypted file at that time.

## What This Tool Does Locally

This tool runs in your browser and performs the recovery checks locally:

- verifies the `.qrm` package signature using Qave's public key
- checks that the package and selected files are still inside the valid access period
- asks your wallet to sign a challenge message so the package payload can unlock locally
- lets you select multiple recoverable files
- shows a verified encrypted-file link for the current file in the queue
- shows only the current file's encrypted-file link
- reads each encrypted file only after you upload it manually
- decrypts selected files one by one
- downloads each recovered original file separately

Your Recovery Key, decrypted file, payload key, and file key are not sent to Qave.

This browser tool does not create a combined ZIP. The Qave Recovery CLI remains the advanced path for restore-all or batch ZIP style workflows.

## Valid Access Period Boundary

The `.qrm` package contains a `subscription_expires_at` timestamp. That timestamp is the hard boundary for official Qave recovery.

- Before expiration: official Qave recovery can continue when the package, wallet, Recovery Key, and encrypted file are valid.
- After expiration: official Qave tools cannot recover this file.

Files in the package also have an `expires_at` timestamp. A file cannot remain recoverable beyond the package expiration.

## Step-by-Step Recovery Flow

### 1. Open The Tool

Open the release package in a modern browser. For wallet signing, use a local static server or an official HTTPS release page so MetaMask or a compatible wallet can inject into the page.

### 2. Load Your Recovery Package

Select your `.qrm` file under "Recovery Package". The tool verifies the package signature, validates Qave's public key, and checks the valid access period.

### 3. Connect Your Wallet And Sign

Click "Connect MetaMask and Sign". The connected wallet must match the `vault_owner` in the `.qrm` package.

Do not enter your wallet seed phrase or private key. This recovery flow only asks your wallet to sign a message.

### 4. Select Files

Choose one or more files to recover. Expired or invalid files are disabled and show the reason they cannot be selected.

### 5. Start The Recovery Queue

Click "Start recovery queue". The browser tool guides you through the selected files one by one.

### 6. Download The Encrypted File For The Current File

For the current queue item, the tool shows a verified encrypted-file link from your recovery package. Click "Download encrypted file" to download the encrypted file for that current file.

Only the current file's encrypted-file link is shown. The browser tool does not show multiple ciphertext links at once, does not download multiple ciphertext files for you, and does not ask you to manually match multiple ciphertext files to multiple package entries.

The link is user-initiated. The tool does not automatically request Qave, a Qave proxy, or the encrypted-file source.

### 7. Upload The Encrypted File Manually

After the encrypted file finishes downloading, click "Upload encrypted file" and select the encrypted file for the current queue item. The uploaded ciphertext is used only for that current file.

### 8. Enter Your Recovery Key And Decrypt

Enter your Recovery Key and click "Decrypt and Download". The tool decrypts the current file locally and starts a recovered-file download in your browser.

You can keep the Recovery Key in this page session while the queue advances. It stays in JavaScript memory only and is cleared by Reset, by queue completion, or when the page is closed.

### 9. Continue Through The Queue

After a file is recovered, click "Continue to next file". Each recovered original file downloads separately. This browser tool does not create a combined ZIP.

### 10. Close The Tool

After recovery, close the page to drop remaining browser memory references.

## How To Download The Encrypted File

The encrypted file is not something you need to save ahead of time. During recovery, this tool reads your signed `.qrm` package and displays a verified HTTPS encrypted-file link for the current queue item when it is safe to do so.

Use the displayed "Download encrypted file" link. The link opens outside the tool, and the download is started by your click.

## Why You Upload The Encrypted File Manually

The release package is intentionally shaped so the tool does not automatically fetch network resources. Its Content Security Policy keeps `connect-src 'none'`.

Manual upload keeps the recovery boundary clear:

- the tool verifies and unlocks the `.qrm` package locally
- only the current file's encrypted-file link is shown
- you click each current file's encrypted-file link yourself
- you upload each current encrypted file yourself
- the tool decrypts only the local encrypted file selected for the current queue item

## Browser Requirements

- Chrome or Edge with Ed25519 WebCrypto support
- Firefox with Ed25519 WebCrypto support
- Safari 17 or later
- MetaMask or a compatible injected wallet provider that supports `personal_sign`

Opening `index.html` directly can be useful for package inspection, but wallet injection is usually more reliable from `http://127.0.0.1`, `http://localhost`, or an official HTTPS static release page.

## Security Warnings

- Use this tool only on a trusted device.
- Do not enter your wallet seed phrase or private key.
- Do not use a release package from an untrusted source.
- Do not paste your Recovery Key into any website that is not the official static recovery tool.
- This tool does not call the Qave backend or any Qave API.
- This tool does not load remote scripts, fonts, analytics, or tracking.
- This tool does not register a service worker.
- This tool does not store secrets in `localStorage`, `sessionStorage`, or `IndexedDB`.
- This tool keeps Recovery Key material, payload keys, file keys, ciphertext, and plaintext in JavaScript memory only and clears byte arrays where JavaScript allows.

## Troubleshooting

### The wallet button does not open MetaMask

Serve the folder from a local static server and open it from `http://127.0.0.1`:

```sh
cd tools/qave-recovery-tool-v1
python3 -m http.server 4173
```

Then open `http://127.0.0.1:4173/`.

### Ed25519 WebCrypto is not supported

Update your browser or try another supported browser. The tool needs Ed25519 WebCrypto to verify Qave's package signature.

### The `.qrm` package is rejected

The package may be expired, corrupted, unsigned, or tampered with. Use the original `.qrm` file and the official Qave Recovery Tool release.

### The connected wallet does not match

Switch MetaMask to the wallet account that owns the vault in the `.qrm` package, then try again.

### No direct encrypted-file URL is available

The browser tool can only show safe HTTPS encrypted-file links from the recovery package. If no direct link is available, use the official Qave Recovery CLI or another Qave-approved recovery path.

### I need restore-all or one combined ZIP

This browser tool recovers selected files one by one and downloads each recovered original file separately. It does not create a combined ZIP. Use the official Qave Recovery CLI for advanced restore-all or batch ZIP style workflows.

### The Recovery Key does not work

Check that you entered the Recovery Key for the same wallet account and package. Spaces and hyphens are allowed; the normalized key must be 20 characters using letters A-Z without I, L, or O and digits 2-9.

### The package or file has expired

Official Qave tools cannot recover this file after the valid access period expires.

## What Qave Does Not Promise After Expiration

Qave does not promise recovery after the package or file expiration boundary. After expiration, official Qave tools cannot recover this file, and this browser tool must not bypass that boundary.

This tool is not an indefinite archival or long-term disaster recovery guarantee. It is an official recovery tool for the valid access period only.

## Release Package Contents

The release zip is expected to contain:

- `index.html`
- `style.css`
- `app.mjs`
- `core.mjs`
- `README.md`
- `RELEASE-MANIFEST.json`

The release zip must not contain tests, fixtures, private seeds, private keys, test `.qrm` files, test ciphertext, `node_modules`, `.git`, or production secrets.

## Maintainer Notes

### Package A Release

From the repository root:

```sh
node tools/qave-recovery-tool-v1/package-release.mjs
node tools/qave-recovery-tool-v1/check-release.mjs
```

By default, release artifacts are written under `dist/recovery-tool/`, which is ignored by git.

### Development Tests

```sh
cd tools/qave-recovery-tool-v1
node --test core.test.mjs
node --check app.mjs
node --check core.mjs
```

### Current Limits

- Manual signature fallback is not supported.
- Automatic encrypted-file fetch is not supported.
- The browser tool processes one current queue file at a time.
- The browser tool does not create a combined ZIP.
- Encrypted-file download guidance and manual ciphertext upload appear only after package signature, package expiry, payload consistency, wallet ownership, and selected-file expiry checks pass.

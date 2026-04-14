# Qave Recovery Tool

This guide is for end users who need to recover files from a Qave Recovery Package.

## System requirements

Before recovery, make sure your computer has:

- macOS
- Terminal
- a web browser
- MetaMask installed in that browser
- internet access
- enough free disk space for:
  - the CLI tool
  - the Recovery Package file (`.qrm`)
  - temporary downloaded encrypted files during recovery
  - the final restored zip

Before recovery, make sure you also have:

- your Recovery Package file ending in `.qrm`
- the wallet account associated with that package
- the Recovery Key for that wallet account

Recovery can take time, especially for larger packages. During recovery, the tool may download encrypted file data, decrypt it locally on your Mac, and then rebuild a final zip that contains the restored files.

## Install and prepare your Mac

Before you run `verify`, `unlock`, or `restore-all`, prepare the recovery environment:

1. Check your Mac architecture in Terminal:

```bash
uname -m
```

Expected output:

- `arm64` for Apple Silicon Macs
- `x86_64` for Intel Macs

2. Open this repository's GitHub Releases page and download the correct macOS asset:

- `qave-recovery-cli-darwin-arm64-<version>.zip` for `arm64`
- `qave-recovery-cli-darwin-amd64-<version>.zip` for `x86_64`

3. Extract the downloaded zip file.
4. Open Terminal in the extracted folder so you can run `./qave-recovery-cli ...`.
5. Make sure MetaMask is installed in your browser, unlocked, and switched to the wallet account associated with your Recovery Package before you run `unlock` or `restore-all`.
6. Keep your `.qrm` file and Recovery Key ready before you continue.

### macOS first-run note

Some macOS users may see the first run blocked after downloading the CLI in a browser. If you see `zsh: killed`, `cannot be opened`, `developer cannot be verified`, or a similar macOS warning, first go to System Settings -> Privacy & Security and allow the app to continue, then try again. If you trust the release asset from this repository and are comfortable with Terminal, you can also run:

```bash
xattr -dr com.apple.quarantine ./qave-recovery-cli
```

## Step 1. Check that the Recovery Package file is okay

Run:

```bash
./qave-recovery-cli verify /path/to/your-file.qrm
```

What you will normally see:

- lines such as `schema=...`, `vault_owner=...`, and `payload_protection=...`
- often `file_count=locked`

Do not worry if you see `file_count=locked`.
That is the normal result for an encrypted Recovery Package.
It does not mean the file is broken.
It means the next step is to unlock it with MetaMask.

## Step 2. Unlock the Recovery Package with MetaMask

Run:

```bash
./qave-recovery-cli unlock /path/to/your-file.qrm --signer metamask
```

Important:

- do not remove `--signer metamask`
- this step must use MetaMask

What you do in this step:

1. Wait for the browser signing page to open
2. If asked, connect MetaMask
3. Click `Sign Challenge`
4. Confirm the signature in MetaMask

What you will normally see in the terminal:

- `challenge_verified=true`
- `payload_unlocked=true`

If the browser does not open by itself, copy the printed `sign_url=...` from the terminal into your browser.

## Step 3. Start full recovery

Run:

```bash
./qave-recovery-cli restore-all /path/to/your-file.qrm --signer metamask
```

Important:

- do not remove `--signer metamask`
- this step asks for MetaMask again
- this step also asks for your Recovery Key

What you do in this step:

1. Wait for the browser signing page to open again
2. Click `Sign Challenge` again
3. Confirm the signature in MetaMask again
4. Return to the terminal
5. Enter your Recovery Key when asked

The terminal prompt looks like this:

```text
Paste recovery key (hyphens/spaces optional):
```

You can enter the same Recovery Key in any of these formats:

- `ABCDE-FGHJK-MNPQR-ST234`
- `ABCDE FGHJK MNPQR ST234`
- `ABCDEFGHJKMNPQRST234`

The tool will recognize the format automatically.
You do not need to guess which one to use.

If the Recovery Key is wrong:

- the tool will say `Recovery Key incorrect. Please try again.`
- the tool will ask for the Recovery Key again
- you do not need to run `unlock` again
- you do not need to sign with MetaMask again

## Step 4. Get the recovered files

When recovery succeeds, the terminal will show lines like these:

- `restore_all_complete=true`
- `files_restored=...`
- `zip_path=...`

What happens next:

- the tool creates one zip file that contains your recovered files
- your browser will usually open automatically and start downloading that zip

How to confirm recovery worked:

1. Confirm the terminal shows `restore_all_complete=true`
2. Find the zip file
3. Open the zip file
4. Check that your recovered files are inside

If the browser does not start downloading automatically, look at the `zip_path=...` line in the terminal and open that file directly.

## Common situations

- `file_count=locked` during `verify` is normal
- seeing the `Sign Challenge` page is normal
- if the Recovery Key is wrong, just type it again in the same `restore-all` session
- if MetaMask is on a different wallet account, recovery will not continue

## Important note

Depending on your network conditions, recovery may be slow. Please be patient and keep the Terminal window open during the process. Do not close the Terminal or interrupt the recovery unless it has clearly completed or failed.

## Commands you need for normal recovery

Check the package:

```bash
./qave-recovery-cli verify /path/to/your-file.qrm
```

Unlock the package:

```bash
./qave-recovery-cli unlock /path/to/your-file.qrm --signer metamask
```

Recover everything:

```bash
./qave-recovery-cli restore-all /path/to/your-file.qrm --signer metamask
```

## Maintainers

If you are preparing an official release asset for users, use the release flow in [RELEASING.md](RELEASING.md).

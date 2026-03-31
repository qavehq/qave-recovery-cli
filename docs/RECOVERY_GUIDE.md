# Recovery Guide

## Recovery Package: what it is

Your Recovery Package is the file that lets you recover your Qave files after you move to a new computer or lose access to your old device. Its file name usually ends with `.qrm`.

It is not a normal download and it is not a plain backup copy of your files. Think of it as the file that tells the official Qave recovery tool how to unlock and rebuild your files.

## Before you start

Prepare these 3 things before you type any command:

* your Recovery Package file, for example `something.qrm`
* the same wallet account that was used when this Recovery Package was created
* the Recovery Key for that same wallet account

## Step 0. Download the official recovery tool

Before you run any recovery command, open this release page:

`https://github.com/lvbu1984/qave-recovery-cli/releases`

On macOS, look for one of these files:

* `qave-recovery-cli-darwin-arm64-v0.1.0.zip` if your Mac uses Apple Silicon
* `qave-recovery-cli-darwin-amd64-v0.1.0.zip` if your Mac uses an Intel chip

Download the zip file that matches your Mac, open it to extract the recovery tool, and then continue with the steps below.

## Step 1. Check that the Recovery Package is okay

You are doing this step only to confirm the package can be read.

### Command

```bash
./qave-recovery-cli verify /path/to/your-file.qrm
```

### Normal result

* you will see basic lines such as `schema=...` and `vault_owner=...`
* if you see `file_count=locked`, do not panic

`file_count=locked` is the normal result for an encrypted Recovery Package. It does not mean the file is broken. It means the next step is to unlock it with MetaMask.

## Step 2. Unlock the Recovery Package with MetaMask

You are doing this step to prove that you still control the correct wallet.

### Command

```bash
./qave-recovery-cli unlock /path/to/your-file.qrm --signer metamask
```

### Important

* do not remove `--signer metamask`
* this command must use MetaMask

### Normal result

* your browser opens a local Qave signing page
* the page shows a button called `Sign Challenge`
* you click `Sign Challenge` to continue
* MetaMask asks you to sign
* the terminal then shows lines such as `challenge_verified=true` and `payload_unlocked=true`

If the browser does not open by itself, look at the terminal and open the printed `sign_url=...` in your browser.

If you are still on the signing page and nothing is happening, the next action is simple: click `Sign Challenge`.

## Step 3. Start full recovery

This is the command that actually rebuilds your files and prepares the recovery zip.

### Command

```bash
./qave-recovery-cli restore-all /path/to/your-file.qrm --signer metamask
```

### Important

* do not remove `--signer metamask`
* this step asks for MetaMask again
* this step also asks for your Recovery Key

### Normal result

* the browser opens the signing page again
* you click `Sign Challenge` again
* MetaMask asks you to sign again
* the terminal then asks: `Paste recovery key (hyphens/spaces optional):`

## How to enter the Recovery Key

You can type the same Recovery Key in any of these 3 ways:

* `ABCDE-FGHJK-MNPQR-ST234`
* `ABCDE FGHJK MNPQR ST234`
* `ABCDEFGHJKMNPQRST234`

The recovery tool will automatically recognize the format. You do not need to guess which one is correct.

If the Recovery Key is wrong, the tool will say `Recovery Key incorrect. Please try again.` and ask for the key again.

If that happens, do not start over. You do not need to run `unlock` again. You do not need to sign with MetaMask again. Just enter the Recovery Key again in the same recovery session.

## Step 4. Get the recovered files

When recovery finishes normally, the terminal will show lines like these:

* `restore_all_complete=true`
* `files_restored=...`
* `zip_path=...`

The tool creates one zip file that contains your recovered files. In most cases, your browser will open automatically and start the zip download for you.

If the browser download starts, save that zip and open it to check your files.

If the browser does not start, look at the terminal output and open the file shown after `zip_path=`. That is your recovery result.

You can treat recovery as successful when all 3 of these are true:

* the terminal shows `restore_all_complete=true`
* you can find the zip file
* you can open the zip and see your recovered files inside

## Common situations

* `file_count=locked` during `verify` is normal; it means you should continue to unlock
* seeing the `Sign Challenge` page is normal; click the button to continue
* if the Recovery Key is wrong, the tool lets you type it again in the same `restore-all` session
* if the wallet in MetaMask is not the same wallet that created the Recovery Package, recovery will not continue

## The 3 things that matter most

* keep the correct `.qrm` file
* use the correct MetaMask wallet
* enter the correct Recovery Key


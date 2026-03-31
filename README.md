# qave-recovery-cli

Open-source recovery CLI for Qave recovery packages.

## What this repository provides

This repository contains the standalone recovery tool for Qave recovery packages.

It is intended to let users independently:

* inspect a recovery package
* verify package structure
* unlock wallet-bound recovery payloads
* decrypt files locally
* restore files without relying on the Qave web app

## Scope

This repository focuses on recovery and verification only.

It does **not** include:

* payment logic
* subscription logic
* backend orchestration
* internal dashboards
* provider-side operational infrastructure

## Install

Download the latest release asset from this repository’s GitHub Releases page.

On macOS, choose the archive that matches your machine:

* `qave-recovery-cli-darwin-arm64-<version>.zip`
* `qave-recovery-cli-darwin-amd64-<version>.zip`

## Quick commands

Verify a recovery package:

```bash
./qave-recovery-cli verify /path/to/your-file.qrm
```

Unlock a wallet-bound recovery package:

```bash
./qave-recovery-cli unlock /path/to/your-file.qrm --signer metamask
```

Restore all files:

```bash
./qave-recovery-cli restore-all /path/to/your-file.qrm --signer metamask
```

## User guide

For the full recovery guide and end-user instructions, see [docs/RECOVERY_GUIDE.md](docs/RECOVERY_GUIDE.md).
## Maintainers

If you are preparing an official release asset, see [RELEASING.md](RELEASING.md).


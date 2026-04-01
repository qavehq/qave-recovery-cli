# qave-recovery-cli

Open-source standalone recovery CLI for Qave Recovery Packages.

## What this repository provides

This repository contains the standalone recovery CLI for an existing Qave Recovery Package.

It is intended to let users independently:

* inspect a recovery package
* verify package structure
* unlock wallet-bound recovery payloads
* decrypt files locally
* restore files without relying on the Qave web app

## Scope

This repository covers the recovery and verification flow for an existing package only.

It does **not** include:

* package generation
* exporter / packer logic
* backend assembly logic
* recovery policy generation
* upload-side integration
* producer-side implementation

For the repository boundary in one place, see [docs/SCOPE.md](docs/SCOPE.md).
For trademark and brand-use boundaries, see [docs/TRADEMARKS.md](docs/TRADEMARKS.md).

## License / Trademark

The code in this repository is licensed under GPLv3. Copyright remains with the respective authors and contributors.

The Qave name, logo, trademarks, and brand assets are not licensed by default under the code license. Modified, forked, or redistributed versions must not imply that they are an official Qave release unless separately authorized.

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

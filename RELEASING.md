# Releasing qave-recovery-cli

This note is for maintainers only.
It is not part of the normal end-user recovery flow.

## Build release assets

From the repository root, run:

```bash
./build-release.sh
```

By default this creates:

* `dist/qave-recovery-cli-darwin-arm64-<version>.zip`
* `dist/qave-recovery-cli-darwin-arm64-<version>.zip.sha256`
* `dist/qave-recovery-cli-darwin-amd64-<version>.zip`
* `dist/qave-recovery-cli-darwin-amd64-<version>.zip.sha256`

Version naming:

* if `VERSION` is set, that value is used
* if the current commit is exactly on a git tag, that tag is used
* otherwise the script uses `v0.0.0-<git-short-sha>`

Example:

```bash
VERSION=v0.1.0 ./build-release.sh
```

## Verify locally

Pick the archive that matches your Mac, unzip it, and run:

```bash
./qave-recovery-cli --help
./qave-recovery-cli version
```

To verify the checksum:

```bash
shasum -a 256 -c qave-recovery-cli-darwin-arm64-<version>.zip.sha256
```

If `-c` is unavailable on your macOS version, use:

```bash
shasum -a 256 qave-recovery-cli-darwin-arm64-<version>.zip
cat qave-recovery-cli-darwin-arm64-<version>.zip.sha256
```

## Publish

Upload the generated `.zip` and `.sha256` files to the GitHub Releases page for this repository.

After the release is published, keep the download instructions in `README.md` aligned with the actual release assets in this repository.


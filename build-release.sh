#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
DIST_DIR="$REPO_ROOT/dist"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

resolve_version() {
  if [[ -n "${VERSION:-}" ]]; then
    printf '%s\n' "$VERSION"
    return
  fi

  if git -C "$REPO_ROOT" describe --tags --exact-match >/dev/null 2>&1; then
    git -C "$REPO_ROOT" describe --tags --exact-match
    return
  fi

  printf 'v0.0.0-%s\n' "$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
}

write_release_notes() {
  local path="$1"
  local version="$2"
  local goos="$3"
  local goarch="$4"
  cat >"$path" <<EOF
Qave Recovery Tool

Version: $version
Platform: $goos/$goarch

1. Open Terminal in this folder.
2. Run ./qave-recovery-cli --help to confirm the tool opens.
3. Then follow the official Qave recovery manual for verify, unlock, and restore-all.
EOF
}

main() {
  require_cmd go
  require_cmd zip
  require_cmd shasum
  require_cmd git

  : "${GOCACHE:=/tmp/qave-recovery-cli-go-build-cache}"
  : "${GOMODCACHE:=/tmp/qave-recovery-cli-go-mod-cache}"
  mkdir -p "$GOCACHE"
  mkdir -p "$GOMODCACHE"

  local version commit build_date
  version="$(resolve_version)"
  commit="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
  build_date="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  local -a targets
  if [[ "$#" -eq 0 ]]; then
    targets=("darwin/arm64" "darwin/amd64")
  else
    targets=("$@")
  fi

  mkdir -p "$DIST_DIR"
  find "$DIST_DIR" -mindepth 1 -maxdepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} +

  local target
  for target in "${targets[@]}"; do
    local goos goarch base_name archive_path checksum_path staging_dir binary_path notes_path ldflags
    goos="${target%/*}"
    goarch="${target#*/}"

    if [[ "$goos" != "darwin" ]]; then
      echo "Unsupported target: $target (this first release flow only packages macOS)" >&2
      exit 1
    fi

    base_name="qave-recovery-cli-${goos}-${goarch}-${version}"
    archive_path="$DIST_DIR/${base_name}.zip"
    checksum_path="${archive_path}.sha256"
    staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/qave-recovery-cli-release.XXXXXX")"
    binary_path="$staging_dir/qave-recovery-cli"
    notes_path="$staging_dir/README.txt"
    ldflags="-s -w -X main.cliVersion=${version} -X main.cliCommit=${commit} -X main.cliBuildDate=${build_date}"

    echo "Building ${base_name}..."
    (
      cd "$REPO_ROOT"
      GOCACHE="$GOCACHE" GOMODCACHE="$GOMODCACHE" GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$binary_path" .
    )

    write_release_notes "$notes_path" "$version" "$goos" "$goarch"

    (
      cd "$staging_dir"
      zip -qry "$archive_path" qave-recovery-cli README.txt
    )

    shasum -a 256 "$archive_path" >"$checksum_path"
    rm -rf "$staging_dir"

    echo "Created:"
    echo "  $archive_path"
    echo "  $checksum_path"
  done

  cat <<EOF

Release assets are ready in:
  $DIST_DIR

Next step:
  Upload the .zip and .sha256 files to the GitHub Releases page for this repository.
EOF
}

main "$@"

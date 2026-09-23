#!/usr/bin/env sh
set -eu

REPO="OloaneShark/Project_Blacklight"
API="https://api.github.com/repos/$REPO/releases?per_page=20"
INSTALL_DIR="${BLACKLIGHT_INSTALL_DIR:-$HOME/.local/bin}"

fail() {
  printf 'Project Blacklight installer: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required."

case "$(uname -s)" in
  Linux) PLATFORM="Linux" ;;
  Darwin) PLATFORM="MacOS" ;;
  *) fail "unsupported operating system: $(uname -s)" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="x64" ;;
  arm64|aarch64) ARCH="ARM64" ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

ASSET="Project-Blacklight-${PLATFORM}-${ARCH}.tar.gz"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

RELEASES="$TMP_DIR/releases.json"
curl -fsSL   -H "Accept: application/vnd.github+json"   -H "X-GitHub-Api-Version: 2022-11-28"   "$API" > "$RELEASES"

ASSET_URL="$(
  grep -o '"browser_download_url":[[:space:]]*"[^"]*"' "$RELEASES"     | sed 's/^.*"\(https:[^"]*\)"$/\1/'     | grep "/$ASSET$"     | head -n 1
)"

CHECKSUM_URL="$(
  grep -o '"browser_download_url":[[:space:]]*"[^"]*"' "$RELEASES"     | sed 's/^.*"\(https:[^"]*\)"$/\1/'     | grep '/SHA256SUMS$'     | head -n 1
)"

[ -n "$ASSET_URL" ] || fail "no published $PLATFORM $ARCH standalone asset was found."
[ -n "$CHECKSUM_URL" ] || fail "release checksum file was not found."

ARCHIVE="$TMP_DIR/$ASSET"
CHECKSUMS="$TMP_DIR/SHA256SUMS"

printf 'Downloading %s...\n' "$ASSET"
curl -fsSL "$ASSET_URL" -o "$ARCHIVE"
curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUMS"

EXPECTED="$(awk -v file="$ASSET" '$2 == file { print $1; exit }' "$CHECKSUMS")"
[ -n "$EXPECTED" ] || fail "checksum for $ASSET was not found."

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
else
  fail "sha256sum or shasum is required to verify the download."
fi

[ "$EXPECTED" = "$ACTUAL" ] || fail "SHA-256 verification failed."

mkdir -p "$TMP_DIR/extracted"
tar -xzf "$ARCHIVE" -C "$TMP_DIR/extracted"

BINARY="$(find "$TMP_DIR/extracted" -type f -name blacklight -print | head -n 1)"
[ -n "$BINARY" ] || fail "blacklight executable was not found in the archive."

mkdir -p "$INSTALL_DIR"
cp "$BINARY" "$INSTALL_DIR/blacklight"
chmod 755 "$INSTALL_DIR/blacklight"

printf '\nProject Blacklight installed to:\n  %s/blacklight\n' "$INSTALL_DIR"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    printf '\nAdd this directory to PATH to run blacklight from any terminal:\n'
    printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
    ;;
esac

"$INSTALL_DIR/blacklight" --version

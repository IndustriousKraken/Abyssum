#!/usr/bin/env bash
#
# Abyssum installer.
#
# Detects the host platform, resolves the release version, downloads both
# binaries (abyssum, abyssum-web) and their SHA-256 checksums, verifies each
# checksum, and installs the verified binaries onto PATH. Verification happens
# before anything is placed on PATH; a failure aborts without installing.
# Run with --help for usage.
set -euo pipefail

REPO="IndustriousKraken/Abyssum"
BINARIES=("abyssum" "abyssum-web")
BASE_URL="${ABYSSUM_BASE_URL:-https://github.com/${REPO}/releases/download}"
API_URL="${ABYSSUM_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
VERSION="${ABYSSUM_VERSION:-}"
USER_INSTALL=0

# Embedded (not read from $0) so --help works under `curl | bash`, where
# $0 is the shell, not this script file.
USAGE="$(cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/IndustriousKraken/Abyssum/master/install.sh | bash
  ./install.sh [--version <tag>] [--user]

Options:
  --version <tag>   install a specific release tag (default: latest)
  --user            install into ~/.local/bin instead of /usr/local/bin

Env overrides (used by the local test harness; not needed in normal use):
  ABYSSUM_VERSION   same as --version
  ABYSSUM_BASE_URL  release asset download base (…/releases/download)
  ABYSSUM_API_URL   latest-release API endpoint (returns JSON with tag_name)
EOF
)"

STEP="startup"
trap 'echo "install.sh: failed during: ${STEP}" >&2' ERR

# --- parse args ---
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
    --user) USER_INSTALL=1; shift ;;
    -h|--help) printf '%s\n' "$USAGE"; exit 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# --- detect host platform -> target triple ---
STEP="detecting host platform"
os="$(uname -s)"
arch="$(uname -m)"
triple=""
case "$os" in
  Linux)
    case "$arch" in
      x86_64|amd64)  triple="x86_64-unknown-linux-gnu" ;;
      aarch64|arm64) triple="aarch64-unknown-linux-gnu" ;;
    esac
    ;;
  Darwin)
    case "$arch" in
      arm64|aarch64) triple="aarch64-apple-darwin" ;;
    esac
    ;;
esac
if [ -z "$triple" ]; then
  echo "install.sh: no pre-built binary for ${os}/${arch}" >&2
  exit 1
fi

# --- pick a checksum verifier (sha256sum on Linux, shasum on macOS) ---
if command -v sha256sum >/dev/null 2>&1; then
  sha_verify() { sha256sum -c "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  sha_verify() { shasum -a 256 -c "$1"; }
else
  echo "install.sh: need 'sha256sum' or 'shasum' to verify downloads" >&2
  exit 1
fi

# --- resolve version (verbatim tag string; never strip/add a leading 'v') ---
STEP="resolving release version"
if [ -z "$VERSION" ]; then
  api_json="$(curl -fsSL "$API_URL")"
  VERSION="$(printf '%s' "$api_json" \
    | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | head -n1 | sed 's/.*"\([^"]*\)"$/\1/')"
  if [ -z "$VERSION" ]; then
    echo "install.sh: could not resolve latest release version from ${API_URL}" >&2
    exit 1
  fi
fi
echo "install.sh: installing Abyssum ${VERSION} for ${triple}"

# --- download both binaries and their checksums into a tempdir ---
STEP="downloading release assets"
tmp="$(mktemp -d)"
for bin in "${BINARIES[@]}"; do
  asset="${bin}-${VERSION}-${triple}"
  curl -fsSL -o "${tmp}/${asset}"        "${BASE_URL}/${VERSION}/${asset}"
  curl -fsSL -o "${tmp}/${asset}.sha256" "${BASE_URL}/${VERSION}/${asset}.sha256"
done

# --- verify every checksum BEFORE touching PATH ---
STEP="verifying checksums"
for bin in "${BINARIES[@]}"; do
  asset="${bin}-${VERSION}-${triple}"
  if ! ( cd "$tmp" && sha_verify "${asset}.sha256" ); then
    echo "install.sh: checksum verification FAILED for ${asset}" >&2
    echo "install.sh: downloads left for inspection in: ${tmp}" >&2
    exit 1
  fi
done

# --- choose install dir by privilege/mode, then install both binaries ---
STEP="selecting install directory"
if [ "$USER_INSTALL" -eq 1 ] || [ "$(id -u)" -ne 0 ]; then
  bin_dir="${HOME}/.local/bin"
else
  bin_dir="/usr/local/bin"
fi
mkdir -p "$bin_dir"

STEP="installing binaries"
for bin in "${BINARIES[@]}"; do
  asset="${bin}-${VERSION}-${triple}"
  install -m 755 "${tmp}/${asset}" "${bin_dir}/${bin}"
done

# --- warn (non-fatal) if the install dir is not on PATH ---
STEP="checking PATH"
case ":${PATH}:" in
  *":${bin_dir}:"*) ;;
  *) echo "install.sh: WARNING: ${bin_dir} is not on your PATH; add it to run 'abyssum' directly." >&2 ;;
esac

rm -rf "$tmp"
echo "install.sh: installed 'abyssum' and 'abyssum-web' to ${bin_dir}"

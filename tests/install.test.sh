#!/usr/bin/env bash
#
# Local tests for repo-root install.sh. Fully offline: release assets and the
# "latest release" API response are served from a temp fixture via file:// URLs,
# so neither the GitHub download host nor api.github.com is ever contacted.
#
# Covers:
#   - correct-triple selection + successful install on good checksums (smoke)
#   - a corrupted artifact aborts non-zero and installs nothing (negative)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="${ROOT}/install.sh"
TAG="v9.9.9-test"

fail() { echo "TEST FAIL: $1" >&2; exit 1; }

# Mirror install.sh's verifier selection so the fixture works on stock macOS
# (shasum) as well as Linux (sha256sum).
if command -v sha256sum >/dev/null 2>&1; then
  sum256() { ( cd "$1" && sha256sum "$2" > "$2.sha256" ); }
elif command -v shasum >/dev/null 2>&1; then
  sum256() { ( cd "$1" && shasum -a 256 "$2" > "$2.sha256" ); }
else
  echo "TEST SKIP: no sha256sum or shasum on host" >&2; exit 0
fi

# Mirror install.sh's host detection so the fixture asset name matches.
os="$(uname -s)"; arch="$(uname -m)"
case "${os}/${arch}" in
  Linux/x86_64|Linux/amd64)    triple="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64|Linux/arm64)   triple="aarch64-unknown-linux-gnu" ;;
  Darwin/arm64|Darwin/aarch64) triple="aarch64-apple-darwin" ;;
  *) echo "TEST SKIP: unsupported test host ${os}/${arch}"; exit 0 ;;
esac

# $1 = fixture root. Lays out latest.json + download/<tag>/<asset>{,.sha256}.
build_fixture() {
  local fix="$1" bin asset
  mkdir -p "${fix}/download/${TAG}"
  printf '{"tag_name": "%s"}\n' "$TAG" > "${fix}/latest.json"
  for bin in abyssum abyssum-web; do
    asset="${bin}-${TAG}-${triple}"
    printf 'FAKE %s binary for %s\n' "$bin" "$triple" > "${fix}/download/${TAG}/${asset}"
    sum256 "${fix}/download/${TAG}" "$asset"
  done
}

# $1 = fixture root, $2 = fake HOME. Resolves version from the mock API (no --version).
run_install() {
  ABYSSUM_BASE_URL="file://$1/download" \
  ABYSSUM_API_URL="file://$1/latest.json" \
  HOME="$2" \
  bash "$INSTALL" --user
}

# --- smoke: good checksums, version resolved from the mock API ---
smoke_fix="$(mktemp -d)"; smoke_home="$(mktemp -d)"
build_fixture "$smoke_fix"
run_install "$smoke_fix" "$smoke_home" || fail "smoke install exited non-zero"
bindir="${smoke_home}/.local/bin"
for bin in abyssum abyssum-web; do
  [ -x "${bindir}/${bin}" ] || fail "smoke: ${bin} not installed or not executable"
  grep -qF "FAKE ${bin} binary for ${triple}" "${bindir}/${bin}" \
    || fail "smoke: ${bin} content/triple mismatch (wrong triple selected?)"
done
echo "PASS: smoke install (selected ${triple}, verified good checksums, installed both binaries)"

# --- negative: a corrupted artifact must abort and install nothing ---
neg_fix="$(mktemp -d)"; neg_home="$(mktemp -d)"
build_fixture "$neg_fix"
# Tamper with one binary AFTER its checksum was computed -> checksum mismatch.
printf 'TAMPERED\n' >> "${neg_fix}/download/${TAG}/abyssum-${TAG}-${triple}"
if run_install "$neg_fix" "$neg_home" >/dev/null 2>&1; then
  fail "negative: install.sh succeeded on a corrupted artifact"
fi
neg_bindir="${neg_home}/.local/bin"
if [ -e "${neg_bindir}/abyssum" ] || [ -e "${neg_bindir}/abyssum-web" ]; then
  fail "negative: install.sh placed a binary despite verification failure"
fi
echo "PASS: negative install (corrupted artifact rejected, nothing installed)"

rm -rf "$smoke_fix" "$smoke_home" "$neg_fix" "$neg_home"
echo "ALL INSTALLER TESTS PASSED"

#!/usr/bin/env bash
#
# Abyssum installer.
#
# Downloads and verifies the prebuilt binaries (abyssum, abyssum-web) and installs
# them onto PATH. On a terminal it then offers optional setup — run as a service,
# how to expose the web UI, and a TLS reverse proxy — all self-contained (no source
# checkout needed). Piped with no flags it just installs the binaries, so the
# one-line `curl … | bash` install is unchanged.
#
#   curl -fsSL <raw>/install.sh | bash                    # binaries (+ wizard on a terminal)
#   curl -fsSL <raw>/install.sh | bash -s -- --service --proxy --site abyssum.lab
#   ./install.sh --uninstall                              # remove an install
#
# Run with --help for the full option list.
set -euo pipefail

REPO="IndustriousKraken/Abyssum"
BINARIES=("abyssum" "abyssum-web")
BASE_URL="${ABYSSUM_BASE_URL:-https://github.com/${REPO}/releases/download}"
API_URL="${ABYSSUM_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
RAW_URL="${ABYSSUM_RAW_URL:-https://raw.githubusercontent.com/${REPO}/master}"
VERSION="${ABYSSUM_VERSION:-}"
USER_INSTALL=0

# Setup selections. DO_* empty = "ask if interactive, else skip".
DO_SERVICE=""          # 1 | 0
DO_PROXY=""            # 1 | 0
PROXY_BIND="all"       # all | loopback — which addresses the PROXY serves on
ALLOW_CIDR=""
SITE=""
ASSUME_YES=0
NO_WIZARD=0
DO_UNINSTALL=0
HAVE_SETUP_FLAG=0

USAGE="$(cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/IndustriousKraken/Abyssum/master/install.sh | bash
  ./install.sh [options]

Install options:
  --version <tag>      install a specific release tag (default: latest)
  --user               install into ~/.local/bin instead of /usr/local/bin

Setup options (Linux/systemd; supplying any of these implies non-interactive setup):
  --service            run abyssum-web as a systemd service (always bound to 127.0.0.1)
  --proxy              set up a Caddy HTTPS reverse proxy (internal, self-signed CA)
  --site <host|ip>     hostname/IP for the proxy (default: this host's primary IP)
  --proxy-bind <where> all (default) | loopback — which addresses the PROXY serves on
  --allow-cidr <cidr>  restrict access to this CIDR (enforced at the proxy)

The web UI itself always stays on 127.0.0.1; network reach comes from the proxy.
  --yes, -y            accept defaults / skip confirmations
  --no-wizard          never prompt (binaries only unless setup flags are given)

Other:
  --uninstall          remove an existing install (see uninstall.sh)
  -h, --help           show this help
EOF
)"

STEP="startup"
trap 'echo "install.sh: failed during: ${STEP}" >&2' ERR

# --- parse args ---
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
    --user) USER_INSTALL=1; shift ;;
    --service) DO_SERVICE=1; HAVE_SETUP_FLAG=1; shift ;;
    --no-service) DO_SERVICE=0; HAVE_SETUP_FLAG=1; shift ;;
    --proxy) DO_PROXY=1; HAVE_SETUP_FLAG=1; shift ;;
    --no-proxy) DO_PROXY=0; HAVE_SETUP_FLAG=1; shift ;;
    --proxy-bind) PROXY_BIND="${2:?--proxy-bind needs a value}"; HAVE_SETUP_FLAG=1; shift 2 ;;
    --allow-cidr) ALLOW_CIDR="${2:?--allow-cidr needs a value}"; HAVE_SETUP_FLAG=1; shift 2 ;;
    --site) SITE="${2:?--site needs a value}"; HAVE_SETUP_FLAG=1; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --no-wizard) NO_WIZARD=1; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    -h|--help) printf '%s\n' "$USAGE"; exit 0 ;;
    *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Privilege helper for setup steps (writing /etc, systemctl, caddy).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

detect_ip() {
  ip route get 1.1.1.1 2>/dev/null \
    | awk '{for (i=1;i<=NF;i++) if ($i=="src") { print $(i+1); exit }}'
}

# --- uninstall short-circuits everything else ---
if [ "$DO_UNINSTALL" -eq 1 ]; then
  STEP="uninstalling"
  self_dir="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" 2>/dev/null && pwd || true)"
  if [ -n "$self_dir" ] && [ -f "${self_dir}/uninstall.sh" ]; then
    if [ "$ASSUME_YES" -eq 1 ]; then exec bash "${self_dir}/uninstall.sh" --yes; fi
    exec bash "${self_dir}/uninstall.sh"
  fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    curl -fsSL "${RAW_URL}/uninstall.sh" | bash -s -- --yes
  else
    curl -fsSL "${RAW_URL}/uninstall.sh" | bash
  fi
  exit $?
fi

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
rm -rf "$tmp"

# --- warn (non-fatal) if the install dir is not on PATH ---
STEP="checking PATH"
case ":${PATH}:" in
  *":${bin_dir}:"*) ;;
  *) echo "install.sh: WARNING: ${bin_dir} is not on your PATH; add it to run 'abyssum' directly." >&2 ;;
esac
echo "install.sh: installed 'abyssum' and 'abyssum-web' to ${bin_dir}"

# ============================ optional guided setup =========================

ask() {  # ask "prompt" "Y|N default" -> 0 for yes, 1 for no
  local prompt="$1" def="$2" ans
  if [ "$ASSUME_YES" -eq 1 ]; then [ "$def" = "Y" ]; return; fi
  printf '%s ' "$prompt" > /dev/tty
  read -r ans < /dev/tty || ans=""
  [ -n "$ans" ] || ans="$def"
  case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

run_wizard() {
  echo
  echo "Optional setup (press Enter for the default):"
  if ask "  Run abyssum-web as a systemd service? [Y/n]" "Y"; then DO_SERVICE=1; else DO_SERVICE=0; fi

  # The web UI always stays on 127.0.0.1. The only network question is what the
  # PROXY serves to, so it is asked solely when the proxy is chosen.
  local d; d="$(detect_ip)"
  if ask "  Make it reachable from other machines (Caddy HTTPS reverse proxy)? [y/N]" "N"; then
    DO_PROXY=1
    printf '  Site hostname or IP for HTTPS [%s]: ' "$d" > /dev/tty
    local s; read -r s < /dev/tty || s=""
    SITE="${s:-$d}"

    printf '  Serve it on [1] all addresses (default) [2] loopback only (for an SSH tunnel): ' > /dev/tty
    local choice; read -r choice < /dev/tty || choice=""
    case "${choice:-1}" in
      2) PROXY_BIND="loopback" ;;
      *) PROXY_BIND="all" ;;
    esac

    printf '  Restrict access to a CIDR (blank for no restriction): ' > /dev/tty
    local c; read -r c < /dev/tty || c=""
    ALLOW_CIDR="$c"
    echo "  -> the app stays on 127.0.0.1; Caddy serves it over HTTPS."
  else
    DO_PROXY=0
    echo "  -> the web UI will be reachable only from this host (127.0.0.1)."
  fi
}

setup_service() {
  STEP="installing systemd service"
  command -v systemctl >/dev/null 2>&1 || { echo "install.sh: systemd not found; skipping service." >&2; return 0; }
  local runuser bin unit protecthome
  runuser="${SUDO_USER:-$(id -un)}"
  bin="${bin_dir}/abyssum-web"
  unit="/etc/systemd/system/abyssum-web.service"
  case "$bin" in /home/*) protecthome="read-only" ;; *) protecthome="true" ;; esac
  # Deliberately no ABYSSUM_SERVER_HOST: the web surface keeps its loopback default.
  # Network reach comes from the reverse proxy, never from binding the app out.
  $SUDO tee "$unit" >/dev/null <<EOF
[Unit]
Description=Abyssum web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${runuser}
ExecStart=${bin}
Environment=ABYSSUM_DATABASE_PATH=/var/lib/abyssum/abyssum.db
StateDirectory=abyssum
Restart=on-failure
RestartSec=5
ProtectHome=${protecthome}
ProtectSystem=strict
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now abyssum-web
  echo "install.sh: abyssum-web service installed and started (User=${runuser}, bound to 127.0.0.1)."
}

setup_proxy() {
  STEP="setting up Caddy reverse proxy"
  if ! command -v caddy >/dev/null 2>&1; then
    echo "install.sh: 'caddy' not found — install it (https://caddyserver.com/docs/install), then re-run with --proxy." >&2
    return 0
  fi
  [ -n "$SITE" ] || SITE="$(detect_ip)"
  [ -n "$SITE" ] || { echo "install.sh: could not determine a site; pass --site <host-or-ip>." >&2; return 0; }

  local body
  if [ -n "$ALLOW_CIDR" ]; then
    body="$(printf '    @allowed remote_ip %s\n    handle @allowed {\n        reverse_proxy 127.0.0.1:8000\n    }\n    respond 403' "$ALLOW_CIDR")"
  else
    body="    reverse_proxy 127.0.0.1:8000"
  fi
  # --proxy-bind loopback keeps the proxy itself off the network (SSH-tunnel use).
  local generated
  generated="# abyssum-managed (install.sh) — safe to remove via uninstall.sh
https://${SITE} {"
  if [ "$PROXY_BIND" = "loopback" ]; then
    generated="${generated}
    bind 127.0.0.1"
  fi
  generated="${generated}
    tls internal
    encode zstd gzip
    header -Server
${body}
}"

  local cf=/etc/caddy/Caddyfile
  $SUDO mkdir -p /etc/caddy
  if [ -f "$cf" ] && ! $SUDO grep -q 'abyssum-managed' "$cf" 2>/dev/null; then
    # A hand-written Caddyfile already fronts abyssum-web — leave it as-is.
    if $SUDO grep -q '127.0.0.1:8000' "$cf" 2>/dev/null; then
      echo "install.sh: /etc/caddy/Caddyfile already proxies abyssum-web (127.0.0.1:8000); leaving it as-is."
      $SUDO systemctl reload caddy >/dev/null 2>&1 || true
      return 0
    fi
    # Otherwise don't clobber it: drop a sibling and tell the operator to import it.
    printf '%s\n' "$generated" | $SUDO tee /etc/caddy/abyssum.caddyfile >/dev/null
    echo "install.sh: your /etc/caddy/Caddyfile was left intact; wrote /etc/caddy/abyssum.caddyfile." >&2
    echo "install.sh: to activate the proxy, add this line to /etc/caddy/Caddyfile and reload caddy:" >&2
    echo "    import abyssum.caddyfile" >&2
    return 0
  fi
  printf '%s\n' "$generated" | $SUDO tee "$cf" >/dev/null
  $SUDO caddy validate --adapter caddyfile --config "$cf" \
    || { echo "install.sh: generated Caddyfile failed validation." >&2; return 1; }
  if $SUDO systemctl list-unit-files caddy.service >/dev/null 2>&1; then
    $SUDO systemctl reload caddy 2>/dev/null || $SUDO systemctl restart caddy
  fi
  # Announce this: it modifies the host's system trust store, and the uninstaller's
  # closing note refers back to it.
  if $SUDO caddy trust >/dev/null 2>&1; then
    echo "install.sh: added Caddy's local certificate authority to this host's trust store."
    echo "install.sh: other machines need that CA imported — see docs/deploy/CADDY.md."
  else
    echo "install.sh: could not add Caddy's CA to the trust store; browsers will warn until you run 'sudo caddy trust'." >&2
  fi
  echo "install.sh: Caddy proxy configured for https://${SITE}/ (internal CA)."
}

# Decide whether to run setup: explicit flags, else an interactive terminal.
run_setup=0
if [ "$HAVE_SETUP_FLAG" -eq 1 ]; then
  run_setup=1
elif [ "$NO_WIZARD" -eq 0 ] && [ -r /dev/tty ] && { [ -t 0 ] || [ -t 1 ]; }; then
  if [ "$os" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
    run_wizard
    run_setup=1
  fi
fi

if [ "$run_setup" -eq 1 ]; then
  if [ "$os" != "Linux" ]; then
    echo "install.sh: service/proxy setup is Linux/systemd only; skipping." >&2
  else
    # The web surface is always on loopback; the proxy carries all network reach.
    [ "${DO_SERVICE:-0}" = "1" ] && setup_service
    [ "${DO_PROXY:-0}" = "1" ] && setup_proxy
  fi
fi

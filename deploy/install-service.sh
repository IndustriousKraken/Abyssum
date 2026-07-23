#!/usr/bin/env bash
#
# Install and enable abyssum-web as a systemd service.
#
# Writes /etc/systemd/system/abyssum-web.service from the deploy/abyssum-web.service
# template (fetched from GitHub when this script is run outside a checkout), filling
# in the account to run as, the installed binary path, and the home-protection mode;
# then reloads systemd and enables the service.
#
# Run with sudo. Linux / systemd only. Install the binaries first (./install.sh).
#
#   sudo deploy/install-service.sh                 # run as the invoking user
#   sudo deploy/install-service.sh --host 0.0.0.0  # + expose directly on the LAN
#   curl -fsSL https://raw.githubusercontent.com/IndustriousKraken/Abyssum/master/deploy/install-service.sh | sudo bash
#
set -euo pipefail

REPO="IndustriousKraken/Abyssum"
TEMPLATE_URL="https://raw.githubusercontent.com/${REPO}/master/deploy/abyssum-web.service"
UNIT_DST="/etc/systemd/system/abyssum-web.service"

RUN_USER="${SUDO_USER:-}"
BIN=""
HOST=""

USAGE="$(cat <<'EOF'
Usage: sudo deploy/install-service.sh [--user <name>] [--bin <path>] [--host 0.0.0.0]

  --user <name>   account to run the service as (default: the sudo-invoking user)
  --bin <path>    path to abyssum-web (default: autodetect in the user's ~/.local/bin
                  or /usr/local/bin)
  --host 0.0.0.0  bind directly on the LAN (unencrypted); default is 127.0.0.1, i.e.
                  behind a Caddy TLS proxy (see docs/deploy/CADDY.md)
  -h, --help      show this help
EOF
)"

STEP="startup"
trap 'echo "install-service.sh: failed during: ${STEP}" >&2' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --user) RUN_USER="${2:?--user needs a value}"; shift 2 ;;
    --bin)  BIN="${2:?--bin needs a value}"; shift 2 ;;
    --host) HOST="${2:?--host needs a value}"; shift 2 ;;
    -h|--help) printf '%s\n' "$USAGE"; exit 0 ;;
    *) echo "install-service.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

STEP="checking privileges"
[ "$(id -u)" -eq 0 ] || { echo "install-service.sh: run with sudo (it writes ${UNIT_DST})." >&2; exit 1; }

STEP="checking for systemd"
command -v systemctl >/dev/null 2>&1 || { echo "install-service.sh: systemd not found (Linux/systemd only)." >&2; exit 1; }

STEP="resolving the run-as user"
[ -n "$RUN_USER" ] || { echo "install-service.sh: could not determine the user; pass --user <name>." >&2; exit 1; }
home="$(getent passwd "$RUN_USER" | cut -d: -f6)"
[ -n "$home" ] || { echo "install-service.sh: no such user: ${RUN_USER}" >&2; exit 1; }
group="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"

STEP="locating the abyssum-web binary"
if [ -z "$BIN" ]; then
  for c in "${home}/.local/bin/abyssum-web" /usr/local/bin/abyssum-web; do
    if [ -x "$c" ]; then BIN="$c"; break; fi
  done
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || {
  echo "install-service.sh: abyssum-web not found; run ./install.sh first, or pass --bin <path>." >&2
  exit 1
}

# A binary read from a home directory needs ProtectHome relaxed so systemd can exec it.
case "$BIN" in
  /home/*|"${home}"/*) protect_home="read-only" ;;
  *) protect_home="true" ;;
esac

STEP="obtaining the unit template"
self_dir="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")" 2>/dev/null && pwd || true)"
if [ -n "$self_dir" ] && [ -f "${self_dir}/abyssum-web.service" ]; then
  tmpl="${self_dir}/abyssum-web.service"
else
  tmpl="$(mktemp)"
  curl -fsSL -o "$tmpl" "$TEMPLATE_URL"
fi

STEP="writing ${UNIT_DST}"
sed \
  -e "s|^User=.*|User=${RUN_USER}|" \
  -e "s|^Group=.*|Group=${group}|" \
  -e "s|^ExecStart=.*|ExecStart=${BIN}|" \
  -e "s|^ProtectHome=.*|ProtectHome=${protect_home}|" \
  "$tmpl" > "$UNIT_DST"
if [ "$HOST" = "0.0.0.0" ]; then
  sed -i 's|^# *Environment=ABYSSUM_SERVER_HOST=0.0.0.0|Environment=ABYSSUM_SERVER_HOST=0.0.0.0|' "$UNIT_DST"
fi

STEP="enabling the service"
systemctl daemon-reload
systemctl enable --now abyssum-web

echo
echo "Installed and started abyssum-web (User=${RUN_USER}, ExecStart=${BIN})."
echo "  status:  systemctl status abyssum-web"
echo "  logs:    journalctl -u abyssum-web -f"
echo "  update:  ./install.sh && sudo systemctl restart abyssum-web"

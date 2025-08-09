#!/usr/bin/env bash
set -euo pipefail

# shellrest-go installer (curl | bash friendly)
# - Builds the binary using Docker (no Go toolchain required)
# - Installs to ~/.local/bin
# - Writes default config to ~/.config/shellrest/sshrest.conf if missing
# - Optional: --start to run in background (nohup) without systemd
#
# Usage:
#   curl -fsSL <RAW_URL>/scripts/install.sh | bash -s -- [--start] [--listen :8080] [--auth-keys /path/to/authorized_keys]
#
# Notes:
# - Requires Docker installed and running.
# - If --auth-keys is provided and file exists, it will be set in config; otherwise keep default /etc/ssh/authorized_keys.

START=0
CUSTOM_LISTEN=""
CUSTOM_KEYS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --start) START=1; shift ;;
    --listen) CUSTOM_LISTEN=${2:-}; shift 2 ;;
    --auth-keys) CUSTOM_KEYS=${2:-}; shift 2 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

BIN_NAME="shellrest-go"
PREFIX="${HOME}/.local/bin"
CFG_DIR="${HOME}/.config/shellrest"
CFG_PATH="${CFG_DIR}/sshrest.conf"
DATA_DIR="${HOME}/.local/share/shellrest"
LOG_DIR="${DATA_DIR}/logs"
RUN_DIR="${DATA_DIR}/run"
PID_FILE="${RUN_DIR}/${BIN_NAME}.pid"

mkdir -p "$PREFIX" "$CFG_DIR" "$LOG_DIR" "$RUN_DIR"

# Build image and extract binary
echo "[install] Building image..." >&2
DOCKER_BUILDKIT=1 docker build -t ${BIN_NAME}:installer .
CID=$(docker create ${BIN_NAME}:installer)
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT

echo "[install] Extracting binary..." >&2
docker cp "$CID":/shellrest-go "${PREFIX}/${BIN_NAME}"
chmod +x "${PREFIX}/${BIN_NAME}"

echo "[install] Writing config if missing..." >&2
if [[ ! -f "$CFG_PATH" ]]; then
  cat >"$CFG_PATH" <<EOF
# shellrest-go config
SRG_LISTEN_ADDR=${CUSTOM_LISTEN:-:8080}
SRG_AUTH_KEYS_PATH=${CUSTOM_KEYS:-/etc/ssh/authorized_keys}
SRG_EXEC_TIMEOUT=120s
EOF
  echo "[install] Config written at $CFG_PATH" >&2
else
  echo "[install] Config exists at $CFG_PATH (not overwritten)" >&2
fi

echo "[install] Installed ${BIN_NAME} to ${PREFIX}" >&2

if [[ "$START" -eq 1 ]]; then
  echo "[install] Starting in background (nohup) ..." >&2
  # Stop existing if running
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[install] Stopping existing process PID $(cat "$PID_FILE")" >&2
    kill "$(cat "$PID_FILE")" || true
    sleep 0.5 || true
  fi
  nohup "${PREFIX}/${BIN_NAME}" --config "$CFG_PATH" >"${LOG_DIR}/stdout.log" 2>"${LOG_DIR}/stderr.log" &
  echo $! >"$PID_FILE"
  echo "[install] Started PID $(cat "$PID_FILE")" >&2
  echo "[install] Logs: $LOG_DIR" >&2
fi

echo "[install] Done." >&2

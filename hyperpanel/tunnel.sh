#!/usr/bin/env bash
# tunnel.sh — Cloudflare Quick Tunnel for Linux/macOS
# Location: /home/user/HyperSlot/hyperpanel/tunnel.sh
#
# Usage:
#   ./tunnel.sh              # tunnel to localhost:8080
#   ./tunnel.sh 9090         # tunnel to localhost:9090

set -euo pipefail

PORT="${1:-8080}"
LOG_FILE="${TUNNEL_LOG:-tunnel.log}"

if ! command -v cloudflared >/dev/null 2>&1; then
    echo "[TUNNEL] ❌ cloudflared not installed" >&2
    echo "[TUNNEL] Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/" >&2
    exit 1
fi

echo "[TUNNEL] Starting Cloudflare tunnel to http://localhost:$PORT"
echo "[TUNNEL] Log: $LOG_FILE"

exec cloudflared tunnel \
    --url "http://localhost:$PORT" \
    --no-autoupdate 2>&1 | tee "$LOG_FILE"
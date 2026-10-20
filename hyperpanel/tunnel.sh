#!/usr/bin/env bash
# tunnel.sh — Cloudflare Quick Tunnel for Linux/macOS
# Location: /home/user/HyperSlot/hyperpanel/tunnel.sh

set -euo pipefail

PORT="${1:-8080}"
LOG_FILE="${TUNNEL_LOG:-tunnel.log}"

# ── ১. cloudflared না থাকলে অটো-ডাউনলোড করুন ──
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "[TUNNEL] ⏳ cloudflared not found, downloading to /tmp..."
    
    # OS এবং Architecture ডিটেক্ট করুন
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo "[TUNNEL] ❌ Unsupported arch: $ARCH" >&2; exit 1 ;;
    esac

    URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-${OS}-${ARCH}"
    
    if ! curl -fsSL "$URL" -o /tmp/cloudflared; then
        echo "[TUNNEL] ❌ Failed to download cloudflared from $URL" >&2
        exit 1
    fi

    chmod +x /tmp/cloudflared
    export PATH="/tmp:$PATH"
    echo "[TUNNEL] ✅ cloudflared installed at /tmp/cloudflared"
fi

echo "[TUNNEL] 🚀 Starting Cloudflare tunnel to http://localhost:$PORT"
echo "[TUNNEL] 📝 Log: $LOG_FILE"

# ── ২. টানেল চালু করুন ──
exec cloudflared tunnel \
    --url "http://localhost:$PORT" \
    --no-autoupdate 2>&1 | tee "$LOG_FILE"
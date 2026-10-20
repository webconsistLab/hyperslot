#!/usr/bin/env bash
# start.sh — Parent launcher for Linux/macOS

set -euo pipefail

SOURCE="${1:-}"
if [[ -z "$SOURCE" ]]; then
    echo "usage: $0 source-url-or-file [--max-wait 30m] [--keep-infra]" >&2
    exit 2
fi
shift

# Defaults
EXTRACTOR_LISTEN="127.0.0.1:1111"
LOCAL_POOL_PORT="2222"
PANEL_PORT="8080"
MAX_WAIT="30m"
KEEP_INFRA=""

# Parse flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --listen)       EXTRACTOR_LISTEN="$2"; shift 2 ;;
        --pool-port)    LOCAL_POOL_PORT="$2"; shift 2 ;;
        --panel-port)   PANEL_PORT="$2"; shift 2 ;;
        --max-wait)     MAX_WAIT="$2"; shift 2 ;;
        --keep-infra)   KEEP_INFRA="-keep-infra"; shift ;;
        *) echo "unknown flag $1" >&2; exit 2 ;;
    esac
done

# Resolve script directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACTOR_DIR="$ROOT_DIR/oee"
PANEL_DIR="$ROOT_DIR/hyperpanel"
POOL_DIR="$ROOT_DIR/local-pool"

# Verify
for d in "$EXTRACTOR_DIR" "$PANEL_DIR" "$POOL_DIR"; do
    if [[ ! -d "$d" ]]; then
        echo "[LAUNCHER] ❌ Not found: $d" >&2
        exit 1
    fi
done

echo "═══════════════════════════════════════════════════════════"
echo " 🚀 HyperSlot Parallel Launch (Linux)"
echo "═══════════════════════════════════════════════════════════"
echo " Root         : $ROOT_DIR"
echo " Extractor    : $EXTRACTOR_DIR"
echo " Local Pool   : $POOL_DIR"
echo " Panel        : $PANEL_DIR"
echo " Source       : $SOURCE"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[LAUNCHER] Shutting down..."
    
    if [[ -n "${EXTRACTOR_PID:-}" ]]; then
        kill "$EXTRACTOR_PID" 2>/dev/null || true
    fi
    if [[ -n "${POOL_PID:-}" ]]; then
        kill "$POOL_PID" 2>/dev/null || true
    fi
    
    wait 2>/dev/null || true
    echo "[LAUNCHER] Done."
}
trap cleanup EXIT INT TERM

# 1. Extractor
echo "[LAUNCHER] Starting extractor (oee)..."
(
    cd "$EXTRACTOR_DIR"
    go run . -source "$SOURCE" -listen "$EXTRACTOR_LISTEN" -max-wait "$MAX_WAIT" $KEEP_INFRA
) > "$ROOT_DIR/extractor.log" 2> "$ROOT_DIR/extractor.err.log" &

EXTRACTOR_PID=$!
echo "[LAUNCHER] ✅ Extractor PID: $EXTRACTOR_PID"

# 2. Local Pool
echo "[LAUNCHER] Starting local-pool on $LOCAL_POOL_PORT..."
(
    cd "$POOL_DIR"
    go run .
) > "$ROOT_DIR/pool.log" 2> "$ROOT_DIR/pool.err.log" &

POOL_PID=$!
echo "[LAUNCHER] ✅ Local Pool PID: $POOL_PID"

sleep 2

# 3. Hyper Panel
echo "[LAUNCHER] Starting hyper-panel..."
echo ""
echo "[LAUNCHER] 🚀 All running. Press Ctrl+C to stop all."
echo ""

cd "$PANEL_DIR"
export EXTRACTOR_URL="http://$EXTRACTOR_LISTEN"

go run . -port ":$PANEL_PORT"
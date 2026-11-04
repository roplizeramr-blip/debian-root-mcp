#!/usr/bin/env bash
set -Eeuo pipefail

: "${MCP_BASE_URL:?MCP_BASE_URL is required}"
: "${MCP_ADMIN_USERNAME:?MCP_ADMIN_USERNAME is required}"
: "${MCP_ADMIN_PASSWORD_HASH:?MCP_ADMIN_PASSWORD_HASH is required}"
: "${MCP_JWT_SECRET:?MCP_JWT_SECRET is required}"

export NOVNC_PORT=6902
cd /opt/debian-root-mcp

/opt/debian-root-mcp/.venv/bin/python /opt/debian-root-mcp/server.py &
MCP_PID=$!

nginx

RADIUS_PID=""
if [[ -n "${RADIUS_API_URL:-}" && -n "${RADIUS_API_KEY:-}" ]]; then
    if /opt/debian-root-mcp/.venv/bin/python /opt/debian-root-mcp/configure_radius.py && freeradius -XC; then
        freeradius -f &
        RADIUS_PID=$!
        echo "FreeRADIUS started with Supabase-backed REST authentication."
    else
        echo "FreeRADIUS configuration failed; web panel and MCP remain available." >&2
    fi
else
    echo "RADIUS_API_URL/RADIUS_API_KEY not configured; FreeRADIUS remains disabled."
fi

/dockerstartup/startup.sh &
DESKTOP_PID=$!

PIDS=("$MCP_PID" "$DESKTOP_PID")
if [[ -n "$RADIUS_PID" ]]; then
    PIDS+=("$RADIUS_PID")
fi

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

set +e
wait -n "${PIDS[@]}"
STATUS=$?
set -e
exit "$STATUS"

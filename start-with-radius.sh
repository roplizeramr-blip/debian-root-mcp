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

# Portwarp login and daemon state are stored on the persistent root volume.
# Use the same profile for initial login and every automatic reconnect.
PORTWARP_HOME="${PORTWARP_HOME:-/root}"
if command -v pwrp >/dev/null 2>&1 && [[ -n "$RADIUS_PID" ]]; then
    if [[ -r "${PORTWARP_HOME}/.portwarp/credentials.json" ]]; then
        if (
            export HOME="$PORTWARP_HOME"
            export XDG_CONFIG_HOME="${PORTWARP_HOME}/.config"
            pwrp connect --all --save --detach
        ); then
            echo "Portwarp tunnel reconnect requested using the persistent root profile."
        else
            echo "Portwarp could not reconnect; dashboard and FreeRADIUS remain available." >&2
        fi
    else
        echo "Portwarp login not found under ${PORTWARP_HOME}; authenticate with HOME=/root XDG_CONFIG_HOME=/root/.config pwrp login." >&2
    fi
fi

/dockerstartup/startup.sh &
DESKTOP_PID=$!

cleanup() {
    for pid in "${MCP_PID:-}" "${RADIUS_PID:-}" "${DESKTOP_PID:-}"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}

trap cleanup EXIT INT TERM

# MCP is the required long-running process. Desktop startup helpers may exit
# after daemonizing their services; FreeRADIUS must not take down MCP if it
# encounters a later network/API failure.
set +e
wait "$MCP_PID"
STATUS=$?
set -e
exit "$STATUS"

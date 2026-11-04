#!/usr/bin/env bash
set -euo pipefail

: "${MCP_BASE_URL:?MCP_BASE_URL is required}"
: "${MCP_ADMIN_USERNAME:?MCP_ADMIN_USERNAME is required}"
: "${MCP_ADMIN_PASSWORD_HASH:?MCP_ADMIN_PASSWORD_HASH is required}"
: "${MCP_JWT_SECRET:?MCP_JWT_SECRET is required}"

export NOVNC_PORT=6902
cd /opt/debian-root-mcp

/opt/debian-root-mcp/.venv/bin/python /opt/debian-root-mcp/server.py &
MCP_PID=$!

if [ -n "${SUPABASE_DATABASE_URL:-}" ]; then
    /opt/debian-root-mcp/.venv/bin/python /opt/debian-root-mcp/configure_radius.py
    freeradius -XC
    freeradius -f &
else
    echo "SUPABASE_DATABASE_URL is not configured; FreeRADIUS will stay disabled."
fi

nginx
exec /dockerstartup/startup.sh

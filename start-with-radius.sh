#!/usr/bin/env bash
set -euo pipefail
if [ -z "$SUPABASE_PROJECT_URL" ]; then echo "SUPABASE_PROJECT_URL required" >&2; exit 1; fi
if [ -z "$MCP_BASE_URL" ]; then echo "MCP_BASE_URL required" >&2; exit 1; fi
if [ -z "$SUPABASE_JWT_ALGORITHM" ]; then export SUPABASE_JWT_ALGORITHM=ES256; fi
export NOVNC_PORT=6902
cd /opt/debian-root-mcp
/opt/debian-root-mcp/.venv/bin/python /opt/debian-root-mcp/server.py &
if command -v freeradius >/dev/null 2>&1; then freeradius -f & fi
nginx
exec /dockerstartup/startup.sh

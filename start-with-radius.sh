#!/usr/bin/env bash
set -euo pipefail

: "${MCP_AUTH_TOKEN:?MCP_AUTH_TOKEN must be configured as a secret (minimum 32 characters)}"
if [ "${#MCP_AUTH_TOKEN}" -lt 32 ]; then
  echo "MCP_AUTH_TOKEN must contain at least 32 characters" >&2
  exit 1
fi

export NOVNC_PORT=6902

# Start the authenticated MCP endpoint as container root.
/opt/debian-root-mcp/.venv/bin/uvicorn server:app \
  --app-dir /opt/debian-root-mcp --host 127.0.0.1 --port 8765 \
  --proxy-headers --forwarded-allow-ips 127.0.0.1 &

# Start FreeRADIUS in foreground mode in the background.
if command -v freeradius >/dev/null 2>&1; then
  freeradius -f &
fi

# nginx exposes MCP on /mcp and forwards all other paths to noVNC.
nginx

# Preserve the upstream Accetto desktop/VNC startup.
exec /dockerstartup/startup.sh

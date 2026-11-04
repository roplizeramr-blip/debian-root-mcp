# Debian Root MCP

Authenticated MCP server for managing the Debian container that also hosts noVNC and FreeRADIUS.

## Features
- MCP over Streamable HTTP at `/mcp`
- Mandatory Bearer-token authentication (no default credentials)
- Root-level shell, file, package, service and system inspection tools
- Existing noVNC web UI remains available at `/`
- FreeRADIUS + PostgreSQL driver installed in the image

## Required environment variable
Set `MCP_AUTH_TOKEN` to a cryptographically random secret of at least 32 characters in the deployment platform's secret/environment settings. Never commit it or put it in browser code.

## MCP connection
- URL: `https://YOUR-APP-DOMAIN/mcp`
- Transport: Streamable HTTP
- Header: `Authorization: Bearer YOUR_MCP_AUTH_TOKEN`

The `/health` endpoint is intentionally unauthenticated and exposes only a basic liveness response. All MCP requests require the bearer token.

## Docker
```sh
docker build -t debian-root-mcp .
docker run --rm -p 6901:6901 -e MCP_AUTH_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" debian-root-mcp
```

## Security
This server intentionally exposes a root command-execution tool. Anyone holding the bearer token can fully control the container. Use a unique secret, store it only as a platform secret, rotate it if exposed, and do not reuse it elsewhere. Container root is not automatically host root; Docker socket access is not mounted by this project.

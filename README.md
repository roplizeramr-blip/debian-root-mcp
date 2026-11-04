# Debian noVNC + Root MCP

Self-hosted OAuth 2.1 authorization server and MCP resource server running inside the existing Debian/noVNC container. No Supabase, external identity provider, static bearer token, or Docker socket is required.

## Endpoints

- MCP Streamable HTTP transport: `https://YOUR-APP-DOMAIN/mcp`
- Canonical OAuth resource identifier (RFC 8707): `https://YOUR-APP-DOMAIN/` (normalized origin, with a trailing slash and no `/mcp` suffix; this exactly matches the published resource metadata)
- Protected resource metadata: `/.well-known/oauth-protected-resource` (root discovery path; the document's `resource` is the origin above)
- OAuth authorization server metadata: `/.well-known/oauth-authorization-server`
- Protected resource metadata: `/.well-known/oauth-protected-resource/mcp`
- Authorization endpoint: `/authorize`
- Token endpoint: `/token`
- Consent screen: `/oauth/consent` (opened automatically during OAuth; a direct visit without a pending transaction is expected to expire)
- noVNC remains at `/`

## Authentication

- OAuth 2.1 Authorization Code grant with PKCE S256.
- ChatGPT Client ID Metadata Documents (CIMD); client metadata is fetched from an allowlisted `chatgpt.com` URL.
- The token endpoint supports `private_key_jwt` and public-client `none` authentication.
- Access tokens are signed JWTs with an exact issuer, canonical origin audience, client ID, subject, scope, expiry, and token ID. The bearer middleware publishes the corresponding `WWW-Authenticate` resource-metadata challenge.
- Required scope: `debian.root`. Refresh tokens are issued for reconnects.
- Consent requires a separate Debian MCP administrator account. This account is not the Linux root password.

## Required environment variables

Configure these through the hosting platform's secret/environment settings. Never commit credentials:

- `MCP_BASE_URL=https://YOUR-APP-DOMAIN`
- `MCP_ADMIN_USERNAME`
- `MCP_ADMIN_PASSWORD_HASH`: PBKDF2-SHA256 encoded value in the form `pbkdf2_sha256$iterations$salt_hex$digest_hex`
- `MCP_JWT_SECRET`: random secret of at least 64 characters

The raw administrator password is used only at the consent form and is not stored by the app; only its PBKDF2 hash is stored in the environment.

## MCP tools

- `system_overview`: Debian version, kernel, uptime, memory, storage, hostname, and active users.
- `root_shell`: run a Bash command as root inside the Debian container. The first call returns a preview; execution requires `confirm_execution=true`.
- `root_read_file`: read regular files inside the container as root.
- `root_write_file`: atomically write files inside the container as root. The first call previews the change; commit requires `confirm_write=true`. Existing files receive a one-time `.mcp.bak` backup.
- `root_list_directory`: list directories and optional descendants.
- `service_control`: systemd service start/stop/restart/reload/enable/disable/status.
- `read_service_logs`: read a service's recent journal logs.

These privileges apply to the Debian container only, not the hosting provider's underlying host.

## Audit and operation

Metadata-only audit events are written to `/var/log/debian-root-mcp/audit.jsonl`. Passwords, bearer tokens, and file contents are not written to the audit log. MCP listens on loopback port 8765 behind Nginx on port 6901; noVNC remains on its original internal port 6902.

The MCP server uses in-memory authorization transactions and revocation state. A container redeploy or restart may require the user to authorize again; do not assume in-memory revocation state survives a restart.

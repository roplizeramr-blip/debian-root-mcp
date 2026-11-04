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


## RADIUS administration panel

The web dashboard is served at `/radius/` on the same HTTPS app domain. It reuses the MCP administrator username and PBKDF2 password hash for login, then provides subscriber, plan, NAS, session, and authentication-log screens.

### Supabase PostgreSQL

Create/use the private `radius` schema in Supabase and a dedicated login role named `radius_runtime`. The application reads a full PostgreSQL URI from the CranL environment variable `SUPABASE_DATABASE_URL`. Use the Supabase **Connect → Session pooler** URI (port **5432**, not transaction mode), and the custom-role username format `radius_runtime.<project-ref>`. The URI must include TLS; the app enforces `sslmode=require`. Do not commit this URI to Git or paste it into logs.

The startup configurator enables FreeRADIUS SQL authorization/accounting and reads NAS clients from the `radius.nas` table. New NAS client entries are loaded when FreeRADIUS starts, so restart/redeploy after changing NAS clients. PAP/CHAP passwords are not written into `radpostauth`.

### Runtime limits and networking

The panel and FreeRADIUS SQL pools are tuned for a small container (one to three PostgreSQL connections for the panel and up to three for FreeRADIUS). The container image declares RADIUS UDP ports 1812/1813, but Docker `EXPOSE` alone does not publish them; the hosting platform must provide public UDP ingress before external MikroTik/NAS devices can reach this instance. Until then, use local `radtest` checks only and do not point production NAS devices at the public HTTP URL.

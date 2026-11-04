# Debian noVNC + FreeRADIUS MCP

OAuth-protected MCP administration for the existing Debian/noVNC container.

## Authentication
- Supabase Auth is the OAuth 2.1 authorization server.
- FastMCP SupabaseProvider verifies Supabase JWTs and publishes MCP protected-resource metadata.
- Authorization Code + PKCE and refresh tokens are handled by Supabase Auth.
- Consent UI: `/oauth/callback`. No static MCP bearer token is used.

## Required environment
- `SUPABASE_PROJECT_URL=https://wloqbuigxcbcxprmnyjq.supabase.co`
- `MCP_BASE_URL=https://YOUR-APP-DOMAIN`
- `SUPABASE_JWT_ALGORITHM=ES256` (must match Supabase Auth signing key)

The publishable key is public and embedded in `oauth-consent.html`. Never put a Supabase secret/service-role key in browser code.

## Supabase Dashboard setup
1. Authentication → OAuth Server → enable OAuth Server.
2. Enable Dynamic OAuth Apps / Dynamic Client Registration.
3. Set Site URL to `https://YOUR-APP-DOMAIN`.
4. Set Authorization Path to `/oauth/callback`.
5. Use an asymmetric JWT signing key (ES256 or RS256) and set the matching algorithm.
6. Create the owner account under Authentication → Users, then disable public sign-ups. Consent UI supports sign-in only.
7. Verify discovery at `https://wloqbuigxcbcxprmnyjq.supabase.co/.well-known/oauth-authorization-server/auth/v1`.

## MCP endpoint
`https://YOUR-APP-DOMAIN/mcp`. Add as a custom MCP server in ChatGPT and choose OAuth.

## Tools
- `system_overview`
- `service_status`, `service_control` (FreeRADIUS and Nginx only)
- `freeradius_config_test`, `nginx_config_test`
- `list_config_files`, `read_config_file`, `write_config_file`
- `read_service_logs`

Writes are limited to .conf files in `/etc/freeradius/3.0` and `/etc/nginx/conf.d`, atomic, size-limited and backed up once. There is no arbitrary shell execution, unrestricted file write, or Docker socket access.

Audit records contain metadata only at `/var/log/debian-root-mcp/audit.jsonl`; tokens and config contents are never logged.

noVNC remains at `/`; MCP uses `/mcp`; OAuth consent uses `/oauth/callback`. Nginx listens on 6901.

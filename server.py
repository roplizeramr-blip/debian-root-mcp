from __future__ import annotations

import base64
import hashlib
import html
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx
import jwt
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from uvicorn import run as uvicorn_run

from mcp.server import MCPServer
from mcp.server.auth.handlers.authorize import AuthorizationHandler
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenVerifier,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


# ---------------------------------------------------------------------------
# Runtime configuration. Credentials and signing material live in the host's
# environment settings, never in the Git repository or the container image.
# ---------------------------------------------------------------------------

BASE_URL = os.environ["MCP_BASE_URL"].rstrip("/")
if not BASE_URL.startswith("https://"):
    raise RuntimeError("MCP_BASE_URL must be a public HTTPS URL")

ISSUER = BASE_URL
RESOURCE = BASE_URL + "/mcp"
AUTHORIZATION_ENDPOINT = BASE_URL + "/authorize"
TOKEN_ENDPOINT = BASE_URL + "/token"
ADMIN_USERNAME = os.environ["MCP_ADMIN_USERNAME"]
ADMIN_PASSWORD_HASH = os.environ["MCP_ADMIN_PASSWORD_HASH"]
JWT_SECRET = os.environ["MCP_JWT_SECRET"]

if len(JWT_SECRET) < 64:
    raise RuntimeError("MCP_JWT_SECRET must contain at least 64 characters")

SCOPE_ADMIN = "debian.root"
SCOPE_OFFLINE = "offline_access"
ALLOWED_SCOPES = {SCOPE_ADMIN, SCOPE_OFFLINE}
ACCESS_TTL = 60 * 60
REFRESH_TTL = 60 * 60 * 24 * 30
AUTH_CODE_TTL = 180
PENDING_TTL = 600
MAX_OUTPUT = 50000
MAX_FILE_BYTES = 2 * 1024 * 1024
AUDIT_FILE = Path("/var/log/debian-root-mcp/audit.jsonl")


def audit(event: str, outcome: str, details: dict[str, Any] | None = None) -> None:
    """Write metadata-only audit entries; never log passwords, tokens, or file contents."""
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "outcome": outcome,
            "details": details or {},
        }
        with AUDIT_FILE.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        AUDIT_FILE.chmod(0o600)
    except Exception:
        pass


def password_matches(username: str, password: str) -> bool:
    if not hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode()):
        return False
    try:
        algorithm, iterations_text, salt_hex, expected_hex = ADMIN_PASSWORD_HASH.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        if not 300000 <= iterations <= 2000000:
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def sign_token(claims: dict[str, Any]) -> str:
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def decode_signed_token(token: str, expected_type: str) -> dict[str, Any] | None:
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            issuer=ISSUER,
            audience=RESOURCE,
            options={
                "require": ["iss", "aud", "sub", "iat", "exp", "jti", "client_id", "scope", "typ"],
            },
        )
        if claims.get("typ") != expected_type:
            return None
        return claims
    except (jwt.InvalidTokenError, TypeError, ValueError):
        return None


def issue_token_pair(
    client_id: str,
    subject: str,
    scopes: list[str],
    resource: str,
) -> tuple[str, str, int]:
    now = int(time.time())
    common = {
        "iss": ISSUER,
        "aud": resource,
        "sub": subject,
        "client_id": client_id,
        "scope": " ".join(scopes),
        "iat": now,
    }
    access_exp = now + ACCESS_TTL
    access_token = sign_token({
        **common,
        "typ": "access",
        "jti": secrets.token_urlsafe(24),
        "exp": access_exp,
    })
    refresh_token = sign_token({
        **common,
        "typ": "refresh",
        "jti": secrets.token_urlsafe(24),
        "exp": now + REFRESH_TTL,
    })
    return access_token, refresh_token, ACCESS_TTL


# ---------------------------------------------------------------------------
# CIMD OAuth client validation. Only ChatGPT's HTTPS-hosted client metadata
# documents and ChatGPT callback URLs are accepted; arbitrary URLs are rejected.
# ---------------------------------------------------------------------------

CLIENT_ID_PATTERN = re.compile(r"^https://chatgpt\.com/oauth/(?:[A-Za-z0-9_-]{1,80}/)?client\.json$")
CALLBACK_PATH_PATTERN = re.compile(r"^/connector/oauth/[A-Za-z0-9_-]{1,80}$")
CLIENT_CACHE: dict[str, tuple[float, OAuthClientInformationFull, dict[str, Any]]] = {}
CLIENT_ASSERTION_JTIS: dict[str, float] = {}
REVOKED_REFRESH_JTIS: set[str] = set()


def allowed_chatgpt_redirect(uri: str) -> bool:
    try:
        parsed = urlsplit(uri)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "chatgpt.com"
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
            and parsed.fragment == ""
            and parsed.query == ""
            and (
                parsed.path == "/connector_platform_oauth_redirect"
                or CALLBACK_PATH_PATTERN.fullmatch(parsed.path) is not None
            )
        )
    except ValueError:
        return False


class LocalOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self) -> None:
        self.pending: dict[str, dict[str, Any]] = {}
        self.codes: dict[str, AuthorizationCode] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if not CLIENT_ID_PATTERN.fullmatch(client_id):
            return None

        now = time.time()
        cached = CLIENT_CACHE.get(client_id)
        if cached and cached[0] > now:
            return cached[1]

        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
                response = await client.get(client_id, headers={"Accept": "application/json"})
            if response.status_code != 200 or len(response.content) > 65536:
                return None
            metadata = response.json()
            if not isinstance(metadata, dict) or metadata.get("client_id") != client_id:
                return None

            redirects = metadata.get("redirect_uris")
            if not isinstance(redirects, list) or not redirects or not all(
                isinstance(uri, str) and allowed_chatgpt_redirect(uri) for uri in redirects
            ):
                return None

            methods = metadata.get("token_endpoint_auth_methods_supported", [])
            if not isinstance(methods, list):
                methods = []
            legacy_method = metadata.get("token_endpoint_auth_method")
            available = {method for method in methods if method in {"none", "private_key_jwt"}}
            if legacy_method in {"none", "private_key_jwt"}:
                if available and legacy_method not in available:
                    return None
                auth_method = legacy_method
            elif "private_key_jwt" in available:
                auth_method = "private_key_jwt"
            elif "none" in available:
                auth_method = "none"
            else:
                return None

            client_info = OAuthClientInformationFull(
                client_id=client_id,
                client_name=str(metadata.get("client_name") or "ChatGPT")[:120],
                redirect_uris=redirects,
                response_types=["code"],
                grant_types=["authorization_code", "refresh_token"],
                token_endpoint_auth_method=auth_method,
                scope=" ".join(sorted(ALLOWED_SCOPES)),
                application_type="web",
            )
            CLIENT_CACHE[client_id] = (now + 300, client_info, metadata)
            return client_info
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError("This server uses ChatGPT Client ID Metadata Documents (CIMD), not DCR")

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource != RESOURCE:
            raise AuthorizeError("invalid_target", "The requested resource does not match this Debian MCP server")
        scopes = list(params.scopes or [SCOPE_ADMIN])
        if SCOPE_ADMIN not in scopes or not set(scopes).issubset(ALLOWED_SCOPES):
            raise AuthorizeError("invalid_scope", "Only the Debian root-administration scope is supported")

        tx = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        self.pending[tx] = {
            "client_id": client.client_id,
            "client_name": client.client_name or "ChatGPT",
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "state": params.state,
            "resource": params.resource,
            "scopes": scopes,
            "csrf": csrf,
            "created": time.time(),
        }
        # Prune expired authorization transactions and codes.
        self.pending = {key: value for key, value in self.pending.items() if time.time() - value["created"] <= PENDING_TTL}
        self.codes = {key: value for key, value in self.codes.items() if value.expires_at > time.time()}
        return BASE_URL + "/oauth/consent?tx=" + quote(tx)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self.codes.get(authorization_code)
        return code if code and code.client_id == client.client_id else None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self.codes.pop(authorization_code.code, None)
        access, refresh, ttl = issue_token_pair(
            client.client_id,
            ADMIN_USERNAME,
            authorization_code.scopes,
            authorization_code.resource or RESOURCE,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ttl,
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh,
        )

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        claims = decode_signed_token(refresh_token, "refresh")
        if not claims or claims.get("client_id") != client.client_id:
            return None
        if claims.get("jti") in REVOKED_REFRESH_JTIS:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=str(claims["scope"]).split(),
            expires_at=int(claims["exp"]),
            resource=str(claims["aud"]),
            subject=str(claims["sub"]),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        claims = decode_signed_token(refresh_token.token, "refresh")
        if not claims or claims.get("jti") in REVOKED_REFRESH_JTIS:
            raise ValueError("Refresh token is no longer valid")
        REVOKED_REFRESH_JTIS.add(str(claims["jti"]))
        access, refresh, ttl = issue_token_pair(
            client.client_id,
            refresh_token.subject or ADMIN_USERNAME,
            scopes,
            refresh_token.resource or RESOURCE,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ttl,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        claims = decode_signed_token(token, "access")
        if not claims:
            return None
        scopes = str(claims["scope"]).split()
        if SCOPE_ADMIN not in scopes:
            return None
        return AccessToken(
            token=token,
            client_id=str(claims["client_id"]),
            scopes=scopes,
            expires_at=int(claims["exp"]),
            resource=str(claims["aud"]),
            subject=str(claims["sub"]),
            claims=claims,
        )

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        for token_type in ("refresh", "access"):
            claims = decode_signed_token(token, token_type)
            if claims:
                REVOKED_REFRESH_JTIS.add(str(claims["jti"]))
                return


provider = LocalOAuthProvider()


class LocalTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        return await provider.load_access_token(token)


def client_metadata_for_assertion(client_id: str) -> dict[str, Any] | None:
    entry = CLIENT_CACHE.get(client_id)
    if not entry:
        return None
    return entry[2]


async def verify_client_assertion(client_id: str, form: Any) -> bool:
    assertion_type = form.get("client_assertion_type")
    assertion = form.get("client_assertion")
    if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        return False
    if not isinstance(assertion, str) or len(assertion) > 20000:
        return False

    metadata = client_metadata_for_assertion(client_id)
    if not metadata:
        return False

    jwks_uri = metadata.get("jwks_uri")
    if jwks_uri:
        parsed = urlsplit(str(jwks_uri))
        if parsed.scheme != "https" or parsed.hostname != "chatgpt.com" or parsed.port is not None:
            return False
        target = str(jwks_uri)
    else:
        target = "https://chatgpt.com/oauth/jwks.json"

    try:
        header = jwt.get_unverified_header(assertion)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in {"RS256", "ES256"} or not isinstance(key_id, str):
            return False

        async with httpx.AsyncClient(timeout=8, follow_redirects=False, trust_env=False) as client:
            response = await client.get(target, headers={"Accept": "application/json"})
        if response.status_code != 200 or len(response.content) > 131072:
            return False
        jwks = response.json()
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        jwk = next((item for item in keys if item.get("kid") == key_id), None)
        if not jwk or (jwk.get("alg") and jwk.get("alg") != algorithm):
            return False

        public_key = jwt.PyJWK.from_dict(jwk).key
        claims = jwt.decode(
            assertion,
            public_key,
            algorithms=[algorithm],
            options={"verify_aud": False, "require": ["iss", "sub", "aud", "exp", "iat", "jti"]},
            leeway=30,
        )
        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if client_id not in (claims.get("iss"), claims.get("sub")):
            return False
        if TOKEN_ENDPOINT not in audiences:
            return False
        now = time.time()
        if int(claims["exp"]) - now > 300 or now - int(claims["iat"]) > 300:
            return False
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti or jti in CLIENT_ASSERTION_JTIS:
            return False
        CLIENT_ASSERTION_JTIS[jti] = float(claims["exp"])
        for old_jti, expiry in list(CLIENT_ASSERTION_JTIS.items()):
            if expiry < now:
                CLIENT_ASSERTION_JTIS.pop(old_jti, None)
        return True
    except (httpx.HTTPError, jwt.InvalidTokenError, ValueError, TypeError, KeyError):
        return False


async def token_endpoint(request: Request) -> Response:
    try:
        form = await request.form()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400, headers={"Cache-Control": "no-store"})

    client_id = form.get("client_id")
    grant_type = form.get("grant_type")
    if not isinstance(client_id, str):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    client = await provider.get_client(client_id)
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"Cache-Control": "no-store"})

    if client.token_endpoint_auth_method == "private_key_jwt":
        if not await verify_client_assertion(client_id, form):
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"Cache-Control": "no-store"})
    elif client.token_endpoint_auth_method == "none":
        if form.get("client_secret") or request.headers.get("Authorization", "").startswith("Basic "):
            return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"Cache-Control": "no-store"})
    else:
        return JSONResponse({"error": "invalid_client"}, status_code=401, headers={"Cache-Control": "no-store"})

    resource = form.get("resource")
    if resource != RESOURCE:
        return JSONResponse({"error": "invalid_target", "error_description": "Resource mismatch"}, status_code=400)

    if grant_type == "authorization_code":
        code_value = form.get("code")
        verifier = form.get("code_verifier")
        redirect_uri = form.get("redirect_uri")
        if not all(isinstance(v, str) for v in (code_value, verifier, redirect_uri)):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        code = provider.codes.get(code_value)
        if not code or code.client_id != client_id or code.expires_at < time.time():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if code.resource != resource or str(code.redirect_uri) != redirect_uri:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if not 43 <= len(verifier) <= 128:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        if not hmac.compare_digest(expected_challenge, code.code_challenge):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        provider.codes.pop(code_value, None)  # one-time use, after all checks pass
        access, refresh, ttl = issue_token_pair(client_id, ADMIN_USERNAME, code.scopes, resource)
        audit("oauth_code_exchange", "success", {"client_id": client_id[:180], "scopes": code.scopes})
        return JSONResponse(
            {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": ttl,
                "refresh_token": refresh,
                "scope": " ".join(code.scopes),
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    if grant_type == "refresh_token":
        refresh_value = form.get("refresh_token")
        if not isinstance(refresh_value, str):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        claims = decode_signed_token(refresh_value, "refresh")
        if (
            not claims
            or claims.get("client_id") != client_id
            or claims.get("aud") != RESOURCE
            or claims.get("jti") in REVOKED_REFRESH_JTIS
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        old_jti = str(claims["jti"])
        REVOKED_REFRESH_JTIS.add(old_jti)
        scopes = str(claims["scope"]).split()
        requested_scope = form.get("scope")
        if isinstance(requested_scope, str) and requested_scope:
            requested = requested_scope.split()
            if not set(requested).issubset(set(scopes)):
                return JSONResponse({"error": "invalid_scope"}, status_code=400)
            scopes = requested
        access, refresh, ttl = issue_token_pair(client_id, str(claims["sub"]), scopes, RESOURCE)
        audit("oauth_refresh", "success", {"client_id": client_id[:180], "scopes": scopes})
        return JSONResponse(
            {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": ttl,
                "refresh_token": refresh,
                "scope": " ".join(scopes),
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


async def revocation_endpoint(request: Request) -> Response:
    try:
        form = await request.form()
        token = form.get("token")
        if isinstance(token, str):
            for kind in ("refresh", "access"):
                claims = decode_signed_token(token, kind)
                if claims:
                    REVOKED_REFRESH_JTIS.add(str(claims["jti"]))
                    break
        return JSONResponse({}, headers={"Cache-Control": "no-store"})
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)


def consent_html(tx: str, pending: dict[str, Any], error: str = "") -> str:
    name = html.escape(str(pending.get("client_name") or "ChatGPT"))
    scopes = html.escape(", ".join(pending.get("scopes", [])))
    redirect = html.escape(str(urlsplit(pending["redirect_uri"]).hostname or ""))
    message = f'<p class="error">{html.escape(error)}</p>' if error else ""
    csrf = html.escape(pending["csrf"])
    safe_tx = html.escape(tx)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Debian MCP</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0b1220;color:#e5e7eb;font:16px/1.55 system-ui,Segoe UI,sans-serif;display:grid;min-height:100vh;place-items:center;padding:24px}}
.card{{width:min(100%,540px);background:#111c2e;border:1px solid #263850;border-radius:18px;padding:28px;box-shadow:0 24px 80px #0008}}
h1{{margin:0 0 8px;font-size:25px}}.muted{{color:#9fb0c4}}.scope{{padding:14px;background:#0b1423;border:1px solid #30445c;border-radius:12px;margin:18px 0}}
label{{display:block;margin:14px 0 6px}}input{{width:100%;padding:12px;border-radius:9px;border:1px solid #3a506d;background:#0b1423;color:white}}
button{{width:100%;padding:13px;margin-top:14px;border:0;border-radius:9px;background:#2563eb;color:white;font-weight:700;cursor:pointer}}
button.deny{{background:#334155}}.error{{color:#fca5a5}}.warning{{color:#fbbf24;font-size:14px}}
</style></head><body><main class="card">
<h1>Authorize Debian Root MCP</h1>
<p class="muted"><b>{name}</b> is requesting access to your Debian environment.</p>
<div class="scope"><b>Requested permission</b><br>{scopes}<p class="warning">This grants root-level access inside this Debian container: execute shell commands, read and write system files, manage services, and install or remove packages.</p><p class="muted">Callback host: {redirect}</p></div>
{message}
<form method="post" action="/oauth/consent">
<input type="hidden" name="tx" value="{safe_tx}"><input type="hidden" name="csrf" value="{csrf}">
<label>Debian MCP username</label><input name="username" autocomplete="username" required>
<label>Debian MCP password</label><input type="password" name="password" autocomplete="current-password" required>
<label style="display:flex;gap:10px;align-items:flex-start"><input type="checkbox" name="root_consent" value="yes" required style="width:auto;margin-top:5px"><span>I understand and approve root-level access for this MCP connection.</span></label>
<button name="decision" value="approve">Approve and connect</button>
<button class="deny" name="decision" value="deny" formnovalidate>Deny access</button>
</form><p class="muted" style="font-size:12px">OAuth 2.1 · PKCE S256 · Short-lived access tokens · Local Debian account</p>
</main></body></html>"""


LOGIN_FAILURES: dict[str, deque[float]] = defaultdict(deque)


async def show_consent(request: Request) -> Response:
    tx = request.query_params.get("tx", "")
    pending = provider.pending.get(tx)
    if not pending or time.time() - pending["created"] > PENDING_TTL:
        return HTMLResponse("<h1>Authorization request expired</h1>", status_code=400)
    return HTMLResponse(consent_html(tx, pending), headers={"Cache-Control": "no-store"})


async def submit_consent(request: Request) -> Response:
    try:
        form = await request.form()
        tx = str(form.get("tx") or "")
        pending = provider.pending.get(tx)
        if not pending or time.time() - pending["created"] > PENDING_TTL:
            return HTMLResponse("<h1>Authorization request expired</h1>", status_code=400)

        csrf = str(form.get("csrf") or "")
        if not hmac.compare_digest(csrf, str(pending["csrf"])):
            return HTMLResponse("<h1>Invalid request. Reload the authorization flow.</h1>", status_code=400)

        decision = str(form.get("decision") or "")
        if decision == "deny":
            provider.pending.pop(tx, None)
            redirect = construct_redirect_uri(
                pending["redirect_uri"],
                error="access_denied",
                **({"state": pending["state"]} if pending["state"] else {}),
            )
            return RedirectResponse(redirect, status_code=303, headers={"Cache-Control": "no-store"})

        if decision != "approve" or form.get("root_consent") != "yes":
            return HTMLResponse(consent_html(tx, pending, "Approval checkbox is required."), status_code=400)

        client_ip = request.client.host if request.client else "unknown"
        attempts = LOGIN_FAILURES[client_ip]
        now = time.time()
        while attempts and now - attempts[0] > 900:
            attempts.popleft()
        if len(attempts) >= 8:
            return HTMLResponse(consent_html(tx, pending, "Too many attempts. Try again in 15 minutes."), status_code=429)

        username = str(form.get("username") or "")
        password = str(form.get("password") or "")
        if len(password) > 512 or not password_matches(username, password):
            attempts.append(now)
            audit("oauth_login", "rejected", {"source": client_ip[:80]})
            return HTMLResponse(consent_html(tx, pending, "Invalid username or password."), status_code=401)

        LOGIN_FAILURES.pop(client_ip, None)
        code = secrets.token_urlsafe(48)
        provider.codes[code] = AuthorizationCode(
            code=code,
            scopes=list(pending["scopes"]),
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending["client_id"],
            code_challenge=pending["code_challenge"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=bool(pending["redirect_uri_provided_explicitly"]),
            resource=pending["resource"],
            subject=ADMIN_USERNAME,
        )
        provider.pending.pop(tx, None)
        audit("oauth_consent", "approved", {"client_id": pending["client_id"][:180], "scopes": pending["scopes"]})
        redirect_args: dict[str, str] = {"code": code}
        if pending["state"]:
            redirect_args["state"] = str(pending["state"])
        redirect = construct_redirect_uri(pending["redirect_uri"], **redirect_args)
        return RedirectResponse(redirect, status_code=303, headers={"Cache-Control": "no-store"})
    except Exception:
        audit("oauth_consent", "failed")
        return HTMLResponse("<h1>Unable to process authorization</h1>", status_code=400)


async def oauth_metadata(request: Request) -> Response:
    payload = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZATION_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "revocation_endpoint": BASE_URL + "/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": [SCOPE_ADMIN, SCOPE_OFFLINE],
        "client_id_metadata_document_supported": True,
    }
    return JSONResponse(payload, headers={"Cache-Control": "public, max-age=300"})


# ---------------------------------------------------------------------------
# MCP resource server and the tools exposed to the authenticated administrator.
# ---------------------------------------------------------------------------

mcp = MCPServer(
    name="Debian Root MCP",
    title="Debian Root Administration",
    description="OAuth-protected root administration for the Debian noVNC container.",
    instructions="All tools require the user's explicit OAuth consent for the debian.root scope.",
    token_verifier=LocalTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=[SCOPE_ADMIN],
        validate_token_resource=True,
    ),
)


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def system_overview() -> dict[str, Any]:
    """Read Debian version, kernel, uptime, memory, storage, and active users."""
    result: dict[str, Any] = {}
    for name, argv in {
        "kernel": ["uname", "-a"],
        "uptime": ["uptime"],
        "memory": ["free", "-h"],
        "disk": ["df", "-hT"],
        "hostname": ["hostnamectl"],
        "users": ["who"],
    }.items():
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
            result[name] = {"exit_code": proc.returncode, "stdout": proc.stdout[-10000:], "stderr": proc.stderr[-3000:]}
        except Exception as exc:
            result[name] = {"error": str(exc)}
    try:
        result["os_release"] = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")[:8000]
    except OSError as exc:
        result["os_release"] = str(exc)
    audit("system_overview", "success")
    return result


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def root_shell(
    command: str,
    working_directory: str = "/",
    timeout_seconds: int = 60,
    confirm_execution: bool = False,
) -> dict[str, Any]:
    """Execute a Bash command as container root. Set confirm_execution=true to run it; otherwise only a preview is returned."""
    if not command.strip():
        return {"error": "Command cannot be empty"}
    if len(command) > 16000:
        return {"error": "Command exceeds the 16 KiB limit"}
    cwd = Path(working_directory)
    if not cwd.is_absolute() or not cwd.is_dir():
        return {"error": "working_directory must be an existing absolute directory"}
    timeout = max(1, min(int(timeout_seconds), 300))
    command_hash = hashlib.sha256(command.encode()).hexdigest()
    if not confirm_execution:
        return {
            "approval_required": True,
            "command_preview": command[:2000],
            "working_directory": str(cwd.resolve()),
            "timeout_seconds": timeout,
            "instruction": "Repeat the call with confirm_execution=true to execute this command as root.",
        }
    try:
        proc = subprocess.run(
            ["/bin/bash", "-lc", command],
            cwd=str(cwd.resolve()),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "USER": "root",
                "LOGNAME": "root",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        audit("root_shell", "success" if proc.returncode == 0 else "nonzero", {
            "command_sha256": command_hash,
            "cwd": str(cwd.resolve()),
            "exit_code": proc.returncode,
        })
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-MAX_OUTPUT:],
            "stderr": proc.stderr[-MAX_OUTPUT:],
            "command_sha256": command_hash,
        }
    except subprocess.TimeoutExpired as exc:
        audit("root_shell", "timeout", {"command_sha256": command_hash, "cwd": str(cwd.resolve())})
        return {
            "exit_code": 124,
            "stdout": (exc.stdout or "")[-MAX_OUTPUT:] if isinstance(exc.stdout, str) else "",
            "stderr": "Command timed out",
            "command_sha256": command_hash,
        }
    except Exception as exc:
        audit("root_shell", "failed", {"command_sha256": command_hash})
        return {"error": str(exc), "command_sha256": command_hash}


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def root_read_file(path: str, max_bytes: int = 1048576) -> dict[str, Any]:
    """Read any regular file inside the Debian container as root."""
    try:
        target = Path(path)
        if not target.is_absolute():
            return {"error": "Absolute path required"}
        resolved = target.resolve(strict=True)
        if not resolved.is_file():
            return {"error": "Path must be a regular file"}
        limit = max(1, min(int(max_bytes), MAX_FILE_BYTES))
        size = resolved.stat().st_size
        if size > limit:
            return {"error": f"File is {size} bytes; requested limit is {limit} bytes"}
        content = resolved.read_text(encoding="utf-8", errors="replace")
        audit("root_read_file", "success", {"path": str(resolved), "bytes": size})
        return {"path": str(resolved), "size_bytes": size, "content": content}
    except Exception as exc:
        audit("root_read_file", "failed", {"path": str(path)[:300]})
        return {"error": str(exc)}


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def root_write_file(
    path: str,
    content: str,
    mode_octal: str = "0644",
    confirm_write: bool = False,
) -> dict[str, Any]:
    """Write any regular path inside Debian as root, using an atomic replace and a one-time backup. Set confirm_write=true to commit."""
    try:
        requested = Path(path)
        if not requested.is_absolute() or requested.name in {"", ".", ".."}:
            return {"error": "A valid absolute file path is required"}
        if not re.fullmatch(r"0[0-7]{3}", mode_octal):
            return {"error": "mode_octal must be a four-digit octal mode such as 0644"}
        raw = content.encode("utf-8")
        if len(raw) > MAX_FILE_BYTES:
            return {"error": "File content exceeds the 2 MiB limit"}
        parent = requested.parent.resolve(strict=True)
        if not parent.is_dir():
            return {"error": "Parent directory does not exist"}
        target = parent / requested.name
        if target.is_symlink():
            return {"error": "Refusing to replace a symbolic link"}
        if any(part in {"proc", "sys", "dev"} for part in target.parts[:2]):
            return {"error": "Writes to pseudo-filesystems are blocked"}
        backup = target.with_name(target.name + ".mcp.bak")
        if not confirm_write:
            return {
                "approval_required": True,
                "path": str(target),
                "bytes": len(raw),
                "existing_file": target.exists(),
                "backup_path": str(backup) if target.exists() and not backup.exists() else None,
                "instruction": "Repeat the call with confirm_write=true to write the file.",
            }
        if target.exists() and not target.is_file():
            return {"error": "Target must be a regular file"}
        if target.exists() and not backup.exists():
            shutil.copy2(target, backup)
            backup.chmod(0o600)
        fd, temporary = tempfile.mkstemp(prefix=".mcp-write-", dir=str(parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, int(mode_octal, 8))
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        audit("root_write_file", "success", {"path": str(target), "bytes": len(raw), "backup": backup.exists()})
        return {
            "ok": True,
            "path": str(target),
            "bytes_written": target.stat().st_size,
            "backup": str(backup) if backup.exists() else None,
        }
    except Exception as exc:
        audit("root_write_file", "failed", {"path": str(path)[:300]})
        return {"error": str(exc)}


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def root_list_directory(path: str = "/", recursive: bool = False) -> dict[str, Any]:
    """List a directory or, optionally, its descendants without following symbolic links."""
    try:
        root = Path(path)
        if not root.is_absolute():
            return {"error": "Absolute path required"}
        root = root.resolve(strict=True)
        if not root.is_dir():
            return {"error": "Path must be a directory"}
        entries: list[dict[str, Any]] = []
        if recursive:
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
                for name in dirs + files:
                    item = Path(current) / name
                    try:
                        info = item.lstat()
                        entries.append({
                            "path": str(item),
                            "type": "directory" if item.is_dir() and not item.is_symlink() else "file",
                            "symlink": item.is_symlink(),
                            "size": info.st_size,
                            "mode": oct(info.st_mode & 0o777),
                        })
                    except OSError:
                        continue
                    if len(entries) >= 2000:
                        break
                if len(entries) >= 2000:
                    break
        else:
            for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
                try:
                    info = item.lstat()
                    entries.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() and not item.is_symlink() else "file",
                        "symlink": item.is_symlink(),
                        "size": info.st_size,
                        "mode": oct(info.st_mode & 0o777),
                    })
                except OSError:
                    continue
                if len(entries) >= 2000:
                    break
        audit("root_list_directory", "success", {"path": str(root), "count": len(entries), "recursive": recursive})
        return {"path": str(root), "entries": entries, "truncated": len(entries) >= 2000}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def service_control(service: str, action: str) -> dict[str, Any]:
    """Start, stop, restart, reload, enable, disable, or inspect any systemd service."""
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", service):
        return {"error": "Invalid service name"}
    if action not in {"start", "stop", "restart", "reload", "enable", "disable", "status"}:
        return {"error": "Unsupported action"}
    argv = ["systemctl", action, service] if action != "status" else ["systemctl", "status", service, "--no-pager"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
        audit("service_control", "success" if proc.returncode == 0 else "nonzero", {
            "service": service, "action": action, "exit_code": proc.returncode,
        })
        return {"exit_code": proc.returncode, "stdout": proc.stdout[-MAX_OUTPUT:], "stderr": proc.stderr[-MAX_OUTPUT:]}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool(meta={"securitySchemes": [{"type": "oauth2", "scopes": [SCOPE_ADMIN]}]})
def read_service_logs(service: str = "", lines: int = 100) -> dict[str, Any]:
    """Read recent systemd journal logs for a service, capped at 500 lines."""
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", service):
        return {"error": "Provide a valid systemd service name"}
    count = max(1, min(int(lines), 500))
    try:
        proc = subprocess.run(
            ["journalctl", "-u", service, "-n", str(count), "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        audit("read_service_logs", "success" if proc.returncode == 0 else "nonzero", {
            "service": service, "lines": count, "exit_code": proc.returncode,
        })
        return {"exit_code": proc.returncode, "stdout": proc.stdout[-MAX_OUTPUT:], "stderr": proc.stderr[-5000:]}
    except Exception as exc:
        return {"error": str(exc)}


# Authorization server endpoints are mounted in the same Debian app and domain.
mcp_app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    stateless_http=True,
    host="127.0.0.1",
)
mcp_app.router.routes = [
    Route("/.well-known/oauth-authorization-server", oauth_metadata, methods=["GET"]),
    Route("/authorize", AuthorizationHandler(provider).handle, methods=["GET", "POST"]),
    Route("/token", token_endpoint, methods=["POST"]),
    Route("/revoke", revocation_endpoint, methods=["POST"]),
    Route("/oauth/consent", show_consent, methods=["GET"]),
    Route("/oauth/consent", submit_consent, methods=["POST"]),
    *mcp_app.router.routes,
]

if __name__ == "__main__":
    uvicorn_run(mcp_app, host="127.0.0.1", port=8765, log_level="info")

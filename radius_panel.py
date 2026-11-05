from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import time
from typing import Any
from pathlib import Path

import httpx
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

ADMIN_USERNAME = os.environ.get("MCP_ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.environ.get("MCP_ADMIN_PASSWORD_HASH", "")
JWT_SECRET = os.environ.get("MCP_JWT_SECRET", "")
RADIUS_API_URL = os.environ.get("RADIUS_API_URL", "")
RADIUS_API_KEY = os.environ.get("RADIUS_API_KEY", "")
COOKIE_NAME = "radius_panel_session"
CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0), limits=httpx.Limits(max_connections=12, max_keepalive_connections=6))
ASSET_DIR = Path(__file__).resolve().parent / "static" / "tabler"


def _json(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})


def _password_ok(username: str, password: str) -> bool:
    if not hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode()):
        return False
    try:
        algorithm, iterations_text, salt_hex, expected_hex = ADMIN_PASSWORD_HASH.split("$", 3)
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 300000 <= iterations <= 2000000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iterations, dklen=len(bytes.fromhex(expected_hex)))
        return hmac.compare_digest(actual, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False


def _session(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token or not JWT_SECRET:
        return None
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if claims.get("scope") != "radius.panel":
            return None
        return claims
    except jwt.PyJWTError:
        return None


def _authorized(request: Request, write: bool = False, roles: tuple[str, ...] = ()) -> tuple[dict[str, Any] | None, Response | None]:
    claims = _session(request)
    if not claims:
        return None, _json({"error": "authentication_required"}, 401)
    if roles and claims.get("role") not in roles:
        return None, _json({"error": "permission_denied"}, 403)
    if write and not hmac.compare_digest(str(request.headers.get("x-csrf-token", "")), str(claims.get("csrf", ""))):
        return None, _json({"error": "csrf_failed"}, 403)
    return claims, None


async def _edge(op: str, data: dict[str, Any] | None = None) -> tuple[Any, int]:
    if not RADIUS_API_URL or not RADIUS_API_KEY:
        return {"error": "RADIUS_API_URL or RADIUS_API_KEY is not configured"}, 503
    try:
        response = await CLIENT.post(
            RADIUS_API_URL,
            json={"op": op, "data": data or {}},
            headers={"x-radius-key": RADIUS_API_KEY, "Content-Type": "application/json"},
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": "Invalid response from Supabase"}
        return payload, response.status_code
    except httpx.TimeoutException:
        return {"error": "Supabase API timed out"}, 504
    except httpx.HTTPError as exc:
        return {"error": "Supabase API connection failed", "detail": str(exc)[:180]}, 502


async def _proxy(request: Request, op: str, *, write: bool = False, roles: tuple[str, ...] = ()) -> Response:
    claims, error = _authorized(request, write, roles)
    if error:
        return error
    data: dict[str, Any] = {}
    if write:
        try:
            data = await request.json()
            if not isinstance(data, dict):
                return _json({"error": "JSON object required"}, 400)
        except Exception:
            return _json({"error": "Invalid JSON body"}, 400)
    tenant_id = claims.get("tenant_id")
    if claims.get("role") != "super_admin":
        if tenant_id:
            data["tenant_id"] = tenant_id
    if claims.get("role") == "reseller":
        data["reseller_id"] = claims.get("reseller_id")
    if claims.get("role") == "customer":
        data["username"] = claims.get("username")
        data["subscriber_username"] = claims.get("subscriber_username")
        data["customer_username"] = claims.get("subscriber_username")
        data["operator_id"] = claims.get("operator_id")
    if claims.get("operator_id") and (write or claims.get("role") == "customer") and "operator_id" not in data:
        data["operator_id"] = claims["operator_id"]
    payload, status = await _edge(op, data)
    return _json(payload, status)


async def login_page(request: Request) -> Response:
    if _session(request):
        return RedirectResponse("/radius/", status_code=303)
    return HTMLResponse(LOGIN_HTML, headers={"Cache-Control": "no-store"})


async def login_submit(request: Request) -> Response:
    try:
        form = await request.form()
        username = str(form.get("username") or "").strip()
        password = str(form.get("password") or "")
    except Exception:
        return HTMLResponse(LOGIN_HTML.replace("<!--ERROR-->", '<p class="error">بيانات الدخول غير صحيحة</p>'), status_code=400)
    claims: dict[str, Any] | None = None
    if _password_ok(username, password):
        claims = {
            "sub": username, "username": username, "role": "super_admin",
            "operator_id": None, "tenant_id": None, "display_name": "System Administrator",
        }
    else:
        result, status = await _edge("operators.authenticate", {"username": username, "password": password})
        if status == 200 and result.get("ok") and result.get("user"):
            user = result["user"]
            claims = {
                "sub": user["username"], "username": user["username"], "role": user["role"],
                "operator_id": user["id"], "tenant_id": user.get("tenant_id"),
                "display_name": user.get("display_name") or user["username"],
                "reseller_id": user.get("reseller_id"),
                "must_change_password": bool(user.get("must_change_password")),
                "subscriber_username": user.get("subscriber_username"),
            }
    if not claims:
        return HTMLResponse(LOGIN_HTML.replace("<!--ERROR-->", '<p class="error">اسم المستخدم أو كلمة المرور غير صحيحة</p>'), status_code=401)
    csrf = os.urandom(24).hex()
    now = int(time.time())
    claims.update({"scope": "radius.panel", "csrf": csrf, "iat": now, "exp": now + 8 * 3600})
    token = jwt.encode(claims, JWT_SECRET, algorithm="HS256")
    response = RedirectResponse("/radius/", status_code=303)
    response.set_cookie(COOKIE_NAME, token, max_age=8 * 3600, httponly=True, secure=True, samesite="strict", path="/radius")
    return response


async def logout(request: Request) -> Response:
    response = RedirectResponse("/radius/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/radius", secure=True, httponly=True, samesite="strict")
    return response


async def dashboard(request: Request) -> Response:
    claims = _session(request)
    if not claims:
        return RedirectResponse("/radius/login", status_code=303)
    csrf = str(claims.get("csrf", ""))
    page = DASHBOARD_HTML.replace("__CSRF__", csrf).replace("__ROLE__", str(claims.get("role", "customer"))).replace("__USERNAME__", str(claims.get("username", ""))).replace("__DISPLAY__", str(claims.get("display_name", "")))
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"})


async def api_health(request: Request) -> Response:
    response = await _proxy(request, "health", roles=("super_admin", "network_owner", "reseller", "support"))
    if response.status_code >= 400:
        return response
    try:
        payload = json.loads(response.body.decode("utf-8"))
        process = subprocess.run(["pgrep", "-x", "freeradius"], capture_output=True, text=True, timeout=3, check=False)
        sockets = subprocess.run(["ss", "-H", "-lun"], capture_output=True, text=True, timeout=3, check=False)
        listeners = sockets.stdout if sockets.returncode == 0 else ""
        payload.update({
            "freeradius_running": process.returncode == 0,
            "auth_udp_listening": ":1812" in listeners,
            "accounting_udp_listening": ":1813" in listeners,
        })
        payload["radius_ready"] = bool(
            payload["freeradius_running"] and payload["auth_udp_listening"] and payload["accounting_udp_listening"]
        )
        return _json(payload)
    except Exception:
        return response


async def api_overview(request: Request) -> Response:
    claims = _session(request)
    if not claims:
        return _json({"error": "authentication_required"}, 401)
    if claims.get("role") == "customer":
        return await _proxy(request, "customer.home")
    return await _proxy(request, "overview", roles=("super_admin", "network_owner", "reseller", "support"))


async def api_users(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "users.list", roles=("super_admin", "network_owner", "support"))
    return await _proxy(request, "users.create", write=True, roles=("super_admin", "network_owner"))


async def api_user_action(request: Request) -> Response:
    claims, error = _authorized(request, True, ("super_admin", "network_owner"))
    if error:
        return error
    try:
        body = await request.json()
    except Exception:
        return _json({"error": "Invalid JSON"}, 400)
    action = str(body.get("action") or "")
    op = {"enable": "users.enable", "disable": "users.disable", "delete": "users.delete", "update": "users.update"}.get(action)
    if not op:
        return _json({"error": "Unsupported action"}, 400)
    if claims.get("tenant_id"):
        body["tenant_id"] = claims["tenant_id"]
    payload, status = await _edge(op, body)
    return _json(payload, status)


async def api_plans(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "plans.list", roles=("super_admin", "network_owner", "reseller", "customer"))
    return await _proxy(request, "plans.create", write=True, roles=("super_admin", "network_owner"))


def _nas_sync_worker() -> dict[str, Any]:
    """Regenerate, validate, and restart FreeRADIUS so its client list is reloaded.

    FreeRADIUS does not reload clients.conf on SIGHUP. Changes are rolled back
    if generation, validation, or restart fails. A NAS DB write is not rolled
    back here; the API response clearly reports a sync failure.
    """
    script = Path("/opt/debian-root-mcp/configure_radius.py")
    if not script.is_file():
        return {"ok": False, "error": "configure_radius.py was not found"}

    base = Path("/etc/freeradius/3.0")
    site_default = (base / "sites-enabled" / "default").resolve()
    snapshot_paths = [
        base / "clients.conf",
        base / "clients.d" / "radius-managed.conf",
        base / "mods-available" / "rest",
        site_default,
    ]
    snapshots: dict[str, bytes | None] = {}
    modes: dict[str, int] = {}
    for path in snapshot_paths:
        key = str(path)
        snapshots[key] = path.read_bytes() if path.is_file() else None
        if path.exists():
            modes[key] = path.stat().st_mode & 0o777

    radius_stopped = False

    def _start_radius() -> int:
        process = subprocess.Popen(
            ["freeradius", "-f"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=os.environ.copy(),
        )
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"FreeRADIUS exited during startup (code {process.returncode}); "
                    "check /var/log/freeradius/radius.log"
                )
            listeners = subprocess.run(
                ["ss", "-H", "-lun"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if (
                listeners.returncode == 0
                and ":1812" in listeners.stdout
                and ":1813" in listeners.stdout
            ):
                return process.pid
            time.sleep(0.15)

        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        raise RuntimeError("FreeRADIUS started but UDP 1812/1813 did not become ready")

    try:
        setup = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=45,
            env=os.environ.copy(),
            check=False,
        )
        if setup.returncode != 0:
            detail = (setup.stderr or setup.stdout or "NAS configuration generation failed")[-1800:]
            raise RuntimeError(detail)

        check = subprocess.run(
            ["freeradius", "-XC"],
            capture_output=True,
            text=True,
            timeout=30,
            env=os.environ.copy(),
            check=False,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout or "Unknown FreeRADIUS validation error")[-1800:]
            raise RuntimeError("FreeRADIUS validation failed: " + detail)

        finder = subprocess.run(
            ["pgrep", "-xo", "freeradius"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        pid_text = finder.stdout.strip()
        if finder.returncode != 0 or not pid_text.isdigit():
            raise RuntimeError("Configuration is valid, but the FreeRADIUS process was not found")

        old_pid = int(pid_text)
        os.kill(old_pid, signal.SIGTERM)
        radius_stopped = True
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            try:
                os.kill(old_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(old_pid, signal.SIGKILL)
            time.sleep(0.2)

        new_pid = _start_radius()
        radius_stopped = False
        return {
            "ok": True,
            "message": "NAS records synchronized; FreeRADIUS configuration validated and service restarted.",
            "generator": (setup.stdout or "").strip()[-500:],
            "validation": "Configuration appears to be OK",
            "process_id": new_pid,
        }
    except Exception as exc:
        rollback_errors = []
        for path in snapshot_paths:
            key = str(path)
            old = snapshots.get(key)
            try:
                if old is None:
                    if path.exists():
                        path.unlink()
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    temporary = path.with_name(path.name + ".rollback")
                    temporary.write_bytes(old)
                    temporary.replace(path)
                    path.chmod(modes.get(key, 0o640))
            except OSError as rollback_exc:
                rollback_errors.append(str(rollback_exc)[:180])

        if radius_stopped:
            try:
                active = subprocess.run(
                    ["pgrep", "-xo", "freeradius"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if active.returncode != 0:
                    _start_radius()
            except Exception as recovery_exc:
                rollback_errors.append("FreeRADIUS recovery failed: " + str(recovery_exc)[:180])

        message = str(exc)[:1600]
        if rollback_errors:
            message += " | recovery warning: " + "; ".join(rollback_errors)
        return {
            "ok": False,
            "error": message,
            "message": "NAS data may be saved, but FreeRADIUS restart did not complete.",
        }

async def _nas_mutation(request: Request, operation: str) -> Response:
    claims, error = _authorized(request, True, ("super_admin", "network_owner"))
    if error:
        return error
    try:
        data = await request.json()
        if not isinstance(data, dict):
            return _json({"error": "JSON object required"}, 400)
    except Exception:
        return _json({"error": "Invalid JSON body"}, 400)

    if claims.get("role") != "super_admin":
        tenant_id = claims.get("tenant_id")
        if not tenant_id:
            return _json({"error": "A network must be selected for this NAS"}, 400)
        data["tenant_id"] = tenant_id

    payload, status = await _edge(operation, data)
    if status >= 400:
        return _json(payload, status)

    sync = await asyncio.to_thread(_nas_sync_worker)
    result = dict(payload) if isinstance(payload, dict) else {"result": payload}
    result["radius_sync"] = sync
    return _json(result, 200)


async def api_nas(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "nas.list", roles=("super_admin", "network_owner", "support"))
    return await _nas_mutation(request, "nas.create")


async def api_nas_update(request: Request) -> Response:
    return await _nas_mutation(request, "nas.update")


async def api_nas_delete(request: Request) -> Response:
    return await _nas_mutation(request, "nas.delete")


async def api_nas_sync(request: Request) -> Response:
    claims, error = _authorized(request, True, ("super_admin", "network_owner"))
    if error:
        return error
    sync = await asyncio.to_thread(_nas_sync_worker)
    return _json(sync, 200 if sync.get("ok") else 503)


async def api_sessions(request: Request) -> Response:
    return await _proxy(request, "sessions.list", roles=("super_admin", "network_owner", "support"))


async def api_logs(request: Request) -> Response:
    return await _proxy(request, "logs.list", roles=("super_admin", "network_owner", "support"))


async def api_tenants(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "tenants.list", roles=("super_admin",))
    return await _proxy(request, "tenants.create", write=True, roles=("super_admin",))


async def api_operators(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "operators.list", roles=("super_admin", "network_owner"))
    return await _proxy(request, "operators.create", write=True, roles=("super_admin", "network_owner"))


async def api_resellers(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "resellers.list", roles=("super_admin", "network_owner"))
    return await _proxy(request, "resellers.create", write=True, roles=("super_admin", "network_owner"))


async def api_vouchers(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "vouchers.list", roles=("super_admin", "network_owner", "reseller"))
    return await _proxy(request, "vouchers.generate", write=True, roles=("super_admin", "network_owner", "reseller"))


async def api_voucher_sell(request: Request) -> Response:
    return await _proxy(request, "vouchers.sell", write=True, roles=("super_admin", "network_owner", "reseller"))


async def api_sales(request: Request) -> Response:
    return await _proxy(request, "sales.list", roles=("super_admin", "network_owner", "reseller"))


async def api_wallet(request: Request) -> Response:
    return await _proxy(request, "wallet.list", roles=("super_admin", "network_owner", "reseller"))


async def api_invoices(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "invoices.list", roles=("super_admin", "network_owner", "reseller", "customer"))
    return await _proxy(request, "invoices.create", write=True, roles=("super_admin", "network_owner"))


async def api_payments(request: Request) -> Response:
    return await _proxy(request, "payments.list", roles=("super_admin", "network_owner", "reseller"))


async def api_tickets(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "tickets.list", roles=("super_admin", "network_owner", "reseller", "support", "customer"))
    return await _proxy(request, "tickets.create", write=True, roles=("super_admin", "network_owner", "reseller", "support", "customer"))


async def api_notifications(request: Request) -> Response:
    return await _proxy(request, "notifications.list", roles=("super_admin", "network_owner", "reseller", "support", "customer"))


async def api_audit(request: Request) -> Response:
    return await _proxy(request, "audit.list", roles=("super_admin", "network_owner"))


async def api_wireguard(request: Request) -> Response:
    return await _proxy(request, "wireguard.peers.list", roles=("super_admin", "network_owner"))


LOGIN_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radius Control | تسجيل الدخول</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 16% 12%,#16435a 0,transparent 34%),radial-gradient(circle at 82% 84%,#1b365c 0,transparent 33%),#071321;font-family:Inter,"Segoe UI",Tahoma,sans-serif;color:#e8f0f8}.card{width:min(450px,calc(100% - 32px));padding:38px;border:1px solid #28445d;border-radius:24px;background:#101f30ee;box-shadow:0 28px 90px #0009}.brand{display:flex;align-items:center;gap:14px;margin-bottom:32px}.mark{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:linear-gradient(135deg,#14a99d,#3d73dc);font-size:24px;font-weight:900}.muted{color:#89a1b7;font-size:13px}.title{font-size:24px;font-weight:800;margin:0 0 8px}.field{margin:20px 0}.field label{display:block;margin-bottom:8px;font-size:13px;color:#b4c6d6}.field input{width:100%;height:49px;border:1px solid #30495f;border-radius:12px;background:#091725;color:#eef7ff;padding:0 14px;font-size:15px;outline:none}.field input:focus{border-color:#31a9a3;box-shadow:0 0 0 3px #31a9a322}button{width:100%;height:50px;border:0;border-radius:12px;background:linear-gradient(105deg,#159f9a,#386ed5);color:white;font-weight:800;font-size:15px;cursor:pointer;margin-top:10px}.error{color:#ff9c9c;font-size:13px}.foot{text-align:center;margin-top:26px;color:#66829a;font-size:12px}.secure{display:flex;gap:8px;align-items:center;color:#78d8bd;font-size:11px;margin-top:20px}</style></head><body><main class="card"><div class="brand"><div class="mark">R</div><div><div style="font-size:18px;font-weight:900;letter-spacing:.7px">RADIUS CONTROL</div><div class="muted">ISP & Hotspot Management Suite</div></div></div><h1 class="title">تسجيل دخول آمن</h1><p class="muted">لوحة موحدة لإدارة الشبكات والمشتركين والموزعين.</p><!--ERROR--><form method="post" action="/radius/login"><div class="field"><label>اسم المستخدم</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>كلمة المرور</label><input type="password" name="password" autocomplete="current-password" required></div><button type="submit">دخول إلى منصة الإدارة</button></form><div class="secure">● اتصال مشفر وجلسة إدارية محمية</div><div class="foot">Radius Control • Multi-tenant Network Platform</div></main></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radius Control Suite</title><meta name="csrf" content="__CSRF__"><link rel="stylesheet" href="/radius/assets/tabler.rtl.min.css"><link rel="stylesheet" href="/radius/assets/tabler-icons.min.css><style>
:root{color-scheme:dark;--rc-bg:#0b1423;--rc-surface:#121e30;--rc-border:#26384e;--rc-muted:#8fa2ba;--rc-accent:#2dd4bf}
html,body{min-height:100%;background:var(--rc-bg)}body{margin:0;color:#e7eef8;font-family:Tahoma,"Segoe UI",system-ui,sans-serif}.page{min-height:100vh;background:var(--rc-bg)}
.navbar-vertical.side{width:17.25rem;min-width:17.25rem;background:#101b2d;border-left:1px solid var(--rc-border);box-shadow:-12px 0 35px rgba(0,0,0,.08);z-index:1030}.side .container-fluid{min-height:100vh;align-items:stretch;padding:1rem .9rem}.side .brand{width:100%;display:flex;align-items:center;gap:.85rem;padding:.65rem .6rem 1.35rem;margin:0 0 .8rem;border:0;border-bottom:1px solid rgba(148,163,184,.13);color:#f4f8ff;text-decoration:none}
.brand .mark{width:46px;height:46px;flex:0 0 46px;display:grid;place-items:center;border-radius:15px;background:linear-gradient(145deg,#21b6a9,#3673d7);color:#fff;font-size:23px;box-shadow:0 8px 22px rgba(33,182,169,.22)}.brand strong{display:block;color:#f4f8ff;font-size:.82rem;font-weight:800;letter-spacing:.055em}.brand small{display:block;color:#8fa4bd;font-size:.68rem;margin-top:.22rem}
.who{margin:.45rem .15rem .9rem;padding:.85rem 1rem;border:1px solid rgba(148,163,184,.13);border-radius:14px;background:rgba(255,255,255,.025);box-shadow:none}.who b{display:block;color:#e7eef8;font-size:.82rem;font-weight:700}.who small{display:block;color:#8fa2ba;margin-top:.35rem;font-size:.68rem;overflow-wrap:anywhere}.navlabel{font-size:.62rem;color:#71859e;font-weight:800;letter-spacing:.14em;padding:1rem .85rem .45rem;text-transform:uppercase}
.navbar-nav.nav{gap:.16rem;width:100%;overflow:visible}.nav button.nav-link{display:flex;align-items:center;gap:.78rem;width:100%;min-height:43px;padding:.65rem .8rem;margin:0;border:1px solid transparent;border-radius:11px;background:transparent;color:#9aabc0;text-align:right;font:inherit;font-size:.79rem;cursor:pointer;transition:background .18s ease,color .18s ease}.nav button.nav-link .nav-link-icon{display:inline-flex;align-items:center;justify-content:center;width:1.25rem;flex:0 0 1.25rem;font-size:1.08rem;color:#8296b0}.nav button.nav-link:hover{background:rgba(255,255,255,.045);color:#f3f7fc}.nav button.nav-link.active{background:linear-gradient(100deg,rgba(45,212,191,.16),rgba(45,212,191,.045));border-color:rgba(45,212,191,.16);color:#e9fffb;box-shadow:inset -3px 0 var(--rc-accent)}.nav button.nav-link.active .nav-link-icon{color:var(--rc-accent)}
.sidebottom{margin-top:auto;padding-top:1rem;border-top:1px solid rgba(148,163,184,.14)}.sidebottom .statusbox{background:rgba(45,212,191,.06);border-color:rgba(45,212,191,.16);color:#a9c7c9}.logout{width:100%;justify-content:center;margin-top:.7rem}
.page-wrapper.main{min-width:0;min-height:100vh;padding:0;background:var(--rc-bg)}.top{display:block;padding:1.4rem 0 .7rem;margin:0}.top-inner{display:flex;align-items:center;justify-content:space-between;gap:1rem}.top h1{margin:0 0 .35rem;color:#f1f6fd;font-size:1.55rem;font-weight:800;letter-spacing:-.02em}.top p{margin:0;color:var(--rc-muted);font-size:.78rem}.top-actions{display:flex;align-items:center;justify-content:flex-end;gap:.65rem;flex-wrap:wrap}
.top-search{position:relative;display:flex;align-items:center;gap:.55rem;width:min(18rem,42vw);height:39px;padding:0 .75rem;border:1px solid var(--rc-border);border-radius:11px;background:var(--rc-surface);color:#8195af}.top-search input{width:100%;min-width:0;border:0;outline:0;background:transparent;color:#eaf2fb;font:inherit;font-size:.75rem}.top-search input::placeholder{color:#71849e}.pill{display:inline-flex;gap:.55rem;align-items:center;padding:.58rem .82rem;border:1px solid rgba(45,212,191,.18);border-radius:99px;background:rgba(45,212,191,.07);color:#b3d8d4;font-size:.72rem;white-space:nowrap}.dot{width:7px;height:7px;background:#35d39e;border-radius:50%;box-shadow:0 0 11px rgba(53,211,158,.6)}
.page-body{padding:.75rem 0 2.5rem}.section{display:none}.section.show{display:block;animation:rc-enter .22s ease-out}@keyframes rc-enter{from{opacity:.55;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}.welcome{margin:.15rem 0 1rem;color:#a9bbd0;font-size:.86rem}
.grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.9rem}.metric{position:relative;isolation:isolate;min-height:132px;padding:1.1rem 1.15rem;border:1px solid var(--rc-border);border-radius:17px;background:linear-gradient(145deg,#16263c,#111c2e);box-shadow:0 9px 28px rgba(0,0,0,.08);overflow:hidden}.metric:after{content:"";position:absolute;z-index:-1;inset:auto -28px -45px auto;width:120px;height:120px;border-radius:50%;background:radial-gradient(circle,rgba(45,212,191,.12),transparent 68%)}.metric .label{color:#9aabc0;font-size:.73rem;font-weight:600}.metric .value{margin:.75rem 0 .3rem;color:#f0f6ff;font-size:1.85rem;line-height:1.15;font-weight:850;letter-spacing:-.04em}.metric .sub{color:#71849d;font-size:.67rem}
.card.panel,.panel{margin-top:1rem;border:1px solid var(--rc-border);border-radius:17px;background:var(--rc-surface);box-shadow:0 10px 30px rgba(0,0,0,.07);overflow:hidden}.card-header.panelhead,.panelhead{display:flex;align-items:center;justify-content:space-between;gap:.9rem;padding:1rem 1.2rem;margin:0;border:0;border-bottom:1px solid rgba(148,163,184,.12);background:transparent}.panelhead h2{margin:0;color:#e8eff9;font-size:.9rem;font-weight:750}.panelhead p{margin:.35rem 0 0;color:#8194ad;font-size:.7rem}.panel .card-body{padding:1.15rem 1.2rem}.quick{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}
.btn{border-radius:10px;font-size:.76rem;font-weight:650;transition:transform .15s ease,filter .15s ease}.btn:hover{transform:translateY(-1px)}.btn-primary{border-color:#239e96;background:linear-gradient(115deg,#159d95,#287cc0);box-shadow:0 7px 18px rgba(21,157,149,.16)}.btn-outline-secondary{color:#c5d1df;border-color:#344760;background:rgba(255,255,255,.025)}.btn-outline-secondary:hover{color:#fff;border-color:#57708d;background:rgba(255,255,255,.075)}.btn-outline-danger{border-color:#74404d;color:#f3a4b0}
.table-responsive.tablewrap{margin:0;padding:0 1rem 1rem;overflow:auto}.tablewrap table{margin:0;color:#d9e4f1;white-space:nowrap}.tablewrap .table>:not(caption)>*>*{padding:.78rem .72rem;border-bottom-color:rgba(148,163,184,.12);background:transparent;vertical-align:middle}.tablewrap .table thead th{color:#8fa2ba;font-size:.69rem;font-weight:750;letter-spacing:.015em}.tablewrap .table tbody td{color:#d1ddec;font-size:.75rem}.tablewrap .table tbody tr:hover td{background:rgba(255,255,255,.025)}.tablewrap .table tbody tr:last-child td{border-bottom:0}.empty{text-align:center;color:#8094ac!important;padding:2.2rem!important}.badge{padding:.35rem .58rem;border-radius:99px;font-size:.65rem;font-weight:700;letter-spacing:0}.badge.off{background:rgba(241,123,140,.13);color:#f49eaa}.badge.warn{background:rgba(238,185,92,.14);color:#edc77f}
.table-toolbar{display:flex;align-items:center;justify-content:space-between;gap:.65rem;padding:.75rem 1rem .6rem;flex-wrap:wrap}.table-toolbar .form-control{width:min(17rem,60vw);min-height:34px;border-radius:9px;background:#0d1929;border-color:#2a3b51;color:#dce7f5;font-size:.72rem}.table-toolbar .form-control::placeholder{color:#71849b}
.subgrid{display:grid;grid-template-columns:1.15fr .85fr;gap:1rem}.statusbox{border:1px solid var(--rc-border);border-radius:13px;background:#0e1a2b;padding:.9rem 1rem;color:#a8b8ca;font-size:.75rem;line-height:1.85}.service-checks{display:grid;gap:.55rem}.service-check{display:flex;align-items:center;justify-content:space-between;gap:.6rem;padding:.48rem .05rem;border-bottom:1px solid rgba(148,163,184,.1);font-size:.74rem}.service-check:last-child{border-bottom:0}.service-check .state{display:inline-flex;align-items:center;gap:.4rem;font-weight:700}.service-check .state:before{content:"";width:7px;height:7px;border-radius:50%;background:#f17b8c}.service-check .state.ok:before{background:#35c99a;box-shadow:0 0 10px rgba(53,201,154,.5)}
.note{color:#91a4bb;font-size:.72rem;line-height:1.8}.warning{border:1px solid rgba(238,185,92,.28);border-radius:13px;background:rgba(238,185,92,.08);color:#e9cb92;padding:.9rem 1rem;font-size:.75rem;line-height:1.8}.accountcard{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:1.35rem 1.5rem;border:1px solid rgba(45,212,191,.18);border-radius:18px;background:linear-gradient(125deg,rgba(20,153,146,.15),rgba(59,105,189,.18))}.accountcard .big{font-size:1.8rem;font-weight:850;color:#f0f7ff}
.kpi{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.7rem 0;border-bottom:1px solid rgba(148,163,184,.12);font-size:.76rem;color:#9aacc1}.kpi b{color:#eaf2fb}.errorbox,.successbox{padding:.85rem 1rem;border-radius:12px;font-size:.77rem}.errorbox{color:#ffadb7;background:rgba(190,55,82,.16);border:1px solid rgba(241,123,140,.18)}.successbox{color:#9ce7ce;background:rgba(35,157,125,.14);border:1px solid rgba(53,201,154,.18)}.loading{color:#8fa2ba;padding:1.2rem;font-size:.75rem}
.radius-modal{position:fixed;inset:0;width:min(760px,calc(100% - 24px));max-width:760px;max-height:calc(100vh - 28px);overflow:auto;padding:1.35rem;border:1px solid #344a64;border-radius:19px;background:#15243a;color:#e7eef8;box-shadow:0 30px 100px rgba(0,0,0,.55)}.radius-modal::backdrop{background:rgba(2,7,15,.78);backdrop-filter:blur(7px)}.radius-modal h3{margin:0 0 1.1rem;color:#f0f6ff;font-size:1rem;font-weight:800}.radius-modal form{margin:0}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:.55rem .85rem}.field{margin-bottom:.65rem;min-width:0}.field label{display:block;margin-bottom:.42rem;color:#9dafc4;font-size:.7rem;font-weight:650}.field input,.field select,.field textarea{width:100%;min-height:40px;padding:.55rem .7rem;border:1px solid #354a64;border-radius:9px;background:#0c1829;color:#e5eef9;font:inherit;font-size:.77rem;outline:none}.field input:focus,.field select:focus,.field textarea:focus{border-color:#2bbcae;box-shadow:0 0 0 3px rgba(43,188,174,.12)}.field textarea{min-height:88px;resize:vertical}.full{grid-column:1/-1}.modalfoot{display:flex;justify-content:flex-start;gap:.55rem;margin-top:1rem;padding-top:.85rem;border-top:1px solid rgba(148,163,184,.14);flex-wrap:wrap}
.auth-trend{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:.65rem;align-items:end;min-height:132px;padding:.35rem 0}.trend-day{display:flex;flex-direction:column;align-items:center;gap:.5rem;min-width:0}.trend-bars{display:flex;align-items:flex-end;justify-content:center;gap:.23rem;width:100%;height:88px;padding:.15rem}.trend-bar{width:min(18px,35%);min-height:3px;border-radius:5px 5px 2px 2px;transition:height .3s ease}.trend-bar.accept{background:linear-gradient(180deg,#3dd5ad,#1d887f)}.trend-bar.reject{background:linear-gradient(180deg,#f58e9c,#a9435a)}.trend-day small{color:#8295ad;font-size:.65rem}.trend-day b{color:#dce8f6;font-size:.64rem}.auth-legend{display:flex;gap:.8rem;align-items:center;color:#92a5bd;font-size:.67rem}.legend-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-inline-end:.35rem}.legend-dot.accept{background:#35c99a}.legend-dot.reject{background:#f17b8c}.top-search:focus-within{border-color:#37bcb1;box-shadow:0 0 0 3px rgba(45,212,191,.1)}.logout{width:100%}
@media(max-width:1399px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:991.98px){.navbar-vertical.side{width:100%;min-width:0;position:relative}.side .container-fluid{min-height:0;padding:.7rem 1rem}.side .brand{padding:.4rem .4rem .65rem;margin:0;border:0}.side .navbar-toggler{position:absolute;top:1.15rem;left:1rem}.side .collapse.navbar-collapse{width:100%;padding-top:.65rem}.side .who,.side .navlabel,.sidebottom{display:block}.navbar-nav.nav{max-height:55vh;overflow:auto}.page-wrapper.main{min-height:calc(100vh - 80px)}.top-inner{align-items:flex-start;flex-direction:column}.top-actions{width:100%;justify-content:space-between}.top-search{width:min(100%,24rem)}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.subgrid{grid-template-columns:1fr}}@media(max-width:575.98px){.top h1{font-size:1.25rem}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}.metric{min-height:112px;padding:.8rem}.metric .value{font-size:1.45rem}.formgrid{grid-template-columns:1fr}.full{grid-column:auto}.accountcard{align-items:flex-start;flex-direction:column}.panelhead{align-items:flex-start;flex-wrap:wrap;padding:.9rem}.table-responsive.tablewrap{padding:0 .55rem .65rem}.table-toolbar{padding:.65rem .55rem}.auth-trend{gap:.2rem}.trend-bars{height:68px}}
body[data-bs-theme="light"]{color-scheme:light;--rc-bg:#f4f7fb;--rc-surface:#fff;--rc-border:#e1e8f0;background:#f4f7fb;color:#182435}body[data-bs-theme="light"] .page,body[data-bs-theme="light"] .page-wrapper.main{background:#f4f7fb}body[data-bs-theme="light"] .navbar-vertical.side{background:#fff;border-color:#e1e8f0;box-shadow:8px 0 28px rgba(20,40,70,.04)}body[data-bs-theme="light"] .brand strong,body[data-bs-theme="light"] .who b,body[data-bs-theme="light"] .panelhead h2,body[data-bs-theme="light"] .metric .value,body[data-bs-theme="light"] .top h1{color:#1c2a3b}body[data-bs-theme="light"] .brand small,body[data-bs-theme="light"] .who small,body[data-bs-theme="light"] .navlabel,body[data-bs-theme="light"] .top p,body[data-bs-theme="light"] .panelhead p{color:#7a899b}body[data-bs-theme="light"] .who,body[data-bs-theme="light"] .metric,body[data-bs-theme="light"] .card.panel,body[data-bs-theme="light"] .panel{background:#fff;border-color:#e1e8f0;box-shadow:0 8px 24px rgba(20,40,70,.035)}body[data-bs-theme="light"] .nav button.nav-link{color:#5b6b80}body[data-bs-theme="light"] .nav button.nav-link.active{color:#087e75;background:rgba(18,160,147,.09)}body[data-bs-theme="light"] .tablewrap .table tbody td{color:#35465b}body[data-bs-theme="light"] .tablewrap .table thead th{color:#75859a}body[data-bs-theme="light"] .table-toolbar .form-control,body[data-bs-theme="light"] .top-search{background:#fff;border-color:#dce4ee;color:#64748b}body[data-bs-theme="light"] .top-search input{color:#223147}body[data-bs-theme="light"] .radius-modal{background:#fff;color:#1c2a3b;border-color:#dce4ee}body[data-bs-theme="light"] .radius-modal h3{color:#1c2a3b}body[data-bs-theme="light"] .field label{color:#5f7085}body[data-bs-theme="light"] .field input,body[data-bs-theme="light"] .field select,body[data-bs-theme="light"] .field textarea{background:#f8fafc;color:#223147;border-color:#dce4ee}
</style></head><body data-bs-theme="dark"><div class="page"><aside class="navbar navbar-vertical navbar-expand-lg side"><div class="container-fluid"><button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#radius-sidebar" aria-controls="radius-sidebar" aria-expanded="false"><span class="navbar-toggler-icon"></span></button><div class="brand navbar-brand navbar-brand-autodark"><div class="mark">R</div><div><strong>RADIUS CONTROL SUITE</strong><small>ISP • Hotspot • Billing • AAA</small></div></div><div class="collapse navbar-collapse" id="radius-sidebar"><div class="d-flex flex-column flex-fill w-100"><div class="who card card-sm"><b>__DISPLAY__</b><small>__ROLE__ • __USERNAME__</small></div><div class="navlabel">COMMAND CENTER</div><nav class="navbar-nav nav pt-lg-3 w-100">
<button type="button" class="nav-link active" data-view="overview"><span class="nav-link-icon"><i class="ti ti-layout-dashboard"></i></span><span class="nav-link-title">لوحة المؤشرات</span></button>
<div class="navlabel">NETWORK &amp; ACCESS</div><button type="button" class="nav-link" data-view="networks" data-roles="super_admin"><span class="nav-link-icon"><i class="ti ti-network"></i></span><span class="nav-link-title">الشبكات والعملاء</span></button>
<button type="button" class="nav-link" data-view="operators" data-roles="super_admin,network_owner"><span class="nav-link-icon"><i class="ti ti-users"></i></span><span class="nav-link-title">المستخدمون الإداريون</span></button>
<button type="button" class="nav-link" data-view="users" data-roles="super_admin,network_owner,support"><span class="nav-link-icon"><i class="ti ti-user-circle"></i></span><span class="nav-link-title">مشتركو الإنترنت</span></button>
<button type="button" class="nav-link" data-view="plans" data-roles="super_admin,network_owner,reseller,customer"><span class="nav-link-icon"><i class="ti ti-package"></i></span><span class="nav-link-title">الباقات والسرعات</span></button>
<button type="button" class="nav-link" data-view="nas" data-roles="super_admin,network_owner,support"><span class="nav-link-icon"><i class="ti ti-router"></i></span><span class="nav-link-title">أجهزة NAS / MikroTik</span></button>
<div class="navlabel">BUSINESS</div><button type="button" class="nav-link" data-view="resellers" data-roles="super_admin,network_owner"><span class="nav-link-icon"><i class="ti ti-users-group"></i></span><span class="nav-link-title">الموزعون والمحافظ</span></button>
<button type="button" class="nav-link" data-view="vouchers" data-roles="super_admin,network_owner,reseller"><span class="nav-link-icon"><i class="ti ti-ticket"></i></span><span class="nav-link-title">كروت الشحن</span></button>
<button type="button" class="nav-link" data-view="sales" data-roles="super_admin,network_owner,reseller"><span class="nav-link-icon"><i class="ti ti-chart-bar"></i></span><span class="nav-link-title">المبيعات والتحصيل</span></button>
<button type="button" class="nav-link" data-view="invoices" data-roles="super_admin,network_owner,reseller,customer"><span class="nav-link-icon"><i class="ti ti-receipt"></i></span><span class="nav-link-title">الفواتير والمدفوعات</span></button>
<button type="button" class="nav-link" data-view="sessions" data-roles="super_admin,network_owner,support"><span class="nav-link-icon"><i class="ti ti-activity"></i></span><span class="nav-link-title">الجلسات النشطة</span></button>
<button type="button" class="nav-link" data-view="logs" data-roles="super_admin,network_owner,support"><span class="nav-link-icon"><i class="ti ti-list-check"></i></span><span class="nav-link-title">سجل المصادقة</span></button>
<div class="navlabel">OPERATIONS</div><button type="button" class="nav-link" data-view="support" data-roles="super_admin,network_owner,reseller,support,customer"><span class="nav-link-icon"><i class="ti ti-headset"></i></span><span class="nav-link-title">الدعم الفني</span></button>
<button type="button" class="nav-link" data-view="wireguard" data-roles="super_admin,network_owner"><span class="nav-link-icon"><i class="ti ti-shield-lock"></i></span><span class="nav-link-title">WireGuard / VPN</span></button>
<button type="button" class="nav-link" data-view="audit" data-roles="super_admin,network_owner"><span class="nav-link-icon"><i class="ti ti-clipboard-list"></i></span><span class="nav-link-title">سجل التدقيق</span></button>
</nav><div class="sidebottom"><div class="statusbox">● جلسة إدارية مشفرة<br>الانتهاء التلقائي بعد 8 ساعات.</div><form method="post" action="/radius/logout"><button class="btn btn-outline-danger logout" type="submit">↪　 تسجيل الخروج</button></form></div></div></div></div></aside>
<main class="page-wrapper main"><header class="top page-header d-print-none"><div class="container-xl"><div class="top-inner"><div><h1 id="viewTitle">لوحة المؤشرات</h1><p id="viewDesc">متابعة الشبكات والمشتركين والاستخدام والمبيعات من مكان واحد.</p></div><div class="top-actions"><label class="top-search"><i class="ti ti-search"></i><input id="globalSearch" type="search" placeholder="بحث في الجدول المفتوح (Ctrl+K)"></label><div class="pill"><span class="dot"></span> مركز التحكم متصل</div><button id="themeToggle" class="btn btn-icon btn-outline-secondary" type="button"><i class="ti ti-sun-moon"></i></button></div></div></div></header><div class="page-body"><div class="container-xl">
<section id="overview" class="section show"><div class="welcome">مرحبًا، __DISPLAY__</div><div id="customerCard" class="accountcard" style="display:none"><div><div class="note">حساب الإنترنت الخاص بك</div><div class="big" id="customerUser">—</div><div class="note" id="customerPlan">—</div></div><div><div class="note">الحالة</div><span class="badge" id="customerStatus">—</span></div></div><div class="grid" id="metrics">
<div class="metric"><div class="label">المشتركون النشطون</div><div id="mUsers" class="value">—</div><div class="sub">حسابات مفعلة</div></div>
<div class="metric"><div class="label">الجلسات الحالية</div><div id="mSessions" class="value">—</div><div class="sub">اتصالات نشطة</div></div>
<div class="metric"><div class="label">أجهزة NAS</div><div id="mNas" class="value">—</div><div class="sub">أجهزة الشبكة</div></div>
<div class="metric"><div class="label">قبول اليوم</div><div id="mAccept" class="value">—</div><div class="sub">Access-Accept</div></div>
<div class="metric"><div class="label">رفض اليوم</div><div id="mReject" class="value">—</div><div class="sub">Access-Reject</div></div>
<div class="metric"><div class="label">الباقات المفعلة</div><div id="mPlans" class="value">—</div><div class="sub">عروض الإنترنت</div></div></div>
<div class="subgrid"><div class="card panel"><div class="card-header panelhead"><div><h2>إجراءات سريعة</h2><p>اختصارات الإدارة اليومية</p></div></div><div class="quick"><button class="btn btn-primary" data-action="new-user">＋ مشترك جديد</button><button class="btn btn-outline-secondary" data-action="new-voucher">＋ إصدار كروت</button><button class="btn btn-outline-secondary" data-action="new-reseller">＋ موزع</button><button class="btn btn-outline-secondary" data-action="new-invoice">＋ فاتورة</button></div></div><div class="card panel"><div class="card-header panelhead"><div><h2>صحة الخدمات</h2><p>قاعدة البيانات ومحرك المصادقة</p></div></div><div id="serviceStatus" class="statusbox">جارٍ فحص اتصال Supabase…</div></div></div>
<div class="card panel trend-panel"><div class="card-header panelhead"><div><h2>نشاط المصادقة خلال 7 أيام</h2><p>قبول ورفض من أحدث سجلات RADIUS.</p></div></div><div class="card-body"><div id="authTrendChart" class="auth-trend"></div></div></div><div class="card panel"><div class="card-header panelhead"><div><h2>آخر محاولات المصادقة</h2><button class="btn btn-outline-secondary" onclick="showView('logs')">عرض السجل</button></div></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>المستخدم</th><th>القرار</th><th>التوقيت</th><th>الجهاز</th></tr></thead><tbody id="recentLogs"><tr><td class="empty" colspan="4">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="networks" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الشبكات والعملاء</h2><p>إدارة مالكي الشبكات والاشتراكات متعددة المؤسسات</p></div><button class="btn btn-primary" data-action="new-tenant">＋ إضافة شبكة</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>اسم الشبكة</th><th>Slug</th><th>Tenant UUID</th><th>الخطة</th><th>الحالة</th><th>العملة</th><th>تاريخ الإنشاء</th></tr></thead><tbody id="networksTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="operators" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>حسابات الإدارة</h2><p>أصحاب الشبكات، المشرفون، الموزعون، والعملاء</p></div><button class="btn btn-primary" data-action="new-operator">＋ حساب جديد</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>اسم الدخول</th><th>الاسم</th><th>الدور</th><th>الشبكة</th><th>البريد</th><th>الحالة</th><th>آخر دخول</th></tr></thead><tbody id="operatorsTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="users" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>مشتركو الإنترنت</h2><p>الاشتراكات، الماك، الأجهزة، وتحديد السرعة</p></div><button class="btn btn-primary" data-action="new-user">＋ مشترك جديد</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>المستخدم</th><th>الاسم</th><th>الباقة</th><th>تنزيل / رفع</th><th>الحالة</th><th>الأجهزة</th><th>الانتهاء</th><th>إجراء</th></tr></thead><tbody id="usersTable"><tr><td class="empty" colspan="8">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="plans" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الباقات والسرعات</h2><p>سرعة التنزيل والرفع والحصة الشهرية والمهلة</p></div><button class="btn btn-primary" data-action="new-plan">＋ باقة جديدة</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الباقة</th><th>تنزيل</th><th>رفع</th><th>الحصة</th><th>مدة الجلسة</th><th>السعر</th><th>الحالة</th></tr></thead><tbody id="plansTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="nas" class="section">
<div class="card panel">
  <div class="card-header panelhead">
    <div><h2>أجهزة NAS / MikroTik</h2><p>تسجيل عملاء RADIUS وإدارة المفاتيح ومزامنة FreeRADIUS</p></div>
    <div class="quick"><button class="btn btn-outline-secondary" type="button" onclick="syncNas()">↻ مزامنة وفحص RADIUS</button><button class="btn btn-primary" data-action="new-nas">＋ إضافة NAS</button></div>
  </div>
  <div id="nasSyncStatus" class="statusbox" style="margin-bottom:14px">لم يتم فحص مزامنة NAS في هذه الجلسة.</div>
  <div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>طريقة الاتصال</th><th>عنوان المصدر على السيرفر</th><th>اسم الجهاز</th><th>النوع</th><th>Shared Secret</th><th>الوصف</th><th>الإجراء</th></tr></thead>
  <tbody id="nasTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div>
</div>
<div class="card panel">
  <h2>قواعد تعريف NAS حسب طريقة الاتصال</h2>
  <div class="note"><b>Portwarp UDP:</b> يصل الطلب إلى FreeRADIUS من المصدر المحلي <code>127.0.0.1</code>، لذلك يُنشأ تعريف RADIUS client واحد فقط لهذا النفق. أجهزة MikroTik التي تمر عبر نفس نقطة الدخول تستخدم Shared Secret واحدًا. يمكن تمييزها منطقيًا باستخدام <code>NAS-Identifier</code>، لكنه لا ينشئ أسرار عميل مستقلة.</div>
  <div class="note" style="margin-top:10px"><b>الاتصال المباشر:</b> أدخل عنوان المصدر أو CIDR الذي يصل فعليًا إلى FreeRADIUS بعد NAT، وليس عنوان LAN للراوتر إذا كان المصدر يتغير عند العبور.</div>
  <div class="note" style="margin-top:10px">تمنع اللوحة تكرار عنوان Portwarp وتداخل نطاقات IPv4 حتى لا يختار FreeRADIUS تعريف عميل غير مقصود.</div>
</div>
</section>
<section id="resellers" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الموزعون والمحافظ</h2><p>العمولات والرصيد وحدود الائتمان</p></div><button class="btn btn-primary" data-action="new-reseller">＋ موزع جديد</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الموزع</th><th>الكود</th><th>العمولة</th><th>الرصيد</th><th>الحد الائتماني</th><th>الحالة</th></tr></thead><tbody id="resellersTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div><div class="card panel"><div class="card-header panelhead"><h2>حركة المحافظ</h2></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الموزع</th><th>النوع</th><th>المبلغ</th><th>الرصيد بعد العملية</th><th>التوقيت</th></tr></thead><tbody id="walletTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="vouchers" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>كروت الشحن</h2><p>دفعات كروت، أكواد فريدة، طباعة وتوزيع</p></div><button class="btn btn-primary" data-action="new-voucher">＋ إصدار دفعة كروت</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الكود</th><th>آخر 4 من PIN</th><th>الباقة</th><th>القيمة</th><th>الحالة</th><th>التاريخ</th></tr></thead><tbody id="vouchersTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="sales" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>المبيعات والتحصيل</h2><p>عمليات بيع الكروت والعمولات وطرق الدفع</p></div></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>رقم العملية</th><th>الموزع</th><th>المستخدم</th><th>الإجمالي</th><th>العمولة</th><th>طريقة الدفع</th><th>الحالة</th><th>التاريخ</th></tr></thead><tbody id="salesTable"><tr><td class="empty" colspan="8">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="invoices" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الفواتير والمدفوعات</h2><p>إصدار فواتير ومتابعة السداد والاستحقاق</p></div><button class="btn btn-primary" data-action="new-invoice">＋ فاتورة جديدة</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>رقم الفاتورة</th><th>العميل</th><th>الإجمالي</th><th>العملة</th><th>الحالة</th><th>الاستحقاق</th><th>السداد</th></tr></thead><tbody id="invoicesTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div><div class="card panel"><div class="card-header panelhead"><h2>سجل المدفوعات</h2></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الفاتورة</th><th>المبلغ</th><th>الوسيلة</th><th>الحالة</th><th>تاريخ الاستلام</th></tr></thead><tbody id="paymentsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="sessions" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الجلسات النشطة</h2><p>المستخدمون المتصلون وحركة المرور</p></div><button class="btn btn-outline-secondary" onclick="loadSessions()">تحديث</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>المستخدم</th><th>IP</th><th>NAS</th><th>بداية الجلسة</th><th>المدة</th><th>رفع</th><th>تنزيل</th></tr></thead><tbody id="sessionsTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="logs" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>سجل المصادقة</h2><p>محاولات الدخول والقبول والرفض، دون تسجيل كلمات المرور</p></div><button class="btn btn-outline-secondary" onclick="loadLogs()">تحديث</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>المستخدم</th><th>القرار</th><th>التوقيت</th><th>Calling Station</th><th>Called Station</th></tr></thead><tbody id="logsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="support" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>الدعم الفني</h2><p>فتح ومتابعة تذاكر الدعم لكل شبكة</p></div><button class="btn btn-primary" data-action="new-ticket">＋ تذكرة جديدة</button></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>الموضوع</th><th>التصنيف</th><th>الأولوية</th><th>الحالة</th><th>آخر تحديث</th></tr></thead><tbody id="ticketsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="wireguard" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>WireGuard / VPN</h2><p>إدارة بيانات الـ peers ومخطط التوصيل الآمن</p></div></div><div class="warning">تنبيه اتصال: تطبيق الويب على CranL لا يملك منفذ UDP عام موثقًا لتشغيل WireGuard Server أو استقبال RADIUS UDP. بيانات الـ peers تحفظ هنا، لكن النفق الفعلي يحتاج VPS بعنوان عام ومنفذ UDP مفتوح، أو منصة تدعم UDP ingress. لن يظهر أي peer كمتصل قبل وجود نقطة WireGuard فعلية.</div><div class="table-responsive tablewrap" style="margin-top:15px"><table class="table table-vcenter"><thead><tr><th>الاسم</th><th>Public Key</th><th>عنوان النفق</th><th>الحالة</th><th>آخر Handshake</th></tr></thead><tbody id="wireguardTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="audit" class="section"><div class="card panel"><div class="card-header panelhead"><div><h2>سجل التدقيق</h2><p>تتبع عمليات الإدارة وتغييرات الحسابات</p></div></div><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>المنفذ</th><th>العملية</th><th>نوع الكيان</th><th>المعرف</th><th>التفاصيل</th><th>التاريخ</th></tr></thead><tbody id="auditTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<div id="errorBox" class="errorbox" style="margin-top:14px"></div><div id="successBox" class="successbox" style="margin-top:14px"></div></div></div></main></div>
<dialog id="userModal" class="radius-modal"><form id="userForm"><h3>إضافة / تعديل مشترك</h3><div class="formgrid"><div class="field"><label>اسم المستخدم *</label><input name="username" required minlength="3"></div><div class="field"><label>كلمة المرور *</label><input name="password" type="password" required minlength="8"></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>الهاتف</label><input name="phone"></div><div class="field"><label>البريد</label><input name="email" type="email"></div><div class="field"><label>الباقة</label><select name="plan_id" id="userPlan"></select></div><div class="field"><label>MAC Binding (اختياري)</label><input name="mac_address" placeholder="AA:BB:CC:DD:EE:FF"></div><div class="field"><label>أقصى أجهزة متزامنة</label><input type="number" name="max_devices" min="1" max="100" value="1"></div><div class="field"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div><div class="field full"><label>انتهاء الاشتراك</label><input type="datetime-local" name="expires_at"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">حفظ المشترك</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('userModal')">إلغاء</button></div></form></dialog>
<dialog id="planModal" class="radius-modal"><form id="planForm"><h3>إنشاء باقة</h3><div class="formgrid"><div class="field full"><label>اسم الباقة</label><input name="name" required></div><div class="field"><label>تنزيل Mbps</label><input type="number" name="download_mbps" min="1" value="4" required></div><div class="field"><label>رفع Mbps</label><input type="number" name="upload_mbps" min="1" value="4" required></div><div class="field"><label>الحصة MB</label><input type="number" name="quota_mb" min="1"></div><div class="field"><label>Session Timeout (ثانية)</label><input type="number" name="session_timeout" min="1"></div><div class="field"><label>السعر EGP</label><input type="number" name="price" min="0" step=".01" value="0"></div><div class="field full"><label>الوصف</label><input name="description"></div><div class="field full"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">حفظ الباقة</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('planModal')">إلغاء</button></div></form></dialog>
<dialog id="nasModal" class="radius-modal"><form id="nasForm"><h3 id="nasFormTitle">إضافة جهاز NAS</h3><input type="hidden" name="id"><div class="formgrid">
<div class="field"><label>طريقة الاتصال</label><select name="transport_mode" id="nasTransport" onchange="updateNasTransport()"><option value="portwarp">Portwarp UDP Tunnel</option><option value="direct">اتصال مباشر (IPv4 / CIDR)</option></select></div>
<div class="field"><label>عنوان عميل RADIUS كما يراه السيرفر</label><input name="nasname" id="nasAddress" required value="127.0.0.1" placeholder="127.0.0.1" dir="ltr"></div>
<div class="field"><label>اسم NAS / Short Name</label><input name="shortname" required maxlength="48" pattern="[A-Za-z0-9_.-]{1,48}" placeholder="mikrotik-main"></div>
<div class="field"><label>النوع</label><select name="type"><option value="mikrotik">MikroTik</option><option value="wireless">Wireless</option><option value="other">Other</option></select></div>
<div class="field full"><label>RADIUS Shared Secret (32 حرفًا على الأقل)</label><div class="quick"><input style="flex:1;min-width:200px" type="password" name="secret" id="nasSecret" minlength="32" autocomplete="new-password" dir="ltr"><button class="btn btn-outline-secondary" type="button" onclick="generateNasSecret()">توليد مفتاح آمن</button><button class="btn btn-outline-secondary" type="button" onclick="toggleNasSecret()">عرض / إخفاء</button></div><p class="note" id="nasSecretHint">يُولّد مفتاح عشوائي 256-bit ويُخزن على قاعدة البيانات. لن يظهر في جدول NAS؛ انسخه بعد الحفظ واضبط القيمة نفسها في MikroTik.</p></div>
<div class="field full"><label>الوصف</label><input name="description" placeholder="الراوتر الرئيسي"></div>
<div class="field full" id="nasTenantField" style="display:none"><label>الشبكة المالكة للجهاز</label><select name="tenant_id" id="nasTenant"><option value="">اختر الشبكة</option></select></div>
<div class="field full"><div class="warning" id="nasTransportHint">Portwarp يمرر المصدر إلى 127.0.0.1. يُسمح بتعريف واحد لهذا النفق.</div></div>
</div><div class="modalfoot"><button class="btn btn-primary" type="submit">حفظ ومزامنة FreeRADIUS</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('nasModal')">إلغاء</button></div></form></dialog>
<dialog id="nasSecretOutput" class="radius-modal"><h3>مفتاح RADIUS</h3><p class="warning" id="nasSecretOutputNote">احفظ المفتاح في مكان آمن واضبط القيمة نفسها في MikroTik. لن يتم عرضه مرة أخرى بعد إغلاق هذه النافذة.</p><div class="field"><input id="nasSecretShown" readonly dir="ltr" style="font-family:monospace"></div><div class="modalfoot"><button class="btn btn-primary" type="button" onclick="copyNasSecret()">نسخ المفتاح</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('nasSecretOutput')">تم</button></div></dialog>
<dialog id="tenantModal" class="radius-modal"><form id="tenantForm"><h3>إضافة شبكة / مالك شبكة</h3><div class="formgrid"><div class="field"><label>اسم الشبكة</label><input name="name" required></div><div class="field"><label>Slug بالإنجليزية</label><input name="slug" required pattern="[a-z0-9-]{3,50}"></div><div class="field"><label>البريد</label><input name="contact_email" type="email"></div><div class="field"><label>الهاتف</label><input name="contact_phone"></div><div class="field"><label>العملة</label><select name="currency"><option>EGP</option><option>USD</option><option>SAR</option></select></div><div class="field"><label>المنطقة الزمنية</label><input name="timezone" value="Africa/Cairo"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">إنشاء الشبكة</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('tenantModal')">إلغاء</button></div></form></dialog>
<dialog id="operatorModal" class="radius-modal"><form id="operatorForm"><h3>إنشاء حساب إداري / عميل</h3><div class="formgrid"><div class="field"><label>اسم الدخول</label><input name="username" required></div><div class="field"><label>كلمة المرور (10 أحرف على الأقل)</label><input name="password" type="password" minlength="10" required></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>البريد</label><input name="email" type="email"></div><div class="field"><label>الهاتف</label><input name="phone"></div><div class="field"><label>الصلاحية</label><select name="role"><option value="network_owner">مالك شبكة</option><option value="reseller">موزع</option><option value="support">دعم فني</option><option value="customer">عميل</option></select></div><div class="field full"><label>معرّف الشبكة UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="يظهر في شاشة الشبكات"></div><div class="field full"><label>اسم مشترك RADIUS المرتبط (لحساب العميل)</label><input name="subscriber_username" placeholder="username من مشتركي الإنترنت"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">إنشاء الحساب</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('operatorModal')">إلغاء</button></div></form></dialog>
<dialog id="resellerModal" class="radius-modal"><form id="resellerForm"><h3>إضافة موزع</h3><div class="formgrid"><div class="field"><label>اسم الدخول</label><input name="username" required></div><div class="field"><label>كلمة المرور</label><input name="password" type="password" minlength="10" required></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>كود الموزع (اختياري)</label><input name="reseller_code"></div><div class="field"><label>عمولة %</label><input type="number" name="commission_percent" min="0" max="100" step=".01" value="0"></div><div class="field"><label>حد ائتماني</label><input type="number" name="credit_limit" min="0" step=".01" value="0"></div><div class="field full"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">حفظ الموزع</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('resellerModal')">إلغاء</button></div></form></dialog>
<dialog id="voucherModal" class="radius-modal"><form id="voucherForm"><h3>إصدار دفعة كروت</h3><div class="formgrid"><div class="field"><label>اسم الدفعة</label><input name="name" value="دفعة جديدة"></div><div class="field"><label>الباقة</label><select name="plan_id" id="voucherPlan" required></select></div><div class="field"><label>العدد (1-1000)</label><input type="number" name="quantity" min="1" max="1000" value="50" required></div><div class="field"><label>بادئة</label><input name="prefix" maxlength="8"></div><div class="field"><label>سعر الكارت</label><input type="number" name="face_value" min="0" step=".01" value="0"></div><div class="field full"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div></div><p class="note">تظهر كلمات مرور الكروت مرة واحدة بعد الإنشاء. نزّل أو اطبع كشف الكروت فورًا.</p><div class="modalfoot"><button class="btn btn-primary" type="submit">إنشاء الكروت</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('voucherModal')">إلغاء</button></div></form></dialog>
<dialog id="invoiceModal" class="radius-modal"><form id="invoiceForm"><h3>إنشاء فاتورة</h3><div class="formgrid"><div class="field"><label>اسم العميل</label><input name="customer_username"></div><div class="field"><label>رقم الفاتورة (اختياري)</label><input name="invoice_number"></div><div class="field"><label>الإجمالي</label><input type="number" name="total" min="0" step=".01" required></div><div class="field"><label>العملة</label><select name="currency"><option>EGP</option><option>USD</option><option>SAR</option></select></div><div class="field"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div><div class="field full"><label>تاريخ الاستحقاق</label><input type="date" name="due_at"></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">إصدار الفاتورة</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('invoiceModal')">إلغاء</button></div></form></dialog>
<dialog id="ticketModal" class="radius-modal"><form id="ticketForm"><h3>فتح تذكرة دعم</h3><div class="formgrid"><div class="field full"><label>الموضوع</label><input name="subject" required></div><div class="field"><label>التصنيف</label><select name="category"><option>technical</option><option>billing</option><option>account</option><option>other</option></select></div><div class="field"><label>الأولوية</label><select name="priority"><option>normal</option><option>low</option><option>high</option><option>urgent</option></select></div><div class="field"><label>Tenant UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="معرّف الشبكة"></div><div class="field full"><label>التفاصيل</label><textarea name="body" required></textarea></div></div><div class="modalfoot"><button class="btn btn-primary" type="submit">إرسال التذكرة</button><button class="btn btn-outline-secondary" type="button" onclick="closeModal('ticketModal')">إلغاء</button></div></form></dialog>
<dialog id="voucherOutput" class="radius-modal"><h3>الكروت التي تم إصدارها</h3><p class="note">احفظ هذا الكشف الآن؛ لا نعرض PIN مرة أخرى بعد إغلاق النافذة.</p><div class="table-responsive tablewrap"><table class="table table-vcenter"><thead><tr><th>اسم المستخدم</th><th>PIN</th></tr></thead><tbody id="voucherOutputTable"></tbody></table></div><div class="modalfoot"><button class="btn btn-primary" onclick="printVouchers()">طباعة</button><button class="btn btn-outline-secondary" onclick="closeModal('voucherOutput')">إغلاق</button></div></dialog>
<script>
var csrf=document.querySelector('meta[name="csrf"]').content;
var role="__ROLE__",username="__USERNAME__",displayName="__DISPLAY__";
var titles={overview:["لوحة المؤشرات","متابعة الشبكات والمشتركين والاستخدام والمبيعات."],networks:["الشبكات والعملاء","إدارة المؤسسات وحسابات مالكي الشبكات."],operators:["المستخدمون الإداريون","حسابات الإدارة والصلاحيات."],users:["مشتركو الإنترنت","إدارة الحسابات والباقات والأجهزة."],plans:["الباقات والسرعات","السرعات والحصص ومحددات الجلسة."],nas:["أجهزة NAS / MikroTik","أجهزة RADIUS المسجلة."],resellers:["الموزعون والمحافظ","إدارة الموزعين والأرصدة والعمولات."],vouchers:["كروت الشحن","إصدار الكروت ومتابعة التفعيل والبيع."],sales:["المبيعات والتحصيل","تقارير العمليات والتحصيل."],invoices:["الفواتير والمدفوعات","الفوترة والمتابعة المالية."],sessions:["الجلسات النشطة","اتصالات المستخدمين الحالية."],logs:["سجل المصادقة","محاولات القبول والرفض."],support:["الدعم الفني","التذاكر ومتابعة طلبات العملاء."],wireguard:["WireGuard / VPN","حالة النفق وبيانات نقاط الاتصال."],audit:["سجل التدقيق","عمليات الإدارة المسجلة."]};
function esc(v){return String(v==null?"—":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function num(v){return Number(v||0).toLocaleString("en-US")}
function dt(v){return v?new Date(v).toLocaleString("ar-EG"):"—"}
function bytes(v){v=Number(v||0);if(v<1024)return num(v)+" B";if(v<1048576)return (v/1024).toFixed(1)+" KB";if(v<1073741824)return (v/1048576).toFixed(1)+" MB";return (v/1073741824).toFixed(2)+" GB"}
function showError(s){var x=document.getElementById("errorBox");x.textContent=s;x.style.display="block";document.getElementById("successBox").style.display="none"}
function showSuccess(s){var x=document.getElementById("successBox");x.textContent=s;x.style.display="block";document.getElementById("errorBox").style.display="none"}
function clearMessages(){document.getElementById("errorBox").style.display="none";document.getElementById("successBox").style.display="none"}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({"Content-Type":"application/json","X-CSRF-Token":csrf},opts.headers||{});var res=await fetch("/radius/api/"+path,opts);var data=await res.json().catch(function(){return {error:"Invalid server response"}});if(res.status===401){location.href="/radius/login";throw new Error("انتهت الجلسة أو بيانات الدخول غير صحيحة.")}if(!res.ok)throw new Error(data.error||data.message||"تعذر تنفيذ الطلب");return data}
function formData(form){var o={};new FormData(form).forEach(function(v,k){if(v!=="")o[k]=v});return o}
function emptyRow(cols,msg){return '<tr><td class="empty" colspan="'+cols+'">'+esc(msg||"لا توجد بيانات بعد")+"</td></tr>"}
function badge(v){var s=String(v||"");var cls=(s==="active"||s==="unused"||s==="paid"||s==="Access-Accept"||s==="open")?"":"off";return '<span class="badge '+cls+'">'+esc(s)+"</span>"}
function openModal(id){document.getElementById(id).showModal()}
function closeModal(id){document.getElementById(id).close()}
function allowedViews(){document.querySelectorAll(".nav button[data-roles]").forEach(function(b){var list=b.dataset.roles.split(",");b.style.display=list.indexOf(role)>=0?"block":"none"})}
function showView(v){document.querySelectorAll(".section").forEach(function(s){s.classList.remove("show")});document.getElementById(v).classList.add("show");document.querySelectorAll(".nav button[data-view]").forEach(function(b){b.classList.toggle("active",b.dataset.view===v)});document.getElementById("viewTitle").textContent=titles[v][0];document.getElementById("viewDesc").textContent=titles[v][1];clearMessages();loadView(v)}
document.querySelectorAll(".nav button[data-view]").forEach(function(b){b.addEventListener("click",function(){showView(b.dataset.view)})});
document.querySelectorAll("[data-action]").forEach(function(b){b.addEventListener("click",function(){var a=b.dataset.action;if(a==="new-nas"){newNas();return}var map={"new-user":"userModal","new-plan":"planModal","new-tenant":"tenantModal","new-operator":"operatorModal","new-reseller":"resellerModal","new-voucher":"voucherModal","new-invoice":"invoiceModal","new-ticket":"ticketModal"};if(map[a])openModal(map[a])})});
async function loadHealth(){var el=document.getElementById("serviceStatus");try{var x=await api("health");el.innerHTML='<span style="color:#55d6b6">● Supabase API متصل</span><br>قاعدة البيانات: '+esc(x.database)+'<br>سجلات المصادقة: '+num(x.radcheck_rows)}catch(e){el.textContent=e.message}}
async function loadOverview(){try{var x=await api("overview");document.getElementById("mUsers").textContent=num(x.subscribers);document.getElementById("mSessions").textContent=num(x.active_sessions);document.getElementById("mNas").textContent=num(x.nas_count);document.getElementById("mAccept").textContent=num(x.accepts_today);document.getElementById("mReject").textContent=num(x.rejects_today);document.getElementById("mPlans").textContent=num(x.active_plans);var logs=await api("logs");document.getElementById("recentLogs").innerHTML=logs.slice(0,6).map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+badge(z.reply)+"</td><td>"+esc(dt(z.authdate))+"</td><td>"+esc(z.callingstationid)+"</td></tr>"}).join("")||emptyRow(4)}catch(e){showError(e.message)}}
async function loadUsers(){try{var x=await api("users");document.getElementById("usersTable").innerHTML=x.map(function(z){return "<tr><td><b>"+esc(z.username)+"</b></td><td>"+esc(z.display_name)+"</td><td>"+esc(z.plan&&z.plan.name)+"</td><td>"+esc(z.plan&&z.plan.download_mbps)+" / "+esc(z.plan&&z.plan.upload_mbps)+" Mbps</td><td>"+badge(z.enabled?"active":"disabled")+" "+(z.online?"<span class='badge'>online</span>":"")+"</td><td>"+num(z.max_devices)+"</td><td>"+esc(dt(z.expires_at))+"</td><td><button class='btn' onclick='userAction(\"disable\",\""+esc(z.username)+"\")'>إيقاف</button></td></tr>"}).join("")||emptyRow(8);var p=await api("plans");var o='<option value="">بدون باقة</option>'+p.map(function(t){return '<option value="'+t.id+'">'+esc(t.name)+" — "+num(t.download_mbps)+"/"+num(t.upload_mbps)+"</option>"}).join("");document.getElementById("userPlan").innerHTML=o;document.getElementById("voucherPlan").innerHTML=o}catch(e){showError(e.message)}}
async function userAction(action,name){try{await api("users/action",{method:"POST",body:JSON.stringify({action:action,username:name})});showSuccess("تم تحديث حالة المشترك");loadUsers()}catch(e){showError(e.message)}}
async function loadPlans(){try{var x=await api("plans");document.getElementById("plansTable").innerHTML=x.map(function(z){return "<tr><td><b>"+esc(z.name)+"</b></td><td>"+num(z.download_mbps)+" Mbps</td><td>"+num(z.upload_mbps)+" Mbps</td><td>"+(z.quota_mb?num(z.quota_mb)+" MB":"غير محدودة")+"</td><td>"+(z.session_timeout?num(z.session_timeout)+" ثانية":"—")+"</td><td>"+num(z.price)+"</td><td>"+badge(z.enabled?"active":"disabled")+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
var nasCache=[];
function nasIsPortwarp(z){return z.transport_mode==="portwarp"||z.nasname==="127.0.0.1"||z.nasname==="127.0.0.1/32"}
function loadNasStatus(message,isError){var e=document.getElementById("nasSyncStatus");if(!e)return;e.textContent=message;e.style.color=isError?"#ffb0b7":"#91dbc8"}
async function loadNasTenants(selected){var field=document.getElementById("nasTenantField"),select=document.getElementById("nasTenant");field.style.display=role==="super_admin"?"block":"none";if(role!=="super_admin")return;var rows=await api("tenants");select.innerHTML='<option value="">اختر الشبكة</option>'+rows.map(function(t){return '<option value="'+esc(t.id)+'">'+esc(t.name)+' — '+esc(t.slug)+'</option>'}).join("");if(selected)select.value=selected;else if(rows.length===1)select.value=rows[0].id}
async function loadNas(){try{var x=await api("nas");nasCache=Array.isArray(x)?x:[];document.getElementById("nasTable").innerHTML=nasCache.map(function(z){var id=Number(z.id),mode=nasIsPortwarp(z)?"Portwarp UDP":"Direct IPv4",secretState=z.secret_configured===false?"غير مضبوط":"مخزن • مخفي";return "<tr><td>"+badge(mode)+"</td><td dir='ltr'>"+esc(z.nasname)+"</td><td>"+esc(z.shortname)+"</td><td>"+esc(z.type)+"</td><td>"+badge(secretState)+"</td><td>"+esc(z.description)+"</td><td><div class='quick'><button class='btn' onclick='editNas("+id+")'>تعديل</button><button class='btn danger' onclick='nasAction(\"delete\","+id+")'>حذف</button></div></td></tr>"}).join("")||emptyRow(7);var pw=nasCache.filter(nasIsPortwarp).length;loadNasStatus("عدد NAS: "+nasCache.length+" • Portwarp ingress: "+pw+" • المفاتيح مخفية في الجدول.",false)}catch(e){showError(e.message);loadNasStatus(e.message,true)}}
function updateNasTransport(){var f=document.getElementById("nasForm"),portwarp=f.elements.transport_mode.value==="portwarp",a=f.elements.nasname,h=document.getElementById("nasTransportHint"),id=Number(f.elements.id.value||0),otherPortwarp=nasCache.some(function(z){return nasIsPortwarp(z)&&Number(z.id)!==id});a.value=portwarp?"127.0.0.1":(a.value==="127.0.0.1"?"":a.value);a.readOnly=portwarp;h.textContent=portwarp?(otherPortwarp?"يوجد بالفعل Portwarp NAS. عدّل السجل الموجود بدلًا من إضافة سجل ثانٍ.":"Portwarp يمرر المصدر إلى السيرفر كـ 127.0.0.1. يستخدم هذا المسار تعريفًا واحدًا ومفتاحًا واحدًا."):"أدخل عنوان IPv4 أو CIDR لمصدر الحزم الذي يصل فعليًا إلى FreeRADIUS بعد NAT."}
function generateNasSecret(){var a=new Uint8Array(32);crypto.getRandomValues(a);document.getElementById("nasSecret").value=Array.from(a,function(b){return b.toString(16).padStart(2,"0")}).join("")}
function toggleNasSecret(){var e=document.getElementById("nasSecret");e.type=e.type==="password"?"text":"password"}
async function newNas(){var f=document.getElementById("nasForm");f.reset();f.elements.id.value="";f.elements.secret.required=true;document.getElementById("nasFormTitle").textContent="إضافة جهاز NAS";var hasPortwarp=nasCache.some(nasIsPortwarp);f.elements.transport_mode.value=hasPortwarp?"direct":"portwarp";f.elements.nasname.value=hasPortwarp?"":"127.0.0.1";f.elements.nasname.readOnly=!hasPortwarp;document.getElementById("nasSecret").type="password";generateNasSecret();document.getElementById("nasSecretHint").textContent="تم توليد مفتاح عشوائي بطول 64 خانة (256-bit). سيظهر مرة واحدة بعد الحفظ.";await loadNasTenants();updateNasTransport();openModal("nasModal")}
async function editNas(id){var z=nasCache.find(function(x){return Number(x.id)===Number(id)});if(!z)return;var f=document.getElementById("nasForm");f.reset();f.elements.id.value=z.id;f.elements.transport_mode.value=nasIsPortwarp(z)?"portwarp":"direct";f.elements.nasname.value=z.nasname;f.elements.shortname.value=z.shortname;f.elements.type.value=z.type||"other";f.elements.description.value=z.description||"";f.elements.secret.value="";f.elements.secret.required=false;document.getElementById("nasFormTitle").textContent="تعديل جهاز NAS";document.getElementById("nasSecretHint").textContent="اترك المفتاح فارغًا للاحتفاظ بالحالي، أو ولّد مفتاحًا جديدًا لتدويره.";document.getElementById("nasSecret").type="password";await loadNasTenants(z.tenant_id||"");updateNasTransport();openModal("nasModal")}
async function copyNasSecret(){var e=document.getElementById("nasSecretShown");try{await navigator.clipboard.writeText(e.value);showSuccess("تم نسخ المفتاح")}catch(_){e.select();document.execCommand("copy");showSuccess("تم نسخ المفتاح")}}
async function syncNas(){try{loadNasStatus("جارٍ توليد إعدادات NAS والتحقق من FreeRADIUS…",false);var x=await api("nas/sync",{method:"POST",body:"{}"});if(!x.ok)throw new Error(x.error||x.message||"فشلت مزامنة RADIUS");loadNasStatus("نجحت المزامنة. "+(x.generator||"")+" • "+(x.validation||"تم فحص الإعداد."),false);showSuccess("تم تطبيق إعدادات NAS على FreeRADIUS")}catch(e){loadNasStatus(e.message,true);showError(e.message)}}
async function nasAction(action,id){if(action!=="delete"||!confirm("سيتم حذف سجل NAS وإعادة توليد إعدادات FreeRADIUS. هل تريد المتابعة؟"))return;try{var x=await api("nas/delete",{method:"POST",body:JSON.stringify({id:id})});if(x.radius_sync&&!x.radius_sync.ok){loadNasStatus("تم حذف السجل لكن فشلت مزامنة FreeRADIUS: "+x.radius_sync.error,true);showError("تم حذف NAS لكن يلزم فحص إعداد RADIUS.")}else{showSuccess("تم حذف NAS وتحديث إعدادات RADIUS");loadNasStatus("تم حذف NAS وإعادة تشغيل خدمة FreeRADIUS.",false)}loadNas()}catch(e){showError(e.message);loadNas()}}
document.getElementById("nasForm").addEventListener("submit",async function(e){e.preventDefault();var f=e.currentTarget;try{var d=formData(f),id=d.id,secret=String(d.secret||"").trim();if(!id&&!secret)throw new Error("يجب إنشاء Shared Secret.");if(secret&&secret.length<32)throw new Error("Shared Secret يجب أن يكون 32 حرفًا على الأقل.");if(d.transport_mode==="portwarp"){if(nasCache.some(function(z){return nasIsPortwarp(z)&&Number(z.id)!==Number(id||0)}))throw new Error("يوجد بالفعل Portwarp NAS. افتح السجل الموجود وعدّله بدلًا من إنشاء سجل ثانٍ.");d.nasname="127.0.0.1"}if(d.transport_mode==="direct"&&!d.nasname)throw new Error("أدخل عنوان IPv4 أو CIDR.");if(role==="super_admin"&&!d.tenant_id)throw new Error("اختر الشبكة المالكة لجهاز NAS.");var path=id?"nas/update":"nas";var x=await api(path,{method:"POST",body:JSON.stringify(d)});closeModal("nasModal");var synced=!!(x.radius_sync&&x.radius_sync.ok);if(!synced){loadNasStatus("تم حفظ NAS لكن مزامنة FreeRADIUS لم تكتمل. لا تستخدم المفتاح الجديد في الراوتر قبل نجاح المزامنة. "+((x.radius_sync&&x.radius_sync.error)||""),true);showError("تم حفظ NAS في قاعدة البيانات لكن لم يتم تطبيق الإعداد على FreeRADIUS.")}else{loadNasStatus("تم حفظ NAS والتحقق من الإعداد وإعادة تشغيل FreeRADIUS.",false);showSuccess("تم حفظ NAS وتطبيق إعداد RADIUS بنجاح")}if(secret){document.getElementById("nasSecretShown").value=secret;document.getElementById("nasSecretOutputNote").textContent=synced?"انسخ المفتاح واضبط القيمة نفسها في MikroTik. لن يمكن استعادته من الواجهة بعد إغلاق النافذة.":"المفتاح محفوظ، لكن مزامنة FreeRADIUS فشلت. لا تستخدمه في MikroTik حتى إصلاح المزامنة.";openModal("nasSecretOutput")}f.reset();loadNas()}catch(err){showError(err.message)}});async function loadSessions(){try{var x=await api("sessions");document.getElementById("sessionsTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+esc(z.framedipaddress)+"</td><td>"+esc(z.nasipaddress)+"</td><td>"+esc(dt(z.acctstarttime))+"</td><td>"+num(z.acctsessiontime)+" s</td><td>"+bytes(z.acctinputoctets)+"</td><td>"+bytes(z.acctoutputoctets)+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
async function loadLogs(){try{var x=await api("logs");document.getElementById("logsTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+badge(z.reply)+"</td><td>"+esc(dt(z.authdate))+"</td><td>"+esc(z.callingstationid)+"</td><td>"+esc(z.calledstationid)+"</td></tr>"}).join("")||emptyRow(5)}catch(e){showError(e.message)}}
async function loadNetworks(){try{var x=await api("tenants");document.getElementById("networksTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.name)+"</td><td>"+esc(z.slug)+"</td><td><code>"+esc(z.id)+"</code></td><td>"+esc(z.plan_code)+"</td><td>"+badge(z.status)+"</td><td>"+esc(z.currency)+"</td><td>"+esc(dt(z.created_at))+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
async function loadOperators(){try{var x=await api("operators");document.getElementById("operatorsTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+esc(z.display_name)+"</td><td>"+esc(z.role)+"</td><td>"+esc(z.tenant_id)+"</td><td>"+esc(z.email)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.last_login_at))+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
async function loadResellers(){try{var x=await api("resellers");document.getElementById("resellersTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.operators&&z.operators.username)+"</td><td>"+esc(z.reseller_code)+"</td><td>"+num(z.commission_percent)+"%</td><td>"+num(z.wallet_balance)+"</td><td>"+num(z.credit_limit)+"</td><td>"+badge(z.status)+"</td></tr>"}).join("")||emptyRow(6);var w=await api("wallet");document.getElementById("walletTable").innerHTML=w.map(function(z){return "<tr><td>"+esc(z.reseller_id)+"</td><td>"+esc(z.direction)+"</td><td>"+num(z.amount)+"</td><td>"+num(z.balance_after)+"</td><td>"+esc(dt(z.created_at))+"</td></tr>"}).join("")||emptyRow(5)}catch(e){showError(e.message)}}
async function loadVouchers(){try{var x=await api("vouchers");document.getElementById("vouchersTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+esc(z.pin_last4)+"</td><td>"+esc(z.plan_id)+"</td><td>"+num(z.face_value)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.created_at))+"</td></tr>"}).join("")||emptyRow(6)}catch(e){showError(e.message)}}
async function loadSales(){try{var x=await api("sales");document.getElementById("salesTable").innerHTML=x.map(function(z){return "<tr><td>"+num(z.id)+"</td><td>"+esc(z.reseller_id)+"</td><td>"+esc(z.customer_username)+"</td><td>"+num(z.gross_amount)+"</td><td>"+num(z.commission_amount)+"</td><td>"+esc(z.payment_method)+"</td><td>"+badge(z.payment_status)+"</td><td>"+esc(dt(z.created_at))+"</td></tr>"}).join("")||emptyRow(8)}catch(e){showError(e.message)}}
async function loadInvoices(){try{var x=await api("invoices");document.getElementById("invoicesTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.invoice_number)+"</td><td>"+esc(z.customer_username)+"</td><td>"+num(z.total)+"</td><td>"+esc(z.currency)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.due_at))+"</td><td>"+esc(dt(z.paid_at))+"</td></tr>"}).join("")||emptyRow(7);var p=await api("payments");document.getElementById("paymentsTable").innerHTML=p.map(function(z){return "<tr><td>"+esc(z.invoice_id)+"</td><td>"+num(z.amount)+"</td><td>"+esc(z.method)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.received_at))+"</td></tr>"}).join("")||emptyRow(5)}catch(e){showError(e.message)}}
async function loadTickets(){try{var x=await api("tickets");document.getElementById("ticketsTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.subject)+"</td><td>"+esc(z.category)+"</td><td>"+badge(z.priority)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.updated_at))+"</td></tr>"}).join("")||emptyRow(5)}catch(e){showError(e.message)}}
async function loadWireguard(){try{var x=await api("wireguard/peers");document.getElementById("wireguardTable").innerHTML=(x.peers||[]).map(function(z){return "<tr><td>"+esc(z.name)+"</td><td>"+esc(String(z.public_key).slice(0,14))+"…</td><td>"+esc(z.assigned_ip)+"</td><td>"+badge(z.status)+"</td><td>"+esc(dt(z.last_handshake_at))+"</td></tr>"}).join("")||emptyRow(5);showError(x.reason||"")}catch(e){showError(e.message)}}
async function loadAudit(){try{var x=await api("audit");document.getElementById("auditTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.actor)+"</td><td>"+esc(z.action)+"</td><td>"+esc(z.entity_type)+"</td><td>"+esc(z.entity_id)+"</td><td>"+esc(JSON.stringify(z.details||{}))+"</td><td>"+esc(dt(z.created_at))+"</td></tr>"}).join("")||emptyRow(6)}catch(e){showError(e.message)}}
async function loadCustomer(){try{var x=await api("overview");document.getElementById("customerCard").style.display="flex";document.getElementById("metrics").style.display="none";document.getElementById("customerUser").textContent=x.username||username;document.getElementById("customerPlan").textContent=(x.plan&&x.plan.name)||"بدون باقة";document.getElementById("customerStatus").textContent=x.enabled?"نشط":"موقوف"}catch(e){showError(e.message)}}
function loadView(v){if(v==="overview"){if(role==="customer")loadCustomer();else{document.getElementById("customerCard").style.display="none";document.getElementById("metrics").style.display="grid";loadOverview();loadHealth()}}if(v==="networks")loadNetworks();if(v==="operators")loadOperators();if(v==="users")loadUsers();if(v==="plans")loadPlans();if(v==="nas")loadNas();if(v==="resellers")loadResellers();if(v==="vouchers")loadVouchers();if(v==="sales")loadSales();if(v==="invoices")loadInvoices();if(v==="sessions")loadSessions();if(v==="logs")loadLogs();if(v==="support")loadTickets();if(v==="wireguard")loadWireguard();if(v==="audit")loadAudit()}
async function submitForm(id,path,method,success){var f=document.getElementById(id);f.addEventListener("submit",async function(e){e.preventDefault();try{var data=formData(f);if(data.expires_at)data.expires_at=new Date(data.expires_at).toISOString();var result=await api(path,{method:method,body:JSON.stringify(data)});closeModal(id.replace("Form","Modal"));f.reset();showSuccess(success);if(path==="vouchers"&&result.vouchers){document.getElementById("voucherOutputTable").innerHTML=result.vouchers.map(function(v){return "<tr><td>"+esc(v.username)+"</td><td>"+esc(v.pin)+"</td></tr>"}).join("");openModal("voucherOutput")}loadView(document.querySelector(".section.show").id)}catch(err){showError(err.message)}})}
submitForm("userForm","users","POST","تم حفظ المشترك");
submitForm("planForm","plans","POST","تم إنشاء الباقة");
submitForm("tenantForm","tenants","POST","تم إنشاء الشبكة");
submitForm("operatorForm","operators","POST","تم إنشاء الحساب");
submitForm("resellerForm","resellers","POST","تم إنشاء الموزع");
submitForm("voucherForm","vouchers","POST","تم إنشاء دفعة الكروت");
submitForm("invoiceForm","invoices","POST","تم إصدار الفاتورة");
submitForm("ticketForm","tickets","POST","تم فتح تذكرة الدعم");
function printVouchers(){var content="<html><head><meta charset='utf-8'><title>Voucher batch</title><style>body{font-family:Arial;direction:rtl}table{width:100%;border-collapse:collapse}td,th{border:1px solid #888;padding:8px;text-align:center}</style></head><body><h2>كروت الإنترنت</h2><table class="table table-vcenter"><tr><th>اسم المستخدم</th><th>PIN</th></tr>"+document.getElementById("voucherOutputTable").innerHTML+"</table></body></html>";var w=window.open("","_blank");w.document.write(content);w.document.close();w.print()}
allowedViews();loadView("overview");
</script><script src="/radius/assets/tabler.min.js"></script></body></html>"""


routes = [
    Route("/radius", dashboard, methods=["GET"]),
    Route("/radius/", dashboard, methods=["GET"]),
    Route("/radius/login", login_page, methods=["GET"]),
    Route("/radius/login", login_submit, methods=["POST"]),
    Route("/radius/logout", logout, methods=["POST"]),
    Route("/radius/api/health", api_health, methods=["GET"]),
    Route("/radius/api/overview", api_overview, methods=["GET"]),
    Route("/radius/api/users", api_users, methods=["GET","POST"]),
    Route("/radius/api/users/action", api_user_action, methods=["POST"]),
    Route("/radius/api/plans", api_plans, methods=["GET","POST"]),
    Route("/radius/api/nas", api_nas, methods=["GET","POST"]),
    Route("/radius/api/nas/update", api_nas_update, methods=["POST"]),
    Route("/radius/api/nas/delete", api_nas_delete, methods=["POST"]),
    Route("/radius/api/nas/sync", api_nas_sync, methods=["POST"]),
    Route("/radius/api/sessions", api_sessions, methods=["GET"]),
    Route("/radius/api/logs", api_logs, methods=["GET"]),
    Route("/radius/api/tenants", api_tenants, methods=["GET","POST"]),
    Route("/radius/api/operators", api_operators, methods=["GET","POST"]),
    Route("/radius/api/resellers", api_resellers, methods=["GET","POST"]),
    Route("/radius/api/vouchers", api_vouchers, methods=["GET","POST"]),
    Route("/radius/api/vouchers/sell", api_voucher_sell, methods=["POST"]),
    Route("/radius/api/sales", api_sales, methods=["GET"]),
    Route("/radius/api/wallet", api_wallet, methods=["GET"]),
    Route("/radius/api/invoices", api_invoices, methods=["GET","POST"]),
    Route("/radius/api/payments", api_payments, methods=["GET"]),
    Route("/radius/api/tickets", api_tickets, methods=["GET","POST"]),
    Route("/radius/api/notifications", api_notifications, methods=["GET"]),
    Route("/radius/api/audit", api_audit, methods=["GET"]),
    Route("/radius/api/wireguard/peers", api_wireguard, methods=["GET"]),
    Mount("/radius/assets", app=StaticFiles(directory=str(ASSET_DIR)), name="radius-assets"),
]

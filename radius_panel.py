from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any

import httpx
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

ADMIN_USERNAME = os.environ.get("MCP_ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.environ.get("MCP_ADMIN_PASSWORD_HASH", "")
JWT_SECRET = os.environ.get("MCP_JWT_SECRET", "")
RADIUS_API_URL = os.environ.get("RADIUS_API_URL", "")
RADIUS_API_KEY = os.environ.get("RADIUS_API_KEY", "")
COOKIE_NAME = "radius_panel_session"
CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(12.0, connect=5.0), limits=httpx.Limits(max_connections=12, max_keepalive_connections=6))


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
    if claims.get("operator_id") and "operator_id" not in data:
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
    return await _proxy(request, "health", roles=("super_admin", "network_owner", "reseller", "support"))


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


async def api_nas(request: Request) -> Response:
    if request.method == "GET":
        return await _proxy(request, "nas.list", roles=("super_admin", "network_owner", "support"))
    return await _proxy(request, "nas.create", write=True, roles=("super_admin", "network_owner"))


async def api_nas_delete(request: Request) -> Response:
    return await _proxy(request, "nas.delete", write=True, roles=("super_admin", "network_owner"))


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


DASHBOARD_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radius Control Suite</title><meta name="csrf" content="__CSRF__"><style>
:root{color-scheme:dark;--bg:#081522;--panel:#102236;--panel2:#142a40;--border:#223f57;--muted:#8ba5bb;--text:#eaf2f9;--teal:#20b9a8;--blue:#5389e5;--red:#e96d7c;--gold:#e8b85f;--green:#55c79d}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI",Tahoma,sans-serif}.shell{min-height:100vh;display:grid;grid-template-columns:260px 1fr}.side{background:#0b1a29;border-left:1px solid var(--border);padding:22px 16px;display:flex;flex-direction:column;min-height:100vh}.brand{display:flex;align-items:center;gap:12px;padding:5px 8px 24px;border-bottom:1px solid var(--border)}.mark{width:45px;height:45px;display:grid;place-items:center;border-radius:14px;background:linear-gradient(135deg,#17a99e,#3b70d3);font-weight:900;font-size:22px}.brand strong{display:block;font-size:13px;letter-spacing:.7px}.brand small{color:var(--muted);font-size:10px}.who{margin:15px 3px 12px;padding:12px;border:1px solid var(--border);border-radius:12px;background:#0d2032}.who b{display:block;font-size:12px}.who small{display:block;color:var(--muted);margin-top:5px;font-size:10px}.navlabel{font-size:10px;color:#66839c;font-weight:800;letter-spacing:1.2px;padding:17px 12px 7px}.nav{overflow:auto}.nav button{width:100%;border:0;background:transparent;color:#94acc0;padding:11px 12px;text-align:right;border-radius:10px;margin:2px 0;cursor:pointer;font-size:12px}.nav button.active,.nav button:hover{background:#19354b;color:#f4fbff}.nav button.active{box-shadow:inset -3px 0 var(--teal)}.sidebottom{margin-top:auto;border-top:1px solid var(--border);padding-top:15px}.logout{background:#33202b!important;color:#f19aa5!important}.main{padding:28px 32px;min-width:0}.top{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:24px}.top h1{font-size:24px;margin:0 0 6px}.top p{margin:0;color:var(--muted);font-size:12px}.pill{display:inline-flex;gap:8px;align-items:center;padding:9px 13px;border:1px solid var(--border);border-radius:99px;background:#102437;color:#b1c5d5;font-size:11px}.dot{width:7px;height:7px;background:#3bd0a3;border-radius:50%;box-shadow:0 0 10px #35c79f}.grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}.metric,.panel{background:linear-gradient(145deg,#132a40,#0e1e2e);border:1px solid var(--border);border-radius:15px}.metric{padding:16px;min-height:119px}.metric .label{color:var(--muted);font-size:11px}.metric .value{font-size:27px;font-weight:850;margin:13px 0 4px;letter-spacing:-.6px}.metric .sub{font-size:10px;color:#69869d}.section{display:none}.section.show{display:block}.panel{margin-top:16px;padding:19px}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}.panelhead h2{margin:0;font-size:14px}.panelhead p{margin:5px 0 0;color:var(--muted);font-size:10px}.btn{border:1px solid #31516b;background:#17364d;color:#e7f2fb;border-radius:9px;padding:9px 13px;font-size:11px;cursor:pointer}.btn.primary{background:linear-gradient(100deg,#168f8e,#356fd1);border:0}.btn.danger{background:#402631;border-color:#683a46;color:#ffbbc3}.btn:hover{filter:brightness(1.14)}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;white-space:nowrap}th{text-align:right;color:#7e9ab0;font-weight:700;font-size:10px;padding:11px;border-bottom:1px solid var(--border)}td{padding:12px 11px;border-bottom:1px solid #1d3448;font-size:11px;color:#d4e2ed}tr:last-child td{border-bottom:0}.empty{text-align:center;color:var(--muted);padding:30px!important}.badge{display:inline-block;padding:5px 8px;border-radius:99px;background:#153e3a;color:#71d9bd;font-size:9px}.badge.off{background:#422731;color:#f5a1ad}.badge.warn{background:#42371f;color:#f4d18a}.subgrid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px}.quick{display:flex;gap:8px;flex-wrap:wrap}.statusbox{border-radius:11px;background:#0b1a28;border:1px solid var(--border);padding:13px;color:#a9bdce;font-size:11px;line-height:1.8}.modal{border:1px solid #34516b;background:#102338;color:var(--text);border-radius:17px;width:min(620px,calc(100% - 24px));padding:23px;box-shadow:0 25px 80px #000b}.modal::backdrop{background:#020911bd;backdrop-filter:blur(5px)}.modal h3{margin:0 0 18px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin-bottom:10px}.field label{display:block;font-size:10px;color:#a3b9cb;margin-bottom:7px}.field input,.field select,.field textarea{width:100%;min-height:41px;border:1px solid #304d66;background:#091725;color:#edf6ff;border-radius:9px;padding:8px 10px;font:inherit}.field textarea{min-height:88px}.full{grid-column:1/-1}.modalfoot{display:flex;justify-content:flex-start;gap:8px;margin-top:13px}.note{font-size:10px;color:var(--muted);line-height:1.7}.errorbox{color:#ffadb2;background:#351f2a;border-radius:10px;padding:12px;font-size:11px;display:none}.successbox{color:#80e2c1;background:#123a34;border-radius:10px;padding:12px;font-size:11px;display:none}.loading{color:var(--muted);font-size:11px;padding:20px}.welcome{font-size:13px;color:#a7bdd0;margin-bottom:12px}.mobilemenu{display:none}.kpi{display:flex;justify-content:space-between;gap:12px;color:#9cb3c6;font-size:11px;padding:10px 0;border-bottom:1px solid #1d3448}.kpi b{color:#e8f3fb}.warning{border:1px solid #66542a;background:#2b2619;color:#e9cb88;padding:13px;border-radius:11px;font-size:11px;line-height:1.7}.accountcard{background:linear-gradient(125deg,#14394a,#19315b);border-radius:16px;padding:22px;display:flex;justify-content:space-between;gap:14px;align-items:center}.accountcard .big{font-size:27px;font-weight:900}
@media(max-width:1300px){.grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:880px){.shell{grid-template-columns:1fr}.side{min-height:auto;padding:12px 14px}.brand{padding-bottom:10px}.who,.navlabel,.sidebottom{display:none}.nav{display:flex;gap:3px;overflow:auto}.nav button{white-space:nowrap;width:auto}.main{padding:18px 13px}.top h1{font-size:20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.subgrid{grid-template-columns:1fr}}@media(max-width:520px){.grid{grid-template-columns:1fr 1fr}.metric{padding:12px}.metric .value{font-size:22px}.formgrid{grid-template-columns:1fr}.full{grid-column:auto}.top{align-items:flex-start;flex-direction:column}.accountcard{align-items:flex-start;flex-direction:column}}
</style></head><body><div class="shell"><aside class="side"><div class="brand"><div class="mark">R</div><div><strong>RADIUS CONTROL SUITE</strong><small>ISP • Hotspot • Billing • AAA</small></div></div><div class="who"><b>__DISPLAY__</b><small>__ROLE__ • __USERNAME__</small></div><div class="navlabel">COMMAND CENTER</div><nav class="nav">
<button class="active" data-view="overview">◈　 لوحة المؤشرات</button>
<button data-view="networks" data-roles="super_admin">▦　 الشبكات والعملاء</button>
<button data-view="operators" data-roles="super_admin,network_owner">♙　 المستخدمون الإداريون</button>
<button data-view="users" data-roles="super_admin,network_owner,support">◉　 مشتركو الإنترنت</button>
<button data-view="plans" data-roles="super_admin,network_owner,reseller,customer">▤　 الباقات والسرعات</button>
<button data-view="nas" data-roles="super_admin,network_owner,support">⌁　 أجهزة NAS / MikroTik</button>
<button data-view="resellers" data-roles="super_admin,network_owner">♧　 الموزعون والمحافظ</button>
<button data-view="vouchers" data-roles="super_admin,network_owner,reseller">▣　 كروت الشحن</button>
<button data-view="sales" data-roles="super_admin,network_owner,reseller">◫　 المبيعات والتحصيل</button>
<button data-view="invoices" data-roles="super_admin,network_owner,reseller,customer">▧　 الفواتير والمدفوعات</button>
<button data-view="sessions" data-roles="super_admin,network_owner,support">◉　 الجلسات النشطة</button>
<button data-view="logs" data-roles="super_admin,network_owner,support">≋　 سجل المصادقة</button>
<button data-view="support" data-roles="super_admin,network_owner,reseller,support,customer">✉　 الدعم الفني</button>
<button data-view="wireguard" data-roles="super_admin,network_owner">⌘　 WireGuard / VPN</button>
<button data-view="audit" data-roles="super_admin,network_owner">◷　 سجل التدقيق</button>
</nav><div class="sidebottom"><div class="statusbox">● جلسة إدارية مشفرة<br>الانتهاء التلقائي بعد 8 ساعات.</div><form method="post" action="/radius/logout"><button class="nav logout" style="margin-top:9px">↪　 تسجيل الخروج</button></form></div></aside>
<main class="main"><header class="top"><div><h1 id="viewTitle">لوحة المؤشرات</h1><p id="viewDesc">متابعة الشبكات والمشتركين والاستخدام والمبيعات من مكان واحد.</p></div><div class="pill"><span class="dot"></span> النظام متصل</div></header>
<section id="overview" class="section show"><div class="welcome">مرحبًا، __DISPLAY__</div><div id="customerCard" class="accountcard" style="display:none"><div><div class="note">حساب الإنترنت الخاص بك</div><div class="big" id="customerUser">—</div><div class="note" id="customerPlan">—</div></div><div><div class="note">الحالة</div><span class="badge" id="customerStatus">—</span></div></div><div class="grid" id="metrics">
<div class="metric"><div class="label">المشتركون النشطون</div><div id="mUsers" class="value">—</div><div class="sub">حسابات مفعلة</div></div>
<div class="metric"><div class="label">الجلسات الحالية</div><div id="mSessions" class="value">—</div><div class="sub">اتصالات نشطة</div></div>
<div class="metric"><div class="label">أجهزة NAS</div><div id="mNas" class="value">—</div><div class="sub">أجهزة الشبكة</div></div>
<div class="metric"><div class="label">قبول اليوم</div><div id="mAccept" class="value">—</div><div class="sub">Access-Accept</div></div>
<div class="metric"><div class="label">رفض اليوم</div><div id="mReject" class="value">—</div><div class="sub">Access-Reject</div></div>
<div class="metric"><div class="label">الباقات المفعلة</div><div id="mPlans" class="value">—</div><div class="sub">عروض الإنترنت</div></div></div>
<div class="subgrid"><div class="panel"><div class="panelhead"><div><h2>إجراءات سريعة</h2><p>اختصارات الإدارة اليومية</p></div></div><div class="quick"><button class="btn primary" data-action="new-user">＋ مشترك جديد</button><button class="btn" data-action="new-voucher">＋ إصدار كروت</button><button class="btn" data-action="new-reseller">＋ موزع</button><button class="btn" data-action="new-invoice">＋ فاتورة</button></div></div><div class="panel"><div class="panelhead"><div><h2>صحة الخدمات</h2><p>قاعدة البيانات ومحرك المصادقة</p></div></div><div id="serviceStatus" class="statusbox">جارٍ فحص اتصال Supabase…</div></div></div>
<div class="panel"><div class="panelhead"><div><h2>آخر محاولات المصادقة</h2><button class="btn" onclick="showView('logs')">عرض السجل</button></div></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>القرار</th><th>التوقيت</th><th>الجهاز</th></tr></thead><tbody id="recentLogs"><tr><td class="empty" colspan="4">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="networks" class="section"><div class="panel"><div class="panelhead"><div><h2>الشبكات والعملاء</h2><p>إدارة مالكي الشبكات والاشتراكات متعددة المؤسسات</p></div><button class="btn primary" data-action="new-tenant">＋ إضافة شبكة</button></div><div class="tablewrap"><table><thead><tr><th>اسم الشبكة</th><th>Slug</th><th>Tenant UUID</th><th>الخطة</th><th>الحالة</th><th>العملة</th><th>تاريخ الإنشاء</th></tr></thead><tbody id="networksTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="operators" class="section"><div class="panel"><div class="panelhead"><div><h2>حسابات الإدارة</h2><p>أصحاب الشبكات، المشرفون، الموزعون، والعملاء</p></div><button class="btn primary" data-action="new-operator">＋ حساب جديد</button></div><div class="tablewrap"><table><thead><tr><th>اسم الدخول</th><th>الاسم</th><th>الدور</th><th>الشبكة</th><th>البريد</th><th>الحالة</th><th>آخر دخول</th></tr></thead><tbody id="operatorsTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="users" class="section"><div class="panel"><div class="panelhead"><div><h2>مشتركو الإنترنت</h2><p>الاشتراكات، الماك، الأجهزة، وتحديد السرعة</p></div><button class="btn primary" data-action="new-user">＋ مشترك جديد</button></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>الاسم</th><th>الباقة</th><th>تنزيل / رفع</th><th>الحالة</th><th>الأجهزة</th><th>الانتهاء</th><th>إجراء</th></tr></thead><tbody id="usersTable"><tr><td class="empty" colspan="8">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="plans" class="section"><div class="panel"><div class="panelhead"><div><h2>الباقات والسرعات</h2><p>سرعة التنزيل والرفع والحصة الشهرية والمهلة</p></div><button class="btn primary" data-action="new-plan">＋ باقة جديدة</button></div><div class="tablewrap"><table><thead><tr><th>الباقة</th><th>تنزيل</th><th>رفع</th><th>الحصة</th><th>مدة الجلسة</th><th>السعر</th><th>الحالة</th></tr></thead><tbody id="plansTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="nas" class="section"><div class="panel"><div class="panelhead"><div><h2>أجهزة NAS / MikroTik</h2><p>إدارة عناوين الأجهزة وRADIUS Shared Secret</p></div><button class="btn primary" data-action="new-nas">＋ إضافة NAS</button></div><div class="tablewrap"><table><thead><tr><th>IP / DNS</th><th>الاسم</th><th>النوع</th><th>الوصف</th><th>إجراء</th></tr></thead><tbody id="nasTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="resellers" class="section"><div class="panel"><div class="panelhead"><div><h2>الموزعون والمحافظ</h2><p>العمولات والرصيد وحدود الائتمان</p></div><button class="btn primary" data-action="new-reseller">＋ موزع جديد</button></div><div class="tablewrap"><table><thead><tr><th>الموزع</th><th>الكود</th><th>العمولة</th><th>الرصيد</th><th>الحد الائتماني</th><th>الحالة</th></tr></thead><tbody id="resellersTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div><div class="panel"><div class="panelhead"><h2>حركة المحافظ</h2></div><div class="tablewrap"><table><thead><tr><th>الموزع</th><th>النوع</th><th>المبلغ</th><th>الرصيد بعد العملية</th><th>التوقيت</th></tr></thead><tbody id="walletTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="vouchers" class="section"><div class="panel"><div class="panelhead"><div><h2>كروت الشحن</h2><p>دفعات كروت، أكواد فريدة، طباعة وتوزيع</p></div><button class="btn primary" data-action="new-voucher">＋ إصدار دفعة كروت</button></div><div class="tablewrap"><table><thead><tr><th>الكود</th><th>آخر 4 من PIN</th><th>الباقة</th><th>القيمة</th><th>الحالة</th><th>التاريخ</th></tr></thead><tbody id="vouchersTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="sales" class="section"><div class="panel"><div class="panelhead"><div><h2>المبيعات والتحصيل</h2><p>عمليات بيع الكروت والعمولات وطرق الدفع</p></div></div><div class="tablewrap"><table><thead><tr><th>رقم العملية</th><th>الموزع</th><th>المستخدم</th><th>الإجمالي</th><th>العمولة</th><th>طريقة الدفع</th><th>الحالة</th><th>التاريخ</th></tr></thead><tbody id="salesTable"><tr><td class="empty" colspan="8">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="invoices" class="section"><div class="panel"><div class="panelhead"><div><h2>الفواتير والمدفوعات</h2><p>إصدار فواتير ومتابعة السداد والاستحقاق</p></div><button class="btn primary" data-action="new-invoice">＋ فاتورة جديدة</button></div><div class="tablewrap"><table><thead><tr><th>رقم الفاتورة</th><th>العميل</th><th>الإجمالي</th><th>العملة</th><th>الحالة</th><th>الاستحقاق</th><th>السداد</th></tr></thead><tbody id="invoicesTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div><div class="panel"><div class="panelhead"><h2>سجل المدفوعات</h2></div><div class="tablewrap"><table><thead><tr><th>الفاتورة</th><th>المبلغ</th><th>الوسيلة</th><th>الحالة</th><th>تاريخ الاستلام</th></tr></thead><tbody id="paymentsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="sessions" class="section"><div class="panel"><div class="panelhead"><div><h2>الجلسات النشطة</h2><p>المستخدمون المتصلون وحركة المرور</p></div><button class="btn" onclick="loadSessions()">تحديث</button></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>IP</th><th>NAS</th><th>بداية الجلسة</th><th>المدة</th><th>رفع</th><th>تنزيل</th></tr></thead><tbody id="sessionsTable"><tr><td class="empty" colspan="7">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="logs" class="section"><div class="panel"><div class="panelhead"><div><h2>سجل المصادقة</h2><p>محاولات الدخول والقبول والرفض، دون تسجيل كلمات المرور</p></div><button class="btn" onclick="loadLogs()">تحديث</button></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>القرار</th><th>التوقيت</th><th>Calling Station</th><th>Called Station</th></tr></thead><tbody id="logsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="support" class="section"><div class="panel"><div class="panelhead"><div><h2>الدعم الفني</h2><p>فتح ومتابعة تذاكر الدعم لكل شبكة</p></div><button class="btn primary" data-action="new-ticket">＋ تذكرة جديدة</button></div><div class="tablewrap"><table><thead><tr><th>الموضوع</th><th>التصنيف</th><th>الأولوية</th><th>الحالة</th><th>آخر تحديث</th></tr></thead><tbody id="ticketsTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="wireguard" class="section"><div class="panel"><div class="panelhead"><div><h2>WireGuard / VPN</h2><p>إدارة بيانات الـ peers ومخطط التوصيل الآمن</p></div></div><div class="warning">تنبيه اتصال: تطبيق الويب على CranL لا يملك منفذ UDP عام موثقًا لتشغيل WireGuard Server أو استقبال RADIUS UDP. بيانات الـ peers تحفظ هنا، لكن النفق الفعلي يحتاج VPS بعنوان عام ومنفذ UDP مفتوح، أو منصة تدعم UDP ingress. لن يظهر أي peer كمتصل قبل وجود نقطة WireGuard فعلية.</div><div class="tablewrap" style="margin-top:15px"><table><thead><tr><th>الاسم</th><th>Public Key</th><th>عنوان النفق</th><th>الحالة</th><th>آخر Handshake</th></tr></thead><tbody id="wireguardTable"><tr><td class="empty" colspan="5">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<section id="audit" class="section"><div class="panel"><div class="panelhead"><div><h2>سجل التدقيق</h2><p>تتبع عمليات الإدارة وتغييرات الحسابات</p></div></div><div class="tablewrap"><table><thead><tr><th>المنفذ</th><th>العملية</th><th>نوع الكيان</th><th>المعرف</th><th>التفاصيل</th><th>التاريخ</th></tr></thead><tbody id="auditTable"><tr><td class="empty" colspan="6">جارٍ التحميل</td></tr></tbody></table></div></div></section>
<div id="errorBox" class="errorbox" style="margin-top:14px"></div><div id="successBox" class="successbox" style="margin-top:14px"></div>
</main></div>
<dialog id="userModal" class="modal"><form id="userForm"><h3>إضافة / تعديل مشترك</h3><div class="formgrid"><div class="field"><label>اسم المستخدم *</label><input name="username" required minlength="3"></div><div class="field"><label>كلمة المرور *</label><input name="password" type="password" required minlength="8"></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>الهاتف</label><input name="phone"></div><div class="field"><label>البريد</label><input name="email" type="email"></div><div class="field"><label>الباقة</label><select name="plan_id" id="userPlan"></select></div><div class="field"><label>MAC Binding (اختياري)</label><input name="mac_address" placeholder="AA:BB:CC:DD:EE:FF"></div><div class="field"><label>أقصى أجهزة متزامنة</label><input type="number" name="max_devices" min="1" max="100" value="1"></div><div class="field full"><label>انتهاء الاشتراك</label><input type="datetime-local" name="expires_at"></div></div><div class="modalfoot"><button class="btn primary" type="submit">حفظ المشترك</button><button class="btn" type="button" onclick="closeModal('userModal')">إلغاء</button></div></form></dialog>
<dialog id="planModal" class="modal"><form id="planForm"><h3>إنشاء باقة</h3><div class="formgrid"><div class="field full"><label>اسم الباقة</label><input name="name" required></div><div class="field"><label>تنزيل Mbps</label><input type="number" name="download_mbps" min="1" value="4" required></div><div class="field"><label>رفع Mbps</label><input type="number" name="upload_mbps" min="1" value="4" required></div><div class="field"><label>الحصة MB</label><input type="number" name="quota_mb" min="1"></div><div class="field"><label>Session Timeout (ثانية)</label><input type="number" name="session_timeout" min="1"></div><div class="field"><label>السعر EGP</label><input type="number" name="price" min="0" step=".01" value="0"></div><div class="field full"><label>الوصف</label><input name="description"></div></div><div class="modalfoot"><button class="btn primary" type="submit">حفظ الباقة</button><button class="btn" type="button" onclick="closeModal('planModal')">إلغاء</button></div></form></dialog>
<dialog id="nasModal" class="modal"><form id="nasForm"><h3>إضافة جهاز NAS</h3><div class="formgrid"><div class="field"><label>IP أو DNS</label><input name="nasname" required placeholder="192.168.88.1"></div><div class="field"><label>الاسم</label><input name="shortname" required placeholder="router-01"></div><div class="field"><label>النوع</label><select name="type"><option value="mikrotik">MikroTik</option><option value="wireless">Wireless</option><option value="other">Other</option></select></div><div class="field"><label>RADIUS Shared Secret</label><input name="secret" minlength="24" required></div><div class="field full"><label>الوصف</label><input name="description"></div></div><div class="modalfoot"><button class="btn primary" type="submit">حفظ NAS</button><button class="btn" type="button" onclick="closeModal('nasModal')">إلغاء</button></div></form></dialog>
<dialog id="tenantModal" class="modal"><form id="tenantForm"><h3>إضافة شبكة / مالك شبكة</h3><div class="formgrid"><div class="field"><label>اسم الشبكة</label><input name="name" required></div><div class="field"><label>Slug بالإنجليزية</label><input name="slug" required pattern="[a-z0-9-]{3,50}"></div><div class="field"><label>البريد</label><input name="contact_email" type="email"></div><div class="field"><label>الهاتف</label><input name="contact_phone"></div><div class="field"><label>العملة</label><select name="currency"><option>EGP</option><option>USD</option><option>SAR</option></select></div><div class="field"><label>المنطقة الزمنية</label><input name="timezone" value="Africa/Cairo"></div></div><div class="modalfoot"><button class="btn primary" type="submit">إنشاء الشبكة</button><button class="btn" type="button" onclick="closeModal('tenantModal')">إلغاء</button></div></form></dialog>
<dialog id="operatorModal" class="modal"><form id="operatorForm"><h3>إنشاء حساب إداري / عميل</h3><div class="formgrid"><div class="field"><label>اسم الدخول</label><input name="username" required></div><div class="field"><label>كلمة المرور (10 أحرف على الأقل)</label><input name="password" type="password" minlength="10" required></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>البريد</label><input name="email" type="email"></div><div class="field"><label>الهاتف</label><input name="phone"></div><div class="field"><label>الصلاحية</label><select name="role"><option value="network_owner">مالك شبكة</option><option value="reseller">موزع</option><option value="support">دعم فني</option><option value="customer">عميل</option></select></div><div class="field full"><label>معرّف الشبكة UUID (للأدمن الأعلى)</label><input name="tenant_id" placeholder="يظهر في شاشة الشبكات"></div><div class="field full"><label>اسم مشترك RADIUS المرتبط (لحساب العميل)</label><input name="subscriber_username" placeholder="username من مشتركي الإنترنت"></div></div><div class="modalfoot"><button class="btn primary" type="submit">إنشاء الحساب</button><button class="btn" type="button" onclick="closeModal('operatorModal')">إلغاء</button></div></form></dialog>
<dialog id="resellerModal" class="modal"><form id="resellerForm"><h3>إضافة موزع</h3><div class="formgrid"><div class="field"><label>اسم الدخول</label><input name="username" required></div><div class="field"><label>كلمة المرور</label><input name="password" type="password" minlength="10" required></div><div class="field"><label>الاسم</label><input name="display_name"></div><div class="field"><label>كود الموزع (اختياري)</label><input name="reseller_code"></div><div class="field"><label>عمولة %</label><input type="number" name="commission_percent" min="0" max="100" step=".01" value="0"></div><div class="field"><label>حد ائتماني</label><input type="number" name="credit_limit" min="0" step=".01" value="0"></div></div><div class="modalfoot"><button class="btn primary" type="submit">حفظ الموزع</button><button class="btn" type="button" onclick="closeModal('resellerModal')">إلغاء</button></div></form></dialog>
<dialog id="voucherModal" class="modal"><form id="voucherForm"><h3>إصدار دفعة كروت</h3><div class="formgrid"><div class="field"><label>اسم الدفعة</label><input name="name" value="دفعة جديدة"></div><div class="field"><label>الباقة</label><select name="plan_id" id="voucherPlan" required></select></div><div class="field"><label>العدد (1-1000)</label><input type="number" name="quantity" min="1" max="1000" value="50" required></div><div class="field"><label>بادئة</label><input name="prefix" maxlength="8"></div><div class="field"><label>سعر الكارت</label><input type="number" name="face_value" min="0" step=".01" value="0"></div></div><p class="note">تظهر كلمات مرور الكروت مرة واحدة بعد الإنشاء. نزّل أو اطبع كشف الكروت فورًا.</p><div class="modalfoot"><button class="btn primary" type="submit">إنشاء الكروت</button><button class="btn" type="button" onclick="closeModal('voucherModal')">إلغاء</button></div></form></dialog>
<dialog id="invoiceModal" class="modal"><form id="invoiceForm"><h3>إنشاء فاتورة</h3><div class="formgrid"><div class="field"><label>اسم العميل</label><input name="customer_username"></div><div class="field"><label>رقم الفاتورة (اختياري)</label><input name="invoice_number"></div><div class="field"><label>الإجمالي</label><input type="number" name="total" min="0" step=".01" required></div><div class="field"><label>العملة</label><select name="currency"><option>EGP</option><option>USD</option><option>SAR</option></select></div><div class="field full"><label>تاريخ الاستحقاق</label><input type="date" name="due_at"></div></div><div class="modalfoot"><button class="btn primary" type="submit">إصدار الفاتورة</button><button class="btn" type="button" onclick="closeModal('invoiceModal')">إلغاء</button></div></form></dialog>
<dialog id="ticketModal" class="modal"><form id="ticketForm"><h3>فتح تذكرة دعم</h3><div class="formgrid"><div class="field full"><label>الموضوع</label><input name="subject" required></div><div class="field"><label>التصنيف</label><select name="category"><option>technical</option><option>billing</option><option>account</option><option>other</option></select></div><div class="field"><label>الأولوية</label><select name="priority"><option>normal</option><option>low</option><option>high</option><option>urgent</option></select></div><div class="field full"><label>التفاصيل</label><textarea name="body" required></textarea></div></div><div class="modalfoot"><button class="btn primary" type="submit">إرسال التذكرة</button><button class="btn" type="button" onclick="closeModal('ticketModal')">إلغاء</button></div></form></dialog>
<dialog id="voucherOutput" class="modal"><h3>الكروت التي تم إصدارها</h3><p class="note">احفظ هذا الكشف الآن؛ لا نعرض PIN مرة أخرى بعد إغلاق النافذة.</p><div class="tablewrap"><table><thead><tr><th>اسم المستخدم</th><th>PIN</th></tr></thead><tbody id="voucherOutputTable"></tbody></table></div><div class="modalfoot"><button class="btn primary" onclick="printVouchers()">طباعة</button><button class="btn" onclick="closeModal('voucherOutput')">إغلاق</button></div></dialog>
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
document.querySelectorAll("[data-action]").forEach(function(b){b.addEventListener("click",function(){var a=b.dataset.action;var map={"new-user":"userModal","new-plan":"planModal","new-nas":"nasModal","new-tenant":"tenantModal","new-operator":"operatorModal","new-reseller":"resellerModal","new-voucher":"voucherModal","new-invoice":"invoiceModal","new-ticket":"ticketModal"};if(map[a])openModal(map[a])})});
async function loadHealth(){var el=document.getElementById("serviceStatus");try{var x=await api("health");el.innerHTML='<span style="color:#55d6b6">● Supabase API متصل</span><br>قاعدة البيانات: '+esc(x.database)+'<br>سجلات المصادقة: '+num(x.radcheck_rows)}catch(e){el.textContent=e.message}}
async function loadOverview(){try{var x=await api("overview");document.getElementById("mUsers").textContent=num(x.subscribers);document.getElementById("mSessions").textContent=num(x.active_sessions);document.getElementById("mNas").textContent=num(x.nas_count);document.getElementById("mAccept").textContent=num(x.accepts_today);document.getElementById("mReject").textContent=num(x.rejects_today);document.getElementById("mPlans").textContent=num(x.active_plans);var logs=await api("logs");document.getElementById("recentLogs").innerHTML=logs.slice(0,6).map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+badge(z.reply)+"</td><td>"+esc(dt(z.authdate))+"</td><td>"+esc(z.callingstationid)+"</td></tr>"}).join("")||emptyRow(4)}catch(e){showError(e.message)}}
async function loadUsers(){try{var x=await api("users");document.getElementById("usersTable").innerHTML=x.map(function(z){return "<tr><td><b>"+esc(z.username)+"</b></td><td>"+esc(z.display_name)+"</td><td>"+esc(z.plan&&z.plan.name)+"</td><td>"+esc(z.plan&&z.plan.download_mbps)+" / "+esc(z.plan&&z.plan.upload_mbps)+" Mbps</td><td>"+badge(z.enabled?"active":"disabled")+" "+(z.online?"<span class='badge'>online</span>":"")+"</td><td>"+num(z.max_devices)+"</td><td>"+esc(dt(z.expires_at))+"</td><td><button class='btn' onclick='userAction(\"disable\",\""+esc(z.username)+"\")'>إيقاف</button></td></tr>"}).join("")||emptyRow(8);var p=await api("plans");var o='<option value="">بدون باقة</option>'+p.map(function(t){return '<option value="'+t.id+'">'+esc(t.name)+" — "+num(t.download_mbps)+"/"+num(t.upload_mbps)+"</option>"}).join("");document.getElementById("userPlan").innerHTML=o;document.getElementById("voucherPlan").innerHTML=o}catch(e){showError(e.message)}}
async function userAction(action,name){try{await api("users/action",{method:"POST",body:JSON.stringify({action:action,username:name})});showSuccess("تم تحديث حالة المشترك");loadUsers()}catch(e){showError(e.message)}}
async function loadPlans(){try{var x=await api("plans");document.getElementById("plansTable").innerHTML=x.map(function(z){return "<tr><td><b>"+esc(z.name)+"</b></td><td>"+num(z.download_mbps)+" Mbps</td><td>"+num(z.upload_mbps)+" Mbps</td><td>"+(z.quota_mb?num(z.quota_mb)+" MB":"غير محدودة")+"</td><td>"+(z.session_timeout?num(z.session_timeout)+" ثانية":"—")+"</td><td>"+num(z.price)+"</td><td>"+badge(z.enabled?"active":"disabled")+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
async function loadNas(){try{var x=await api("nas");document.getElementById("nasTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.nasname)+"</td><td>"+esc(z.shortname)+"</td><td>"+esc(z.type)+"</td><td>"+esc(z.description)+"</td><td>"+badge("registered")+"</td></tr>"}).join("")||emptyRow(5)}catch(e){showError(e.message)}}
async function loadSessions(){try{var x=await api("sessions");document.getElementById("sessionsTable").innerHTML=x.map(function(z){return "<tr><td>"+esc(z.username)+"</td><td>"+esc(z.framedipaddress)+"</td><td>"+esc(z.nasipaddress)+"</td><td>"+esc(dt(z.acctstarttime))+"</td><td>"+num(z.acctsessiontime)+" s</td><td>"+bytes(z.acctinputoctets)+"</td><td>"+bytes(z.acctoutputoctets)+"</td></tr>"}).join("")||emptyRow(7)}catch(e){showError(e.message)}}
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
submitForm("nasForm","nas","POST","تم تسجيل جهاز NAS");
submitForm("tenantForm","tenants","POST","تم إنشاء الشبكة");
submitForm("operatorForm","operators","POST","تم إنشاء الحساب");
submitForm("resellerForm","resellers","POST","تم إنشاء الموزع");
submitForm("voucherForm","vouchers","POST","تم إنشاء دفعة الكروت");
submitForm("invoiceForm","invoices","POST","تم إصدار الفاتورة");
submitForm("ticketForm","tickets","POST","تم فتح تذكرة الدعم");
function printVouchers(){var content="<html><head><meta charset='utf-8'><title>Voucher batch</title><style>body{font-family:Arial;direction:rtl}table{width:100%;border-collapse:collapse}td,th{border:1px solid #888;padding:8px;text-align:center}</style></head><body><h2>كروت الإنترنت</h2><table><tr><th>اسم المستخدم</th><th>PIN</th></tr>"+document.getElementById("voucherOutputTable").innerHTML+"</table></body></html>";var w=window.open("","_blank");w.document.write(content);w.document.close();w.print()}
allowedViews();loadView("overview");
</script></body></html>"""


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
    Route("/radius/api/nas/delete", api_nas_delete, methods=["POST"]),
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
]

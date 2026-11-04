from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

ADMIN_USERNAME = os.environ.get("MCP_ADMIN_USERNAME", "")
ADMIN_PASSWORD_HASH = os.environ.get("MCP_ADMIN_PASSWORD_HASH", "")
JWT_SECRET = os.environ.get("MCP_JWT_SECRET", "")
COOKIE_NAME = "radius_panel_session"
_pool: asyncpg.Pool | None = None


def _password_ok(username: str, password: str) -> bool:
    if not hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode()):
        return False
    try:
        algorithm, iterations_text, salt_hex, expected_hex = ADMIN_PASSWORD_HASH.split("$", 3)
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 300000 <= iterations <= 2000000:
            return False
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), iterations, dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _session(request: Request) -> dict[str, Any] | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token or not JWT_SECRET:
        return None
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if claims.get("scope") != "radius.panel" or claims.get("sub") != ADMIN_USERNAME:
            return None
        return claims
    except jwt.PyJWTError:
        return None


def _json(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})


async def _db() -> asyncpg.Pool:
    global _pool
    if _pool is not None:
        return _pool
    dsn = os.environ.get("SUPABASE_DATABASE_URL", "").strip()
    if not dsn:
        raise RuntimeError("SUPABASE_DATABASE_URL is not configured")
    parts = urlsplit(dsn)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.pop("sslmode", None)
    query.pop("ssl", None)
    clean_dsn = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
    _pool = await asyncpg.create_pool(
        dsn=clean_dsn,
        min_size=1,
        max_size=3,
        ssl="require",
        server_settings={"search_path": "radius,public", "application_name": "debian-radius-panel"},
        command_timeout=8,
    )
    return _pool


def _authorized(request: Request, write: bool = False) -> tuple[dict[str, Any] | None, Response | None]:
    claims = _session(request)
    if not claims:
        return None, _json({"error": "authentication_required"}, 401)
    if write and not hmac.compare_digest(
        str(request.headers.get("x-csrf-token", "")), str(claims.get("csrf", ""))
    ):
        return None, _json({"error": "csrf_failed"}, 403)
    return claims, None


async def login_page(request: Request) -> Response:
    if _session(request):
        return RedirectResponse("/radius/", status_code=303)
    return HTMLResponse(LOGIN_HTML, headers={"Cache-Control": "no-store"})


async def login_submit(request: Request) -> Response:
    try:
        form = await request.form()
    except Exception:
        return HTMLResponse(LOGIN_HTML.replace("<!--ERROR-->", '<p class="error">بيانات الدخول غير صحيحة</p>'), status_code=400)
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    if len(password) > 512 or not _password_ok(username, password):
        return HTMLResponse(LOGIN_HTML.replace("<!--ERROR-->", '<p class="error">اسم المستخدم أو كلمة المرور غير صحيحة</p>'), status_code=401)
    csrf = os.urandom(24).hex()
    now = int(time.time())
    token = jwt.encode(
        {"sub": ADMIN_USERNAME, "scope": "radius.panel", "csrf": csrf, "iat": now, "exp": now + 8 * 3600},
        JWT_SECRET,
        algorithm="HS256",
    )
    response = RedirectResponse("/radius/", status_code=303)
    response.set_cookie(
        COOKIE_NAME, token, max_age=8 * 3600, httponly=True, secure=True,
        samesite="strict", path="/radius"
    )
    return response


async def logout(request: Request) -> Response:
    response = RedirectResponse("/radius", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/radius", secure=True, httponly=True, samesite="strict")
    return response


async def dashboard(request: Request) -> Response:
    claims = _session(request)
    if not claims:
        return RedirectResponse("/radius/login", status_code=303)
    page = DASHBOARD_HTML.replace("__CSRF__", str(claims.get("csrf", "")))
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


async def api_health(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            row = await con.fetchrow("SELECT current_database() AS database, current_user AS role, now() AS server_time")
        return _json({"ok": True, "database": row["database"], "role": row["role"], "server_time": row["server_time"].isoformat()})
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)[:240], "setup_required": "SUPABASE_DATABASE_URL" not in os.environ}, 503)


async def api_overview(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            row = await con.fetchrow("""
                SELECT
                  (SELECT count(*) FROM radius.subscriber_meta WHERE enabled) AS subscribers,
                  (SELECT count(*) FROM radius.nas) AS nas_count,
                  (SELECT count(*) FROM radius.radacct WHERE acctstoptime IS NULL) AS active_sessions,
                  (SELECT count(*) FROM radius.radpostauth WHERE authdate >= date_trunc('day', now()) AND reply='Access-Accept') AS accepts_today,
                  (SELECT count(*) FROM radius.radpostauth WHERE authdate >= date_trunc('day', now()) AND reply='Access-Reject') AS rejects_today,
                  (SELECT coalesce(sum(coalesce(acctinputoctets,0)+coalesce(acctoutputoctets,0)),0) FROM radius.radacct) AS total_octets
            """)
        return _json(dict(row))
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def api_users(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            rows = await con.fetch("""
                SELECT m.username, m.display_name, m.phone, m.email, m.enabled, m.expires_at,
                       m.created_at, p.name AS plan_name, p.download_mbps, p.upload_mbps, p.quota_mb,
                       EXISTS(SELECT 1 FROM radius.radacct a WHERE a.username=m.username AND a.acctstoptime IS NULL) AS online
                FROM radius.subscriber_meta m
                LEFT JOIN radius.radius_plans p ON p.id=m.plan_id
                ORDER BY m.created_at DESC LIMIT 300
            """)
        return _json([dict(row) for row in rows])
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def _apply_plan(con: asyncpg.Connection, username: str, plan_id: int) -> None:
    plan = await con.fetchrow("SELECT * FROM radius.radius_plans WHERE id=$1 AND enabled", plan_id)
    if not plan:
        raise ValueError("الخطة غير موجودة أو غير مفعلة")
    group = "radius_plan_" + str(plan_id)
    await con.execute("DELETE FROM radius.radgroupreply WHERE groupname=$1", group)
    rate = f"{int(plan['upload_mbps'])}M/{int(plan['download_mbps'])}M"
    await con.execute(
        "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Mikrotik-Rate-Limit',':=',$2)",
        group, rate
    )
    if plan["quota_mb"]:
        await con.execute(
            "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Mikrotik-Total-Limit',':=',$2)",
            group, str(int(plan["quota_mb"]) * 1024 * 1024)
        )
    if plan["session_timeout"]:
        await con.execute(
            "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Session-Timeout',':=',$2)",
            group, str(int(plan["session_timeout"]))
        )
    await con.execute("DELETE FROM radius.radusergroup WHERE username=$1", username)
    await con.execute(
        "INSERT INTO radius.radusergroup(username,groupname,priority) VALUES($1,$2,1)",
        username, group
    )


async def api_create_user(request: Request) -> Response:
    _, error = _authorized(request, write=True)
    if error:
        return error
    try:
        body = await request.json()
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", username):
            return _json({"error": "اسم المستخدم يجب أن يكون 3-64 حرفًا ويحتوي أحرفًا وأرقامًا فقط"}, 400)
        if not 8 <= len(password) <= 128:
            return _json({"error": "كلمة المرور يجب أن تكون بين 8 و128 حرفًا"}, 400)
        plan_id = int(body["plan_id"]) if body.get("plan_id") else None
        pool = await _db()
        async with pool.acquire() as con:
            async with con.transaction():
                await con.execute("""
                    INSERT INTO radius.subscriber_meta(username,display_name,phone,email,plan_id,expires_at,enabled)
                    VALUES($1,$2,$3,$4,$5,$6,true)
                    ON CONFLICT(username) DO UPDATE SET
                      display_name=EXCLUDED.display_name, phone=EXCLUDED.phone,
                      email=EXCLUDED.email, plan_id=EXCLUDED.plan_id,
                      expires_at=EXCLUDED.expires_at, enabled=true, updated_at=now()
                """, username, str(body.get("display_name") or ""), str(body.get("phone") or ""),
                     str(body.get("email") or ""), plan_id, body.get("expires_at") or None)
                await con.execute("DELETE FROM radius.radcheck WHERE username=$1 AND attribute IN ('Cleartext-Password','Auth-Type')", username)
                await con.execute(
                    "INSERT INTO radius.radcheck(username,attribute,op,value) VALUES($1,'Cleartext-Password',':=',$2)",
                    username, password
                )
                if plan_id:
                    await _apply_plan(con, username, plan_id)
                await con.execute(
                    "INSERT INTO radius.audit_events(actor,action,entity_type,entity_id) VALUES($1,'create_or_update','subscriber',$2)",
                    ADMIN_USERNAME, username
                )
        return _json({"ok": True, "username": username})
    except ValueError as exc:
        return _json({"error": str(exc)}, 400)
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def api_nas(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            rows = await con.fetch("""
                SELECT id,nasname,shortname,type,ports,server,community,description
                FROM radius.nas ORDER BY id DESC LIMIT 200
            """)
        return _json([dict(row) for row in rows])
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def api_create_nas(request: Request) -> Response:
    _, error = _authorized(request, write=True)
    if error:
        return error
    try:
        body = await request.json()
        nasname = str(body.get("nasname") or "").strip()
        shortname = str(body.get("shortname") or "").strip()
        secret = str(body.get("secret") or "")
        if not nasname or len(nasname) > 128 or not shortname or len(shortname) > 64:
            return _json({"error": "عنوان NAS والاسم المختصر مطلوبان"}, 400)
        if len(secret) < 24 or len(secret) > 128:
            return _json({"error": "Shared Secret يجب أن يكون 24 حرفًا على الأقل"}, 400)
        pool = await _db()
        async with pool.acquire() as con:
            row = await con.fetchrow("""
                INSERT INTO radius.nas(nasname,shortname,type,secret,description)
                VALUES($1,$2,$3,$4,$5) RETURNING id
            """, nasname, shortname, str(body.get("type") or "other"), secret, str(body.get("description") or ""))
            await con.execute(
                "INSERT INTO radius.audit_events(actor,action,entity_type,entity_id) VALUES($1,'create','nas',$2)",
                ADMIN_USERNAME, str(row["id"])
            )
        return _json({"ok": True, "id": row["id"]})
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 400)


async def api_plans(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            rows = await con.fetch("SELECT * FROM radius.radius_plans ORDER BY id DESC")
        return _json([dict(row) for row in rows])
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def api_create_plan(request: Request) -> Response:
    _, error = _authorized(request, write=True)
    if error:
        return error
    try:
        body = await request.json()
        name = str(body.get("name") or "").strip()
        down = int(body.get("download_mbps") or 0)
        up = int(body.get("upload_mbps") or 0)
        quota = int(body["quota_mb"]) if body.get("quota_mb") else None
        timeout = int(body["session_timeout"]) if body.get("session_timeout") else None
        price = float(body.get("price") or 0)
        if not name or len(name) > 80 or not (1 <= down <= 10000) or not (1 <= up <= 10000):
            return _json({"error": "اسم الخطة والسرعات المطلوبة غير صحيحة"}, 400)
        if quota is not None and quota <= 0:
            return _json({"error": "الحصة يجب أن تكون أكبر من صفر"}, 400)
        if timeout is not None and timeout <= 0:
            return _json({"error": "مدة الجلسة يجب أن تكون أكبر من صفر"}, 400)
        if price < 0 or price > 100000000:
            return _json({"error": "السعر غير صحيح"}, 400)
        pool = await _db()
        async with pool.acquire() as con:
            row = await con.fetchrow("""
              INSERT INTO radius.radius_plans(name,download_mbps,upload_mbps,quota_mb,session_timeout,price,description)
              VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id
            """, name, down, up, quota, timeout, price, str(body.get("description") or ""))
            group = "radius_plan_" + str(row["id"])
            await con.execute(
                "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Mikrotik-Rate-Limit',':=',$2)",
                group, f"{up}M/{down}M"
            )
            if quota:
                await con.execute(
                    "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Mikrotik-Total-Limit',':=',$2)",
                    group, str(quota * 1024 * 1024)
                )
            if timeout:
                await con.execute(
                    "INSERT INTO radius.radgroupreply(groupname,attribute,op,value) VALUES($1,'Session-Timeout',':=',$2)",
                    group, str(timeout)
                )
            await con.execute(
                "INSERT INTO radius.audit_events(actor,action,entity_type,entity_id) VALUES($1,'create','plan',$2)",
                ADMIN_USERNAME, str(row["id"])
            )
        return _json({"ok": True, "id": row["id"]})
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 400)


async def api_sessions(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            rows = await con.fetch("""
              SELECT radacctid,username,nasipaddress::text AS nasipaddress,nasportid,
                     framedipaddress::text AS framedipaddress,acctstarttime,
                     acctsessiontime,acctinputoctets,acctoutputoctets,callingstationid,calledstationid
              FROM radius.radacct WHERE acctstoptime IS NULL
              ORDER BY acctstarttime DESC LIMIT 300
            """)
        return _json([dict(row) for row in rows])
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


async def api_logs(request: Request) -> Response:
    _, error = _authorized(request)
    if error:
        return error
    try:
        pool = await _db()
        async with pool.acquire() as con:
            rows = await con.fetch("""
              SELECT id,username,reply,authdate,calledstationid,callingstationid
              FROM radius.radpostauth ORDER BY authdate DESC LIMIT 100
            """)
        return _json([dict(row) for row in rows])
    except Exception as exc:
        return _json({"error": str(exc)[:240]}, 503)


LOGIN_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radius Control | تسجيل الدخول</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 18% 15%,#1b3b57 0,transparent 32%),linear-gradient(145deg,#071321,#0c1b2c 62%,#10283b);font-family:Inter,"Segoe UI",Tahoma,sans-serif;color:#e8f0f8}.card{width:min(430px,calc(100% - 32px));padding:38px;border:1px solid #28445d;border-radius:24px;background:#101f30ed;box-shadow:0 28px 90px #0008}.brand{display:flex;align-items:center;gap:14px;margin-bottom:32px}.mark{width:50px;height:50px;border-radius:15px;display:grid;place-items:center;background:linear-gradient(135deg,#1ba7a0,#386ad5);font-size:23px;font-weight:800}.muted{color:#89a1b7;font-size:13px}.title{font-size:23px;font-weight:750;margin:0 0 8px}.field{margin:20px 0}.field label{display:block;margin-bottom:8px;font-size:13px;color:#b4c6d6}.field input{width:100%;height:48px;border:1px solid #30495f;border-radius:12px;background:#0a1725;color:#eef7ff;padding:0 14px;font-size:15px;outline:none}.field input:focus{border-color:#31a9a3;box-shadow:0 0 0 3px #31a9a322}button{width:100%;height:49px;border:0;border-radius:12px;background:linear-gradient(105deg,#159f9a,#386ed5);color:white;font-weight:750;font-size:15px;cursor:pointer;margin-top:10px}.error{color:#ff9c9c;font-size:13px}.foot{text-align:center;margin-top:25px;color:#66829a;font-size:12px}</style></head><body><main class="card"><div class="brand"><div class="mark">R</div><div><div style="font-size:18px;font-weight:800">RADIUS CONTROL</div><div class="muted">Network Access Management</div></div></div><h1 class="title">تسجيل دخول المسؤول</h1><p class="muted">استخدم بيانات دخول إدارة Debian الحالية.</p><!--ERROR--><form method="post" action="/radius/login"><div class="field"><label>اسم المستخدم</label><input name="username" autocomplete="username" required autofocus></div><div class="field"><label>كلمة المرور</label><input type="password" name="password" autocomplete="current-password" required></div><button type="submit">دخول آمن إلى لوحة التحكم</button></form><div class="foot">Protected by Debian MCP • TLS session • Admin only</div></main></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radius Control Center</title><meta name="csrf" content="__CSRF__"><style>
:root{color-scheme:dark;--bg:#091522;--panel:#101f30;--panel2:#13263a;--border:#213b52;--muted:#8aa2b8;--text:#e9f1f8;--teal:#22b5a8;--blue:#5389e5;--red:#ef6b78;--gold:#e6b75b}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"Segoe UI",Tahoma,sans-serif}.layout{min-height:100vh;display:grid;grid-template-columns:255px 1fr}.side{background:#0d1b2a;border-left:1px solid var(--border);padding:26px 17px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:12px;padding:5px 10px 27px;border-bottom:1px solid var(--border)}.mark{width:43px;height:43px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(135deg,#17a89f,#3d73dc);font-weight:900;font-size:21px}.brand strong{display:block;font-size:14px;letter-spacing:.7px}.brand small{color:var(--muted);font-size:11px}.navlabel{font-size:10px;color:#607b94;font-weight:800;letter-spacing:1.3px;padding:24px 12px 9px}.nav button{width:100%;border:0;background:transparent;color:#91a8bd;padding:12px 13px;text-align:right;border-radius:10px;margin:2px 0;cursor:pointer;font-size:13px}.nav button.active,.nav button:hover{background:#1a3449;color:#f4fbff}.nav button.active{box-shadow:inset -3px 0 var(--teal)}.sidebottom{margin-top:auto;border-top:1px solid var(--border);padding-top:17px}.logout{background:#311f2b!important;color:#f59aa4!important}.main{padding:30px 34px;min-width:0}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:29px;gap:15px}.top h1{font-size:25px;margin:0 0 7px}.top p{margin:0;color:var(--muted);font-size:12px}.pill{display:inline-flex;gap:8px;align-items:center;padding:9px 13px;border:1px solid var(--border);border-radius:99px;background:#102335;color:#a8bfd0;font-size:11px}.dot{width:7px;height:7px;background:#35c79f;border-radius:50%;box-shadow:0 0 10px #35c79f}.grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:14px}.metric,.panel{background:linear-gradient(145deg,#13263a,#0f1e2d);border:1px solid var(--border);border-radius:16px}.metric{padding:19px;min-height:130px}.metric .label{color:var(--muted);font-size:12px}.metric .value{font-size:28px;font-weight:800;margin:14px 0 5px;letter-spacing:-.7px}.metric .sub{font-size:10px;color:#66859d}.section{display:none}.section.show{display:block}.panel{margin-top:18px;padding:21px}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:17px}.panelhead h2{margin:0;font-size:15px}.panelhead p{margin:5px 0 0;color:var(--muted);font-size:11px}.btn{border:1px solid #31516b;background:#17334a;color:#e7f2fb;border-radius:10px;padding:10px 14px;font-size:12px;cursor:pointer}.btn.primary{background:linear-gradient(100deg,#168e8d,#346dd2);border:0}.btn:hover{filter:brightness(1.15)}.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;white-space:nowrap}th{text-align:right;color:#7893a9;font-weight:650;font-size:11px;padding:12px;border-bottom:1px solid var(--border)}td{padding:13px 12px;border-bottom:1px solid #1b3145;font-size:12px;color:#d4e1ec}tr:last-child td{border-bottom:0}.empty{text-align:center;color:var(--muted);padding:35px!important}.badge{padding:5px 9px;border-radius:99px;background:#173b3b;color:#67d8bd;font-size:10px}.badge.off{background:#3a2a31;color:#fa9ba5}.subgrid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px}.quick{display:flex;gap:9px;flex-wrap:wrap}.statusbox{border-radius:12px;background:#0c1b2a;border:1px solid var(--border);padding:14px;color:#a5bacc;font-size:12px;line-height:1.8}.modal{border:1px solid #34516b;background:#102338;color:var(--text);border-radius:18px;width:min(520px,calc(100% - 24px));padding:24px;box-shadow:0 25px 80px #000b}.modal::backdrop{background:#020911bb;backdrop-filter:blur(5px)}.modal h3{margin:0 0 18px}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:13px}.field{margin-bottom:12px}.field.full{grid-column:1/-1}.field label{display:block;font-size:11px;color:#a3b9cb;margin-bottom:7px}.field input,.field select{width:100%;height:42px;border:1px solid #304d66;background:#091725;color:#edf6ff;border-radius:9px;padding:0 11px}.modalfoot{display:flex;justify-content:flex-start;gap:8px;margin-top:15px}.note{font-size:11px;color:var(--muted);line-height:1.7}.errorbox{color:#ffadb2;background:#351f2a;border-radius:10px;padding:12px;font-size:12px;display:none}.loading{color:var(--muted);font-size:12px;padding:22px}.mobilemenu{display:none}@media(max-width:1200px){.grid{grid-template-columns:repeat(3,1fr)}}@media(max-width:850px){.layout{grid-template-columns:1fr}.side{position:static;padding:13px 15px}.brand{padding-bottom:12px}.nav{display:flex;overflow:auto;gap:4px}.navlabel,.sidebottom{display:none}.nav button{white-space:nowrap;width:auto}.main{padding:20px 14px}.top h1{font-size:21px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.subgrid{grid-template-columns:1fr}}@media(max-width:480px){.grid{grid-template-columns:1fr 1fr}.metric{padding:14px}.metric .value{font-size:22px}.formgrid{grid-template-columns:1fr}.field.full{grid-column:auto}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><div class="layout"><aside class="side"><div class="brand"><div class="mark">R</div><div><strong>RADIUS CONTROL</strong><small>Network Access Management</small></div></div><div class="navlabel">WORKSPACE</div><nav class="nav"><button class="active" data-view="overview">◈　 نظرة عامة</button><button data-view="users">♙　 المشتركون</button><button data-view="plans">▤　 الباقات والسرعات</button><button data-view="nas">⌁　 أجهزة NAS</button><button data-view="sessions">◉　 الجلسات النشطة</button><button data-view="logs">▣　 سجل المصادقة</button></nav><div class="sidebottom"><div class="statusbox">● لوحة الإدارة محمية<br>الجلسة تنتهي تلقائيًا بعد 8 ساعات.</div><form method="post" action="/radius/logout"><button class="nav logout" style="margin-top:12px">↪　 تسجيل الخروج</button></form></div></aside><main class="main"><header class="top"><div><h1 id="viewTitle">نظرة عامة</h1><p id="viewDesc">مراقبة خدمات الوصول والمشتركين وحالة الشبكة.</p></div><div class="pill"><span class="dot"></span> لوحة الإدارة نشطة</div></header><section id="overview" class="section show"><div class="grid"><div class="metric"><div class="label">إجمالي المشتركين</div><div id="mUsers" class="value">—</div><div class="sub">حسابات مفعلة</div></div><div class="metric"><div class="label">الجلسات النشطة</div><div id="mSessions" class="value">—</div><div class="sub">اتصالات حالية</div></div><div class="metric"><div class="label">أجهزة NAS</div><div id="mNas" class="value">—</div><div class="sub">أجهزة الشبكة المسجلة</div></div><div class="metric"><div class="label">قبول اليوم</div><div id="mAccept" class="value">—</div><div class="sub">Access-Accept</div></div><div class="metric"><div class="label">رفض اليوم</div><div id="mReject" class="value">—</div><div class="sub">Access-Reject</div></div></div><div class="subgrid"><div class="panel"><div class="panelhead"><div><h2>إجراءات سريعة</h2><p>إدارة حسابات الشبكة من مكان واحد</p></div></div><div class="quick"><button class="btn primary" onclick="openModal('userModal')">＋ إضافة مشترك</button><button class="btn" onclick="showView('plans')">إدارة الباقات</button><button class="btn" onclick="showView('nas')">إضافة NAS</button><button class="btn" onclick="showView('sessions')">عرض الجلسات</button></div></div><div class="panel"><div class="panelhead"><div><h2>حالة الاتصال</h2><p>قاعدة البيانات وخدمة RADIUS</p></div></div><div id="dbStatus" class="statusbox">جارٍ فحص الاتصال بقاعدة البيانات…</div></div></div><div class="panel"><div class="panelhead"><div><h2>آخر محاولات المصادقة</h2><button class="btn" onclick="showView('logs')">عرض الكل</button></div></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>النتيجة</th><th>التوقيت</th><th>الجهاز</th></tr></thead><tbody id="recentLogs"><tr><td class="empty" colspan="4">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<section id="users" class="section"><div class="panel"><div class="panelhead"><div><h2>إدارة المشتركين</h2><p>الحسابات وبيانات الاتصال والباقات المرتبطة</p></div><button class="btn primary" onclick="openModal('userModal')">＋ مشترك جديد</button></div><div class="tablewrap"><table><thead><tr><th>اسم المستخدم</th><th>الاسم</th><th>الباقة</th><th>السرعة ↓ / ↑</th><th>الحالة</th><th>انتهاء الاشتراك</th></tr></thead><tbody id="usersTable"><tr><td colspan="6" class="empty">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<section id="plans" class="section"><div class="panel"><div class="panelhead"><div><h2>الباقات والسرعات</h2><p>تحديد حدود التنزيل والرفع والحصة الشهرية</p></div><button class="btn primary" onclick="openModal('planModal')">＋ إنشاء باقة</button></div><div class="tablewrap"><table><thead><tr><th>اسم الباقة</th><th>تنزيل</th><th>رفع</th><th>الحصة</th><th>المهلة</th><th>السعر</th></tr></thead><tbody id="plansTable"><tr><td colspan="6" class="empty">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<section id="nas" class="section"><div class="panel"><div class="panelhead"><div><h2>أجهزة NAS</h2><p>أجهزة MikroTik ونقاط الوصول وموجهات RADIUS</p></div><button class="btn primary" onclick="openModal('nasModal')">＋ إضافة NAS</button></div><div class="tablewrap"><table><thead><tr><th>العنوان</th><th>الاسم</th><th>النوع</th><th>الوصف</th></tr></thead><tbody id="nasTable"><tr><td colspan="4" class="empty">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<section id="sessions" class="section"><div class="panel"><div class="panelhead"><div><h2>الجلسات النشطة</h2><p>المشتركون المتصلون حاليًا وحركة المرور</p></div><button class="btn" onclick="loadSessions()">تحديث</button></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>IP المشترك</th><th>NAS</th><th>بداية الاتصال</th><th>مدة الجلسة</th><th>رفع</th><th>تنزيل</th></tr></thead><tbody id="sessionsTable"><tr><td colspan="7" class="empty">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<section id="logs" class="section"><div class="panel"><div class="panelhead"><div><h2>سجل المصادقة</h2><p>آخر 100 محاولة دخول؛ لا يتم عرض كلمات المرور</p></div><button class="btn" onclick="loadLogs()">تحديث</button></div><div class="tablewrap"><table><thead><tr><th>المستخدم</th><th>القرار</th><th>التوقيت</th><th>Calling Station</th><th>Called Station</th></tr></thead><tbody id="logsTable"><tr><td colspan="5" class="empty">جارٍ التحميل…</td></tr></tbody></table></div></div></section>
<div id="globalError" class="errorbox" style="margin-top:16px"></div></main></div>
<dialog id="userModal" class="modal"><form id="userForm"><h3>إضافة مشترك جديد</h3><div class="formgrid"><div class="field"><label>اسم المستخدم *</label><input name="username" required minlength="3"></div><div class="field"><label>كلمة المرور *</label><input name="password" type="password" required minlength="8"></div><div class="field"><label>الاسم الظاهر</label><input name="display_name"></div><div class="field"><label>رقم الهاتف</label><input name="phone"></div><div class="field"><label>البريد الإلكتروني</label><input name="email" type="email"></div><div class="field"><label>الباقة</label><select name="plan_id" id="userPlan"><option value="">بدون باقة</option></select></div><div class="field full"><label>تاريخ انتهاء الاشتراك (اختياري)</label><input type="datetime-local" name="expires_at"></div></div><p class="note">سيُحفظ حساب المصادقة في جداول FreeRADIUS داخل Supabase.</p><div class="modalfoot"><button class="btn primary" type="submit">حفظ المشترك</button><button class="btn" type="button" onclick="closeModal('userModal')">إلغاء</button></div></form></dialog>
<dialog id="planModal" class="modal"><form id="planForm"><h3>إنشاء باقة جديدة</h3><div class="formgrid"><div class="field full"><label>اسم الباقة *</label><input name="name" required></div><div class="field"><label>سرعة التنزيل Mbps *</label><input type="number" name="download_mbps" min="1" value="4" required></div><div class="field"><label>سرعة الرفع Mbps *</label><input type="number" name="upload_mbps" min="1" value="4" required></div><div class="field"><label>الحصة MB (اختياري)</label><input type="number" name="quota_mb" min="1"></div><div class="field"><label>مدة الجلسة بالثواني</label><input type="number" name="session_timeout" min="1"></div><div class="field"><label>السعر</label><input type="number" name="price" min="0" step="0.01" value="0"></div><div class="field full"><label>الوصف</label><input name="description"></div></div><p class="note">تُطبَّق السرعة على MikroTik عبر Mikrotik-Rate-Limit. صيغة القيمة: رفع/تنزيل.</p><div class="modalfoot"><button class="btn primary" type="submit">حفظ الباقة</button><button class="btn" type="button" onclick="closeModal('planModal')">إلغاء</button></div></form></dialog>
<dialog id="nasModal" class="modal"><form id="nasForm"><h3>تسجيل جهاز NAS</h3><div class="formgrid"><div class="field"><label>IP أو نطاق الجهاز *</label><input name="nasname" required placeholder="192.168.88.1"></div><div class="field"><label>الاسم المختصر *</label><input name="shortname" required placeholder="mikrotik-main"></div><div class="field"><label>النوع</label><select name="type"><option value="other">Other</option><option value="mikrotik">MikroTik</option><option value="wireless">Wireless</option><option value="cisco">Cisco</option></select></div><div class="field"><label>Shared Secret *</label><input name="secret" required minlength="24"></div><div class="field full"><label>الوصف</label><input name="description"></div></div><p class="note">احفظ نفس الـ Shared Secret في جهاز NAS. لا تستخدم RADIUS عبر الإنترنت المفتوح دون نفق VPN أو RADIUS/TLS.</p><div class="modalfoot"><button class="btn primary" type="submit">حفظ NAS</button><button class="btn" type="button" onclick="closeModal('nasModal')">إلغاء</button></div></form></dialog>
<script>
var csrf=document.querySelector('meta[name="csrf"]').content;
var titles={overview:['نظرة عامة','مراقبة خدمات الوصول والمشتركين وحالة الشبكة.'],users:['المشتركون','إدارة الحسابات والبيانات والباقات.'],plans:['الباقات والسرعات','تحديد سرعات الرفع والتنزيل والحصص.'],nas:['أجهزة NAS','إدارة أجهزة الشبكة المصرح لها بإرسال RADIUS.'],sessions:['الجلسات النشطة','الاتصالات القائمة وحركة البيانات.'],logs:['سجل المصادقة','محاولات القبول والرفض من FreeRADIUS.']};
function esc(v){return String(v==null?'—':v).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function n(v){return Number(v||0).toLocaleString('en-US')}
function date(v){return v?new Date(v).toLocaleString('ar-EG'):'—'}
function bytes(v){v=Number(v||0);if(v<1024)return n(v)+' B';if(v<1048576)return (v/1024).toFixed(1)+' KB';if(v<1073741824)return (v/1048576).toFixed(1)+' MB';return (v/1073741824).toFixed(2)+' GB'}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'Content-Type':'application/json','X-CSRF-Token':csrf},opts.headers||{});var res=await fetch('/radius/api/'+path,opts);var data=await res.json().catch(function(){return {error:'Invalid server response'}});if(res.status===401){location.href='/radius/login';throw new Error('انتهت الجلسة. سجّل الدخول مرة أخرى.')}if(!res.ok)throw new Error(data.error||'تعذر تنفيذ الطلب');return data}
function showError(msg){var e=document.getElementById('globalError');e.textContent=msg;e.style.display='block'}
function clearError(){var e=document.getElementById('globalError');e.style.display='none';e.textContent=''}
function emptyRow(cols,msg){return '<tr><td colspan="'+cols+'" class="empty">'+esc(msg||'لا توجد بيانات حتى الآن')+'</td></tr>'}
function showView(v){document.querySelectorAll('.section').forEach(function(s){s.classList.remove('show')});document.getElementById(v).classList.add('show');document.querySelectorAll('.nav button[data-view]').forEach(function(b){b.classList.toggle('active',b.dataset.view===v)});document.getElementById('viewTitle').textContent=titles[v][0];document.getElementById('viewDesc').textContent=titles[v][1];clearError();if(v==='users')loadUsers();if(v==='plans')loadPlans();if(v==='nas')loadNas();if(v==='sessions')loadSessions();if(v==='logs')loadLogs()}
document.querySelectorAll('.nav button[data-view]').forEach(function(b){b.addEventListener('click',function(){showView(b.dataset.view)})});
function openModal(id){document.getElementById(id).showModal()}
function closeModal(id){document.getElementById(id).close()}
async function loadHealth(){var el=document.getElementById('dbStatus');try{var r=await api('health');el.innerHTML='<span style="color:#55d6b6">● متصل بقاعدة Supabase</span><br>قاعدة البيانات: '+esc(r.database)+'<br>Role: '+esc(r.role)}catch(e){el.innerHTML='<span style="color:#f3a0a7">● قاعدة البيانات غير متصلة</span><br>'+esc(e.message)+'<br>يلزم ضبط SUPABASE_DATABASE_URL في Cranl.'}}
async function loadOverview(){try{var r=await api('overview');document.getElementById('mUsers').textContent=n(r.subscribers);document.getElementById('mSessions').textContent=n(r.active_sessions);document.getElementById('mNas').textContent=n(r.nas_count);document.getElementById('mAccept').textContent=n(r.accepts_today);document.getElementById('mReject').textContent=n(r.rejects_today);var logs=await api('logs');document.getElementById('recentLogs').innerHTML=logs.slice(0,6).map(function(x){return '<tr><td>'+esc(x.username)+'</td><td><span class="badge '+(x.reply==='Access-Reject'?'off':'')+'">'+esc(x.reply)+'</span></td><td>'+esc(date(x.authdate))+'</td><td>'+esc(x.callingstationid)+'</td></tr>'}).join('')||emptyRow(4)}catch(e){showError(e.message)}}
async function loadUsers(){try{var data=await api('users');document.getElementById('usersTable').innerHTML=data.map(function(x){return '<tr><td><b>'+esc(x.username)+'</b></td><td>'+esc(x.display_name)+'</td><td>'+esc(x.plan_name)+'</td><td>'+esc(x.download_mbps)+' / '+esc(x.upload_mbps)+' Mbps</td><td><span class="badge '+(x.online?'':'off')+'">'+(x.online?'متصل':'غير متصل')+'</span></td><td>'+esc(date(x.expires_at))+'</td></tr>'}).join('')||emptyRow(6);var plans=await api('plans');document.getElementById('userPlan').innerHTML='<option value="">بدون باقة</option>'+plans.map(function(p){return '<option value="'+p.id+'">'+esc(p.name)+' — '+esc(p.download_mbps)+'/'+esc(p.upload_mbps)+' Mbps</option>'}).join('')}catch(e){showError(e.message)}}
async function loadPlans(){try{var data=await api('plans');document.getElementById('plansTable').innerHTML=data.map(function(x){return '<tr><td><b>'+esc(x.name)+'</b></td><td>'+n(x.download_mbps)+' Mbps</td><td>'+n(x.upload_mbps)+' Mbps</td><td>'+ (x.quota_mb?n(x.quota_mb)+' MB':'غير محدودة')+'</td><td>'+(x.session_timeout?n(x.session_timeout)+' ثانية':'—')+'</td><td>'+n(x.price)+'</td></tr>'}).join('')||emptyRow(6)}catch(e){showError(e.message)}}
async function loadNas(){try{var data=await api('nas');document.getElementById('nasTable').innerHTML=data.map(function(x){return '<tr><td><b>'+esc(x.nasname)+'</b></td><td>'+esc(x.shortname)+'</td><td>'+esc(x.type)+'</td><td>'+esc(x.description)+'</td></tr>'}).join('')||emptyRow(4)}catch(e){showError(e.message)}}
async function loadSessions(){try{var data=await api('sessions');document.getElementById('sessionsTable').innerHTML=data.map(function(x){return '<tr><td>'+esc(x.username)+'</td><td>'+esc(x.framedipaddress)+'</td><td>'+esc(x.nasipaddress)+'</td><td>'+esc(date(x.acctstarttime))+'</td><td>'+n(x.acctsessiontime)+' s</td><td>'+bytes(x.acctinputoctets)+'</td><td>'+bytes(x.acctoutputoctets)+'</td></tr>'}).join('')||emptyRow(7)}catch(e){showError(e.message)}}
async function loadLogs(){try{var data=await api('logs');document.getElementById('logsTable').innerHTML=data.map(function(x){return '<tr><td>'+esc(x.username)+'</td><td><span class="badge '+(x.reply==='Access-Reject'?'off':'')+'">'+esc(x.reply)+'</span></td><td>'+esc(date(x.authdate))+'</td><td>'+esc(x.callingstationid)+'</td><td>'+esc(x.calledstationid)+'</td></tr>'}).join('')||emptyRow(5)}catch(e){showError(e.message)}}
function formData(form){var o={};new FormData(form).forEach(function(v,k){if(v!=='')o[k]=v});return o}
document.getElementById('userForm').addEventListener('submit',async function(e){e.preventDefault();try{var o=formData(e.target);if(o.expires_at)o.expires_at=new Date(o.expires_at).toISOString();await api('users',{method:'POST',body:JSON.stringify(o)});closeModal('userModal');e.target.reset();loadUsers();loadOverview()}catch(err){showError(err.message)}});
document.getElementById('planForm').addEventListener('submit',async function(e){e.preventDefault();try{await api('plans',{method:'POST',body:JSON.stringify(formData(e.target))});closeModal('planModal');e.target.reset();loadPlans()}catch(err){showError(err.message)}});
document.getElementById('nasForm').addEventListener('submit',async function(e){e.preventDefault();try{await api('nas',{method:'POST',body:JSON.stringify(formData(e.target))});closeModal('nasModal');e.target.reset();loadNas()}catch(err){showError(err.message)}});
loadHealth();loadOverview();
</script></body></html>"""


routes = [
    Route("/radius", dashboard, methods=["GET"]),
    Route("/radius/", dashboard, methods=["GET"]),
    Route("/radius/login", login_page, methods=["GET"]),
    Route("/radius/login", login_submit, methods=["POST"]),
    Route("/radius/logout", logout, methods=["POST"]),
    Route("/radius/api/health", api_health, methods=["GET"]),
    Route("/radius/api/overview", api_overview, methods=["GET"]),
    Route("/radius/api/users", api_users, methods=["GET"]),
    Route("/radius/api/users", api_create_user, methods=["POST"]),
    Route("/radius/api/nas", api_nas, methods=["GET"]),
    Route("/radius/api/nas", api_create_nas, methods=["POST"]),
    Route("/radius/api/plans", api_plans, methods=["GET"]),
    Route("/radius/api/plans", api_create_plan, methods=["POST"]),
    Route("/radius/api/sessions", api_sessions, methods=["GET"]),
    Route("/radius/api/logs", api_logs, methods=["GET"]),
]

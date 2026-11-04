from __future__ import annotations
import json, os, re, shutil, subprocess, tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthContext, RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse
from starlette.routing import Route

SUPABASE_PROJECT_URL = os.environ["SUPABASE_PROJECT_URL"].rstrip("/")
SUPABASE_ISSUER = SUPABASE_PROJECT_URL + "/auth/v1"
BASE_URL = os.environ["MCP_BASE_URL"].rstrip("/")
JWT_ALGORITHM = os.environ.get("SUPABASE_JWT_ALGORITHM", "ES256").upper()
if JWT_ALGORITHM not in {"ES256", "RS256"}:
    raise RuntimeError("Use an asymmetric Supabase JWT signing algorithm: ES256 or RS256")

verifier = JWTVerifier(
    jwks_uri=SUPABASE_ISSUER + "/.well-known/jwks.json",
    issuer=SUPABASE_ISSUER,
    audience="authenticated",
)

class SupabaseMCPAuth(RemoteAuthProvider):
    """Supabase JWT resource server with Supabase's path-aware OAuth metadata URL."""

    def get_routes(self, mcp_path: str | None = None):
        routes = super().get_routes(mcp_path=mcp_path)

        async def authorization_server_metadata(request):
            metadata_url = SUPABASE_PROJECT_URL + "/.well-known/oauth-authorization-server/auth/v1"
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    response = await client.get(metadata_url)
                try:
                    payload = response.json()
                except Exception:
                    payload = {"error": "Supabase OAuth metadata is not valid JSON"}
                return JSONResponse(payload, status_code=response.status_code)
            except Exception as exc:
                return JSONResponse({"error": "Unable to fetch Supabase OAuth metadata",
                                     "detail": str(exc)}, status_code=502)

        routes.append(Route("/.well-known/oauth-authorization-server", authorization_server_metadata,
                            methods=["GET"]))
        return routes

auth = SupabaseMCPAuth(
    token_verifier=verifier,
    authorization_servers=[AnyHttpUrl(SUPABASE_ISSUER)],
    base_url=BASE_URL,
)
mcp = FastMCP("Debian noVNC and FreeRADIUS Admin", auth=auth)

def require_supabase_oauth(ctx: AuthContext) -> bool:
    """Reject ordinary Supabase sessions; only OAuth-issued access tokens carry client_id."""
    token = ctx.token
    return bool(token and token.claims.get("sub") and token.claims.get("client_id"))

AUDIT_FILE = Path("/var/log/debian-root-mcp/audit.jsonl")
FR_ROOT = Path("/etc/freeradius/3.0")
NG_ROOT = Path("/etc/nginx/conf.d")
ROOTS = (FR_ROOT, NG_ROOT)
SERVICES = {"freeradius", "nginx"}
MAX_BYTES = 256 * 1024

def audit(tool: str, outcome: str, details: dict[str, Any] | None = None) -> None:
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(),
                "tool": tool, "outcome": outcome, "details": details or {}}, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        AUDIT_FILE.chmod(0o600)
    except Exception:
        pass

def run(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=max(1, min(timeout, 180)), check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                 "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        return {"exit_code": p.returncode, "stdout": p.stdout[-30000:], "stderr": p.stderr[-12000:]}
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Command timed out"}
    except Exception as e:
        return {"exit_code": 1, "stdout": "", "stderr": str(e)}

def checked_file(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError("Absolute path required")
    resolved = p.resolve(strict=True)
    if not any(resolved == root or root in resolved.parents for root in ROOTS):
        raise ValueError("Path is outside approved config directories")
    if not resolved.is_file():
        raise ValueError("Path must be a regular file")
    return resolved

@mcp.tool
def system_overview() -> dict[str, Any]:
    """Read Debian version, kernel, uptime, disk, memory and top processes."""
    result = {"os_release": Path("/etc/os-release").read_text(encoding="utf-8", errors="replace"),
        "kernel": run(["uname", "-a"], 5), "uptime": run(["uptime"], 5),
        "disk": run(["df", "-h"], 10), "memory": run(["free", "-h"], 5),
        "processes": run(["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu"], 10)}
    audit("system_overview", "success")
    return result

@mcp.tool
def service_status(service: str = "freeradius") -> dict[str, Any]:
    """Get status of FreeRADIUS or Nginx."""
    if service not in SERVICES: return {"error": "Allowed services: freeradius, nginx"}
    r = run(["service", service, "status"], 20)
    audit("service_status", "success" if r["exit_code"] == 0 else "nonzero", {"service": service})
    return r

@mcp.tool
def service_control(service: str, action: str) -> dict[str, Any]:
    """Start, stop, restart or reload only FreeRADIUS or Nginx."""
    if service not in SERVICES: return {"error": "Allowed services: freeradius, nginx"}
    if action not in {"start", "stop", "restart", "reload"}:
        return {"error": "Allowed actions: start, stop, restart, reload"}
    r = run(["service", service, action], 60)
    audit("service_control", "success" if r["exit_code"] == 0 else "failed",
          {"service": service, "action": action, "exit_code": r["exit_code"]})
    return r

@mcp.tool
def freeradius_config_test() -> dict[str, Any]:
    """Validate FreeRADIUS configuration without changing the running service."""
    r = run(["freeradius", "-XC"], 90)
    audit("freeradius_config_test", "success" if r["exit_code"] == 0 else "failed",
          {"exit_code": r["exit_code"]})
    return r

@mcp.tool
def nginx_config_test() -> dict[str, Any]:
    """Validate Nginx configuration without reloading it."""
    r = run(["nginx", "-t"], 30)
    audit("nginx_config_test", "success" if r["exit_code"] == 0 else "failed",
          {"exit_code": r["exit_code"]})
    return r

@mcp.tool
def list_config_files(component: str = "freeradius") -> dict[str, Any]:
    """List .conf files under FreeRADIUS or Nginx conf.d."""
    roots = {"freeradius": FR_ROOT, "nginx": NG_ROOT}
    if component not in roots: return {"error": "Component must be freeradius or nginx"}
    root, entries = roots[component], []
    try:
        for p in sorted(root.rglob("*.conf")):
            if p.is_file() and not p.is_symlink():
                st = p.stat()
                entries.append({"path": str(p), "size_bytes": st.st_size,
                    "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})
                if len(entries) >= 500: break
        audit("list_config_files", "success", {"component": component, "count": len(entries)})
        return {"component": component, "files": entries}
    except Exception as e:
        audit("list_config_files", "failed", {"component": component})
        return {"error": str(e)}

@mcp.tool
def read_config_file(path: str) -> dict[str, Any]:
    """Read a text config file only from approved FreeRADIUS and Nginx config directories."""
    try:
        p = checked_file(path)
        if p.stat().st_size > MAX_BYTES: return {"error": "File exceeds 256 KiB limit"}
        content = p.read_text(encoding="utf-8", errors="replace")
        audit("read_config_file", "success", {"path": str(p), "bytes": p.stat().st_size})
        return {"path": str(p), "content": content}
    except Exception as e:
        audit("read_config_file", "rejected", {"requested_path": str(path)[:300]})
        return {"error": str(e)}

@mcp.tool
def write_config_file(path: str, content: str, mode_octal: str = "0640") -> dict[str, Any]:
    """Atomically write a .conf file only under /etc/freeradius/3.0 or /etc/nginx/conf.d.
    Existing files get a one-time .bak backup. Content is never logged. Validate before reload.
    """
    try:
        requested = Path(path)
        if not requested.is_absolute(): raise ValueError("Absolute path required")
        target = requested.resolve(strict=False)
        if not any(root == target.parent or root in target.parents for root in ROOTS):
            raise ValueError("Writes limited to FreeRADIUS and Nginx conf.d")
        if target.suffix != ".conf": raise ValueError("Only .conf files can be written")
        if not target.parent.is_dir(): raise ValueError("Parent directory must already exist")
        if requested.is_symlink() or (target.exists() and target.is_symlink()):
            raise ValueError("Symbolic links cannot be modified")
        if target.exists() and not target.is_file(): raise ValueError("Target must be a regular file")
        raw = content.encode("utf-8")
        if len(raw) > MAX_BYTES: raise ValueError("Configuration exceeds 256 KiB limit")
        if not re.fullmatch(r"0[0-7]{3}", mode_octal): raise ValueError("Invalid octal mode")
        backup = target.with_name(target.name + ".bak")
        if target.exists() and not backup.exists():
            shutil.copy2(target, backup)
            backup.chmod(0o600)
        fd, tmp = tempfile.mkstemp(prefix=".mcp-", suffix=".tmp", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content); f.flush(); os.fsync(f.fileno())
            os.chmod(tmp, int(mode_octal, 8))
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
        audit("write_config_file", "success", {"path": str(target), "bytes": len(raw),
              "backup_created": backup.exists()})
        return {"ok": True, "path": str(target), "bytes_written": target.stat().st_size,
                "backup": str(backup) if backup.exists() else None,
                "next_step": "Run the relevant config test before reloading the service."}
    except Exception as e:
        audit("write_config_file", "rejected", {"requested_path": str(path)[:300]})
        return {"error": str(e)}

@mcp.tool
def read_service_logs(service: str = "freeradius", lines: int = 100) -> dict[str, Any]:
    """Read recent FreeRADIUS or Nginx logs, capped at 200 lines."""
    if service not in SERVICES: return {"error": "Allowed services: freeradius, nginx"}
    count = max(1, min(int(lines), 200))
    paths = {"freeradius": [Path("/var/log/freeradius/radius.log"), Path("/var/log/freeradius/freeradius.log")],
             "nginx": [Path("/var/log/nginx/error.log"), Path("/var/log/nginx/access.log")]}
    for p in paths[service]:
        try:
            if p.is_file():
                lines_out = p.read_text(encoding="utf-8", errors="replace").splitlines()[-count:]
                audit("read_service_logs", "success", {"service": service, "source": str(p), "lines": len(lines_out)})
                return {"service": service, "source": str(p), "lines": lines_out}
        except Exception: pass
    r = run(["journalctl", "-u", service, "-n", str(count), "--no-pager"], 20)
    audit("read_service_logs", "success" if r["exit_code"] == 0 else "unavailable",
          {"service": service, "lines": count})
    return {"service": service, **r}

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8765, path="/mcp")

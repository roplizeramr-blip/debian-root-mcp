from __future__ import annotations

import hmac
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
if len(TOKEN) < 32:
    raise RuntimeError("MCP_AUTH_TOKEN must be set to a random secret of at least 32 characters")

mcp = FastMCP("Debian Root MCP", json_response=True)


def _run(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=max(1, min(timeout, 300)), check=False)
        return {"exit_code": p.returncode, "stdout": p.stdout[-40000:], "stderr": p.stderr[-20000:]}
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "Command timed out"}
    except Exception as exc:
        return {"exit_code": 1, "stdout": "", "stderr": str(exc)}


@mcp.tool()
def system_info() -> dict[str, Any]:
    """Return Debian identity, kernel, disk, memory, uptime and current privileges."""
    commands = {
        "identity": ["id"],
        "os": ["bash", "-lc", "cat /etc/os-release"],
        "kernel": ["uname", "-a"],
        "disk": ["df", "-h"],
        "memory": ["free", "-h"],
        "uptime": ["uptime"],
    }
    return {name: _run(argv, 10) for name, argv in commands.items()}


@mcp.tool()
def run_command(command: str, timeout_seconds: int = 60) -> dict[str, Any]:
    """Execute an arbitrary Bash command as the MCP server's OS user (container root)."""
    if not command.strip():
        return {"exit_code": 2, "stdout": "", "stderr": "Command is empty"}
    return _run(["/bin/bash", "-lc", command], timeout_seconds)


@mcp.tool()
def read_file(path: str, max_bytes: int = 200000) -> dict[str, Any]:
    """Read a UTF-8 text file from any container path."""
    try:
        p = Path(path)
        data = p.read_bytes()
        limit = max(1, min(max_bytes, 2_000_000))
        return {"path": str(p), "size_bytes": len(data), "truncated": len(data) > limit,
                "content": data[:limit].decode("utf-8", errors="replace")}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def write_file(path: str, content: str, mode_octal: str = "0644") -> dict[str, Any]:
    """Write a UTF-8 text file at any container path; parent directories are created."""
    try:
        if not re.fullmatch(r"0[0-7]{3}", mode_octal):
            return {"error": "mode_octal must be a four-digit octal mode such as 0644"}
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        p.chmod(int(mode_octal, 8))
        return {"ok": True, "path": str(p), "bytes_written": p.stat().st_size}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def list_directory(path: str = "/") -> dict[str, Any]:
    """List files and directories with basic metadata."""
    try:
        p = Path(path)
        entries = []
        for item in sorted(p.iterdir(), key=lambda x: x.name.lower())[:1000]:
            try:
                st = item.lstat()
                entries.append({"name": item.name, "path": str(item), "directory": item.is_dir(),
                                "symlink": item.is_symlink(), "size": st.st_size,
                                "mode": oct(st.st_mode & 0o777)})
            except OSError as exc:
                entries.append({"name": item.name, "error": str(exc)})
        return {"path": str(p), "entries": entries}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
def service_control(service: str, action: str = "status") -> dict[str, Any]:
    """Control a systemd service: status, start, stop, restart, enable or disable."""
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", service):
        return {"error": "Invalid service name"}
    if action not in {"status", "start", "stop", "restart", "enable", "disable"}:
        return {"error": "Unsupported action"}
    return _run(["systemctl", action, service], 60)


@mcp.tool()
def apt_install(packages: list[str], update_index: bool = True) -> dict[str, Any]:
    """Install Debian packages using apt. Package names are validated before installation."""
    if not packages or len(packages) > 50:
        return {"error": "Provide between 1 and 50 package names"}
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.-]{0,127}", p) for p in packages):
        return {"error": "One or more package names are invalid"}
    if update_index:
        result = _run(["apt-get", "update"], 240)
        if result["exit_code"] != 0:
            return {"stage": "apt-get update", **result}
    return _run(["apt-get", "install", "-y", "--no-install-recommends", *packages], 300)


class BearerAuth:
    """ASGI middleware requiring a bearer token for every MCP HTTP request."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            path = scope.get("path", "")
            if path == "/health":
                body = b'{"status":"ok","service":"debian-root-mcp"}'
                await send({"type": "http.response.start", "status": 200,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            auth = headers.get(b"authorization", b"").decode("latin-1")
            expected = "Bearer " + TOKEN
            if not hmac.compare_digest(auth, expected):
                body = b'{"error":"unauthorized"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode()),
                                        (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


app = BearerAuth(mcp.streamable_http_app())

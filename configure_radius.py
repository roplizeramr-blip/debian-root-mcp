#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE = Path("/etc/freeradius/3.0")
API_URL = os.environ.get("RADIUS_API_URL", "").strip()
API_KEY = os.environ.get("RADIUS_API_KEY", "").strip()


def q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "").replace("\r", "") + '"'


def api_post(op: str, data: dict | None = None):
    if not API_URL or len(API_KEY) < 32:
        raise RuntimeError("RADIUS_API_URL or RADIUS_API_KEY is missing")
    body = json.dumps({"op": op, "data": data or {}}, separators=(",", ":")).encode()
    req = urllib.request.Request(API_URL, data=body, headers={
        "Content-Type": "application/json", "x-radius-key": API_KEY
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            payload = json.loads(response.read(2_000_000).decode())
            if response.status >= 300:
                raise RuntimeError(f"RADIUS API returned HTTP {response.status}")
            if isinstance(payload, dict) and payload.get("error"):
                raise RuntimeError(str(payload["error"]))
            return payload
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"RADIUS API returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"RADIUS API unreachable: {exc.reason}") from exc


def managed_clients() -> None:
    rows = api_post("nas.radius-clients")
    if not isinstance(rows, list):
        raise RuntimeError("NAS API returned an invalid payload")
    directory = BASE / "clients.d"
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    blocks = []
    count = 0
    for row in rows:
        raw_addr = str(row.get("nasname") or "").strip()
        short = str(row.get("shortname") or "nas").strip()
        secret = str(row.get("secret") or "")
        kind = str(row.get("type") or "other").lower()
        if not raw_addr or len(secret) < 24:
            continue
        try:
            network = ipaddress.ip_network(raw_addr, strict=False)
        except ValueError:
            print(f"Skipping NAS with non-IP address: {short}", file=sys.stderr)
            continue
        if network.version != 4:
            continue
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", short)[:48] or "nas"
        safe_type = "mikrotik" if kind == "mikrotik" else "other"
        address = network.with_prefixlen if network.prefixlen < 32 else network.network_address.compressed
        blocks.extend([
            f"client {safe_name}_{row.get('id', 0)} {{",
            f"    ipaddr = {address}",
            f"    secret = {q(secret)}",
            f"    shortname = {safe_name}",
            f"    nastype = {safe_type}",
            "}",
            "",
        ])
        count += 1
    target = directory / "radius-managed.conf"
    temporary = target.with_suffix(".conf.tmp")
    temporary.write_text("\n".join(blocks), encoding="utf-8")
    temporary.chmod(0o640)
    temporary.replace(target)
    clients_conf = BASE / "clients.conf"
    content = clients_conf.read_text(encoding="utf-8")
    include = "$INCLUDE clients.d/radius-managed.conf"
    if include not in content:
        clients_conf.write_text(content.rstrip() + "\n\n" + include + "\n", encoding="utf-8")
    print(f"Loaded {count} IPv4 NAS clients.")


def insert_in_block(text: str, block_name: str, payload: str) -> str:
    marker = f"# radius-managed-{block_name}"
    if marker in text:
        return text
    match = re.search(rf"(?m)^(\s*){re.escape(block_name)}\s*\{{", text)
    if not match:
        raise RuntimeError(f"FreeRADIUS {block_name} block not found")
    depth = 0
    end = None
    quote_char = None
    escaped = False
    for line_start, line in _line_spans(text[match.start():]):
        clean = line.split("#", 1)[0]
        for i, char in enumerate(clean):
            if escaped:
                escaped = False
                continue
            if quote_char:
                if char == "\\":
                    escaped = True
                elif char == quote_char:
                    quote_char = None
                continue
            if char in ("'", '"'):
                quote_char = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = match.start() + line_start + i
                    break
        if end is not None:
            break
    if end is None:
        raise RuntimeError(f"Could not find end of FreeRADIUS {block_name} block")
    indent = match.group(1) + "\t"
    payload_lines = "\n".join(indent + line if line else "" for line in payload.splitlines())
    return text[:end] + "\n" + indent + marker + "\n" + payload_lines + "\n" + text[end:]


def _line_spans(text: str):
    pos = 0
    for line in text.splitlines(keepends=True):
        yield pos, line
        pos += len(line)


def main() -> int:
    if not API_URL or len(API_KEY) < 32:
        print("RADIUS API settings missing; FreeRADIUS remains disabled.", file=sys.stderr)
        return 2
    api_post("health")
    connect_uri = API_URL.replace("\\", "\\\\").replace('"', '\\"')
    secret = API_KEY.replace("\\", "\\\\").replace('"', '\\"')
    module_text = f'''rest {{
    connect_uri = "{connect_uri}"
    tls {{
        check_cert = yes
        check_cert_cn = yes
    }}
    authorize {{
        uri = "\u0024{{..connect_uri}}?op=radius.authorize"
        method = "post"
        body = "json"
        force_to = "json"
        timeout = 5.0
        tls = \u0024{{..tls}}
        do_xlat = no
    }}
    accounting {{
        uri = "\u0024{{..connect_uri}}?op=radius.accounting"
        method = "post"
        body = "json"
        timeout = 5.0
        tls = \u0024{{..tls}}
        do_xlat = no
    }}
    post-auth {{
        uri = "\u0024{{..connect_uri}}?op=radius.postauth"
        method = "post"
        body = "json"
        timeout = 5.0
        tls = \u0024{{..tls}}
        do_xlat = no
    }}
    pool {{
        start = 0
        min = 0
        max = 3
        spare = 0
        idle_timeout = 30
        retry_delay = 5
    }}
}}
'''
    module = BASE / "mods-available" / "rest"
    module.write_text(module_text, encoding="utf-8")
    module.chmod(0o640)
    enabled = BASE / "mods-enabled" / "rest"
    if not enabled.exists():
        enabled.symlink_to("../mods-available/rest")
    site_path = BASE / "sites-enabled" / "default"
    site = site_path.read_text(encoding="utf-8")
    for block in ("authorize", "accounting", "post-auth"):
        payload = (
            "update control {\n"
            f'    REST-HTTP-Header := "x-radius-key: {secret}"\n'
            "}\n"
            "rest"
        )
        site = insert_in_block(site, block, payload)
    site_path.write_text(site, encoding="utf-8")
    managed_clients()
    print("FreeRADIUS REST authorize/accounting/post-auth configured.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FreeRADIUS setup failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

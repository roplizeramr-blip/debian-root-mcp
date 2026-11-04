#!/usr/bin/env python3
from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import os
import pwd
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


def secure_freeradius_path(path: Path, mode: int) -> None:
    path.chmod(mode)
    try:
        uid = pwd.getpwnam("freerad").pw_uid
        gid = grp.getgrnam("freerad").gr_gid
        os.chown(path, uid, gid)
    except KeyError as exc:
        raise RuntimeError("freerad service account is missing") from exc


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
        detail = exc.read(2000).decode("utf-8", "replace")
        raise RuntimeError(f"RADIUS API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"RADIUS API unreachable: {exc.reason}") from exc


def managed_clients() -> None:
    rows = api_post("nas.radius-clients")
    if not isinstance(rows, list):
        raise RuntimeError("NAS API returned an invalid payload")

    directory = BASE / "clients.d"
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    secure_freeradius_path(directory, 0o750)

    loopback = ipaddress.ip_network("127.0.0.0/8")
    portwarp_network = ipaddress.ip_network("127.0.0.1/32")
    portwarp_rows: list[dict] = []
    direct_blocks: list[str] = []
    direct_networks: list[tuple[ipaddress.IPv4Network, str]] = []
    direct_count = 0

    for row in rows:
        raw_addr = str(row.get("nasname") or "").strip()
        short = str(row.get("shortname") or "nas").strip()
        secret = str(row.get("secret") or "")
        kind = str(row.get("type") or "other").lower()

        if not raw_addr:
            raise RuntimeError(f"NAS '{short}' has no source address")
        if len(secret) < 32:
            raise RuntimeError(f"NAS '{short}' has a Shared Secret shorter than 32 characters")

        try:
            network = ipaddress.ip_network(raw_addr, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"NAS '{short}' must use a valid IPv4 address or CIDR") from exc

        if network.version != 4:
            raise RuntimeError(f"NAS '{short}' must use IPv4")

        if network.overlaps(loopback):
            if network != portwarp_network:
                raise RuntimeError("Portwarp NAS must use exactly 127.0.0.1/32; other loopback ranges are not allowed")
            portwarp_rows.append(row)
            continue

        for previous_network, previous_name in direct_networks:
            if network.overlaps(previous_network):
                raise RuntimeError(
                    f"NAS '{short}' source range {network} overlaps NAS '{previous_name}' ({previous_network})"
                )
        direct_networks.append((network, short))

        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", short)[:48] or "nas"
        safe_type = "mikrotik" if kind == "mikrotik" else "other"
        address = network.with_prefixlen if network.prefixlen < 32 else network.network_address.compressed
        direct_blocks.extend([
            f"client {safe_name}_{row.get('id', 0)} {{",
            f"    ipaddr = {address}",
            "    proto = udp",
            f"    secret = {q(secret)}",
            f"    shortname = {q(safe_name)}",
            f"    nastype = {safe_type}",
            "    require_message_authenticator = yes",
            "    limit_proxy_state = yes",
            "}",
            "",
        ])
        direct_count += 1

    if len(portwarp_rows) > 1:
        raise RuntimeError(
            "Only one NAS may use 127.0.0.1 for the current Portwarp ingress. "
            "Routers behind the same tunnel share one RADIUS client secret."
        )

    target = directory / "radius-managed.conf"
    temporary = target.with_suffix(".conf.tmp")
    temporary.write_text("\n".join(direct_blocks), encoding="utf-8")
    temporary.chmod(0o640)
    temporary.replace(target)
    secure_freeradius_path(target, 0o640)

    clients_conf = BASE / "clients.conf"
    content = clients_conf.read_text(encoding="utf-8")
    include = "$INCLUDE clients.d/radius-managed.conf"
    if include not in content:
        content = content.rstrip() + "\n\n" + include + "\n"

    local_pattern = re.compile(r"(?ms)^client localhost\s*\{.*?^\}")
    local_match = local_pattern.search(content)
    if not local_match:
        raise RuntimeError("Default FreeRADIUS client localhost block was not found")

    if portwarp_rows:
        row = portwarp_rows[0]
        local_secret = str(row.get("secret") or "")
        local_name = re.sub(
            r"[^A-Za-z0-9_.-]", "_", str(row.get("shortname") or "mikrotik-portwarp")
        )[:48] or "mikrotik-portwarp"
    else:
        # No Portwarp NAS is registered: make the loopback client unusable from
        # an unregistered public tunnel, while keeping the FreeRADIUS config valid.
        seed = os.environ.get("MCP_JWT_SECRET", "").encode() + b":radius-disabled-portwarp"
        local_secret = hashlib.sha256(seed).hexdigest()
        local_name = "disabled-portwarp-ingress"

    local_block = "\n".join([
        "client localhost {",
        "    ipaddr = 127.0.0.1",
        "    proto = udp",
        f"    secret = {q(local_secret)}",
        f"    shortname = {q(local_name)}",
        "    nastype = mikrotik",
        "    require_message_authenticator = yes",
        "    limit_proxy_state = yes",
        "}",
    ])
    content = content[:local_match.start()] + local_block + content[local_match.end():]

    temporary_clients = clients_conf.with_suffix(".conf.tmp")
    temporary_clients.write_text(content, encoding="utf-8")
    temporary_clients.chmod(0o640)
    temporary_clients.replace(clients_conf)
    secure_freeradius_path(clients_conf, 0o640)

    print(
        f"Loaded {direct_count} direct IPv4 NAS client(s) and "
        f"{len(portwarp_rows)} Portwarp ingress client(s)."
    )



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
    secure_freeradius_path(module, 0o640)
    enabled = BASE / "mods-enabled" / "rest"
    if not enabled.exists():
        enabled.symlink_to("../mods-available/rest")
    site_path = BASE / "sites-enabled" / "default"
    site = site_path.read_text(encoding="utf-8")
    for block in ("authorize", "accounting", "post-auth"):
        payload = (
            "update control {\n"
            f'    &REST-HTTP-Header := "x-radius-key: {secret}"\n'
            "}\n"
            "rest"
        )
        site = insert_in_block(site, block, payload)
    site_path.write_text(site, encoding="utf-8")
    secure_freeradius_path(site_path, 0o640)
    clients_conf = BASE / "clients.conf"
    if clients_conf.exists():
        local_seed = os.environ.get("MCP_JWT_SECRET", "").encode() + b":radius-local-client"
        local_secret = hashlib.sha256(local_seed).hexdigest()
        local_text = clients_conf.read_text(encoding="utf-8").replace("secret = testing123", "secret = " + q(local_secret))
        clients_conf.write_text(local_text, encoding="utf-8")

    managed_clients()
    print("FreeRADIUS REST authorize/accounting/post-auth configured.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FreeRADIUS setup failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

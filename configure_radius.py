#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASE = Path("/etc/freeradius/3.0")


def pg_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def main() -> int:
    dsn = os.environ.get("SUPABASE_DATABASE_URL", "").strip()
    if not dsn:
        print("SUPABASE_DATABASE_URL is missing", file=sys.stderr)
        return 2

    parts = urlsplit(dsn)
    if parts.scheme not in {"postgres", "postgresql"} or not parts.hostname or not parts.username or not parts.password:
        print("SUPABASE_DATABASE_URL must be a full PostgreSQL connection URI", file=sys.stderr)
        return 2

    host = parts.hostname
    port = parts.port or 5432
    database = unquote(parts.path.lstrip("/") or "postgres")
    username = unquote(parts.username)
    password = unquote(parts.password)
    if port != 5432:
        print("RADIUS requires Supavisor Session Mode on port 5432", file=sys.stderr)
        return 2

    conninfo = " ".join([
        "host=" + pg_quote(host),
        "port=" + pg_quote(str(port)),
        "dbname=" + pg_quote(database),
        "user=" + pg_quote(username),
        "password=" + pg_quote(password),
        "sslmode='require'",
        "application_name='FreeRADIUS'",
    ])

    module = BASE / "mods-available/sql"
    text = module.read_text(encoding="utf-8")
    text = re.sub(r'(?m)^(\s*)dialect\s*=\s*"[^"]+"', r'\1dialect = "postgresql"', text, count=1)
    text = re.sub(r'(?m)^(\s*)driver\s*=\s*"rlm_sql_null"', r'\1driver = "rlm_sql_postgresql"', text, count=1)
    text = re.sub(r'(?m)^(\s*)radius_db\s*=\s*"radius"\s*$', lambda m: m.group(1) + 'radius_db = "' + conninfo.replace('"', '\\"') + '"', text, count=1)
    text = re.sub(r'(?m)^\s*#\s*read_clients\s*=\s*yes\s*$', 'read_clients = yes', text, count=1)
    text = re.sub(r'(?m)^(\s*)start\s*=\s*\$\{thread\[pool\]\.start_servers\}', r'\1start = 1', text, count=1)
    text = re.sub(r'(?m)^(\s*)min\s*=\s*\$\{thread\[pool\]\.min_spare_servers\}', r'\1min = 1', text, count=1)
    text = re.sub(r'(?m)^(\s*)max\s*=\s*\$\{thread\[pool\]\.max_servers\}', r'\1max = 3', text, count=1)
    text = re.sub(r'(?m)^(\s*)spare\s*=\s*\$\{thread\[pool\]\.max_spare_servers\}', r'\1spare = 1', text, count=1)
    module.write_text(text, encoding="utf-8")
    module.chmod(0o640)

    enabled = BASE / "mods-enabled/sql"
    if not enabled.exists():
        enabled.symlink_to("../mods-available/sql")

    for site_name in ("default", "inner-tunnel"):
        site = BASE / "sites-enabled" / site_name
        if site.exists():
            site_text = site.read_text(encoding="utf-8")
            site_text = re.sub(r"(?m)^(\s*)-sql\s*$", r"\1sql", site_text)
            site.write_text(site_text, encoding="utf-8")

    # Do not persist PAP/CHAP credentials in the authentication audit table.
    queries = BASE / "mods-config/sql/main/postgresql/queries.conf"
    if queries.exists():
        query_text = queries.read_text(encoding="utf-8")
        query_text = query_text.replace("'%{%{User-Password}:-%{Chap-Password}}',", "NULL,")
        queries.write_text(query_text, encoding="utf-8")

    # Replace the package's sample localhost shared secret with a derived secret.
    clients = BASE / "clients.conf"
    if clients.exists():
        client_text = clients.read_text(encoding="utf-8")
        seed = os.environ.get("MCP_JWT_SECRET", "").encode() + b":radius-local-client"
        local_secret = hashlib.sha256(seed).hexdigest()
        client_text = client_text.replace("secret = testing123", "secret = " + local_secret, 1)
        clients.write_text(client_text, encoding="utf-8")

    print("FreeRADIUS SQL configured for Supabase PostgreSQL session pooler.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

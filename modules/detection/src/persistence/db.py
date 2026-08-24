"""PostgreSQL connection helper for M4 canonical event persistence.

Mirrors the connection conventions already established in
``modules/backend/app/db.py`` (same environment variables, same driver), but
targets the dedicated ``m4_canonical`` schema instead of the legacy ``public``
alerts schema. This module never touches ``modules/storage/schema.sql`` or the
legacy alert sink.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def pg_settings() -> dict[str, Any]:
    """Return connection parameters from the same env vars as the legacy sink."""
    return {
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": int(os.getenv("POSTGRES_PORT", "5432")),
        "dbname": os.getenv("POSTGRES_DB", "cybersentinel"),
        "user": os.getenv("POSTGRES_USER", "cybersentinel"),
        "password": os.getenv("POSTGRES_PASSWORD", "cybersentinel"),
    }


def get_connection(connect_timeout: int = 3):
    """Return a psycopg connection, or None if PostgreSQL is unreachable.

    Never raises on connection failure — the caller decides how to react.
    Consistent with the legacy sink's fail-soft connection behavior.
    """
    try:
        import psycopg
    except ImportError:
        return None
    try:
        return psycopg.connect(connect_timeout=connect_timeout, **pg_settings())
    except Exception:
        return None


def ensure_m4_schema(conn) -> None:
    """Apply schema_v2.sql (idempotent DDL: CREATE ... IF NOT EXISTS only).

    Safe to call on every run — every statement in schema_v2.sql is written to
    be a no-op if the schema/tables/indexes already exist.
    """
    ddl_path = Path(__file__).resolve().parent / "schema_v2.sql"
    ddl = ddl_path.read_text(encoding="utf-8")
    with conn.cursor() as cur:
        cur.execute(ddl)
    conn.commit()

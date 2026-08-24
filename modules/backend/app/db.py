"""PostgreSQL alert sink (Couche 2).

Inserts scored alerts into the ``alerts`` table defined in
modules/storage/schema.sql. Connection parameters come from environment
variables (see .env.example). If PostgreSQL is unreachable (e.g. Docker not
running), callers should fall back to the JSONL sink — see
scripts/generate_alerts.py.
"""
from __future__ import annotations

import os
from typing import Iterable

INSERT_SQL = """
INSERT INTO alerts (
    attack_type, ml_confidence, asset_criticality, cve_severity,
    composite_score, level, model_name, status, explanation
) VALUES (
    %(attack_type)s, %(ml_confidence)s, %(asset_criticality)s, %(cve_severity)s,
    %(composite_score)s, %(level)s, %(model_name)s, %(status)s, %(explanation)s
)
"""


def pg_settings() -> dict:
    return {
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": int(os.getenv("POSTGRES_PORT", "5432")),
        "dbname": os.getenv("POSTGRES_DB", "cybersentinel"),
        "user": os.getenv("POSTGRES_USER", "cybersentinel"),
        "password": os.getenv("POSTGRES_PASSWORD", "cybersentinel"),
    }


def get_connection(connect_timeout: int = 3):
    """Return a psycopg connection, or None if PostgreSQL is unreachable.

    Never raises on connection failure — the caller decides on a fallback.
    """
    try:
        import psycopg
    except ImportError:
        return None
    try:
        return psycopg.connect(connect_timeout=connect_timeout, **pg_settings())
    except Exception:
        return None


def truncate_alerts(conn) -> None:
    """Empty the alerts table (and cascade) for a clean reload."""
    with conn.cursor() as cur:
        cur.execute("TRUNCATE alerts RESTART IDENTITY CASCADE;")
    conn.commit()


def insert_alerts(conn, alerts: Iterable[dict]) -> int:
    """Insert alert dicts; returns the number of rows written."""
    import json

    rows = list(alerts)
    if not rows:
        return 0
    payload = [
        {**row, "explanation": json.dumps(row.get("explanation"))}
        if not isinstance(row.get("explanation"), (str, type(None)))
        else row
        for row in rows
    ]
    with conn.cursor() as cur:
        cur.executemany(INSERT_SQL, payload)
    conn.commit()
    return len(rows)

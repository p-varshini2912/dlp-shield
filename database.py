# database.py
# Persistence layer for scan records. Uses Postgres (Render free-tier DB)
# so history survives even when the free web service sleeps/redeploys.

import os
import json
import hashlib
import psycopg2
from datetime import datetime, timezone

DATABASE_URL = os.getenv("DATABASE_URL")


class DBError(Exception):
    pass


def get_conn():
    if not DATABASE_URL:
        raise DBError("DATABASE_URL environment variable is not set")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scan_records (
                        id SERIAL PRIMARY KEY,
                        filename TEXT NOT NULL,
                        scanned_at TEXT NOT NULL,
                        entity_types TEXT NOT NULL,
                        entity_count INTEGER NOT NULL,
                        severity TEXT NOT NULL,
                        redacted_text_hash TEXT NOT NULL,
                        alert_sent INTEGER DEFAULT 0
                    )
                """)
            conn.commit()
    except Exception as e:
        # Never let a DB startup problem crash the whole app
        print(f"[database] init_db failed: {e}")


def insert_scan_record(filename: str, entity_types: list, redacted_text: str,
                        entity_count: int, severity: str) -> int:
    try:
        text_hash = hashlib.sha256(redacted_text.encode("utf-8")).hexdigest()
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO scan_records
                       (filename, scanned_at, entity_types, entity_count, severity, redacted_text_hash)
                       VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                    (
                        filename,
                        datetime.now(timezone.utc).isoformat(),
                        json.dumps(entity_types),
                        entity_count,
                        severity,
                        text_hash,
                    ),
                )
                record_id = cur.fetchone()[0]
            conn.commit()
            return record_id
    except Exception as e:
        print(f"[database] insert_scan_record failed: {e}")
        return -1


def mark_alert_sent(record_id: int):
    if record_id == -1:
        return
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scan_records SET alert_sent = 1 WHERE id = %s", (record_id,))
            conn.commit()
    except Exception as e:
        print(f"[database] mark_alert_sent failed: {e}")


def get_all_records(limit: int = 100) -> list:
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT id, filename, scanned_at, entity_types, entity_count,
                              severity, alert_sent
                       FROM scan_records ORDER BY id DESC LIMIT %s""",
                    (limit,),
                )
                cols = [d[0] for d in cur.description]
                return [dict(zip(cols, row)) for row in cur.fetchall()]
    except Exception as e:
        print(f"[database] get_all_records failed: {e}")
        return []

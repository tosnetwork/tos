"""Read-only views of the relayer operator's two databases.

The provider keeps the fee notes it imported in `leases.db`; the service keeps
its jobs, quotes and finalized evidence in `journal.db`. Both are opened
read-only, so the operator's own processes keep the only writer.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from adjudicate import FeeNote

JSON = dict[str, Any]


def _open(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def fee_notes(leases_db: Path) -> list[FeeNote]:
    with _open(leases_db) as db:
        rows = db.execute("SELECT transaction_hash, leaf FROM fee_notes ORDER BY leaf").fetchall()
    return [FeeNote(str(row["transaction_hash"]), int(row["leaf"])) for row in rows]


def jobs(journal_db: Path) -> list[JSON]:
    """Every job with its decoded evidence (None until finalized)."""
    with _open(journal_db) as db:
        rows = db.execute(
            "SELECT id, state, slot, message_hash, evidence FROM jobs ORDER BY issued"
        ).fetchall()
    result: list[JSON] = []
    for row in rows:
        evidence = json.loads(bytes(row["evidence"])) if row["evidence"] else None
        result.append(
            {
                "id": str(row["id"]),
                "state": str(row["state"]),
                "slot": int(row["slot"]),
                "message_hash": row["message_hash"],
                "evidence": evidence,
            }
        )
    return result


def fee_credits(journal_db: Path) -> list[JSON]:
    """The fee-credit records of every executed job."""
    return [
        job["evidence"]["fee_credit"]
        for job in jobs(journal_db)
        if job["evidence"] is not None and job["evidence"].get("fee_credit") is not None
    ]


def quoted_note_index(journal_db: Path, job_id: str) -> int | None:
    """The note key index the operator quoted for the job, from its own quote row."""
    with _open(journal_db) as db:
        row = db.execute("SELECT note_index FROM quotes WHERE job = ?", (job_id,)).fetchone()
    return None if row is None else int(row["note_index"])


def job_for_message(journal_db: Path, message_hash: str) -> JSON | None:
    for job in jobs(journal_db):
        if job["message_hash"] == message_hash:
            return job
    return None

#!/usr/bin/env python3
"""Bounded, read-only C09 retention inventory. It never selects rows to delete."""

import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

PAGE_ROWS = 64
PAGE_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 128
MAX_Q_ORIGINS = 4096
MAX_CONTROL_REFS = 2304
DEADLINE_SECONDS = 5


class Refused(Exception):
    pass


def identity(path):
    meta = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_mode & 0o077 or meta.st_nlink != 1):
        raise Refused("file_identity")
    return meta.st_dev, meta.st_ino


def reader(path, deadline):
    before = identity(path)
    db = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=0.1)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=100")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        db.execute("BEGIN TRANSACTION")
        opened = db.execute("PRAGMA database_list").fetchall()
        if len(opened) != 1 or opened[0][1] != "main" or identity(opened[0][2]) != before:
            raise Refused("file_replaced")
        if identity(path) != before:
            raise Refused("file_replaced")
        return db, before
    except Exception:
        db.close()
        raise


def bounded_int(value, ceiling):
    if type(value) is not int or not 0 <= value <= ceiling:
        raise Refused("counter")
    return value


def inspect(m_path, q_path, control_path, network, after_seq=0):
    if re.fullmatch(r"[0-9a-f]{64}", network) is None:
        raise Refused("network")
    bounded_int(after_seq, 2**63 - 1)
    deadline = time.monotonic() + DEADLINE_SECONDS
    m = q = control = None
    try:
        # This is an advisory cross-database inventory, never a deletion fence.
        m, m_id = reader(m_path, deadline)
        q, q_id = reader(q_path, deadline)
        control, control_id = reader(control_path, deadline)
        for db in (m, control):
            found = db.execute("SELECT network FROM database_identity WHERE singleton=1").fetchone()
            if found != (network,):
                raise Refused("network_identity")
        cursor = q.execute("SELECT network,device,inode,watermark,anchor_seq,anchor_hash "
                           "FROM query_manager_cursor WHERE singleton=1").fetchone()
        if (cursor is None or cursor[0] != network or cursor[1:3] != tuple(map(str, m_id))
                or type(cursor[3]) is not int or cursor[3] < 0):
            raise Refused("q_cursor_identity")
        _, _, _, q_watermark, anchor_seq, anchor_hash = cursor
        if (q_watermark == 0 and (anchor_seq is not None or anchor_hash is not None)) or (
                q_watermark > 0 and (type(anchor_seq) is not int or anchor_seq != q_watermark
                                     or not isinstance(anchor_hash, str)
                                     or re.fullmatch(r"[0-9a-f]{64}", anchor_hash) is None)):
            raise Refused("q_anchor")
        if anchor_seq is not None:
            found = m.execute("SELECT content_hash FROM observations WHERE store_seq=?", (anchor_seq,)).fetchone()
            if found != (anchor_hash,):
                raise Refused("q_anchor_missing")
        highwater_row = m.execute("SELECT seq FROM sqlite_sequence WHERE name='observations'").fetchone()
        highwater = 0 if highwater_row is None else bounded_int(highwater_row[0], 2**63 - 1)
        if highwater < q_watermark or after_seq > highwater:
            raise Refused("m_watermark")
        origins = q.execute("SELECT manager_seq FROM query_origins LIMIT ?", (MAX_Q_ORIGINS + 1,)).fetchall()
        if len(origins) > MAX_Q_ORIGINS:
            raise Refused("q_origin_bound")
        q_pins = {bounded_int(row[0], highwater) for row in origins}
        refs = control.execute("SELECT store_seq FROM source_state LIMIT ?", (MAX_CONTROL_REFS + 1,)).fetchall()
        if len(refs) > MAX_CONTROL_REFS:
            raise Refused("control_ref_bound")
        control_pins = {bounded_int(row[0], highwater) for row in refs}
        unresolved = control.execute("SELECT count(*) FROM incidents").fetchone()[0]
        pending = control.execute("SELECT count(*) FROM outbox WHERE delivered=0").fetchone()[0]
        if bounded_int(unresolved, MAX_CONTROL_REFS) > MAX_CONTROL_REFS or bounded_int(pending, 4096) > 4096:
            raise Refused("control_bound")
        rows = m.execute("SELECT store_seq,length(CAST(source AS BLOB)),"
                         "CASE WHEN length(CAST(source AS BLOB))<=128 THEN source ELSE NULL END,"
                         "length(CAST(body AS BLOB)) FROM observations "
                         "WHERE store_seq>? ORDER BY store_seq LIMIT ?", (after_seq, PAGE_ROWS + 1)).fetchall()
        page = rows[:PAGE_ROWS]
        bytes_seen = 0
        process = unclassified = q_pinned = control_pinned = 0
        for seq, source_len, source, length in page:
            bounded_int(seq, highwater)
            if (type(source_len) is not int or not 0 <= source_len <= MAX_SOURCE_BYTES
                    or not isinstance(source, str)):
                raise Refused("source_size")
            if type(length) is not int or not 0 <= length <= 32768:
                raise Refused("row_size")
            bytes_seen += length
            if bytes_seen > PAGE_BYTES:
                raise Refused("page_bytes")
            process += source == "process"
            unclassified += source != "process"
            q_pinned += seq in q_pins or seq == anchor_seq
            control_pinned += seq in control_pins
        if time.monotonic() >= deadline:
            raise Refused("deadline")
        if (identity(m_path) != m_id or identity(q_path) != q_id
                or identity(control_path) != control_id):
            raise Refused("file_replaced")
        return {"schema_version": 1, "dry_run_ok": True, "advisory_only": True,
                "pin_view": "provisional_cross_database_snapshot", "deletion_candidates": 0,
                "pin_integrity": "not_verified",
                "age_eligibility": "not_evaluated_unknown_class_or_clock",
                "raw_process_ttl": "undecided",
                "raw_witness_ttl": "undecided", "m_highwater": str(highwater),
                "q_cursor_watermark": str(q_watermark), "page_after_seq": str(after_seq),
                "page_last_seq": str(page[-1][0]) if page else None,
                "page_rows": len(page), "page_body_bytes": bytes_seen,
                "page_has_more": len(rows) > PAGE_ROWS,
                "page_process_rows": process, "page_unclassified_rows": unclassified,
                "page_q_pinned_rows": q_pinned,
                "page_control_pinned_rows": control_pinned, "q_retained_origin_count": len(origins),
                "control_source_ref_count": len(refs), "control_incident_count": unresolved,
                "control_pending_outbox_count": pending}
    except (sqlite3.Error, OSError) as exc:
        raise Refused("read_unavailable") from exc
    finally:
        for db in (control, q, m):
            if db is not None:
                db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--m-db", required=True)
    parser.add_argument("--q-db", required=True)
    parser.add_argument("--control-db", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--after-seq", type=int, default=0)
    args = parser.parse_args()
    try:
        result = inspect(args.m_db, args.q_db, args.control_db, args.network, args.after_seq)
    except Refused as exc:
        result = {"schema_version": 1, "dry_run_ok": False, "advisory_only": True,
                  "deletion_candidates": 0, "error_kind": str(exc)}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["dry_run_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

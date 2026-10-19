#!/usr/bin/env python3
"""Disposable real Q/M socket control; reads live M only to seed private fixtures."""

import datetime as dt
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path.home() / "nhm-supervision" / "c09-local" / "runtime"
LIVE_M = RUNTIME / "evidence" / "evidence.db"
BIN = RUNTIME / "bin" / "tos-observability"
NODES = ("validator1", "validator2", "validator3", "validator4", "observer5", "observer6")
network = json.loads((RUNTIME / "deployment-public.json").read_text())["network_id"]

with tempfile.TemporaryDirectory(prefix="c09-isolated-", dir=Path.home()) as raw:
    d = Path(raw)
    d.chmod(0o700)
    m, q = d / "m.db", d / "q.db"
    control, mcp = d / "control.sock", d / "mcp.sock"
    c = sqlite3.connect(m)
    c.executescript("""CREATE TABLE database_identity(singleton INTEGER PRIMARY KEY,network TEXT NOT NULL);
      CREATE TABLE observations(store_seq INTEGER PRIMARY KEY AUTOINCREMENT,node TEXT NOT NULL,
      scope TEXT NOT NULL,process_epoch TEXT NOT NULL,source_epoch TEXT NOT NULL,source TEXT NOT NULL,
      source_record TEXT NOT NULL,content_hash TEXT NOT NULL,body TEXT NOT NULL,
      UNIQUE(node,scope,process_epoch,source_epoch,source,source_record));
      CREATE TABLE quarantined(node TEXT,scope TEXT,process_epoch TEXT,source_epoch TEXT,source TEXT,
      PRIMARY KEY(node,scope,process_epoch,source_epoch,source));""")
    c.execute("INSERT INTO database_identity VALUES(1,?)", (network,))
    with sqlite3.connect("file:" + str(LIVE_M) + "?mode=ro", uri=True) as live:
        for node in NODES:
            row = live.execute(
                "SELECT body FROM observations WHERE source='process' AND node=? ORDER BY store_seq DESC LIMIT 1",
                (node,),
            ).fetchone()
            assert row, node
            parent = json.loads(row[0])
            record, source = parent["record"], parent["record"]["payload"]["source"]
            now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=5)
            stamp = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            ms = int(now.timestamp() * 1000)
            record["observed_at_ms"] = ms
            record["received_at_ms"] = ms
            record["quality"]["observed_at_ms"] = ms
            record["quality"]["last_success_at_ms"] = ms
            source["observed_at"] = stamp
            source["last_success_at"] = stamp
            source["source_age_ms"] = 0
            canonical = json.loads(json.dumps(parent))
            canonical["record"]["received_at_ms"] = 0
            digest = hashlib.sha256(
                json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest()
            c.execute(
                "INSERT INTO observations(node,scope,process_epoch,source_epoch,source,source_record,content_hash,body) VALUES(?,?,?,?,?,?,?,?)",
                (
                    record["node_id"],
                    record["scope_id"],
                    record["process_epoch"],
                    parent["source_epoch"],
                    record["source_id"],
                    record["source_record_id"],
                    digest,
                    json.dumps(parent, ensure_ascii=False, separators=(",", ":")),
                ),
            )
    c.commit()
    c.close()
    (d / "inventory.json").write_text(
        json.dumps({"network_id": network, "nodes": NODES, "scopes": ["node"]})
    )
    for name in ("operator", "ingest", "service"):
        p = d / (name + ".token")
        p.write_text(secrets.token_hex(32) + "\n")
        p.chmod(0o600)
    cmd = [
        str(BIN),
        str(d / "inventory.json"),
        "127.0.0.1:0",
        str(d / "operator.token"),
        str(d / "ingest.token"),
        str(d / "service.token"),
        str(q),
        str(control),
        "-",
        str(m),
        str(mcp),
    ]
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(60):
            if control.exists() and mcp.exists() and q.exists():
                break
            if process.poll() is not None:
                raise RuntimeError("isolated Q exit: " + process.stderr.read()[-800:])
            time.sleep(0.1)
        else:
            raise RuntimeError("isolated Q sockets absent")
        # Wait until Q's first import commits a nonempty projection cursor.
        for _ in range(60):
            try:
                with sqlite3.connect("file:" + str(q) + "?mode=ro", uri=True) as qc:
                    cursor = qc.execute(
                        "SELECT watermark FROM query_manager_cursor WHERE singleton=1"
                    ).fetchone()
                    if cursor and cursor[0] >= len(NODES):
                        break
            except sqlite3.Error:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("isolated Q projection cursor absent")
        meta = q.stat()
        sha = hashlib.sha256(BIN.read_bytes()).hexdigest()
        with sqlite3.connect("file:" + str(q) + "?mode=ro", uri=True) as qc:
            grants, body = qc.execute(
                "SELECT count(*),coalesce(sum(length(body)),0) FROM query_grants"
            ).fetchone()
            attempts = qc.execute("SELECT count(*) FROM query_attempts").fetchone()[0]
        window_id = "a" * 64
        baseline = {
            "schema_version": 2,
            "window_id": window_id,
            "prior_log_sha256": "b" * 64,
            "prior_marker_sha256": "c" * 64,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "time_namespace": os.readlink("/proc/self/ns/time"),
            "q_device": str(meta.st_dev),
            "q_inode": str(meta.st_ino),
            "grants": grants,
            "grant_body_bytes": body,
            "attempts": attempts,
            "query_sha256": sha,
            "max_new_grants": 1024,
            "max_new_grant_body_bytes": 33554432,
            "max_new_attempts": 3072,
        }
        bp = d / "baseline.json"
        bp.write_text(json.dumps(baseline, separators=(",", ":")))
        bp.chmod(0o600)
        digest = hashlib.sha256(bp.read_bytes()).hexdigest()
        fake = d / "systemctl"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" ' + str(process.pid) + "\n")
        fake.chmod(0o700)
        env = {**os.environ, "PATH": str(d) + ":" + os.environ["PATH"]}
        script = ROOT / "scripts/sample-query-functional.py"
        forced_slot = ((int(time.time()) // 300) // 12) * 12
        runner = (
            "import importlib.util,sys; from unittest.mock import patch; "
            "sys.argv=sys.argv[1:]; spec=importlib.util.spec_from_file_location('witness',sys.argv[0]); "
            "w=importlib.util.module_from_spec(spec); spec.loader.exec_module(w); "
            "patch('time.time',return_value=" + str(forced_slot * 300) + ").start(); "
            "sys.exit(w.main())"
        )
        args = [
            "/usr/bin/python3",
            "-c",
            runner,
            str(script),
            "--control-socket",
            str(control),
            "--mcp-socket",
            str(mcp),
            "--operator-token-file",
            str(d / "operator.token"),
            "--service-token-file",
            str(d / "service.token"),
            "--m-db",
            str(m),
            "--q-ledger",
            str(q),
            "--log-file",
            str(d / "sample.jsonl"),
            "--query-unit",
            "isolated-query",
            "--expected-query-sha256",
            sha,
            "--baseline-file",
            str(bp),
            "--expected-baseline-sha256",
            digest,
            "--window-id",
            window_id,
        ]
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=35)
        sample = (
            json.loads((d / "sample.jsonl").read_text().strip())
            if (d / "sample.jsonl").exists()
            else None
        )
        with sqlite3.connect("file:" + str(q) + "?mode=ro", uri=True) as qc:
            grant_state = qc.execute(
                "SELECT count(*),coalesce(sum(revoked),0) FROM query_grants"
            ).fetchone()
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        assert (
            sample and sample["status"] == "pass" and sample["fixed_grant_query_status"] == "pass"
        )
        assert sample["negative_controls"] is True and sample["cleanup_confirmed"] is True
        assert grant_state == (2, 2)
        assert not (d / "sample.jsonl.inflight").exists()
        print(
            json.dumps(
                {
                    "exit": result.returncode,
                    "stdout": result.stdout.strip(),
                    "sample": sample,
                    "ledger_grants_total_revoked": grant_state,
                },
                sort_keys=True,
            )
        )
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()

#!/usr/bin/env python3
"""Collect complete hash-linked pool history from a native head, RPC pages and optional archives."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from control import configuration, write_new

MAX_TRANSACTIONS = 4096
MAX_BYTES = 64 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--backend-sha256", required=True)
    parser.add_argument("--native-python", type=Path, required=True)
    parser.add_argument("--archive", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = configuration(args.config)
    if config["release"].global_id != 3:
        parser.error("isolated local network only")
    os.umask(0o077)
    args.out.mkdir(mode=0o700, exist_ok=False)
    subprocess.run(
        [
            str(args.native_python),
            str(Path(__file__).with_name("pool_head.py")),
            "--config",
            str(args.config),
            "--backend",
            str(args.backend),
            "--backend-sha256",
            args.backend_sha256,
            "--out",
            str(args.out / "proven-head.json"),
        ],
        check=True,
        timeout=45,
    )
    proven = json.loads((args.out / "proven-head.json").read_bytes())["head"]
    provider = json.loads((Path(config["state_dir"]) / "provider.json").read_bytes())
    endpoint = urllib.parse.urlsplit(provider["rpc_url"])
    if (
        endpoint.scheme != "http"
        or endpoint.hostname != "127.0.0.1"
        or endpoint.username
        or endpoint.password
        or endpoint.query
        or endpoint.fragment
    ):
        raise RuntimeError("local RPC origin required")
    from pytosiq_core import Cell, Transaction

    pool = bytes.fromhex(config["release"].pool.split(":")[1])
    indexed, total, scanned = {}, 0, 0

    def index(raw):
        nonlocal total, scanned
        scanned += 1
        if scanned > MAX_TRANSACTIONS or not 0 < len(raw) <= 512 * 1024:
            raise RuntimeError("transaction input bound")
        cell = Cell.one_from_boc(raw)
        digest = cell.hash.hex()
        if digest in indexed:
            return
        transaction = Transaction.deserialize(cell.begin_parse())
        if transaction.account_addr != pool:
            raise RuntimeError("archive transaction belongs to another account")
        total += len(raw)
        if total > MAX_BYTES:
            raise RuntimeError("history byte bound")
        indexed[digest] = (raw, transaction)

    for archive in args.archive:
        for path in sorted(archive.glob("*.boc")):
            if path.stat().st_size > 512 * 1024:
                raise RuntimeError("archive transaction byte bound")
            index(path.read_bytes())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    cursor = proven["last_transaction_hash"]
    lt = proven["last_transaction_lt"]
    backwards, seen, pages = [], set(), 0
    while lt:
        if len(seen) >= MAX_TRANSACTIONS or cursor in seen:
            raise RuntimeError("history depth/cycle bound")
        if cursor not in indexed:
            query = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getTransactions",
                "params": {
                    "address": config["release"].pool,
                    "limit": 16,
                    "lt": str(lt),
                    "hash": base64.b64encode(bytes.fromhex(cursor)).decode(),
                },
            }
            request = urllib.request.Request(
                provider["rpc_url"],
                json.dumps(query).encode(),
                {"Content-Type": "application/json"},
            )
            with opener.open(request, timeout=15) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise RuntimeError("RPC answer byte bound")
            rows = json.loads(data).get("result")
            if not isinstance(rows, list) or not 0 < len(rows) <= 16:
                raise RuntimeError("history page missing/bound")
            pages += 1
            for row in rows:
                raw = base64.b64decode(row["data"], validate=True)
                if base64.b64encode(raw).decode() != row["data"]:
                    raise RuntimeError("noncanonical transaction base64")
                index(raw)
        if cursor not in indexed:
            raise RuntimeError("authenticated predecessor missing; cannot invent history")
        raw, transaction = indexed[cursor]
        if transaction.lt != lt:
            raise RuntimeError("authenticated logical-time mismatch")
        seen.add(cursor)
        backwards.append((cursor, raw, transaction))
        cursor, lt = transaction.prev_trans_hash.hex(), transaction.prev_trans_lt
    if cursor != "00" * 32:
        raise RuntimeError("creation predecessor is not zero")
    directory = args.out / "transactions"
    directory.mkdir(mode=0o700)
    listed = []
    for digest, raw, transaction in reversed(backwards):
        name = f"{transaction.lt:020d}-{digest}.boc"
        (directory / name).write_bytes(raw)
        listed.append({"file": name, "lt": transaction.lt, "hash": digest})
    write_new(
        args.out / "MANIFEST.json",
        {
            "schema": "tos.br1.authenticated-history.v1",
            "head": proven,
            "transactions_dir": str(directory),
            "transactions": listed,
            "rpc_pages": pages,
            "transaction_bytes": total,
            "ignored_unlinked_transactions": len(indexed) - len(seen),
            "manifest_body_sha256": hashlib.sha256(
                json.dumps(listed, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        },
    )
    print("BR1_AUTHENTICATED_HISTORY_PASS", len(listed), "transactions", pages, "RPC pages")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Read-only, exact-query E04 wallet-to-Agent-Account transaction capture.

Run against a retained node database reopened on a disposable copy with
--json-rpc-readonly. This script never broadcasts or edits custody state.
The raw RPC bodies are saved before interpreting any absence as a finding.
"""

import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import urllib.error
import urllib.request

from pytosiq_core import Cell, Transaction


def rpc(origin: str, method: str, **params):
    body = json.dumps({"jsonrpc": "2.0", "id": method, "method": method,
                       "params": params}).encode()
    request = urllib.request.Request(
        origin.rstrip("/") + "/jsonRPC", data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    return {"request": body.decode(), "http_status": status,
            "response": raw.decode(errors="replace")}


def result(exchange):
    parsed = json.loads(exchange["response"])
    assert exchange["http_status"] == 200 and parsed.get("ok") is True, parsed
    return parsed["result"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--query-id", type=int, required=True)
    parser.add_argument("--tosctl", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    raw = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "masterchain": rpc(args.origin, "getMasterchainInfo"),
        "wallet_info": rpc(args.origin, "getWalletInformation", address=args.wallet),
        "wallet_transactions": rpc(args.origin, "getTransactions", address=args.wallet, limit=10),
        "account_info": rpc(args.origin, "getAddressInformation", address=args.account),
        "account_transactions": rpc(args.origin, "getTransactions", address=args.account, limit=10),
    }
    show = subprocess.run(
        [str(args.tosctl), "agent", "account", "show", "--address", args.account,
         "--format", "json", "-c", str(args.config)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    raw["account_show"] = {"command": show.args, "exit_code": show.returncode,
                           "stdout": show.stdout, "stderr": show.stderr}
    (args.output / "raw.json").write_text(json.dumps(raw, indent=2) + "\n")

    wallet_rows = result(raw["wallet_transactions"])
    account_rows = result(raw["account_transactions"])
    matched = []
    for row in wallet_rows:
        tx = Transaction.deserialize(
            Cell.one_from_boc(base64.b64decode(row["data"])).begin_parse())
        for out in tx.out_msgs:
            body = out.body.begin_parse()
            try:
                op, query_id = body.load_uint(32), body.load_uint(64)
            except Exception:
                continue
            if query_id != args.query_id:
                continue
            msg_hash = base64.b64encode(out.cell.hash).decode()
            matching_json = [item for item in row["out_msgs"] if item["hash"] == msg_hash]
            matched.append({"wallet_row": row, "op": op, "query_id": query_id,
                            "outgoing_hash": msg_hash, "outgoing_json": matching_json})
    assert len(matched) == 1, f"query ID matched {len(matched)} wallet messages"
    wallet_match = matched[0]
    wallet_tx = wallet_match["wallet_row"]
    assert len(wallet_match["outgoing_json"]) == 1
    assert wallet_tx["aborted"] is False and wallet_tx["compute"]["success"] is True
    assert wallet_tx["action"]["success"] is True
    target = wallet_match["outgoing_json"][0]["destination"]
    account_matches = [row for row in account_rows
                       if (row.get("in_msg") or {}).get("hash") == wallet_match["outgoing_hash"]]
    assert len(account_matches) == 1, f"account received {len(account_matches)} matching messages"
    account_tx = account_matches[0]
    assert account_tx["aborted"] is False and account_tx["compute"]["success"] is True
    assert account_tx["action"]["success"] is True
    assert show.returncode == 0, show.stderr
    policy = json.loads(show.stdout)
    assert policy["max_per_tx"] == 1_000_000_000 and policy["daily_limit"] == 5_000_000_000
    summary = {
        "query_id": args.query_id, "op_hex": f"0x{wallet_match['op']:08x}",
        "wallet": args.wallet, "account": args.account, "destination": target,
        "outgoing_hash": wallet_match["outgoing_hash"],
        "wallet_transaction_id": wallet_tx["transaction_id"],
        "wallet_block_id": wallet_tx.get("block_id"),
        "wallet_compute": wallet_tx["compute"], "wallet_action": wallet_tx["action"],
        "account_transaction_id": account_tx["transaction_id"],
        "account_block_id": account_tx.get("block_id"),
        "account_compute": account_tx["compute"], "account_action": account_tx["action"],
        "policy": {"max_per_tx": policy["max_per_tx"],
                   "daily_limit": policy["daily_limit"], "seqno": policy["seqno"]},
        "masterchain_last": result(raw["masterchain"])["last"],
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("E04_POLICY_QUERY_EXECUTED", args.query_id, wallet_tx["transaction_id"]["lt"],
          account_tx["transaction_id"]["lt"])


if __name__ == "__main__":
    main()

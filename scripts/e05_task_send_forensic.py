#!/usr/bin/env python3
"""Read-only wallet-to-Task-Escrow evidence from a retained E05 node copy.

The raw RPC exchanges are saved before any interpretation. Run only against
the disposable --json-rpc-readonly copy; this script never sends a message.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
import subprocess
import urllib.error
import urllib.request

from pytosiq_core import Address


def rpc(origin: str, method: str, **params):
    request_body = json.dumps({"jsonrpc": "2.0", "id": method,
                               "method": method, "params": params}).encode()
    request = urllib.request.Request(origin.rstrip("/") + "/jsonRPC", data=request_body,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read()
    return {"request": request_body.decode(), "http_status": status,
            "response": body.decode(errors="replace")}


def result(exchange):
    response = json.loads(exchange["response"])
    assert exchange["http_status"] == 200 and response.get("ok") is True, response
    return response["result"]


def normalized_address(value: str) -> str:
    return Address(value).to_str(is_user_friendly=False).lower()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--task", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tosctl", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    raw = {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
           "masterchain": rpc(args.origin, "getMasterchainInfo"),
           "wallet_info": rpc(args.origin, "getWalletInformation", address=args.wallet),
           "wallet_transactions": rpc(args.origin, "getTransactions", address=args.wallet,
                                      limit=10),
           "task_info": rpc(args.origin, "getAddressInformation", address=args.task),
           "task_transactions": rpc(args.origin, "getTransactions", address=args.task,
                                    limit=10)}
    show = subprocess.run([str(args.tosctl), "agent", "task", "show", "--address", args.task,
                           "--format", "json", "-c", str(args.config)],
                          capture_output=True, text=True, timeout=30, check=False)
    raw["task_show"] = {"command": show.args, "exit_code": show.returncode,
                        "stdout": show.stdout, "stderr": show.stderr}
    (args.output / "raw.json").write_text(json.dumps(raw, indent=2) + "\n")

    wallet_rows = result(raw["wallet_transactions"])
    task_rows = result(raw["task_transactions"])
    matched = []
    for wallet_row in wallet_rows:
        for out in wallet_row.get("out_msgs", []):
            if normalized_address(out.get("destination", "")) != normalized_address(args.task):
                continue
            inbox = [task_row for task_row in task_rows
                     if (task_row.get("in_msg") or {}).get("hash") == out.get("hash")]
            matched.append({"wallet_transaction": wallet_row,
                            "outgoing_message": out, "task_transactions": inbox})
    summary = {"wallet": args.wallet, "task": args.task,
               "masterchain_last": result(raw["masterchain"])["last"],
               "wallet_info": result(raw["wallet_info"]),
               "task_info": result(raw["task_info"]),
               "matching_messages": matched}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    assert len(matched) == 1, f"matched {len(matched)} wallet sends to the Task Escrow"
    match = matched[0]
    assert len(match["task_transactions"]) == 1, "exact outbound has no unique Task inbound"
    for transaction in (match["wallet_transaction"], match["task_transactions"][0]):
        assert transaction["aborted"] is False and transaction["compute"]["success"] is True
        assert transaction["action"]["success"] is True
    assert show.returncode == 0, show.stderr
    assert json.loads(show.stdout)["status"] == "accepted", show.stdout
    print("E05_TASK_WALLET_OUTBOUND_MATCHES", len(matched),
          "TASK_INBOUND_MATCHES", sum(len(item["task_transactions"]) for item in matched))


if __name__ == "__main__":
    main()

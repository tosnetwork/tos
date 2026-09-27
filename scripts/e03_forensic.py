#!/usr/bin/env python3
"""Bind a captured tosctl sendBoc to wallet and destination transactions.

Run against the retained E03 chain database after a CLI timeout. This script
does not resend the message; it saves the node's raw JSON-RPC replies first,
then checks exact message hashes and execution flags.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.error
import urllib.request

from pytosiq_core import Cell


def rpc(origin, method, **params):
    request_body = json.dumps({"jsonrpc": "2.0", "id": method, "method": method, "params": params}).encode()
    request = urllib.request.Request(origin + "/jsonRPC", data=request_body,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    return {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "request_body": request_body.decode(), "status": status,
            "response_body": raw.decode()}


def result(exchange):
    body = json.loads(exchange["response_body"])
    assert exchange["status"] == 200 and body.get("ok") is True, body
    return body["result"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--wallet", required=True)
    parser.add_argument("--origin", default="http://127.0.0.1:19451")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--captured", type=Path,
                        help="re-evaluate already captured raw replies without reopening the network")
    parser.add_argument("--require-block-context", action="store_true",
                        help="refuse a poll lacking its exact masterchain and shard references")
    parser.add_argument("--scan-mc-from", type=int,
                        help="first historical masterchain height to query for this wallet")
    parser.add_argument("--scan-mc-to", type=int,
                        help="last historical masterchain height to query for this wallet")
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.trace.read_text().splitlines()]
    requests = [json.loads(row["request_body"]) for row in rows]
    sends = [(index, query) for index, query in enumerate(requests) if query["method"] == "sendBoc"]
    assert sends, "no captured tosctl sendBoc"
    send_index, send = sends[-1]
    message_hash = base64.b64encode(Cell.one_from_boc(base64.b64decode(send["params"]["boc"])).hash).decode()
    wallet_rows = [(index, json.loads(row["response_body"])["result"])
                   for index, (row, query) in enumerate(zip(rows, requests))
                   if query["method"] == "getWalletInformation" and
                   query["params"].get("address") == args.wallet and row["status"] == 200]
    assert wallet_rows and any(index > send_index for index, _ in wallet_rows), (
        "no captured wallet seqno polling after sendBoc")
    pre_send_seqnos = [row.get("seqno") for index, row in wallet_rows if index < send_index]
    post_send_seqnos = [row.get("seqno") for index, row in wallet_rows if index > send_index]
    pre_send_balances = [row.get("balance") for index, row in wallet_rows if index < send_index]
    post_send_balances = [row.get("balance") for index, row in wallet_rows if index > send_index]
    post_send_observed_blocks = [{"masterchain": row.get("observed_masterchain_block"),
                                  "shard": row.get("observed_shard_block")}
                                 for index, row in wallet_rows if index > send_index]
    if args.require_block_context:
        assert all(item["masterchain"] is not None and item["shard"] is not None
                   for item in post_send_observed_blocks), "a wallet poll omitted its block references"
    raw = (json.loads(args.captured.read_text())["raw"] if args.captured else {
        "wallet_info": rpc(args.origin, "getWalletInformation", address=args.wallet),
        "wallet_transactions": rpc(args.origin, "getTransactions", address=args.wallet, limit=10),
    })
    args.output.write_text(json.dumps({"raw": raw}, indent=2) + "\n")
    wallet_transactions = result(raw["wallet_transactions"])
    matches = [tx for tx in wallet_transactions if tx.get("in_msg_hash") == message_hash or
               (tx.get("in_msg") or {}).get("hash") == message_hash]
    assert len(matches) == 1, "captured sendBoc was not uniquely found in wallet transactions"
    wallet_tx = matches[0]
    assert wallet_tx["aborted"] is False and wallet_tx["compute"]["success"] is True
    assert wallet_tx["action"]["success"] is True and len(wallet_tx["out_msgs"]) == 1
    outgoing = wallet_tx["out_msgs"][0]
    destination = outgoing["destination"]
    if not args.captured:
        raw["destination_info"] = rpc(args.origin, "getAddressInformation", address=destination)
        raw["destination_transactions"] = rpc(args.origin, "getTransactions", address=destination, limit=10)
    args.output.write_text(json.dumps({"raw": raw}, indent=2) + "\n")
    target_matches = [tx for tx in result(raw["destination_transactions"])
                      if (tx.get("in_msg") or {}).get("hash") == outgoing["hash"]]
    assert len(target_matches) == 1, "wallet outgoing message was not uniquely found at destination"
    target_tx = target_matches[0]
    assert target_tx["aborted"] is False and target_tx["compute"]["success"] is True
    assert result(raw["destination_info"])["state"] == "active"
    first_visible = None
    if args.scan_mc_from is not None or args.scan_mc_to is not None:
        assert args.scan_mc_from is not None and args.scan_mc_to is not None
        assert 0 < args.scan_mc_from <= args.scan_mc_to and args.scan_mc_to - args.scan_mc_from <= 32
        raw["historical_wallet_info"] = [
            rpc(args.origin, "getWalletInformation", address=args.wallet, seqno=height)
            for height in range(args.scan_mc_from, args.scan_mc_to + 1)
        ]
        args.output.write_text(json.dumps({"raw": raw}, indent=2) + "\n")
        history = [result(exchange) for exchange in raw["historical_wallet_info"]]
        visible = [entry for entry in history
                   if entry.get("last_transaction_id", {}).get("lt") == wallet_tx["transaction_id"]["lt"]]
        assert visible, "wallet transaction was not visible in the requested masterchain interval"
        first_visible = {"masterchain": visible[0].get("observed_masterchain_block"),
                         "shard": visible[0].get("observed_shard_block")}
    summary = {"trace_sha256": hashlib.sha256(args.trace.read_bytes()).hexdigest(),
               "forensic_observed_at_utc": datetime.now(timezone.utc).isoformat(),
               "send_request_id": send["id"], "send_index": send_index,
               "external_message_hash": message_hash, "wallet": args.wallet,
               "pre_send_seqnos": pre_send_seqnos, "post_send_seqnos": post_send_seqnos,
               "pre_send_balances": pre_send_balances, "post_send_balances": post_send_balances,
               "post_send_observed_blocks": post_send_observed_blocks,
               "reopened_seqno": result(raw["wallet_info"])["seqno"],
               "reopened_balance": result(raw["wallet_info"])["balance"],
               "wallet_transaction_id": wallet_tx["transaction_id"],
               "wallet_transaction_block_id": wallet_tx.get("block_id"),
               "wallet_transaction_utime": wallet_tx["utime"],
               "wallet_outgoing_hash": outgoing["hash"], "destination": destination,
               "destination_transaction_id": target_tx["transaction_id"],
               "destination_transaction_block_id": target_tx.get("block_id"),
               "destination_transaction_utime": target_tx["utime"]}
    if first_visible is not None:
        summary["first_visible_historical_reference"] = first_visible
    args.output.write_text(json.dumps({"summary": summary, "raw": raw}, indent=2) + "\n")
    print("E03_CAPTURED_SEND_EXECUTED", message_hash, wallet_tx["transaction_id"]["lt"],
          target_tx["transaction_id"]["lt"])


if __name__ == "__main__":
    main()

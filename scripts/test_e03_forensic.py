"""The E03 timeout diagnosis must bind the exact sent BOC across both transactions."""

import base64
import json
import sys

import pytest
from pytosiq_core import Builder

import e03_forensic


def test_captured_send_binds_wallet_and_destination(tmp_path, monkeypatch):
    message = Builder().store_uint(7, 8).end_cell()
    sent_hash = base64.b64encode(message.hash).decode()
    trace = tmp_path / "trace.jsonl"
    rows = []
    for method, params, response in [
        ("getWalletInformation", {"address": "wallet"}, {"result": {"seqno": 1, "balance": "120"}}),
        ("sendBoc", {"boc": base64.b64encode(message.to_boc()).decode()}, {"ok": True}),
        ("getWalletInformation", {"address": "wallet"}, {"result": {"seqno": 1, "balance": "120"}}),
    ]:
        rows.append(json.dumps({"request_body": json.dumps({"id": method, "method": method, "params": params}),
                                "response_body": json.dumps(response), "status": 200}))
    trace.write_text("\n".join(rows) + "\n")

    def exchange(result):
        return {"status": 200, "request_body": "{}",
                "response_body": json.dumps({"ok": True, "result": result})}

    wallet_tx = {"transaction_id": {"lt": "10"}, "utime": 100, "in_msg_hash": sent_hash,
                 "aborted": False, "compute": {"success": True}, "action": {"success": True},
                 "out_msgs": [{"destination": "target", "hash": "outgoing"}]}
    target_tx = {"transaction_id": {"lt": "12"}, "utime": 100,
                 "in_msg": {"hash": "outgoing"}, "aborted": False,
                 "compute": {"success": True}}
    captured = tmp_path / "captured.json"
    output = tmp_path / "output.json"

    def run():
        monkeypatch.setattr(sys, "argv", ["e03_forensic.py", "--trace", str(trace),
                                             "--wallet", "wallet", "--captured", str(captured),
                                             "--output", str(output)])
        e03_forensic.main()

    captured.write_text(json.dumps({"raw": {
        "wallet_info": exchange({"seqno": 2, "balance": "90"}),
        "wallet_transactions": exchange([wallet_tx]),
        "destination_info": exchange({"state": "active"}),
        "destination_transactions": exchange([target_tx]),
    }}))
    run()
    summary = json.loads(output.read_text())["summary"]
    assert summary["pre_send_seqnos"] == [1]
    assert summary["post_send_seqnos"] == [1]
    assert summary["reopened_seqno"] == 2
    assert summary["pre_send_balances"] == ["120"]
    assert summary["post_send_balances"] == ["120"]
    assert summary["reopened_balance"] == "90"
    assert summary["external_message_hash"] == sent_hash

    target_tx["in_msg"]["hash"] = "different"
    captured.write_text(json.dumps({"raw": {
        "wallet_info": exchange({"seqno": 2, "balance": "90"}),
        "wallet_transactions": exchange([wallet_tx]),
        "destination_info": exchange({"state": "active"}),
        "destination_transactions": exchange([target_tx]),
    }}))
    with pytest.raises(AssertionError, match="outgoing message was not uniquely found"):
        run()

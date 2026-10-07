"""Real native transaction BOC regressions; input is the fee runner's export directory."""
import argparse
import base64
import copy
import json
import hashlib
from pathlib import Path
from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.transaction import Transaction
from quantum_transaction_chain import verify


def run(directory):
    exported = json.loads((directory / "PUBLIC-TEST-ONLY-network-input.json").read_text())
    message = (directory / "PUBLIC-TEST-ONLY-external.boc").read_bytes()
    observations = {}
    for role in ("vault", "module", "wallet", "recipient"):
        raw = json.loads((directory / (role + "-result.json")).read_text())["transaction"]
        cell = Boc(base64.b64decode(raw)).deserialize()[0]
        tx = Transaction.deserialize(cell.begin_parse())
        observations[role] = dict(ok=True, result=[dict(data=raw, transaction_id=dict(
            lt=str(tx.lt), hash=base64.b64encode(cell.hash).decode()))])
    assert len(verify(exported, message, observations)["receipts"]) == 4
    for fault in ("missing_recipient", "wrong_hash", "wrong_external", "wrong_amount"):
        changed = copy.deepcopy(observations)
        external = message
        changed_export = copy.deepcopy(exported)
        if fault == "missing_recipient":
            changed["recipient"]["result"] = []
        elif fault == "wrong_hash":
            changed["wallet"]["result"][0]["transaction_id"]["hash"] = base64.b64encode(bytes(32)).decode()
        elif fault == "wrong_amount":
            changed_export["payment_amount"] += 1
        else:
            from pytosiq_core import Builder
            external = Builder().store_uint(0, 8).end_cell().to_boc()
            changed_export["message_sha256"] = hashlib.sha256(external).hexdigest()
        expected = {"missing_recipient": "transaction-bound recipient", "wrong_hash": "transaction hash mismatch",
                    "wrong_external": "transaction-bound vault", "wrong_amount": "payment amount mismatch"}[fault]
        try:
            verify(changed_export, external, changed)
        except ValueError as error:
            assert expected in str(error), (fault, str(error))
        else:
            raise AssertionError("Transaction chain guard missing: " + fault)
    print("Native BOC linkage and four exact negative controls pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    run(parser.parse_args().input)

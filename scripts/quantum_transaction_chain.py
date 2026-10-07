"""Decode raw transaction BOCs and bind a test payment's full message chain.

RPC data is untrusted: this verifies internal consistency/execution, not inclusion
in authenticated finalized blocks. Callers must prove that separately.
"""

import base64
import hashlib

from pytosiq_core.boc.deserialize import Boc
from pytosiq_core.tlb.transaction import Transaction


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_rows(response, address):
    require(response.get("ok") is True, "transaction query refused")
    rows = response.get("result")
    require(isinstance(rows, list) and len(rows) <= 16, "transaction history bounds")
    result = []
    for row in rows:
        roots = Boc(base64.b64decode(row["data"], validate=True)).deserialize()
        require(len(roots) == 1, "transaction BOC root count")
        tx = Transaction.deserialize(roots[0].begin_parse())
        require(tx.account_addr.hex() == address.split(":", 1)[1], "transaction account mismatch")
        require(str(tx.lt) == str(row["transaction_id"]["lt"]), "transaction LT mismatch")
        require(
            base64.b64decode(row["transaction_id"]["hash"], validate=True) == roots[0].hash,
            "transaction hash mismatch",
        )
        result.append(tx)
    return result


def verify(exported, message, observations):
    require(
        hashlib.sha256(message).hexdigest() == exported["message_sha256"],
        "exported message digest mismatch",
    )
    roots = Boc(message).deserialize()
    require(len(roots) == 1, "external message BOC root count")
    expected = roots[0].hash
    receipts = []
    previous_lt = None
    roles = ("vault", "module", "wallet", "recipient")
    for index, role in enumerate(roles):
        address = exported["accounts"][role]["address"]
        candidates = [
            tx
            for tx in decode_rows(observations[role], address)
            if tx.in_msg is not None and tx.in_msg.cell.hash == expected
        ]
        require(len(candidates) == 1, "missing or ambiguous transaction-bound " + role)
        tx = candidates[0]
        if role == "recipient":
            require(
                tx.in_msg.is_internal and tx.in_msg.info.bounced is False,
                "recipient received bounce or external message",
            )
            require(
                tx.in_msg.info.value_coins == exported["payment_amount"],
                "recipient payment amount mismatch",
            )
        description = tx.description
        require(
            description.type_ == "ordinary"
            and description.aborted is False
            and description.destroyed is False,
            "aborted or nonordinary " + role,
        )
        compute = description.compute_ph
        require(
            compute.type_ == "vm" and compute.success is True and compute.exit_code in (0, 1),
            "compute failed " + role,
        )
        require(
            description.action is None
            or (description.action.success is True and description.action.result_code == 0),
            "action failed " + role,
        )
        require(previous_lt is None or tx.lt > previous_lt, "message chain LT order")
        receipts.append(
            dict(
                role=role,
                address=address,
                lt=str(tx.lt),
                transaction_hash=tx.cell.hash.hex(),
                incoming_message_hash=expected.hex(),
            )
        )
        previous_lt = tx.lt
        if index + 1 < len(roles):
            target = exported["accounts"][roles[index + 1]]["address"]
            outgoing = [
                msg
                for msg in tx.out_msgs
                if msg.is_internal
                and msg.info.dest.to_str(is_user_friendly=False) == target
                and msg.info.bounced is False
            ]
            require(len(outgoing) == 1, "missing or ambiguous outgoing " + role)
            require(
                outgoing[0].info.src.to_str(is_user_friendly=False) == address,
                "message source mismatch",
            )
            expected = outgoing[0].cell.hash
    return dict(
        scope="Raw transaction execution and message linkage only; block inclusion/finality unproven",
        authenticated_finality=False,
        receipts=receipts,
    )

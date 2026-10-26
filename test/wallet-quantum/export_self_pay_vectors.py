#!/usr/bin/env python3
"""Export public self-pay mobile vectors after executing every signed operation."""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from test_self_pay import NETWORK, ROOT, TAGS, Cell, Harness, native, provenance, run


def raw_bytes(cell):
    result = b""
    while True:
        result += int(cell.bits, 2).to_bytes(len(cell.bits) // 8, "big")
        if not cell.refs:
            return result
        cell = cell.refs[0]


def main():
    if not __debug__:
        raise SystemExit("Vector export requires enabled Python assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    work = args.output.parent / "vector-build"
    h = Harness(work)
    probe = native.compile_contract("wallet-quantum-possession-probe.fc", work / "probe.boc")
    cases = []
    for name, role, kind in [
        ("primary", 1, 0),
        ("rescue", 2, 0),
        ("configure", 2, 1),
        ("lock", 2, 3),
        ("migrate", 2, 4),
    ]:
        payload = (
            None if kind != 4 else Cell().uint(TAGS[4], 32).ref(h.make_authority(policy_value=2))
        )
        message = h.message(role=role, kind=kind, payload=payload)
        h.send(name, message)
        row = h.rows[-1]
        assert row["compute_success"] and not row["aborted"] and row["action"]["success"], row
        expected_state = dict(
            seqno=1 if kind in (0, 1) else 0,
            wallet_id=0,
            retired=2 if kind == 3 else 0,
            epoch=0 if kind == 0 else 1,
            primary=int(kind == 0 and role == 1),
            rescue=int(kind == 0 and role == 2),
            authority=(
                h.make_authority(policy_value=2) if kind in (1, 4) else h.authority
            ).hash.hex(),
        )
        assert row["state"] == expected_state, (name, row)
        body = message.refs[0]
        cases.append(
            dict(
                name=name,
                role=role,
                kind=kind,
                request_hash=body.refs[0].hash.hex(),
                signature=raw_bytes(body.refs[1]).hex(),
                submission_hash=body.hash.hex(),
                external_hash=message.hash.hex(),
            )
        )
    immutable = (
        Cell()
        .uint(0x51505031, 32)
        .sint(native.GLOBAL_ID, 32)
        .uint(NETWORK, 256)
        .addr(h.address)
        .uint(123, 256)
        .uint(native.NOW + 600, 32)
        .ref(h.authority)
    )
    probe_data = Cell().uint(1, 8).uint(0, 1).ref(immutable)
    probe_init = native.state_init(probe, probe_data)
    probe_digest = Cell().uint(0x51505031, 32).raw(probe.hash).ref(immutable).hash
    identity = (
        Cell().uint(0x51534931, 32).uint(h.address[1], 256).ref(native.state_init(h.code, h.data))
    )
    origins = provenance()
    origins["sources"][str(Path(__file__).relative_to(ROOT))] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    vector = dict(
        schema="tos-quantum-self-pay-v1",
        source_commit=run("git", "-C", ROOT, "rev-parse", "HEAD").strip(),
        source_files=origins["sources"],
        tools={k: v["sha256"] for k, v in origins["executables"].items()},
        global_id=native.GLOBAL_ID,
        namespace=NETWORK.to_bytes(32, "big").hex(),
        now=native.NOW,
        deadline=native.NOW + 600,
        primary_seed="11" * 32,
        rescue_seed="22" * 48,
        primary_key=h.pkfile.read_bytes().hex(),
        rescue_key=h.slh_pk.hex(),
        wallet_code=base64.b64encode(h.code.boc()).decode(),
        wallet_code_hash=h.code.hash.hex(),
        probe_code=base64.b64encode(probe.boc()).decode(),
        probe_code_hash=probe.hash.hex(),
        authority_hash=h.authority.hash.hex(),
        initial_state_hash=h.data.hash.hex(),
        wallet_address=f"0:{h.address[1]:064x}",
        identity_hash=identity.hash.hex(),
        identity_boc=base64.b64encode(identity.boc()).decode(),
        cases=cases,
        probe=dict(
            challenge=f"{123:064x}",
            immutable_hash=immutable.hash.hex(),
            initial_state_hash=probe_data.hash.hex(),
            address="0:" + probe_init.hash.hex(),
            digest=probe_digest.hex(),
        ),
    )
    args.output.write_text(json.dumps(vector, indent=2) + "\n")


if __name__ == "__main__":
    main()

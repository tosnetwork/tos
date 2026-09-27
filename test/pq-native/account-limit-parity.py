#!/usr/bin/env python3
"""Whole-transaction parity for the account-state ceiling, across a version boundary.

The masterchain-specific ceiling only exists from global version 12. Which ceiling
applies is decided inside the action phase, after the compute phase has already produced
the new state, so a helper that asks the limit what it thinks proves nothing: the same
account and the same message have to go through both executors and end in the same place.

Three cases carry the boundary. A masterchain account that outgrows the masterchain
ceiling but not the ordinary one must be accepted below version 12 and refused from
version 12 on, and a basechain account of the same size must be accepted throughout.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Serialising a cell chain recurses once per cell, and these chains are deliberately long.
sys.setrecursionlimit(10000)

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions")]

# The boundary under test is which ceiling applies, not what the shipped numbers are, so
# the configuration states a small masterchain ceiling and an ordinary one far above it.
# The payload sits between them, where the two ceilings give opposite answers about the
# same account.
PAYLOAD_CELLS = 400
MASTERCHAIN_CEILING = 200
ORDINARY_CEILING = 65536


def compile_probe(build, out):
    """The probe lives with this test rather than in the production contract directory."""
    from cells import from_boc

    source = ROOT / "test/pq-native/account-state-limit-probe.fc"
    asm = out / "probe.fif"
    subprocess.run(
        [
            str(build / "crypto/func"),
            "-SPA",
            "-o",
            str(asm),
            str(ROOT / "crypto/smartcont/stdlib.fc"),
            str(source),
        ],
        check=True,
        capture_output=True,
    )
    run = out / "probe.run.fif"
    boc = out / "probe.boc"
    run.write_text(f'"Asm.fif" include\n"{asm}" include\n2 boc+>B "{boc}" B>file\n')
    subprocess.run(
        [
            str(build / "crypto/fift"),
            "-I",
            f"{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont",
            "-s",
            str(run),
        ],
        check=True,
        capture_output=True,
    )
    return from_boc(boc.read_bytes())


def chain(cells):
    """A chain of mostly empty cells: many cells, few bits, so the cell ceiling is what
    the account runs into rather than the message-size ceiling."""
    from cells import Cell

    tail = Cell().uint(0, 8)
    for _ in range(cells - 1):
        tail = Cell().uint(0, 8).ref(tail)
    return tail


def size_limits_v2():
    """ConfigParam 43 version 2, which is the first that carries both ceilings."""
    from cells import Cell

    return (
        Cell()
        .uint(0x02, 8)
        .uint(1 << 21, 32)
        .uint(1 << 13, 32)
        .uint(1000, 32)
        .uint(512, 16)
        .uint(65535, 32)
        .uint(512, 16)
        .uint(ORDINARY_CEILING, 32)
        .uint(MASTERCHAIN_CEILING, 32)
        .uint(256, 32)
        .uint(256, 32)
        .uint(2, 32)
        .uint(8, 8)
        .uint(26, 32)
    )


def configuration(global_version):
    import native
    from cells import Cell, from_boc, make_dict, read_dict

    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    entries = read_dict(fixture.refs[0], 32)
    entries[0] = Cell().ref(Cell().uint(int(fixture.bits, 2), 256))
    old = entries[8].refs[0].slice()
    assert old.uint(8) == 0xC4
    old.uint(32)
    caps = old.uint(64)
    entries[8] = Cell().ref(Cell().uint(0xC4, 8).uint(global_version, 32).uint(caps, 64))
    entries[19] = Cell().ref(Cell().sint(native.GLOBAL_ID, 32))
    entries[43] = Cell().ref(size_limits_v2())
    return make_dict(entries, 32)


def report(left, right):
    """Agreement between two implementations that both refuse everything is not evidence,
    so the transcript has to contain an acceptance and a refusal before it counts."""
    if len(left) != len(right) or len(left) < 4:
        raise ValueError("missing or truncated transaction evidence")
    rows = [line.split("\t") for line in left]
    if any(len(row) != 6 for row in rows):
        raise ValueError("malformed transaction row")
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate transaction identifier")
    stored = any(row[1] == "0" and row[2] == "0" for row in rows)
    refused = any(row[2] != "0" for row in rows)
    if not (stored and refused):
        raise ValueError("transcript lacks an accepted state or a refused one")
    differences = [(a, b) for a, b in zip(left, right) if a != b]
    if differences:
        raise SystemExit(
            "executors disagree:\n" + "\n".join(f"  cpp: {a}\n  rust: {b}" for a, b in differences)
        )
    return {
        "cases": len(rows),
        "accepted": sum(1 for r in rows if r[2] == "0"),
        "refused": sum(1 for r in rows if r[2] != "0"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    build, out = args.build.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ.update(FUNC_PATH=str(build / "crypto/func"), FIFT_PATH=str(build / "crypto/fift"))
    sys.path[:0] = [str(ROOT / "test/mldsa-auth"), str(ROOT / "test/pq-readiness")]
    from protocol import emulator_library

    os.environ["EMULATOR_PATH"] = str(emulator_library(build))
    import native
    from cells import Cell, from_boc
    from native import NOW, Emulator, active_account, internal
    from tx_parity import account_state

    code = compile_probe(build, out)
    payload, small = chain(PAYLOAD_CELLS), chain(4)
    sender = (-1, 0x1111111111111111111111111111111111111111111111111111111111111111)
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())

    # Four accounts per version: both workchains, over and under the masterchain ceiling.
    # The pair that stays under it is the control -- without it, a version that refused
    # everything would look the same as a version applying the ceiling correctly.
    shapes = [
        ("mc-oversized", -1, payload),
        ("mc-small", -1, small),
        ("basechain-oversized", 0, payload),
        ("basechain-small", 0, small),
    ]

    left, right = [], []
    for version in (11, 12, 16):
        config_dict = configuration(version)
        native.config = lambda global_version=6, max_msg_cells=None, _dict=config_dict: _dict
        rows, scenarios = [], []
        emulator = Emulator(version)
        try:
            for shape, workchain, body_payload in shapes:
                name = f"{shape}-v{version}"
                address = (
                    workchain,
                    0x2222222222222222222222222222222222222222222222222222222222222222,
                )
                shard = active_account(address, code, Cell().uint(0, 8))
                message = internal(sender, address, Cell().ref(body_payload))
                result = emulator.send(shard, message)
                if not result["success"]:
                    raise SystemExit(f"{name}: native emulator refused to run: {result}")
                details = result.get("details", result)
                after = from_boc(result["shard_account"])
                rows.append(
                    "\t".join(
                        [
                            name,
                            str(details.get("exit")),
                            str((details.get("action") or {}).get("code", 0)),
                            "-",
                            account_state(after.refs[0] if after.refs else None),
                        ]
                    )
                )
                scenarios.append(
                    "\t".join(
                        [
                            name,
                            str(NOW),
                            str(emulator.lt),
                            shard.refs[0].boc().hex(),
                            message.boc().hex(),
                            "-",
                        ]
                    )
                )
        finally:
            emulator.close()
        left.extend(rows)

        config_path = out / f"config-v{version}.boc"
        config_path.write_bytes(Cell().uint(int(fixture.bits, 2), 256).ref(config_dict).boc())
        scenario_path = out / f"scenarios-v{version}.tsv"
        scenario_path.write_text("\n".join(scenarios) + "\n")
        rust = subprocess.run(
            [str(args.driver.resolve()), str(config_path), str(scenario_path), str(version)],
            capture_output=True,
            text=True,
        )
        if rust.returncode != 0:
            raise SystemExit(f"version {version}: rust driver failed: {rust.stderr.strip()[:400]}")
        right.extend(rust.stdout.strip().splitlines())

    (out / "cpp.tsv").write_text("\n".join(left) + "\n")
    (out / "rust.tsv").write_text("\n".join(right) + "\n")
    summary = report(left, right)
    (out / "account-limit-parity.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()

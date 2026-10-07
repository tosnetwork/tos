#!/usr/bin/env python3
"""The commands that bring a validator controller into existence.

`init-data` builds the data a controller is deployed with and `state-init` the state an
operator's wallet sends. What their bytes must be is pinned against the election
fixture in test/tostester/tests/tostester/test_controller_deploy_tools.py; this is the
layer where an operator's typing arrives: the two input forms of the root agree, and
everything that is not a controller's initial data is refused.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT_SEED_HEX = "11" * 32
CONSENSUS_SEED_HEX = "22" * 32


class Failure(Exception):
    pass


def run(tool: Path, args: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([str(tool), *args], input=stdin, capture_output=True, timeout=120)


def field(output: bytes, name: str, digits: str = "64") -> str:
    m = re.search(
        rb"^" + name.encode() + rb"\s+([0-9a-f]{" + digits.encode() + rb"})$", output, re.M
    )
    if not m:
        raise Failure(f"no {name} in {output!r}")
    return m.group(1).decode()


def boc(output: bytes) -> bytes:
    text = output.decode().strip()
    if "\n" in text:
        raise Failure(f"more than one BOC printed: {output!r}")
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError as error:
        raise Failure(f"not base64: {output!r}") from error
    if raw[:4] != bytes.fromhex("b5ee9c72"):
        raise Failure(f"not a BOC: {raw[:8].hex()}")
    return raw


def check(controller: Path, consensus: Path, work: Path) -> None:
    keys = work / "keys"
    keys.mkdir(mode=0o700)
    keys.chmod(0o700)
    placed = run(consensus, ["import", str(keys / "root.seed")], ROOT_SEED_HEX.encode())
    if placed.returncode != 0:
        raise Failure(f"cannot place the root seed: {placed.stderr!r}")
    root_public = field(placed.stdout, "public", "2624")
    root_id = field(placed.stdout, "key_id")
    placed = run(consensus, ["import", str(keys / "consensus.seed")], CONSENSUS_SEED_HEX.encode())
    if placed.returncode != 0:
        raise Failure(f"cannot place the consensus seed: {placed.stderr!r}")
    consensus_id = field(placed.stdout, "key_id")

    # The root seed and the public key it derives are the same root.
    from_seed = run(controller, ["init-data", str(keys / "root.seed"), consensus_id])
    from_public = run(controller, ["init-data", root_public, consensus_id])
    from_upper = run(controller, ["init-data", root_public.upper(), consensus_id.upper()])
    for done in (from_seed, from_public, from_upper):
        if done.returncode != 0:
            raise Failure(f"init-data failed: {done.stderr!r}")
    data = boc(from_seed.stdout)
    if boc(from_public.stdout) != data or boc(from_upper.stdout) != data:
        raise Failure("init-data built different data from the root seed and its public key")
    if field(from_seed.stderr, "root_key_id") != root_id:
        raise Failure("init-data reported a root identity the root key does not derive")
    if field(from_seed.stderr, "consensus_key_id") != consensus_id:
        raise Failure("init-data reported a different consensus identity")
    # 64 + 64 + 16 + 256 bits and one reference: the 400-bit root cell holds the consensus
    # key identity in full.
    if bytes.fromhex(consensus_id) not in data:
        raise Failure("the initial data does not carry the consensus key identity")
    if ROOT_SEED_HEX.encode() in from_seed.stdout + from_seed.stderr:
        raise Failure("init-data printed the root seed")

    # A different consensus key is a different controller.
    other = run(controller, ["init-data", root_public, "33" * 32])
    if other.returncode != 0 or boc(other.stdout) == data:
        raise Failure("init-data ignored the consensus key identity")

    # Each refusal names its reason: any failure, a crash included, exits non-zero.
    key_shape = b"a root public key is 2624 hexadecimal digits"
    bad = {
        "a zero consensus key": ([root_public, "00" * 32], b"key_id is zero"),
        "the root's own key as the consensus key": ([root_public, root_id], b"root key's own"),
        "a short consensus key id": ([root_public, consensus_id[:-2]], b"expected 32 bytes of hex"),
        "a non-hex consensus key id": (
            [root_public, "zz" + consensus_id[2:]],
            b"expected 32 bytes of hex",
        ),
        "a short root public key": ([root_public[:-2], consensus_id], key_shape),
        "a long root public key": ([root_public + "00", consensus_id], key_shape),
        "a root public key that is not hex": (["zz" + root_public[2:], consensus_id], key_shape),
        "a missing root seed": ([str(keys / "absent.seed"), consensus_id], b"cannot be opened"),
        "a missing argument": ([root_public], b"usage:"),
        "an extra argument": ([root_public, consensus_id, "0"], b"usage:"),
    }
    for why, (args, reason) in bad.items():
        refused = run(controller, ["init-data", *args])
        if refused.returncode == 0:
            raise Failure(f"init-data accepted {why}")
        if refused.stdout != b"":
            raise Failure(f"init-data printed data for {why}")
        if reason not in refused.stderr:
            raise Failure(f"init-data refused {why} without saying why: {refused.stderr[:300]!r}")

    # A root seed path that is a FIFO is refused at once, not waited on.
    fifo = keys / "fifo.seed"
    os.mkfifo(fifo, 0o600)
    try:
        refused = subprocess.run(
            [str(controller), "init-data", str(fifo), consensus_id], capture_output=True, timeout=20
        )
    except subprocess.TimeoutExpired:
        raise Failure("init-data hung on a FIFO root seed")
    if refused.returncode == 0 or b"is not a regular file" not in refused.stderr:
        raise Failure(f"init-data did not refuse a FIFO root seed: {refused.stderr!r}")

    # The state init lands where the witness says the controller lives.
    # Any cell serves as code here; the fixture test uses the compiled controller.
    stand_in = run(controller, ["init-data", root_public, "44" * 32])
    boc(stand_in.stdout)
    code_b64 = stand_in.stdout.decode().strip()
    data_b64 = from_seed.stdout.decode().strip()
    state = run(controller, ["state-init", code_b64, data_b64])
    witness = run(controller, ["witness", code_b64, data_b64])
    if state.returncode != 0 or witness.returncode != 0:
        raise Failure(f"state-init or witness failed: {state.stderr!r} {witness.stderr!r}")
    boc(state.stdout)
    address = re.search(rb"^address (-1:[0-9a-f]{64})$", state.stderr, re.M)
    if address is None:
        raise Failure(f"state-init printed no address: {state.stderr!r}")
    # The witness command prints the address in upper case; it is the same address.
    if f"address {address.group(1).decode()}".encode() not in witness.stderr.lower():
        raise Failure("state-init and witness disagree about the controller's address")
    field(state.stderr, "code_hash")
    other_state = run(controller, ["state-init", code_b64, other.stdout.decode().strip()])
    if other_state.returncode != 0 or other_state.stderr == state.stderr:
        raise Failure("state-init ignored the initial data")
    for why, (args, reason) in {
        "data that is not base64": ([code_b64, "@@@"], b"not base64"),
        "code that is not a BOC": (
            [base64.b64encode(b"not a boc").decode(), data_b64],
            b"bag-of-cells",
        ),
        "data that is not a BOC": (
            [code_b64, base64.b64encode(b"not a boc").decode()],
            b"bag-of-cells",
        ),
        "a missing argument": ([code_b64], b"usage:"),
    }.items():
        refused = run(controller, ["state-init", *args])
        if refused.returncode == 0 or refused.stdout != b"":
            raise Failure(f"state-init accepted {why}")
        if reason not in refused.stderr:
            raise Failure(f"state-init refused {why} without saying why: {refused.stderr!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", required=True, help="path to tos-pq-controller")
    parser.add_argument("--consensus-key", required=True, help="path to tos-pq-consensus-key")
    args = parser.parse_args()
    controller = Path(args.controller).resolve()
    consensus = Path(args.consensus_key).resolve()
    for tool in (controller, consensus):
        if not tool.is_file():
            print(f"no tool at {tool}", file=sys.stderr)
            return 2
    with tempfile.TemporaryDirectory() as tmp:
        try:
            check(controller, consensus, Path(tmp))
        except Failure as failure:
            print(f"CONTROLLER_TOOL_FAILED {failure}", file=sys.stderr)
            return 1
    print(
        "CONTROLLER_TOOL_OK init-data agrees across both root forms and refuses what is not "
        "a controller's data; state-init lands at the witness address"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Exercise numeric intent at both offline signing entry points, without a node."""

from __future__ import annotations

import argparse
import base64
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-extensions"))
from cells import Cell, from_boc  # noqa: E402


def run(tool: Path, args: list[str], data: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([str(tool), *args], input=data, capture_output=True, timeout=30)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def check(controller: Path, vote: Path, key_tool: Path, work: Path, rejections_only: bool) -> None:
    root = str(work / "root.seed")
    incoming = str(work / "incoming.seed")
    absent = str(work / "absent.seed")
    identity = "33" * 32
    payload = base64.b64encode(Cell().boc()).decode()
    # (argument index, diagnostic name, wire width, signed, smallest signable value)
    common = [
        (2, "GLOBAL_ID", 32, True, -(2**31)),
        (4, "EPOCH", 64, False, 0),
        (5, "NONCE", 64, False, 0),
        (6, "VALID_UNTIL", 32, False, 0),
    ]
    commands = []
    for name in ("send", "bind", "rotate-root", "fund-operations", "withdraw-operations"):
        tail = (
            ["3", payload]
            if name == "send"
            else [incoming if name in ("bind", "rotate-root") else payload]
        )
        fields = common + ([(7, "MODE", 8, False, 0)] if name == "send" else [])
        commands.append((controller, [name, root, "2", identity, "0", "0", "1", *tail], fields))
    for name in ("config", "complaint", "stake"):
        fields = [(2, "GLOBAL_ID", 32, True, -(2**31))]
        if name == "stake":
            args = [name, incoming, "2", identity, "1", "65536", identity, identity]
            fields += [(4, "ELECTION_ID", 32, False, 0), (5, "MAX_FACTOR", 32, False, 65536)]
        else:
            args = [name, incoming, "2", identity, identity, "0"]
            fields += [(5, "IDX", 16, False, 0)]
            if name == "complaint":
                args += ["1"]
                fields += [(6, "ELECTION_ID", 32, False, 0)]
            args += [identity]
        commands.append((vote, args, fields))

    refused_count = 0
    for tool, args, fields in commands:
        for index, field, width, signed, _ in fields:
            low = -(2 ** (width - 1)) if signed else 0
            high = 2 ** (width - int(signed)) - 1
            invalid = [
                "",
                "+1",
                " 1",
                "1 ",
                "1\n",
                "\t1",
                "-",
                "1x",
                "1.0",
                "1e2",
                "0x10",
                "--1",
                "9" * 1000,
                str(low - 1),
                str(high + 1),
            ]
            invalid += ["4294967298", "-4294967294"] if signed else ["-1", "-0"]
            for value in invalid:
                candidate = args.copy()
                candidate[1] = absent
                candidate[index] = value
                done = run(tool, candidate)
                label = f"{args[0]} {field}={value[:40]!r}"
                require(
                    done.returncode == 1,
                    f"{label}: expected controlled refusal, got {done.returncode}",
                )
                require(done.stdout == b"", f"{label}: refusal produced signing output")
                reason = f"{field} must be a whole decimal integer in [{low}, {high}]".encode()
                require(
                    reason in done.stderr,
                    f"{label}: numeric validation did not run: {done.stderr[:200]!r}",
                )
                refused_count += 1
    print(f"SIGNING_TOOL_INTEGER_REFUSALS_OK {refused_count} cases across all eight commands")
    if rejections_only:
        return

    # Public, deterministic fixture seeds. No operator keys or network are used.
    for path, byte in ((root, "11"), (incoming, "22")):
        done = run(key_tool, ["import", path], (byte * 32).encode())
        require(done.returncode == 0, "could not provision a test seed")

    accepted_count = 0
    for tool, args, fields in commands:
        variants = [args]
        for index, _, width, signed, low in fields:
            high = 2 ** (width - int(signed)) - 1
            for value in (str(low), str(high), "00065536" if low == 65536 else "0002"):
                candidate = args.copy()
                candidate[index] = value
                variants.append(candidate)
        # Hold all wire maxima simultaneously, including both uint64 counters.
        candidate = args.copy()
        for index, _, width, signed, _ in fields:
            candidate[index] = str(2 ** (width - int(signed)) - 1)
        variants.append(candidate)
        for candidate in variants:
            done = run(tool, candidate)
            require(
                done.returncode == 0,
                f"{candidate[0]} refused a legal boundary: {done.stderr[:200]!r}",
            )
            if candidate[0] == "stake":
                signature = bytes.fromhex(done.stdout.decode().strip())
                require(len(signature) == 2420, "stake did not emit an ML-DSA-44 signature")
            else:
                body = from_boc(base64.b64decode(done.stdout.strip(), validate=True))
                view = body.slice()
                view.uint(32)  # operation
                require(view.uint(64) == 1, "query id changed")
                if tool == controller:
                    require(view.sint(32) == int(candidate[2]), "GLOBAL_ID changed on the wire")
                    require(view.uint(64) == int(candidate[4]), "EPOCH changed on the wire")
                    require(view.uint(64) == int(candidate[5]), "NONCE changed on the wire")
                    require(view.uint(32) == int(candidate[6]), "VALID_UNTIL changed on the wire")
                    if candidate[0] == "send":
                        require(
                            body.refs[0].slice().uint(8) == int(candidate[7]),
                            "MODE changed on the wire",
                        )
                else:
                    require(view.uint(16) == int(candidate[5]), "IDX changed on the wire")
                    if candidate[0] == "complaint":
                        require(
                            view.uint(32) == int(candidate[6]), "ELECTION_ID changed on the wire"
                        )
            accepted_count += 1
    print(f"SIGNING_TOOL_INTEGER_BOUNDARIES_OK {accepted_count} valid signing cases")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", required=True, type=Path)
    parser.add_argument("--vote", required=True, type=Path)
    parser.add_argument("--consensus-key", required=True, type=Path)
    parser.add_argument(
        "--rejections-only",
        action="store_true",
        help="never create keys or sign; for sensitivity checks",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        check(
            args.controller.resolve(),
            args.vote.resolve(),
            args.consensus_key.resolve(),
            Path(tmp),
            args.rejections_only,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

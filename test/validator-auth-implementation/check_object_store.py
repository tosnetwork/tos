#!/usr/bin/env python3
"""Cross-check principal/anchor scoped object storage in C++ and Rust."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

SMALL = 65_537
FOUR_SMALL = 4 * SMALL
TABLE_RESERVED = 1024 * SMALL


def publish(principal: int, seqno: int, fill: int, now: int) -> str:
    return f"publish {principal} {seqno} {fill} {SMALL} {now}"


def cases() -> dict[str, tuple[str, list[str]]]:
    scoped = "\n".join(
        [
            "config 268435456 60",
            publish(10, 0, 7, 1),
            f"get 11 0 7 {SMALL} 0 1",
            f"get 10 1 7 {SMALL} 0 1",
            f"get 10 0 7 {SMALL} 0 1",
            "reserved",
        ]
    )
    atomic = "\n".join(
        [
            "config 268435456 60",
            f"publish_bad 10 0 7 {SMALL} 1",
            "reserved",
            publish(10, 0, 7, 1),
        ]
    )
    reservation = "\n".join(
        [
            "config 268435456 60",
            "put_large 1 0 67108864 1 1",
            "reserved",
        ]
    )
    objects = ["config 268435456 60"]
    for slot in range(4):
        objects.append(publish(10, slot, 7 + slot, 1))
    objects.append(publish(10, 4, 20, 1))
    objects.append("reserved")

    principal_bytes = "\n".join(
        [
            "config 268435456 60",
            "put_large 1 0 67108864 1 1",
            publish(1, 1, 9, 1),
            "reserved",
        ]
    )
    global_bytes = "\n".join(
        [
            f"config {SMALL} 60",
            publish(1, 0, 7, 1),
            publish(2, 0, 7, 1),
            "reserved",
        ]
    )

    table = ["config 268435456 60"]
    for principal in range(1, 1025):
        table.append(publish(principal, 0, 7, 1))
    table.append(publish(1025, 0, 7, 1))
    table.append("reserved")

    expiry = [f"config {FOUR_SMALL} 10"]
    for round_index in range(16):
        now = 1 + round_index * 11
        for slot in range(4):
            expiry.append(publish(11, slot, 20 + slot, now))
        expiry.append("reserved")
    expiry.append("config 268435456 10")
    for principal in range(1, 1025):
        expiry.append(publish(principal, 0, 77, 1))
    for principal in range(1025, 2049):
        expiry.append(publish(principal, 0, 77, 12))
    expiry.append("reserved")

    clock = "\n".join(
        [
            "config 268435456 60",
            publish(10, 0, 7, 61),
            f"get 10 0 7 {SMALL} 0 60",
            "reserved",
        ]
    )

    return {
        "principal-anchor-scope": (
            scoped,
            [
                f"ERR get object-unavailable {SMALL}",
                f"OK get {SMALL} {SMALL}",
                f"STATE reserved {SMALL}",
            ],
        ),
        "atomic-publication": (
            atomic,
            [
                "ERR publish_bad published-object-binding 0",
                "STATE reserved 0",
                f"OK publish - {SMALL}",
            ],
        ),
        "full-length-reservation": (
            reservation,
            [
                "OK put_large - 67108864",
                "STATE reserved 67108864",
            ],
        ),
        "principal-object-quota": (
            "\n".join(objects),
            [
                f"ERR publish principal-storage-quota {FOUR_SMALL}",
                f"STATE reserved {FOUR_SMALL}",
            ],
        ),
        "principal-byte-quota": (
            principal_bytes,
            [
                "ERR publish principal-storage-quota 67108864",
                "STATE reserved 67108864",
            ],
        ),
        "global-byte-quota": (
            global_bytes,
            [
                f"ERR publish global-storage-quota {SMALL}",
                f"STATE reserved {SMALL}",
            ],
        ),
        "principal-table-bound": (
            "\n".join(table),
            [
                f"ERR publish storage-unavailable {TABLE_RESERVED}",
                f"STATE reserved {TABLE_RESERVED}",
            ],
        ),
        "expiry-releases-all": (
            "\n".join(expiry),
            [
                f"STATE reserved {FOUR_SMALL}",
                "OK config - 0",
                f"STATE reserved {TABLE_RESERVED}",
            ],
        ),
        "clock-regression": (
            clock,
            [
                f"ERR get storage-clock-regression {SMALL}",
                f"STATE reserved {SMALL}",
            ],
        ),
    }


def invoke(driver: str, script: Path, output: Path) -> bytes:
    command = [driver, str(script), str(output)]
    if Path(driver).name == "conformance":
        command = [driver, "object-store", str(script), str(output)]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=180, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"driver failure {driver}: exit={result.returncode} "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    if result.stdout or result.stderr:
        raise RuntimeError(
            f"driver wrote unexpected console output {driver}: "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
    return output.read_bytes()


def run_case(name: str, cpp: str, rust: str, directory: Path) -> bool:
    corpus = cases()
    script_text, required = corpus[name]
    script = directory / f"{name}.script"
    cpp_out = directory / f"{name}.cpp.out"
    rust_out = directory / f"{name}.rust.out"
    script.write_text(script_text + "\n")
    cpp_bytes = invoke(cpp, script, cpp_out)
    rust_bytes = invoke(rust, script, rust_out)
    if cpp_bytes != rust_bytes:
        return False
    text = cpp_bytes.decode()
    return all(marker in text for marker in required)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp", required=True)
    parser.add_argument("--rust", required=True)
    parser.add_argument("--case")
    parser.add_argument("--exclude")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()

    corpus = cases()
    if args.list:
        for name in corpus:
            print(name)
        return 0
    if args.case and args.exclude:
        print("HARNESS_FAILURE case and exclude are mutually exclusive", file=sys.stderr)
        return 2
    if args.case and args.case not in corpus:
        print("HARNESS_FAILURE unknown case", file=sys.stderr)
        return 2
    if args.exclude and args.exclude not in corpus:
        print("HARNESS_FAILURE unknown exclusion", file=sys.stderr)
        return 2

    selected = list(corpus)
    if args.case:
        selected = [args.case]
    if args.exclude:
        selected = [name for name in selected if name != args.exclude]

    try:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            passed = 0
            for name in selected:
                print(f"SETUP_OK {name}")
                if not run_case(name, args.cpp, args.rust, directory):
                    print(f"ASSERTION_FAILED {name}", file=sys.stderr)
                    return 1
                print(f"CASE_PASS {name}")
                passed += 1
            print(f"SUMMARY cases={len(selected)} passed={passed}")
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, UnicodeError) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

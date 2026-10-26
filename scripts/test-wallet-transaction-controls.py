#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Remove guards in an otherwise clean build source, require runtime failures, restore."""

import argparse
import json
import pathlib
import subprocess

CONTROL_FILES = (
    "lite-client/proof-verify/wallet-transaction.cpp",
    "lite-client/proof-verify/wallet-transaction.h",
    "lite-client/proof-verify/embedded.cpp",
    "lite-client/proof-verify/embedded.h",
    "lite-client/proof-verify/CMakeLists.txt",
    "test/pq-native/wallet-transaction-test.py",
    "test/pq-native/data/wallet-transactions/manifest.json",
    "test/pq-native/data/wallet-transactions/transaction-0.boc",
    "test/pq-native/data/wallet-transactions/transaction-1.boc",
    "test/pq-native/data/wallet-transactions/transaction-2.boc",
    "test/auth-extensions/cells.py",
)


def checked_source(build, checkout):
    """Check configured compile inputs without requiring Git in a source mirror."""
    cache = (build / "CMakeCache.txt").read_text()
    homes = [
        line.split("=", 1)[1]
        for line in cache.splitlines()
        if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")
    ]
    if len(homes) != 1:
        raise RuntimeError("expected one configured CMake source")
    source = pathlib.Path(homes[0]).resolve()
    print(json.dumps({"checkout": str(checkout), "configured_source": str(source)}), flush=True)
    # The invoked, reviewed checkout owns Git metadata. A configured source copy
    # may not; check its actual inputs before any write instead of assuming it is
    # another Git worktree. A different/missing input refuses the control run.
    subprocess.run(["git", "diff", "--exit-code"], cwd=checkout, check=True)
    for relative in CONTROL_FILES:
        if (source / relative).read_bytes() != (checkout / relative).read_bytes():
            raise RuntimeError(f"configured source differs from checkout: {relative}")
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    checkout = pathlib.Path(__file__).resolve().parents[1]
    source = checked_source(build, checkout)

    engine = source / "lite-client/proof-verify/wallet-transaction.cpp"
    abi = source / "lite-client/proof-verify/embedded.cpp"
    original = {engine: engine.read_bytes(), abi: abi.read_bytes()}
    command = ["cmake", "--build", str(build), "--target", "tos-proof-embedded", "-j", "4"]
    patterns = [
        (
            "wallet-transaction-hash",
            engine,
            " || root->get_hash(0).as_slice() != transaction_hash",
            "",
            "wrong-hash",
        ),
        (
            "wallet-transaction-account",
            engine,
            " || tx.account_addr.as_slice() != account_hash",
            "",
            "wrong-account",
        ),
        ("wallet-transaction-lt", engine, " || tx.lt != logical_time", "", "wrong-lt"),
        (
            "wallet-transaction-cells",
            engine,
            " || header.cell_count > kMaxWalletTransactionCells",
            "",
            "cell-count-16385",
        ),
        (
            "wallet-transaction-layout",
            engine,
            "!block::tlb::t_Transaction.validate_ref(65536, root)",
            "false",
            "malformed-state-update",
        ),
        (
            "wallet-transaction-messages",
            engine,
            "tx.outmsg_cnt > kMaxWalletTransactionMessages",
            "false",
            "message-count-257",
        ),
    ]

    def replace(path, before, after):
        text = path.read_text()
        if text.count(before) != 1:
            raise RuntimeError(f"mutation target missing or repeated: {before}")
        path.write_text(text.replace(before, after))

    def restore():
        for path, data in original.items():
            path.write_bytes(data)

    def run_test():
        return subprocess.run(
            [
                "ctest",
                "--test-dir",
                str(build),
                "--output-on-failure",
                "--no-tests=error",
                "-R",
                "^wallet-transaction$",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

    receipts = []
    try:
        # A failing baseline/setup cannot masquerade as a sensitivity result.
        subprocess.run(command, check=True)
        good = run_test()
        print(good.stdout, flush=True)
        if good.returncode:
            raise RuntimeError("baseline transaction regression failed")
        for name, path, before, after, marker in patterns + [
            ("wallet-transaction-depth", engine, None, None, "depth-1024"),
            ("wallet-transaction-bytes", abi, None, None, "byte-boundary-1048577"),
        ]:
            restore()
            if name == "wallet-transaction-depth":
                replace(engine, "depths[links[i].refs[j]] >= kMaxWalletTransactionDepth", "false")
                replace(engine, "root->get_depth() > kMaxWalletTransactionDepth", "false")
            elif name == "wallet-transaction-bytes":
                replace(abi, "boc_size > pv::kMaxWalletTransactionBytes", "false")
                replace(engine, " || bytes.size() > kMaxWalletTransactionBytes", "")
            else:
                replace(path, before, after)
            subprocess.run(command, check=True)
            result = run_test()
            print(result.stdout, flush=True)
            if result.returncode == 0 or "AssertionError: " + marker not in result.stdout:
                raise RuntimeError(f"{name}: missing intended runtime rejection failure")
            receipts.append(
                {"guard": name, "runtime_failed_at": marker, "test_exit": result.returncode}
            )
    finally:
        restore()
        if any(path.read_bytes() != data for path, data in original.items()):
            raise RuntimeError("control source restoration mismatch")
        subprocess.run(command, check=True)

    restored = run_test()
    print(restored.stdout, flush=True)
    if restored.returncode:
        raise RuntimeError("restored regression failed")
    subprocess.run(["git", "diff", "--exit-code"], cwd=checkout, check=True)
    print(json.dumps({"controls": receipts, "restored_exit": restored.returncode}, indent=2))


if __name__ == "__main__":
    main()

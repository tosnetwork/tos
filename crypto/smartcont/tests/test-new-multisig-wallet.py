#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Checks crypto/smartcont/new-multisig-wallet.fif, the multisig deployment script.

The wallet gives each signer index one vote, so the script must list signers in increasing
address order and refuse an address given twice; it then checks the state it built with the
wallet's own get_checked_signer_count. This test runs the script on accepted and refused
inputs, reads the StateInit it saves back through the wallet code, and runs a copy of the
script that skips the ordering to show the wallet's check refuses it.

usage: test-new-multisig-wallet.py <fift> <source-root> <build-root>
"""

import os
import re
import subprocess
import sys
import tempfile

FIFT, SOURCE_ROOT, BUILD_ROOT = sys.argv[1:4]
SCRIPT = os.path.join(SOURCE_ROOT, "crypto/smartcont/new-multisig-wallet.fif")
INCLUDE = ":".join(
    [
        os.path.join(SOURCE_ROOT, "crypto/fift/lib"),
        os.path.join(SOURCE_ROOT, "crypto/smartcont"),
        os.path.join(BUILD_ROOT, "crypto/smartcont"),
    ]
)

A = "0:" + "11" * 32
B = "0:" + "22" * 32
C = "0:" + "33" * 32
M = "-1:" + "ff" * 32


def fift(args, cwd, script=SCRIPT):
    return subprocess.run(
        [FIFT, "-I", INCLUDE, "-s", script, *args], cwd=cwd, capture_output=True, text=True, errors="replace"
    )


def error_of(result):
    found = re.search(r"Error interpreting file [^\n]*?:\d+:\s*(?:[^:\n]*:)?([^\n\x1b]*)", result.stderr)
    return found.group(1).strip() if found else None


def expect_refused(work, args, reason, script=SCRIPT):
    result = fift(args, work, script)
    assert result.returncode != 0, (args, "was accepted")
    assert error_of(result) == reason, (args, error_of(result), reason)


def friendly(work, raw):
    wc, account = raw.split(":")
    probe = os.path.join(work, "friendly.fif")
    with open(probe, "w") as f:
        f.write('"TosUtil.fif" include\n%s 0x%s 6 .Addr cr\n' % (wc, account))
    result = subprocess.run([FIFT, "-I", INCLUDE, "-s", probe], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def read_back(work, base):
    """Runs the wallet code from the saved StateInit: (signer count, threshold, address hex)."""
    probe = os.path.join(work, "read-back.fif")
    with open(probe, "w") as f:
        f.write(
            '"TosUtil.fif" include\n'
            '"%s.init.boc" file>B B>boc dup hashu 64 0x. cr\n'
            "<s ref@+ =: code ref@ =: data\n"
            "108550 code <s data runvm drop 0<> abort\"get_checked_signer_count failed\" . cr\n"
            "107307 code <s data runvm drop 0<> abort\"get_multisig_data failed\" "
            "drop drop drop . drop cr\n" % base
        )
    result = subprocess.run([FIFT, "-I", INCLUDE, "-s", probe], cwd=work, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    address, count, threshold = result.stdout.split()
    return int(count), int(threshold), address


def main():
    with tempfile.TemporaryDirectory() as work:
        # Accepted: signers given out of order and across workchains, plus a proposer.
        result = fift(["0", "2", "ms", C, A, M, "-p", B], work)
        assert result.returncode == 0, result.stderr
        listed = re.findall(r"^\s+(\d+)\s+(-?\d+:[0-9a-f]{64})", result.stdout.split("Proposers")[0], re.M)
        assert listed == [("0", M), ("1", A), ("2", C)], listed
        assert os.path.getsize(os.path.join(work, "ms.addr")) == 36
        count, threshold, address = read_back(work, "ms")
        assert (count, threshold) == (3, 2), (count, threshold)
        assert ("0:" + address) in result.stdout, "the printed address is the StateInit hash"

        # Refused.
        expect_refused(work, ["0", "1", "x", A, B, A], "the same signer address is listed twice")
        expect_refused(work, ["0", "1", "x", A, B, friendly(work, A)], "the same signer address is listed twice")
        expect_refused(work, ["0", "0", "x", A, B], "the threshold must be between 1 and the number of signers")
        expect_refused(work, ["0", "3", "x", A, B], "the threshold must be between 1 and the number of signers")
        expect_refused(work, ["0", "1", "x", "-p", A], "no signers given")
        expect_refused(work, ["0", "1", "x", "0:zz"], "invalid smart-contract address")

        # The wallet's own check is live: a copy that lists signers in reverse order fails it.
        with open(SCRIPT) as f:
            source = f.read()
        walk = "256 ' add-signer dictforeach"
        assert source.count(walk) == 1
        mutant = os.path.join(work, "mutant.fif")
        with open(mutant, "w") as f:
            f.write(source.replace(walk, "256 ' add-signer dictforeachrev"))
        expect_refused(work, ["0", "1", "x", A, B], "the wallet refuses this signer set", mutant)
    print("new-multisig-wallet.fif: all checks passed")


if __name__ == "__main__":
    main()

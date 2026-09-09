"""Wallet source contracts. These are structural checks, not side-channel proofs."""
from pathlib import Path
import re
import subprocess
import os
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT.parent / "crypto"


def graph(root):
    return subprocess.check_output(
        ["cargo", "tree", "--locked", "--offline", "-e", "normal", "--prefix", "none"],
        cwd=root, env=dict(os.environ, CARGO_NET_OFFLINE="true"), text=True)


class WalletGates(unittest.TestCase):
    def test_distinct_entropy_graphs(self):
        wallet = {line.split()[0] for line in graph(ROOT).splitlines() if line.strip()}
        verifier = {line.split()[0] for line in graph(KERNEL).splitlines() if line.strip()}
        self.assertTrue({"tos-uno-wallet-prover", "rand", "getrandom", "chacha20"} <= wallet)
        self.assertFalse(verifier & {"tos-uno-wallet-prover", "rand", "getrandom", "chacha20"})

    def test_external_sources_are_covered_by_kernel_archive_checks(self):
        def sources(root):
            lock = tomllib.loads((root / "Cargo.lock").read_text())
            return {(p["name"], p["version"], p["source"], p.get("checksum"))
                    for p in lock["package"] if "source" in p}
        # The kernel archive gate checks every package in its lock, including
        # test dependencies. New wallet sources need their own audit before this
        # equality may be changed; runtime feature graphs are checked separately.
        self.assertEqual(sources(ROOT), sources(KERNEL))
        subprocess.run(["python3", str(KERNEL / "tests/kernel-gates.py")], check=True,
                       env=dict(os.environ, CARGO_NET_OFFLINE="true"))

    def test_nonpublic_inner_product_constructions_use_constant_time_msm(self):
        source = (KERNEL / "vendor/bulletproofs/src/inner_product_proof.rs").read_text()
        # Review established that these L/R sites consume non-public vectors;
        # generator folding uses public challenges and may stay variable-time.
        sites = re.findall(r"let [LR] = RistrettoPoint::(\w+)\(", source)
        self.assertEqual(sites, ["multiscalar_mul"] * 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)

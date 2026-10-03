"""Each guard in the vault must be load-bearing: remove it and test_fee_gate.py must fail on
an assertion. Baseline must pass first. Same environment as test_fee_gate.py."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/smartcont/rescue-fee-vault.fc"
TEST = ROOT / "test/rescue-fee-gate/test_fee_gate.py"

MUTATIONS = {
    "drop signature check": (
        "  throw_unless(fee::bad_signature, pq_check_suite(digest, context, signature, public_key, fee::suite_lms));\n",
        "",
    ),
    "drop stale-leaf check": ("  throw_unless(fee::stale_leaf, leaf >= next_leaf);\n", ""),
    "drop digest binding": (
        "  throw_unless(fee::digest_mismatch, dg.preload_uint(256) == cell_hash(intent));\n",
        "",
    ),
    "drop expiry check": (
        "  throw_unless(fee::expired, (valid_until > now()) & (valid_until <= now() + fee::max_ttl));\n",
        "",
    ),
}


def run(source_name):
    env = dict(os.environ, VAULT_SOURCE=source_name)
    return subprocess.run([sys.executable, str(TEST)], capture_output=True, text=True, env=env)


def main():
    base = run(SOURCE.name)
    if base.returncode != 0:
        sys.exit("baseline failed:\n" + base.stdout + base.stderr)
    print("baseline: passed")
    text = SOURCE.read_text()
    failed = False
    for name, (old, new) in MUTATIONS.items():
        if text.count(old) != 1:
            sys.exit(f"{name}: anchor not found exactly once")
        mutant = SOURCE.with_name("rescue-fee-vault-mutant.fc")
        mutant.write_text(text.replace(old, new))
        try:
            r = run(mutant.name)
        finally:
            mutant.unlink()
        out = r.stdout + r.stderr
        caught = (
            r.returncode != 0
            and "AssertionError" in out
            and "Error:" not in out.replace("AssertionError", "")
        )
        print(f"{name}: {'caught' if caught else 'ESCAPED'} (exit {r.returncode})")
        failed |= not caught
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

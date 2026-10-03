"""Each guard in a vault must be load-bearing: remove it and that vault's test must fail on an
assertion. Baseline must pass first. Same environment as test_fee_gate.py.

Usage: mutations.py [counter|slot]   (default: both)
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "test/rescue-fee-gate"

SIGNATURE = (
    "  throw_unless(fee::bad_signature, pq_check_suite(digest, context, signature, public_key, fee::suite_lms));\n",
    "",
)
STALE = ("  throw_unless(fee::stale_leaf, leaf >= next_leaf);\n", "")
DIGEST = (
    "  throw_unless(fee::digest_mismatch, dg.preload_uint(256) == cell_hash(intent));\n",
    "",
)

VAULTS = {
    "counter": (
        "rescue-fee-vault.fc",
        "test_fee_gate.py",
        {
            "drop signature check": SIGNATURE,
            "drop stale-leaf check": STALE,
            "drop digest binding": DIGEST,
            "drop expiry check": (
                "  throw_unless(fee::expired, (valid_until > now()) & (valid_until <= now() + fee::max_ttl));\n",
                "",
            ),
        },
    ),
    "slot": (
        "rescue-fee-vault-slot.fc",
        "test_slot_vault.py",
        {
            "drop signature check": SIGNATURE,
            "drop stale-leaf check": STALE,
            "drop digest binding": DIGEST,
            "drop network check": (
                "  throw_unless(fee::wrong_network, is~load_int(32) == network);\n",
                "  is~load_int(32);\n",
            ),
            "drop vault check": (
                "  throw_unless(fee::wrong_vault, equal_slice_bits(is~load_msg_addr(), my_address()));\n",
                "  is~load_msg_addr();\n",
            ),
            "drop expiry check": (
                "  throw_unless(fee::expired, (valid_until > t) & (valid_until <= t + 2 * slot_seconds));\n",
                "",
            ),
            "drop expiry upper bound": (
                "(valid_until > t) & (valid_until <= t + 2 * slot_seconds)",
                "valid_until > t",
            ),
            "drop slot check": (
                "  throw_unless(fee::wrong_slot, (leaf_slot <= slot) & (leaf_slot + fee::slot_window >= slot));\n",
                "",
            ),
            "drop slot upper bound": (
                "(leaf_slot <= slot) & (leaf_slot + fee::slot_window >= slot)",
                "leaf_slot + fee::slot_window >= slot",
            ),
            "drop slot lower bound": (
                "(leaf_slot <= slot) & (leaf_slot + fee::slot_window >= slot)",
                "leaf_slot <= slot",
            ),
            "slot by leaf, ignoring leaves per slot": (
                "  int leaf_slot = leaf / per_slot;\n",
                "  int leaf_slot = leaf;\n",
            ),
            "widen slot window": ("const int fee::slot_window = 1;", "const int fee::slot_window = 2;"),
            "drop value cap": ("  throw_unless(fee::value_too_high, value <= max_value);\n", ""),
            "drop rescue-only payload": (
                "  throw_unless(fee::not_rescue, ps.preload_uint(32) == fee::rescue_submit);\n",
                "",
            ),
            "drop cached budget from the check": (
                "value + budget <= get_balance().pair_first()",
                "value <= get_balance().pair_first()",
            ),
            "keep the stale budget": (".store_coins(fresh_budget)", ".store_coins(budget)"),
            "drop compute budget": ("  int fresh_budget = get_compute_fee(0, fee::max_gas)\n", "  int fresh_budget = 0\n"),
            "drop storage floor": (
                "    + get_storage_fee(0, fee::storage_horizon, fee::state_bits, fee::state_cells);\n",
                ";\n",
            ),
            "drop q == leaf": ("  throw_unless(fee::leaf_mismatch, ss~load_uint(32) == leaf);\n", ""),
            "drop balance check": (
                "  throw_unless(fee::insufficient_balance, value + budget <= get_balance().pair_first());\n",
                "",
            ),
            "pay the intent signer instead of the pinned target": (
                ".store_uint(0x18, 6).store_slice(target)",
                ".store_uint(0x18, 6).store_slice(my_address())",
            ),
        },
    ),
}


def run(test, source_name):
    env = dict(os.environ, VAULT_SOURCE=source_name, NO_COLOR="1", PYTHON_COLORS="0")
    return subprocess.run([sys.executable, str(HERE / test)], capture_output=True, text=True, env=env)


def check(label, source_name, test, mutations):
    source = ROOT / "crypto/smartcont" / source_name
    base = run(test, source.name)
    if base.returncode != 0:
        sys.exit(f"{label} baseline failed:\n" + base.stdout + base.stderr)
    print(f"{label} baseline: passed")
    text = source.read_text()
    failed = False
    for name, (old, new) in mutations.items():
        if text.count(old) != 1:
            sys.exit(f"{label} {name}: anchor not found exactly once")
        mutant = source.with_name("rescue-fee-vault-mutant.fc")
        mutant.write_text(text.replace(old, new))
        try:
            r = run(test, mutant.name)
        finally:
            mutant.unlink()
        out = r.stdout + r.stderr
        caught = (
            r.returncode != 0
            and "AssertionError" in out
            and "Error:" not in out.replace("AssertionError", "")
        )
        print(f"{label} {name}: {'caught' if caught else 'ESCAPED'} (exit {r.returncode})")
        failed |= not caught
    return failed


def main():
    chosen = sys.argv[1:] or list(VAULTS)
    failed = False
    for label in chosen:
        failed |= check(label, *VAULTS[label])
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

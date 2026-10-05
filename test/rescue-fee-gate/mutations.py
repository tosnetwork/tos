"""Each guard in a vault must be load-bearing: remove it and that vault's test must fail on an
assertion. Baseline must pass first. Environment as test_slot_vault.py and test_rescue_e2e.py.

Usage: mutations.py [slot|module|account]   (default: all)
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
            "widen slot window": (
                "const int fee::slot_window = 1;",
                "const int fee::slot_window = 2;",
            ),
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
            "drop compute budget": (
                "  int fresh_budget = get_compute_fee(0, fee::max_gas)\n",
                "  int fresh_budget = 0\n",
            ),
            "drop storage floor": (
                "    + get_storage_fee(0, fee::storage_horizon, fee::state_bits, fee::state_cells);\n",
                ";\n",
            ),
            "drop q == leaf": (
                "  throw_unless(fee::leaf_mismatch, ss~load_uint(32) == leaf);\n",
                "",
            ),
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
    "module": (
        "rescue-dual-module.fc",
        "test_rescue_e2e.py",
        {
            "drop network tag": (
                "  throw_unless(dual::wrong_network, rs~load_uint(256) == network_tag);\n",
                "  rs~load_uint(256);\n",
            ),
            "drop workchain-0 account": ("  throw_unless(dual::wrong_account, wc == 0);\n", ""),
            "drop root binding": (
                "  throw_unless(dual::wrong_account, rs~load_uint(256) == my_hash);\n",
                "  rs~load_uint(256);\n",
            ),
            "drop expiry": (
                "  throw_unless(dual::expired, (valid_until > now()) & (valid_until <= now() + dual::max_ttl));\n",
                "",
            ),
            "drop payload/kind match": (
                "  throw_unless(dual::payload_mismatch, payload.begin_parse().preload_uint(32) == payload_tag(kind));\n",
                "",
            ),
            "drop REQUIRED policy for PRIMARY": (
                "    throw_unless(dual::policy_requires_rescue, policy == dual::policy_ready);\n",
                "",
            ),
            "drop PRIMARY execute-only": (
                "    throw_unless(dual::kind_not_allowed, kind == dual::kind_execute);\n",
                "",
            ),
            "drop SLH signature check": (
                "    throw_unless(dual::bad_signature, pq_check_suite(digest, context, signature, key, dual::suite_slhdsa));\n",
                "    pq_check_suite(digest, context, signature, key, dual::suite_slhdsa);\n",
            ),
            "drop ML-DSA signature check": (
                "    throw_unless(dual::bad_signature, pq_check_suite(digest, context, signature, primary_key, dual::suite_mldsa44));\n",
                "",
            ),
            "relay without funded_by": (
                ".store_slice(funded_by).end_cell())",
                ".store_slice(my_address()).end_cell())",
            ),
        },
    ),
    "account": (
        "rescue-v5r2-account.fc",
        "test_rescue_e2e.py",
        {
            "drop sender == root": (
                "  throw_unless(acc::not_module, (sender_wc == 0) & (sender_hash == root));\n",
                "",
            ),
            "drop epoch check": (
                "  throw_unless(acc::stale_epoch, rs~load_uint(64) == epoch);\n",
                "  rs~load_uint(64);\n",
            ),
            "drop primary nonce": (
                "    throw_unless(acc::bad_nonce, nonce == primary_nonce);\n",
                "",
            ),
            "drop local retirement": (
                "    throw_if(acc::primary_retired, (local_retired >> daily) & 1);\n",
                "",
            ),
            "drop fee-route PRIMARY refusal": (
                "    throw_if(acc::primary_on_fee_route,\n",
                "    throw_if(0 & acc::primary_on_fee_route,\n",
            ),
            "drop successor address check": (
                "      throw_unless(acc::bad_successor, module == module_init_hash);\n",
                "",
            ),
            "lock does not set the bit": ("      local_retired |= (1 << daily);\n", ""),
            "control does not advance epoch": ("    epoch += 1;\n", ""),
        },
    ),
}


# Which environment variable makes each test compile the mutant instead of the original.
SOURCE_VARIABLE = {
    "rescue-dual-module.fc": "MODULE_SOURCE",
    "rescue-v5r2-account.fc": "ACCOUNT_SOURCE",
}


def run(test, source_name, variable="VAULT_SOURCE"):
    env = dict(os.environ, NO_COLOR="1", PYTHON_COLORS="0")
    env[variable] = source_name
    return subprocess.run(
        [sys.executable, str(HERE / test)], capture_output=True, text=True, env=env
    )


def check(label, source_name, test, mutations):
    source = ROOT / "crypto/smartcont" / source_name
    variable = SOURCE_VARIABLE.get(source_name, "VAULT_SOURCE")
    base = run(test, source.name, variable)
    if base.returncode != 0:
        sys.exit(f"{label} baseline failed:\n" + base.stdout + base.stderr)
    print(f"{label} baseline: passed")
    text = source.read_text()
    failed = False
    for name, (old, new) in mutations.items():
        if text.count(old) != 1:
            sys.exit(f"{label} {name}: anchor not found exactly once")
        mutant = source.with_name("rescue-mutant.fc")
        mutant.write_text(text.replace(old, new))
        try:
            r = run(test, mutant.name, variable)
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

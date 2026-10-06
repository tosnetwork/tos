"""Require each native migration gate to fail semantically when deleted."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "tosctl/src/node-control/contracts/src"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    state = SOURCES / "wallet_v5r2_wallet_state.rs"
    tx = SOURCES / "proven_transactions.rs"
    vault = SOURCES / "wallet_v5r2_state.rs"
    schedule = SOURCES / "lms_fee_schedule.rs"
    originals = {path: path.read_text() for path in (state, tx, vault, schedule)}
    cases = [
        (
            "generic_bypass",
            state,
            "!matches!(action, AuthAction::Migrate { .. })",
            "true",
            "ungated migration signed",
        ),
        (
            "both_roles",
            state,
            "evidence.primary_request.role() == AuthRole::Primary\n                && evidence.rescue_request.role() == AuthRole::Rescue",
            "true",
            "accepted duplicate rescue POPs",
        ),
        (
            "fresh_pop",
            state,
            'age <= self.max_age, "stale migration POP"',
            'true, "stale migration POP"',
            "accepted stale or unrelated POP",
        ),
        (
            "receipt_checkpoint",
            tx,
            "&self.checkpoint == checkpoint && &self.anchor_id == anchor",
            "true",
            "accepted stale or unrelated POP",
        ),
        (
            "vault_checkpoint",
            state,
            "evidence.vault.evidence().checkpoint == self.checkpoint\n                && evidence.vault.evidence().block_gen_utime == self.master_time\n                && evidence.vault.anchor_id() == &self.anchor_id",
            "true",
            "accepted unproven successor vault",
        ),
        (
            "vault_live",
            vault,
            'evidence.live, "fee signing requires a live proof"',
            'true, "fee signing requires a live proof"',
            "accepted unproven successor vault",
        ),
        (
            "vault_exhaustion",
            state,
            "fee.plan(now, evidence.fee_continuity)?;",
            "",
            "accepted exhausted successor fee tree",
        ),
    ]
    cases.append(
        (
            "vault_slot_capacity",
            schedule,
            "if leaf >= end {",
            "if false {",
            "accepted exhausted successor slot",
        )
    )
    for name, old, new, witness in [
        (
            "custody_reservations",
            "chain_next_leaf.max(local_next)",
            "chain_next_leaf",
            "migration ignored local reservations",
        ),
        (
            "custody_route",
            "state.route != route",
            "false",
            "migration accepted wrong custody route",
        ),
        (
            "custody_time",
            "proven_time < state.last_proven_time",
            "false",
            "migration accepted regressed custody time",
        ),
        (
            "custody_restore",
            "proven_time < barrier.resume_at",
            "false",
            "migration ignored custody restore barrier",
        ),
    ]:
        cases.append((name, schedule, old, new, witness))
    for role in ("primary", "rescue"):
        statement = f"evidence.{role}_request.require_successor_funded_receipt(\n            evidence.{role}_receipts,\n            evidence.{role}_external,\n            successor,\n        )?;"
        cases.append((f"{role}_funding", state, statement, "", f"{role} funded POP bypassed"))

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--features",
                "native-wallet-signer",
                "--lib",
                "native_migration_requires_both_funded_pops",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    for name, path, old, _, _ in cases:
        assert originals[path].count(old) == 1, name

    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "1 passed" in log, log[-4000:]
        for name, path, old, new, witness in cases:
            assert originals[path].count(old) == 1, name
            path.write_text(originals[path].replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "native_migration_requires_both_funded_pops ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_failure": witness}
            path.write_text(originals[path])
    finally:
        for path, source in originals.items():
            path.write_text(source)
        code, log = run("restored")
        assert code == 0 and "1 passed" in log, log[-4000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(cases)} migration signing controls detected; restored test passes")


if __name__ == "__main__":
    main()

"""Require independently falsifiable installed-route and live-checkpoint guards.

Run exclusively: this runner temporarily edits Rust sources and rebuilds the
actual CLI. Every source is restored and a final two-rotation baseline is run.
The native transaction fixture uses public keys, mocked account proofs and an
explicit test wall clock; it is not live admission, delivery or finality proof.
"""

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_SUCCESS = "Two installed-route promotions, encrypted restarts, exact retries and native recipient payments passed"
ATTACH_SUCCESS = "Private zero-limit Attach preflight refused before opening successor journal"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = (
        "cli",
        "genesis-driver",
        "fee-session-tree",
        "successor-fee-fixture",
        "second-successor-fee-fixture",
        "fixture",
    )
    for name in (*inputs, "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        help="Run only this named mutation; repeat to select several (default: all).",
    )
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    command_dir = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl"
    contract_dir = ROOT / "tosctl/src/node-control/contracts/src"
    promotion = command_dir / "wallet_pq_migration_session.rs"
    inspection = command_dir / "wallet_pq_inspect_cmd.rs"
    session = command_dir / "wallet_pq_fee_session.rs"
    wallet = contract_dir / "wallet_v5r2_wallet_state.rs"
    fee = contract_dir / "wallet_v5r2_state.rs"
    getters = contract_dir / "proven_getters.rs"
    cases = [
        (
            "installed_tuple",
            wallet,
            "auth.checked_drain_reference()?.repr_hash() == module_init.repr_hash()\n"
            "                && auth.checked_drain_reference()?.repr_hash() == metadata.repr_hash()",
            "true",
            "cli",
            "promotion accepted a proposed tuple before wallet installation",
        ),
        (
            "epoch",
            promotion,
            "proof.view.epoch() > held.predecessor_epoch",
            "true",
            "cli",
            "promotion accepted regressed epoch",
        ),
        (
            "retirement",
            promotion,
            "proof.view.retired() & held.predecessor_retired == held.predecessor_retired",
            "true",
            "cli",
            "promotion accepted regressed retirement",
        ),
        (
            "retired_journal_lock",
            promotion,
            "retired_journals.push(previous);",
            "drop(previous);",
            "cli",
            "promotion released the old journal lock",
        ),
        (
            "historical_fee_selector",
            inspection,
            "let account = self.fee_at(wallet.evidence().checkpoint.clone()).await?;",
            "let (account, _) = self.fee_snapshot().await?;",
            "cli",
            "promotion did not bind fee to live wallet checkpoint",
        ),
        (
            "retired_fee_history",
            inspection,
            "!context.known_fee_keys.iter().any(|key| *key != current_key && *key == proposed_key)",
            "true",
            "cli",
            "rotation accepted retired intermediate tree after promotion",
        ),
        (
            "restore_history_memory",
            session,
            "command.proof.retain_fee_history(&context)?;",
            "",
            "cli",
            "rotation accepted retired intermediate tree after history-file-rewrite-restore",
        ),
        (
            "absolute_export_paths",
            inspection,
            "let absolute = std::path::absolute(path)?;",
            "let absolute = path.to_path_buf();",
            "cli",
            "installed export retained a relative path",
        ),
        (
            "successor_history_capacity",
            inspection,
            "context.require_fee_history_capacity()?;",
            "",
            "cli",
            "prepare accepted full fee history",
        ),
        (
            "migration_history_capacity",
            promotion,
            "self.proof.require_fee_history_capacity()?;",
            "",
            "cli",
            "migration accepted full fee history",
        ),
        (
            "journal_rotation_capacity",
            session,
            "retired_count < 32,",
            "true,",
            "command_unit",
            "session accepted a 33rd retired journal",
        ),
        (
            "journal_attachment_preflight",
            session,
            "require_rotation_capacity(retired_journals.len())?;",
            "",
            "attachment_fixture",
            "attachment accepted full journal capacity",
        ),
        (
            "historical_live_source",
            fee,
            "source.evidence().live,",
            "true,",
            "unit",
            "historical source authorized fee signing",
        ),
        (
            "authenticated_checkpoint",
            getters,
            "self.anchor_id == other.anchor_id\n"
            "                && self.evidence.checkpoint == other.evidence.checkpoint\n"
            "                && self.evidence.block_gen_utime == other.evidence.block_gen_utime",
            "true",
            "unit",
            "different anchor accepted",
        ),
    ]
    available = {case[0] for case in cases}
    assert set(args.case) <= available, "unknown rotation mutation name"
    if args.case:
        cases = [case for case in cases if case[0] in args.case]
    originals = {path: path.read_bytes() for _, path, *_ in cases}
    for label, path, old, _, _, _ in cases:
        assert originals[path].decode().count(old) == 1, f"nonunique source guard: {label}"
    records = []
    progress = dict(
        status="running",
        selected_mutations=[case[0] for case in cases],
        source_sha256={
            str(path.relative_to(ROOT)): digest(value) for path, value in originals.items()
        },
        runs=records,
    )
    cargo = ["cargo", "--locked", "--manifest-path", str(ROOT / "tosctl/src/Cargo.toml")]

    def checkpoint():
        # Preserve successful sensitivity receipts even if a later build fails.
        # A progress file never represents a completed restored regression.
        temporary = args.output / "progress.next"
        temporary.write_text(json.dumps(progress, indent=2) + "\n")
        temporary.replace(args.output / "progress.json")

    def execute(command, label, timeout):
        started = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
        log = result.stdout + result.stderr
        log_path = args.output / (label + ".log")
        log_path.write_text(log)
        record = dict(
            label=label,
            command=command,
            exit=result.returncode,
            elapsed_seconds=round(time.monotonic() - started, 3),
            log=log_path.name,
            log_sha256=digest(log_path.read_bytes()),
            log_bytes=log_path.stat().st_size,
        )
        records.append(record)
        checkpoint()
        return result.returncode, log, record

    def build(label):
        command = [cargo[0], "build", *cargo[1:], "-p", "tosctl", "--features", "pq-wallet"]
        code, log, record = execute(command, label + "-build", 1200)
        if code != 0 and "error: linking with" in log and "undefined hidden symbol" in log:
            # Retry only the observed cached-artifact linker failure. The failed
            # build is retained and cannot count as a semantic red result.
            clean = [
                cargo[0],
                "clean",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "-p",
                "commands",
                "-p",
                "tosctl",
            ]
            clean_code, clean_log, _ = execute(clean, label + "-cache-clean", 60)
            assert clean_code == 0, clean_log[-4000:]
            code, log, record = execute(command, label + "-build-after-clean", 1200)
        assert code == 0, "CLI mutation did not compile: " + log[-4000:]
        record["cli_sha256"] = digest(args.cli.read_bytes())
        checkpoint()

    def cli_run(label, witness=None, attachment_fixture=False):
        command = [
            sys.executable,
            str(ROOT / "test/wallet-v5r2/cli_sign_primary.py"),
            "--fee-session-rotation",
        ]
        for name in inputs:
            command += ["--" + name, str(getattr(args, name.replace("-", "_")).resolve())]
        command += ["--output", str(args.output / label)]
        if attachment_fixture:
            command += ["--expect-rotation-capacity-refusal"]
        code, log, record = execute(command, label, 900)
        if witness is None:
            assert code == 0 and (ATTACH_SUCCESS if attachment_fixture else CLI_SUCCESS) in log, (
                log[-6000:]
            )
            record[
                "attachment_preflight_passed" if attachment_fixture else "two_rotations_passed"
            ] = True
        else:
            assert code != 0 and "AssertionError" in log and witness in log, log[-6000:]
            assert "TimeoutExpired" not in log and "SyntaxError" not in log, log[-6000:]
            record.update(semantic_witness=witness, failure_excerpt=log[-3000:])
        checkpoint()
        return record

    def unit_run(label, witness=None):
        command = [
            cargo[0],
            "test",
            *cargo[1:],
            "-p",
            "contracts",
            "--features",
            "native-wallet-vault",
            "--lib",
            "checkpoint",
            "--",
            "--nocapture",
        ]
        code, log, record = execute(command, label + "-units", 1200)
        assert "could not compile" not in log and "Running unittests" in log, log[-6000:]
        assert "running 3 tests" in log, "checkpoint filter did not run all three expected tests"
        if witness is None:
            assert code == 0 and "3 passed; 0 failed" in log, log[-6000:]
        else:
            assert code != 0 and witness in log and "test result: FAILED" in log, log[-6000:]
            record.update(semantic_witness=witness, failure_excerpt=log[-3000:])
        checkpoint()
        return record

    def capacity_unit_run(label, witness=None):
        command = [
            cargo[0],
            "test",
            *cargo[1:],
            "-p",
            "commands",
            "--features",
            "pq-wallet",
            "--lib",
            "journal_rotation_capacity_boundary",
            "--",
            "--nocapture",
        ]
        code, log, record = execute(command, label + "-capacity-unit", 1200)
        assert "could not compile" not in log and "Running unittests" in log, log[-6000:]
        assert "running 1 test" in log, "journal capacity test did not run"
        if witness is None:
            assert code == 0 and "1 passed; 0 failed" in log, log[-6000:]
        else:
            assert code != 0 and witness in log and "test result: FAILED" in log, log[-6000:]
            record.update(semantic_witness=witness, failure_excerpt=log[-3000:])
        checkpoint()
        return record

    def migration_unit_run(label, witness=None):
        command = [
            cargo[0],
            "test",
            *cargo[1:],
            "-p",
            "contracts",
            "--features",
            "native-wallet-vault",
            "--lib",
            "requires_both_funded_pops",
            "--",
            "--nocapture",
        ]
        code, log, record = execute(command, label + "-migration-units", 1200)
        assert "could not compile" not in log and "Running unittests" in log, log[-6000:]
        assert "running 2 tests" in log, "migration and same-module rollover tests did not both run"
        if witness is None:
            assert code == 0 and "2 passed; 0 failed" in log, log[-6000:]
        else:
            assert code != 0 and witness in log and "test result: FAILED" in log, log[-6000:]
            record.update(semantic_witness=witness, failure_excerpt=log[-3000:])
        checkpoint()
        return record

    try:
        build("baseline")
        unit_run("baseline")
        capacity_unit_run("baseline")
        migration_unit_run("baseline")
        cli_run("baseline")
        for label, path, old, new, boundary, witness in cases:
            progress.update(active_mutation=label, sources_restored=False)
            original = originals[path].decode()
            fixture_source = None
            if boundary == "attachment_fixture":
                # Exercise the actual Attach call without constructing 33 native
                # rotations. Both control binaries use the same private limit 0;
                # only the Attach call differs, while Promote retains its guard.
                assert original.count("retired_count < 32,") == 1
                fixture_source = original.replace("retired_count < 32,", "retired_count < 0,")
                path.write_text(fixture_source)
                checkpoint()
                build(label + "-limit-zero")
                cli_run(label + "-limit-zero", attachment_fixture=True)
            path.write_text((fixture_source or original).replace(old, new))
            checkpoint()
            print("Running semantic mutation: " + label, flush=True)
            if boundary == "cli":
                build(label)
                record = cli_run(label, witness)
            elif boundary == "attachment_fixture":
                build(label)
                record = cli_run(label, witness, attachment_fixture=True)
                record.update(
                    private_fixture_source_sha256=digest(fixture_source.encode()),
                    private_test_limit=0,
                    production_limit=32,
                    fixture_scope="Real Attach entry point with zero retired journals; no 33 native rotations",
                )
            elif boundary == "command_unit":
                record = capacity_unit_run(label, witness)
            else:
                record = unit_run(label, witness)
                if label == "historical_live_source":
                    migration_unit_run(label, "accepted unproven successor vault")
            record.update(
                source=str(path.relative_to(ROOT)),
                original_sha256=digest(originals[path]),
                mutated_sha256=digest(path.read_bytes()),
            )
            path.write_bytes(originals[path])
            progress.update(active_mutation=None, sources_restored=True)
            checkpoint()
    finally:
        for path, original in originals.items():
            path.write_bytes(original)
        progress.update(active_mutation=None, sources_restored=True, status="restoring")
        checkpoint()
        build("restored")
        unit_run("restored")
        capacity_unit_run("restored")
        migration_unit_run("restored")
        cli_run("restored")
    assert all(path.read_bytes() == original for path, original in originals.items())
    report = dict(
        schema="TOS-WALLET-V5R2-CLI-ROTATION-CONTROLS-v1",
        semantic_mutations=len(cases),
        source_sha256={
            str(path.relative_to(ROOT)): digest(value) for path, value in originals.items()
        },
        cli_sha256=digest(args.cli.read_bytes()),
        genesis_driver_sha256=digest(args.genesis_driver.read_bytes()),
        sources_restored=True,
        scope=(
            "Actual CLI and native full transactions with public mnemonic fixtures, mocked "
            "authenticated account inputs, diagnostic gas credit 20000 at version 17 and "
            "a process-local fixture clock. No live proof acquisition, broadcast/finality, "
            "cross-device journal revocation or unknown fee-key history claim."
        ),
        runs=records,
    )
    progress.update(status="completed", sources_restored=True)
    checkpoint()
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"{len(cases)} rotation semantic mutations detected; restored native two-rotation flow passed"
    )


if __name__ == "__main__":
    main()

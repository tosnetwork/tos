#!/usr/bin/env python3
"""Compile native session-history mutants; require the named assertion."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/validator-auth-session-birth"))
from admission_mutations import compiled, invoke, named_failure, passing_suite  # noqa: E402


def mutations() -> list[tuple[str, str, str, str, str]]:
    # guard, named case, kind, exact source, replacement
    return [
        (
            "state-hash-binding",
            "state_hash_binding",
            "guard-disable",
            "hash(state->get_hash().as_slice()) != anchor.state_",
            "false",
        ),
        (
            "state-coordinate-binding",
            "state_coordinate_binding",
            "guard-disable",
            "header.seq_no != anchor.seqno_ ||",
            "false ||",
        ),
        (
            "state-reader-error",
            "state_reader_error",
            "semantic-fault",
            "      if (!loaded.ok())\n        return loaded.error();",
            "      if (!loaded.ok())\n        return Error{\"session-history-state-unavailable\"};",
        ),
        (
            "identity-reader-error",
            "identity_reader_error",
            "semantic-fault",
            "    if (!loaded_input.ok())\n      return loaded_input.error();",
            "    if (!loaded_input.ok())\n      return Error{\"session-history-identity-unavailable\"};",
        ),
        (
            "identity-shard-binding",
            "identity_shard_binding",
            "guard-disable",
            "    if (identity_input.workchain != target.workchain ||\n"
            "        identity_input.shard != target.shard)\n"
            "      return Error{\"session-history-identity-shard\"};",
            "    if (false && (identity_input.workchain != target.workchain ||\n"
            "                  identity_input.shard != target.shard))\n"
            "      return Error{\"session-history-identity-shard\"};",
        ),
        (
            "per-state-identity",
            "options_transition_is_boundary",
            "semantic-fault",
            "            return identity_reader_(authenticated.value(), state, target_);",
            "            auto input = identity_reader_(authenticated.value(), state, target_);\n"
            "            if (input.ok()) {\n"
            "              input.value().native_options_hash = expected_.native_options_hash;\n"
            "              input.value().maximal_vertical_seqno = expected_.vertical_seqno;\n"
            "              input.value().last_key_block_seqno = expected_.key_block_seqno;\n"
            "            }\n"
            "            return input;",
        ),
        (
            "preactivation-boundary",
            "preactivation_is_boundary",
            "semantic-fault",
            "    if (cfg.get_global_version() < 16 ||\n"
            "        !(cfg.get_capabilities() & tos::capValidatorAuth))\n"
            "      return std::optional<SessionBirthEpoch>{};",
            "    if (cfg.get_global_version() < 16 ||\n"
            "        !(cfg.get_capabilities() & tos::capValidatorAuth))\n"
            "      return Error{\"session-history-capability\"};",
        ),
        (
            "identity-commit",
            "epoch_uses_native_identity",
            "semantic-fault",
            "        established.native_session_id, election_hash,",
            "        established.native_options_hash, election_hash,",
        ),
        (
            "election-commit",
            "epoch_uses_native_identity",
            "semantic-fault",
            "        established.native_session_id, election_hash,\n"
            "        established.native_options_hash, established.workchain,",
            "        established.native_session_id, established.native_session_id,\n"
            "        established.native_options_hash, established.workchain,",
        ),
        (
            "observation-budget",
            "observation_budget_no_fallback",
            "semantic-fault",
            "      read, budget.observations);",
            "      read, 4096);",
        ),
        (
            "selected-state",
            "authenticated_birth_state",
            "semantic-fault",
            "  return NativeSessionBirth(std::move(selected.value()),\n"
            "                            std::move(selected_state.value()));",
            "  return NativeSessionBirth(std::move(selected.value()),\n"
            "                            std::move(head_state));",
        ),
        (
            "parent-history-error",
            "finalized_budget_no_fallback",
            "semantic-fault",
            "      if (!authenticated_parent.ok())\n"
            "        return authenticated_parent.error();",
            "      if (!authenticated_parent.ok())\n"
            "        return Error{\"session-birth-budget\"};",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()

    source = ROOT / "validator/auth/native-session-history.h"
    build = args.build.resolve()
    mutant_source = (
        build
        / "validator/auth/session-history-mutant/validator/auth/native-session-history.h"
    )
    binary = build / "validator/auth/test-p0-native-session-history-mutant"
    original = source.read_text()
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    mutant_source.parent.mkdir(parents=True, exist_ok=True)
    mutant_source.write_text(original)

    build_command = [
        "cmake",
        "--build",
        str(build),
        "--target",
        "test-p0-native-session-history-mutant",
        "-j2",
    ]
    if not compiled(build_command, binary, args.out / "baseline-build.log"):
        raise RuntimeError("baseline did not produce an executable")
    listed = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve()), "--list"],
        args.out / "cases.log",
    )
    expected = len(listed.stdout.splitlines())
    if listed.returncode != 0 or expected == 0:
        raise RuntimeError("case inventory failed")
    baseline = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve())],
        args.out / "baseline.log",
    )
    if not passing_suite(baseline, expected):
        raise RuntimeError("baseline tests failed")

    records: list[dict[str, object]] = []
    selected = mutations()[args.start : args.stop]
    if not selected:
        raise RuntimeError("no mutations selected")
    try:
        for guard, case, kind, old, new in selected:
            if original.count(old) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard}")
            changed = original.replace(old, new, 1)
            mutant_source.write_text(changed)
            (args.out / f"{guard}.diff").write_text(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(True),
                        changed.splitlines(True),
                        fromfile=str(source),
                        tofile=str(mutant_source),
                    )
                )
            )
            ok = compiled(
                build_command, binary, args.out / f"{guard}-build.log"
            )
            record: dict[str, object] = {
                "guard": guard,
                "case": case,
                "kind": kind,
                "compiled": ok,
                "assertion_name": case,
                "assertion_failed": False,
                "restored_baseline": False,
            }
            if ok:
                actual = invoke(
                    [
                        str(binary),
                        str(args.owner.resolve()),
                        str(args.committee.resolve()),
                        case,
                    ],
                    args.out / f"{guard}-run.log",
                )
                record["assertion_failed"] = named_failure(actual, case)
                record["mutant_exit_code"] = actual.returncode

            mutant_source.write_text(original)
            restored_compiled = compiled(
                build_command, binary, args.out / f"{guard}-restored-build.log"
            )
            restored = invoke(
                [str(binary), str(args.owner.resolve()), str(args.committee.resolve())],
                args.out / f"{guard}-restored.log",
            )
            restored_ok = restored_compiled and passing_suite(restored, expected)
            record["restored_source_matches"] = (
                mutant_source.read_bytes() == source.read_bytes()
            )
            record["restored_method"] = "restore-header-rebuild-and-rerun"
            record["restored_baseline"] = restored_ok
            record["restored_cases"] = expected if restored_ok else 0
            record["source_unchanged"] = (
                hashlib.sha256(source.read_bytes()).hexdigest() == source_digest
            )
            records.append(record)
            (args.out / "mutations.json").write_text(
                json.dumps(records, indent=2) + "\n"
            )
            print(json.dumps(record), flush=True)
            if not (
                ok
                and record["assertion_failed"]
                and restored_ok
                and record["restored_source_matches"]
                and record["source_unchanged"]
            ):
                raise RuntimeError(
                    f"mutation did not establish its named assertion: {guard}"
                )
    finally:
        mutant_source.write_text(original)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE: {error}", file=sys.stderr)
        sys.exit(2)

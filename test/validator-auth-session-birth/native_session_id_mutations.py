#!/usr/bin/env python3
"""Compile native-session identity mutants and require named failures."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from mutations import compiled, invoke, named_failure, passing_suite


def mutations() -> list[tuple[str, str, str, str, str]]:
    return [
        ("options-guard", "zero_options_are_refused", "guard-disable",
         "if (input.native_options_hash == Hash{})",
         "if (false && input.native_options_hash == Hash{})"),
        ("catchain-commit", "nonzero_catchain_is_committed", "semantic-fault",
         "key_block, catchain, input.native_options_hash, members",
         "key_block, 0, input.native_options_hash, members"),
        ("catchain-owned", "nonzero_catchain_is_committed", "semantic-fault",
         "input.workchain, input.shard, catchain, vertical,",
         "input.workchain, input.shard, 0, vertical,"),
        ("legacy-key-normalization", "legacy_key_block_is_normalized", "semantic-fault",
         "std::uint32_t key_block = 0;",
         "std::uint32_t key_block = input.last_key_block_seqno;"),
        ("new-key-commit", "new_key_block_is_committed", "semantic-fault",
         "key_block = input.last_key_block_seqno;",
         "key_block = 0;"),
        ("vertical-commit", "vertical_sequence_is_committed", "semantic-fault",
         "std::uint32_t vertical = input.maximal_vertical_seqno;",
         "std::uint32_t vertical = 0;"),
        ("options-commit", "options_hash_is_committed", "semantic-fault",
         "key_block, catchain, input.native_options_hash, members",
         "key_block, catchain, Hash{}, members"),
        ("workchain-commit", "group_matches_manager_bytes", "semantic-fault",
         "input.form, input.workchain, input.shard, vertical,",
         "input.form, 0, input.shard, vertical,"),
        ("shard-commit", "group_matches_manager_bytes", "semantic-fault",
         "input.form, input.workchain, input.shard, vertical,",
         "input.form, input.workchain, std::uint64_t{1} << 62, vertical,"),
        ("constructor-form", "group_ex_matches_manager_bytes", "semantic-fault",
         "auto encoded = encode(input.form, input.workchain, input.shard, vertical,",
         "auto encoded = encode(NativeSessionIdForm::group, input.workchain, input.shard, vertical,"),
        ("member-order", "member_order_is_committed", "semantic-fault",
         "key_block, catchain, input.native_options_hash, members",
         "key_block, catchain, input.native_options_hash, members.first(0)"),
        ("encoder-error-fallback", "encoder_failure_has_no_fallback", "semantic-fault",
         "  if (!encoded.ok())\n    return encoded.error();",
         "  if (!encoded.ok())\n    return Error{\"native-session-id\"};"),
        ("zero-id-guard", "zero_encoded_id_is_refused", "guard-disable",
         "if (encoded.value() == Hash{})",
         "if (false && encoded.value() == Hash{})"),
        ("group-form-vertical", "constructor_form_must_match_vertical", "guard-disable",
         "if (vertical != 0)",
         "if (false && vertical != 0)"),
        ("group-ex-form-vertical", "constructor_form_must_match_vertical", "guard-disable",
         "if (vertical == 0)",
         "if (false && vertical == 0)"),
        ("roster-guard", "empty_roster_is_refused", "guard-disable",
         "if (members.empty())",
         "if (false && members.empty())"),
        ("member-guard", "invalid_member_is_refused", "guard-disable",
         "if (member.short_id == Hash{} || member.weight == 0)",
         "if (false && (member.short_id == Hash{} || member.weight == 0))"),
        ("coordinate-guard", "invalid_coordinate_is_refused", "guard-disable",
         "if (input.workchain < -1 || input.shard == 0)",
         "if (false && (input.workchain < -1 || input.shard == 0))"),
        ("encoder-guard", "missing_encoder_is_refused", "semantic-fault",
         'return Error{"native-session-encoder"};',
         'return Error{"native-session-id"};'),
        ("owned-options", "group_matches_manager_bytes", "semantic-fault",
         "return NativeSessionIdentity{encoded.value(), input.native_options_hash,",
         "return NativeSessionIdentity{encoded.value(), Hash{},"),
        ("owned-form", "group_ex_matches_manager_bytes", "semantic-fault",
         "key_block, input.form};",
         "key_block, NativeSessionIdForm::group};"),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--stop", type=int)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root / "validator/auth/native-session-id-core.h"
    codec = root / "validator/auth/codec.h"
    driver = Path(__file__).with_name("native-session-id-test.cpp")
    original = source.read_text()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(args.cxx)
    if compiler is None:
        raise RuntimeError("compiler not found")
    invoke([compiler, "--version"], args.out / "compiler.log")
    flags = ["-std=c++20", "-O0", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    overlay = args.out / "overlay/validator/auth"
    overlay.mkdir(parents=True, exist_ok=True)
    mutant = overlay / source.name
    mutant.write_text(original)
    shutil.copyfile(codec, overlay / codec.name)
    baseline = args.out / "baseline"
    command = [compiler, *flags, "-I", str(args.out / "overlay"), str(driver), "-o", str(baseline)]
    if not compiled(command, baseline, args.out / "baseline-build.log"):
        raise RuntimeError("baseline did not produce an executable")
    listed = invoke([str(baseline), "--list"], args.out / "cases.log")
    expected = len(listed.stdout.splitlines())
    if listed.returncode != 0 or expected == 0:
        raise RuntimeError("case inventory failed")
    if not passing_suite(invoke([str(baseline)], args.out / "baseline.log"), expected):
        raise RuntimeError("baseline tests failed")
    baseline_digest = hashlib.sha256(baseline.read_bytes()).hexdigest()
    records: list[dict[str, object]] = []
    selected = mutations()[args.start:args.stop]
    if not selected:
        raise RuntimeError("no mutations selected")
    for guard, case, kind, old, new in selected:
        if original.count(old) != 1:
            raise RuntimeError(f"source anchor is not unique: {guard}")
        changed = original.replace(old, new, 1)
        mutant.write_text(changed)
        (args.out / f"{guard}.diff").write_text("".join(difflib.unified_diff(
            original.splitlines(True), changed.splitlines(True),
            fromfile=str(source), tofile=str(mutant))))
        binary = args.out / f"mutant-{guard}"
        ok = compiled([compiler, *flags, "-I", str(args.out / "overlay"), str(driver), "-o", str(binary)],
                      binary, args.out / f"{guard}-build.log")
        record: dict[str, object] = {
            "guard": guard, "case": case, "kind": kind, "compiled": ok,
            "assertion_name": case, "assertion_failed": False,
            "restored_baseline": False,
        }
        if ok:
            actual = invoke([str(binary), case], args.out / f"{guard}-run.log")
            record["assertion_failed"] = named_failure(actual, case)
            record["mutant_exit_code"] = actual.returncode
        mutant.write_text(original)
        restored_source = mutant.read_bytes() == source.read_bytes()
        restored_binary = hashlib.sha256(baseline.read_bytes()).hexdigest() == baseline_digest
        restored_ok = restored_source and restored_binary and passing_suite(
            invoke([str(baseline)], args.out / f"{guard}-restored.log"), expected)
        record["restored_source_matches"] = restored_source
        record["baseline_binary_unchanged"] = restored_binary
        record["restored_method"] = "restored-source-and-rerun-original-baseline"
        record["restored_baseline"] = restored_ok
        record["restored_cases"] = expected if restored_ok else 0
        record["source_unchanged"] = hashlib.sha256(source.read_bytes()).hexdigest() == digest
        records.append(record)
        (args.out / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
        if not (ok and record["assertion_failed"] and restored_ok and record["source_unchanged"]):
            raise RuntimeError(f"mutation did not establish its named assertion: {guard}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE: {error}", file=sys.stderr)
        sys.exit(2)

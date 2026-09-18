#!/usr/bin/env python3
"""Compile native-session C0 provider mutants and require isolated named failures."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "validator/auth/native-session-provider.cpp"

MUTATIONS = [
    (
        "birth-state-bound",
        "later_state_cannot_replace_birth",
        '  if (authenticated_birth_state.is_null() ||\n'
        '      state_hash(authenticated_birth_state) != birth.state)\n'
        '    return Error{"session-c0-birth-state"};',
        '  if (authenticated_birth_state.is_null())\n'
        '    return Error{"session-c0-birth-state"};',
    ),
    (
        "chain-domain-bound",
        "session_chain_must_match_birth_registry",
        '  if (view.value().chain_domain() != session->chain_.chain_domain)\n'
        '    return Error{"session-c0-chain"};',
        '  if (false && view.value().chain_domain() != session->chain_.chain_domain)\n'
        '    return Error{"session-c0-chain"};',
    ),
    (
        "installed-identity-copied",
        "exact_birth_inventory_installed",
        '      session, std::move(admission.value()), identity,\n'
        '      session->native_session_id_, session->p0_session_id_,\n'
        '      birth.seqno, role_keys.value());',
        '      session, std::move(admission.value()), Hash{},\n'
        '      session->native_session_id_, session->p0_session_id_,\n'
        '      birth.seqno, role_keys.value());',
    ),
    (
        # The permit/session slot must carry the canonical P0 session id, never
        # the native ValidatorSessionId. Feeding the native id into the P0 slot
        # is the "native group ID in PermitBody.session" error the split forbids.
        "permit-session-not-native",
        "exact_birth_inventory_installed",
        '      session->native_session_id_, session->p0_session_id_,\n'
        '      birth.seqno, role_keys.value());',
        '      session->native_session_id_, session->native_session_id_,\n'
        '      birth.seqno, role_keys.value());',
    ),
    (
        "committee-role-key-copied",
        "exact_birth_inventory_installed",
        '  return NativeSessionC0Authority(\n'
        '      session, std::move(admission.value()), identity,\n'
        '      session->native_session_id_, session->p0_session_id_,\n'
        '      birth.seqno, role_keys.value());',
        '  auto installed_keys = role_keys.value();\n'
        '  std::swap(installed_keys[0], installed_keys[1]);\n'
        '  return NativeSessionC0Authority(\n'
        '      session, std::move(admission.value()), identity,\n'
        '      session->native_session_id_, session->p0_session_id_,\n'
        '      birth.seqno, installed_keys);',
    ),
    (
        "role-has-no-fallback",
        "invalid_role_has_no_fallback",
        '  if (role < 1 || role > role_keys_.size())\n'
        '    return Error{"session-c0-role"};',
        '  if (role < 1 || role > role_keys_.size())\n'
        '    role = 1;',
    ),
    (
        "release-revokes-route",
        "release_revokes_c0_route",
        '  if (!session || !session->context_)\n'
        '    return Error{"session-context-released"};\n'
        '  if (session->native_session_id_ != native_session_id_ ||',
        '  if (!session)\n'
        '    return Error{"session-context-released"};\n'
        '  if (!session->context_) {\n'
        '    auto cached = admission_.route(role_keys_[role - 1]);\n'
        '    if (!cached.ok())\n'
        '      return cached.error();\n'
        '    return NativeSessionC0Route{role_keys_[role - 1], cached.value()};\n'
        '  }\n'
        '  if (session->native_session_id_ != native_session_id_ ||',
    ),
]


def invoke(command: list[str], log: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=900)
    log.write_text(
        "$ " + " ".join(command) + f"\nexit_code={result.returncode}\n"
        "--- stdout ---\n" + result.stdout + "--- stderr ---\n" + result.stderr
    )
    return result


def build(tree: Path, binary: Path, log: Path) -> bool:
    binary.unlink(missing_ok=True)
    result = invoke(
        ["cmake", "--build", str(tree), "--target",
         "test-p0-native-session-provider-mutant", "-j2"], log)
    return result.returncode == 0 and binary.is_file()


def passing(result: subprocess.CompletedProcess[str], expected: int) -> bool:
    lines = result.stdout.splitlines()
    return (result.returncode == 0 and result.stderr == "" and
            lines[-1:] == [f"SUMMARY cases={expected} passed={expected}"] and
            sum(line.startswith("CASE_PASS ") for line in lines) == expected)


def named_failure(result: subprocess.CompletedProcess[str], case: str) -> bool:
    return (result.returncode == 1 and
            result.stdout.splitlines() == [f"SETUP_OK {case}"] and
            result.stderr.splitlines()[-1:] == [f"ASSERTION_FAILED {case}"])


def run_case(binary: Path, owner: Path, committee: Path, work: Path,
             selector: str, log: Path) -> subprocess.CompletedProcess[str]:
    shutil.rmtree(work, ignore_errors=True)
    return invoke([str(binary), str(owner), str(committee), str(work), selector], log)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--committee", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    tree = args.build.resolve()
    binary = tree / "validator/auth/test-p0-native-session-provider-mutant"
    mutant = tree / "validator/auth/mutated-native-session-provider.cpp"
    original = SOURCE.read_text()
    digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    mutant.write_text(original)

    if not build(tree, binary, args.out / "baseline-build.log"):
        raise RuntimeError("baseline mutant target did not compile")
    listed = invoke(
        [str(binary), str(args.owner.resolve()), str(args.committee.resolve()),
         str((args.work / "list").resolve()), "--list"],
        args.out / "cases.log")
    cases = listed.stdout.splitlines()
    if listed.returncode != 0 or not cases:
        raise RuntimeError("case inventory failed")

    records = []
    try:
        for guard, case, before, after in MUTATIONS:
            if original.count(before) != 1:
                raise RuntimeError(f"source anchor is not unique: {guard} ({original.count(before)})")
            changed = original.replace(before, after, 1)
            mutant.write_text(changed)
            if mutant.read_text() != changed:
                raise RuntimeError(f"mutation did not reach source: {guard}")
            (args.out / f"{guard}.diff").write_text("".join(difflib.unified_diff(
                original.splitlines(True), changed.splitlines(True),
                fromfile=str(SOURCE), tofile=str(mutant))))

            compiled = build(tree, binary, args.out / f"{guard}-build.log")
            target = None
            named = False
            isolated = False
            if compiled:
                target = run_case(binary, args.owner.resolve(), args.committee.resolve(),
                                  args.work / f"named-{guard}", case,
                                  args.out / f"{guard}-named.log")
                named = named_failure(target, case)
                spared = [name for name in cases if name != case]
                isolated = True
                for index, other in enumerate(spared):
                    result = run_case(binary, args.owner.resolve(), args.committee.resolve(),
                                      args.work / f"other-{guard}-{index}", other,
                                      args.out / f"{guard}-other-{index}.log")
                    if not passing(result, 1):
                        isolated = False
                        break

            mutant.write_text(original)
            restored_compile = build(tree, binary, args.out / f"{guard}-restored-build.log")
            restored = invoke(
                [str(binary), str(args.owner.resolve()), str(args.committee.resolve()),
                 str((args.work / f"restored-{guard}").resolve())],
                args.out / f"{guard}-restored.log")
            restored_ok = restored_compile and passing(restored, len(cases))
            record = {
                "guard": guard,
                "case": case,
                "compiled": compiled,
                "named_assertion_failed": named,
                "other_cases_passed": isolated,
                "restored_baseline": restored_ok,
                "source_unchanged": hashlib.sha256(SOURCE.read_bytes()).hexdigest() == digest,
            }
            if target is not None:
                record.update({"named_returncode": target.returncode,
                               "named_stdout": target.stdout,
                               "named_stderr": target.stderr})
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("compiled", "named_assertion_failed",
                                                "other_cases_passed", "restored_baseline",
                                                "source_unchanged")):
                raise RuntimeError(f"mutation did not isolate its named case: {guard}")
    finally:
        mutant.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)

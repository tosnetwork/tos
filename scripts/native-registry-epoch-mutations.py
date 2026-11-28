#!/usr/bin/env python3
"""Prove the registry's epoch and delegation tests kill specific broken rules.

Each contract case edits crypto/smartcont/native-registry-code.fc in a temporary
copy, compiles it with FunC and Fift, and runs one named sandbox test against the
mutant through NATIVE_REGISTRY_CODE_BOC; the test must fail with the stated
assertion. Each reader case edits the Rust strict reader in place, runs one named
library test, and restores the file byte for byte. Each Python case edits the
local-network Gate C builder in a temporary copy and runs the script encoder
check against it. The unmodified sources must pass every named test first.

Requires FUNC_BIN and FIFT_BIN (default build/crypto/{func,fift}), and for the
Python cases PQ_TEST_SIGNER. Usage: native-registry-epoch-mutations.py [--layer LAYER]
[--only NAME] [--release]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crypto/smartcont/native-registry-code.fc"
READER = ROOT / "tosctl/src/node-control/contracts/src/native_registry.rs"
GATE = ROOT / "scripts/tos-service-native-registry-local-gate-c.py"
FUNC = Path(os.environ.get("FUNC_BIN", ROOT / "build/crypto/func"))
FIFT = Path(os.environ.get("FIFT_BIN", ROOT / "build/crypto/fift"))

BUMP_UPDATE = "      recovery = empty_recovery(); bump = 1;\n    } elseif (delegation_kind) {"
BUMP_COMPLETE = (
    "      recovery = empty_recovery(); bump = 1;\n    } elseif (kind == kind::revoke_agent) {"
)
BUMP_TOMBSTONE = "      p.end_parse(); tombstone = 1; recovery = empty_recovery(); bump = 1;"
CHECKED_BUMP = (
    "      throw_unless(err::epoch_exhausted, epoch < max::authorization_epoch);\n"
    "      epoch += 1;\n"
)
CLEAR_ON_BUMP = "      delegations = empty_delegations();\n    }\n    save_object("
ADD_BOUNDS = (
    "        throw_unless(err::capacity_full, (live < max::live_delegations) &\n"
    "          (admitted < max::admitted_delegations));\n"
)
WITHDRAWN_READD = (
    "        throw_unless(err::withdrawn_digest, withdrawn == 0);\n"
    "        throw_unless(err::bad_transition, ~ existed);\n"
)
WITHDRAW_FLIP = "        live -= 1;\n"
REPLAY = "    int old_action = replay~load_uint(256);\n"

# (name, sandbox test, anchor, replacement, assertion text the failure must show)
CONTRACT = [
    (
        "omit the update bump",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        BUMP_UPDATE,
        BUMP_UPDATE.replace(" bump = 1;", ""),
        "A to B",
    ),
    (
        "omit the recovery-completion bump",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        BUMP_COMPLETE,
        BUMP_COMPLETE.replace(" bump = 1;", ""),
        "completion advances and clears",
    ),
    (
        "omit the tombstone bump",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        BUMP_TOMBSTONE,
        BUMP_TOMBSTONE.replace(" bump = 1;", ""),
        "tombstone advances and clears",
    ),
    (
        "bump on add",
        "epoch_add_withdraw_readd_and_replay",
        "        live += 1; admitted += 1;\n",
        "        live += 1; admitted += 1; epoch += 1;\n",
        "two adds at epoch 1",
    ),
    (
        "bump on withdrawal",
        "epoch_add_withdraw_readd_and_replay",
        WITHDRAW_FLIP,
        "        live -= 1; epoch += 1;\n",
        "live drops, admitted and epoch stay",
    ),
    (
        "bump on recovery initiation",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        "        .store_ref(recovery_policy).end_cell();\n",
        "        .store_ref(recovery_policy).end_cell(); bump = 1;\n",
        "initiation keeps the epoch and the delegations",
    ),
    (
        "wrap the epoch at MAX",
        "the_largest_epoch_cannot_advance_and_still_admits_delegations",
        CHECKED_BUMP,
        "      epoch = (epoch + 1) & max::authorization_epoch;\n",
        "update at MAX",
    ),
    (
        "saturate the epoch at MAX",
        "the_largest_epoch_cannot_advance_and_still_admits_delegations",
        CHECKED_BUMP,
        "      if (epoch < max::authorization_epoch) { epoch += 1; }\n",
        "update at MAX",
    ),
    (
        "check overflow before the exact replay",
        "the_largest_epoch_cannot_advance_and_still_admits_delegations",
        REPLAY,
        REPLAY + "    throw_if(err::epoch_exhausted, (object_kind == 1) &\n"
        "      (replay.preload_uint(64) == max::authorization_epoch) &\n"
        "      ((kind == kind::update_agent_policy) | (kind == kind::complete_recovery) |\n"
        "       (kind == kind::revoke_agent)));\n",
        "expected first transaction to succeed",
    ),
    (
        "keep the delegation set on a bump",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        CLEAR_ON_BUMP,
        "    }\n    save_object(",
        "A to B",
    ),
    (
        "keep the entries but zero the counts on a bump",
        "every_bump_advances_the_epoch_once_and_clears_both_sets",
        CLEAR_ON_BUMP,
        "      slice kept = delegations.begin_parse(); kept~skip_bits(32);\n"
        "      delegations = begin_cell().store_uint(0, 32).store_slice(kept).end_cell();\n"
        "    }\n    save_object(",
        "the strict reader admits the state",
    ),
    (
        "ignore the expected epoch",
        "expected_epoch_must_be_the_current_one",
        "      throw_unless(err::epoch_mismatch, expected_epoch == epoch);\n",
        "",
        "kind 3 epoch 1",
    ),
    (
        "permit a withdrawn re-add",
        "epoch_add_withdraw_readd_and_replay",
        WITHDRAWN_READD,
        "        throw_unless(err::bad_transition, (~ existed) | (withdrawn != 0));\n",
        "re-add of a withdrawn digest",
    ),
    (
        "capacity check on withdrawal",
        "withdrawal_at_every_position_needs_no_capacity",
        WITHDRAW_FLIP,
        "        throw_unless(err::capacity_full, (live < max::live_delegations) &\n"
        "          (admitted < max::admitted_delegations));\n" + WITHDRAW_FLIP,
        "expected first transaction to succeed",
    ),
    (
        "weaken the live bound",
        "each_bound_refuses_independently",
        ADD_BOUNDS,
        ADD_BOUNDS.replace("(live < max", "(live <= max"),
        "live 128, admitted 128",
    ),
    (
        "weaken the admitted bound",
        "each_bound_refuses_independently",
        ADD_BOUNDS,
        ADD_BOUNDS.replace("(admitted < max", "(admitted <= max"),
        "live 127, admitted 384",
    ),
    (
        "withdrawal changes the admitted count",
        "epoch_add_withdraw_readd_and_replay",
        WITHDRAW_FLIP,
        "        live -= 1; admitted -= 1;\n",
        "live drops, admitted and epoch stay",
    ),
    (
        "withdrawal emits an out action",
        "epoch_add_withdraw_readd_and_replay",
        WITHDRAW_FLIP,
        WITHDRAW_FLIP
        + "        send_raw_message(begin_cell().store_uint(0x10, 6).store_slice(sender)\n"
        "          .store_tomis(0).store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1).end_cell(), 64);\n",
        "a withdrawal emits nothing",
    ),
    (
        "Agent identity tag 3 to 1",
        "agent_identity_tag_is_three",
        "const int identity::agent = 3;",
        "const int identity::agent = 1;",
        "exit_code: 2210",
    ),
    (
        "Agent identity tag 3 to 2",
        "agent_identity_tag_is_three",
        "const int identity::agent = 3;",
        "const int identity::agent = 2;",
        "exit_code: 2210",
    ),
    (
        "Capability identity tag 2 to 3",
        "capability_state_is_schema_two_with_its_layout_unchanged",
        "const int identity::capability = 2;",
        "const int identity::capability = 3;",
        "expected transaction to succeed",
    ),
    (
        "Capability state schema 1",
        "capability_state_is_schema_two_with_its_layout_unchanged",
        "  return begin_cell().store_uint(magic::state, 32).store_uint(state::schema, 16)\n"
        "    .store_uint(2, 8)",
        "  return begin_cell().store_uint(magic::state, 32).store_uint(1, 16)\n"
        "    .store_uint(2, 8)",
        "Capability schema 2",
    ),
]

# (name, library test, anchor, replacement, assertion text)
READER_CASES = [
    (
        "ignore the stored admission epoch",
        "delegation_reader_refuses_every_malformed_shape",
        "                ensure!(\n                    admission_epoch == epoch,\n"
        '                    "native registry delegation admitted in another epoch"\n'
        "                );\n",
        "",
        "admitted in another epoch",
    ),
    (
        "drop the count equality",
        "delegation_reader_refuses_every_malformed_shape",
        "        entries.len() == usize::from(admitted) && live_entries == usize::from(live),",
        "        true,",
        "differ from the entries",
    ),
    (
        "drop the count bounds",
        "delegation_reader_refuses_every_malformed_shape",
        "        live <= NATIVE_REGISTRY_MAX_DELEGATIONS\n"
        "            && admitted <= NATIVE_REGISTRY_MAX_ADMITTED_DELEGATIONS\n"
        "            && live <= admitted,",
        "        true,",
        "out of bounds",
    ),
    (
        "drop the leaf shape check",
        "delegation_reader_refuses_every_malformed_shape",
        "                    value.remaining_bits() == 0 && value.remaining_references() == 0,\n"
        '                    "native registry delegation leaf shape"',
        '                    true,\n                    "native registry delegation leaf shape"',
        "leaf shape",
    ),
    (
        "accept schema 1",
        "capability_reader_requires_schema_two_with_the_unchanged_layout",
        "        s.get_next_u32()? == MAGIC_STATE && s.get_next_u16()? == STATE_SCHEMA,",
        "        s.get_next_u32()? == MAGIC_STATE && matches!(s.get_next_u16()?, 1 | 2),",
        "decode_native_registry_state(&capability(1)?).is_err()",
    ),
    (
        "Agent identity tag 3 to 1",
        "identity_tags_separate_agent_releases_and_kinds",
        "pub const NATIVE_IDENTITY_TAG_AGENT: u8 = 3;",
        "pub const NATIVE_IDENTITY_TAG_AGENT: u8 = 1;",
        "tag 3 derives the Agent id",
    ),
    (
        "Agent identity tag 3 to 2",
        "identity_tags_separate_agent_releases_and_kinds",
        "pub const NATIVE_IDENTITY_TAG_AGENT: u8 = 3;",
        "pub const NATIVE_IDENTITY_TAG_AGENT: u8 = 2;",
        "tag 3 derives the Agent id",
    ),
]

# (name, anchor, replacement, assertion text) against the Gate C builder
AGENT_ID_TEST = "FAIL: test_the_policy_reproduces_the_agent_identity"
CAPABILITY_ID_TEST = "FAIL: test_capability_registration_identity_action_and_body_are_byte_exact"
GATE_CASES = [
    ("Gate C Agent tag 3 to 1", "AGENT_IDENTITY_TAG = 3", "AGENT_IDENTITY_TAG = 1", AGENT_ID_TEST),
    ("Gate C Agent tag 3 to 2", "AGENT_IDENTITY_TAG = 3", "AGENT_IDENTITY_TAG = 2", AGENT_ID_TEST),
    (
        "Gate C Capability tag 2 to 3",
        "CAPABILITY_IDENTITY_TAG = 2",
        "CAPABILITY_IDENTITY_TAG = 3",
        CAPABILITY_ID_TEST,
    ),
]

CARGO = [
    "cargo",
    "test",
    "--locked",
    "--manifest-path",
    str(ROOT / "tosctl/src/Cargo.toml"),
    "-p",
    "contracts",
]


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"mutation anchor is not unique: {old!r}")
    return text.replace(old, new, 1)


def compile_registry(source: Path, out: Path) -> None:
    fif = out.with_suffix(".fif")
    subprocess.run(
        [
            str(FUNC),
            "-W",
            str(out),
            "-AP",
            "-o",
            str(fif),
            str(ROOT / "crypto/smartcont/stdlib.fc"),
            str(source),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [str(FIFT), str(fif)],
        check=True,
        capture_output=True,
        env=dict(os.environ, FIFTPATH=str(ROOT / "crypto/fift/lib")),
    )


def run(cmd: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)


def expect(label: str, result: subprocess.CompletedProcess, red: bool, assertion: str) -> None:
    output = result.stdout + result.stderr
    if not red:
        if result.returncode != 0:
            raise RuntimeError(f"{label}: baseline failed\n{output[-4000:]}")
        print(f"PASS baseline: {label}", flush=True)
        return
    if result.returncode == 0:
        raise RuntimeError(f"{label}: the mutant survived")
    if "error[E" in output or "could not compile" in output:
        raise RuntimeError(f"{label}: the mutant failed to compile, which proves nothing")
    if assertion not in output:
        panics = "\n".join(
            line
            for line in output.splitlines()
            if "panicked" in line
            or "FAIL" in line
            or "Error" in line
            or line.startswith(("  left", " right", "expected"))
        )
        raise RuntimeError(f"{label}: failed, but not with {assertion!r}\n{panics[-4000:]}")
    print(f"KILLED: {label} (red with {assertion!r})", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="run only the cases whose name contains this text")
    parser.add_argument("--release", action="store_true", help="build the tests optimized")
    parser.add_argument(
        "--layer",
        choices=("contract", "reader", "gate"),
        action="append",
        help="run only this layer's cases (repeatable; default every layer)",
    )
    args = parser.parse_args()
    layers = set(args.layer or ("contract", "reader", "gate"))
    if args.release:
        CARGO.insert(2, "--release")

    def pick(name: str) -> bool:
        return args.only is None or args.only in name

    env = dict(os.environ, TOS_ROOT=str(ROOT), CARGO_TERM_COLOR="never")
    env.pop("NATIVE_REGISTRY_CODE_BOC", None)
    source = SOURCE.read_text()
    reader = READER.read_bytes()

    with tempfile.TemporaryDirectory(prefix="registry-epoch-mutants-") as tmp:
        tmp_dir = Path(tmp)
        for include in re.findall(r'^#include "([^"\n]+)";', source, re.MULTILINE):
            (tmp_dir / include).write_bytes((SOURCE.parent / include).read_bytes())

        contract = [case for case in CONTRACT if "contract" in layers and pick(case[0])]
        if contract:
            baseline = tmp_dir / "baseline.boc"
            (tmp_dir / "baseline.fc").write_text(source)
            compile_registry(tmp_dir / "baseline.fc", baseline)
            for test in sorted({case[1] for case in contract}):
                expect(
                    test,
                    run(
                        CARGO
                        + ["--test", "native_registry_sandbox", f"epochs::{test}", "--", "--exact"],
                        dict(env, NATIVE_REGISTRY_CODE_BOC=str(baseline)),
                    ),
                    False,
                    "",
                )
            for index, (name, test, old, new, assertion) in enumerate(contract):
                path = tmp_dir / f"mutant-{index}.fc"
                path.write_text(replace_once(source, old, new))
                boc = tmp_dir / f"mutant-{index}.boc"
                compile_registry(path, boc)
                result = run(
                    CARGO
                    + ["--test", "native_registry_sandbox", f"epochs::{test}", "--", "--exact"],
                    dict(env, NATIVE_REGISTRY_CODE_BOC=str(boc)),
                )
                expect(name, result, True, assertion)

        cases = [case for case in READER_CASES if "reader" in layers and pick(case[0])]
        if cases:
            for test in sorted({case[1] for case in cases}):
                expect(test, run(CARGO + ["--lib", test], env), False, "")
            digest = hashlib.sha256(reader).hexdigest()
            try:
                for name, test, old, new, assertion in cases:
                    READER.write_bytes(replace_once(reader.decode(), old, new).encode())
                    expect(f"reader: {name}", run(CARGO + ["--lib", test], env), True, assertion)
            finally:
                READER.write_bytes(reader)
            if hashlib.sha256(READER.read_bytes()).hexdigest() != digest:
                raise RuntimeError("the strict reader was not restored")

        gates = [case for case in GATE_CASES if "gate" in layers and pick(case[0])]
        if gates:
            check = ROOT / "scripts/test_tos_service_native_registry_pq.py"
            expect("Gate C encoders", run([sys.executable, str(check)], env), False, "")
            gate = GATE.read_text()
            for name, old, new, assertion in gates:
                # Beside the original, so the copy resolves the repository as it does.
                with tempfile.NamedTemporaryFile(
                    "w", dir=GATE.parent, prefix=".gate-mutant-", suffix=".py"
                ) as copy:
                    copy.write(replace_once(gate, old, new))
                    copy.flush()
                    result = run(
                        [sys.executable, str(check)], dict(env, NATIVE_REGISTRY_GATE=copy.name)
                    )
                expect(name, result, True, assertion)
    print("PASS: every epoch, delegation and identity mutant was killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

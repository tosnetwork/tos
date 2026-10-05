"""Exercise the actual governance installer and PRIMARY policy reader in transactions."""

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402

NETWORK = 123
ADDRESS = (0, 456)
SENDER = (0, 789)
PROFILE = b"TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;deadline=u32;network=bits256;monotonic"
SPEC = int.from_bytes(hashlib.sha256(PROFILE).digest(), "big")


def policy(
    sequence=0, retired=0, deadline=None, network=NETWORK, tag=0xA1, spec=SPEC, schedule=None
):
    if schedule is None:
        schedule = {} if deadline is None else {1: Cell().uint(deadline, 32)}
    return (
        Cell()
        .uint(tag, 8)
        .uint(network, 256)
        .uint(sequence, 64)
        .uint(retired, 16)
        .maybe(make_dict(schedule, 8) if schedule else None)
        .uint(spec, 256)
    )


DRIVER = """
() recv_internal(int value, cell message, slice body) impure {
  int operation = body~load_uint(8);
  if (operation == 0) {
    int parameter = body~load_uint(8);
    cell next = body~load_maybe_ref();
    body.end_parse();
    cell dictionary = get_data().begin_parse().preload_dict();
    (cell updated, int accepted) = install_param(dictionary, parameter, next);
    throw_unless(1999, accepted);
    set_data(begin_cell().store_dict(updated).end_cell());
  } else {
    if (operation == 1) {
      auth_policy_require_primary(123, 1);
    }
    set_data(begin_cell().store_uint(1, 1).end_cell());
  }
}
"""


def compile_driver(work, output, mutation=None):
    for p in (ROOT / "crypto/smartcont").glob("*.fc"):
        shutil.copyfile(p, work / p.name)
    if mutation:
        path = work / "auth-policy.fc"
        s = path.read_text()
        assert s.count(mutation[0]) == 1
        path.write_text(s.replace(*mutation))
    source = (work / "config-code.fc").read_text()
    source = source.replace("() recv_internal(", "() original_recv_internal(")
    source = source.replace("() recv_external(", "() original_recv_external(")
    (work / "driver.fc").write_text(source + DRIVER)
    try:
        return native.compile_contract(str(work / "driver.fc"), output)
    except subprocess.CalledProcessError as error:
        print(error.stderr.decode(), file=sys.stderr)
        raise


def transact(code, current, next=None, operation=0, expected=0, parameter=48, memberships=True):
    base_config = native.config(17)
    entries = read_dict(base_config, 32)
    if current is not None:
        entries[48] = Cell().ref(current)
    cfg = make_dict(entries, 32)
    state_entries = {48: Cell().ref(current)} if current else {}
    if memberships:
        state_entries.update({i: Cell().ref(make_dict({48: Cell()}, 32)) for i in (9, 10)})
    data = Cell().maybe(make_dict(state_entries, 32) if state_entries else None)
    body = Cell().uint(operation, 8)
    if operation == 0:
        body.uint(parameter, 8).maybe(next)
    with patch.object(native, "config", return_value=cfg):
        e = native.Emulator(global_version=17)
    try:
        r = e.send(
            native.active_account(ADDRESS, code, data), native.internal(SENDER, ADDRESS, body)
        )
        assert r["success"], r
        d = r["details"]
        assert d["exit"] == expected, f"expected exit {expected}, got {d['exit']}: {d}"
        stored, _ = native.account_data(from_boc(r["shard_account"]))
        if expected:
            assert stored.hash == data.hash, "refusal changed stored policy"
        elif operation == 0:
            installed = read_dict(stored.refs[0], 32)[parameter].refs[0]
            assert installed.hash == next.hash
        else:
            assert stored.bits == "1"
        return d
    finally:
        e.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        code = compile_driver(work, args.output / "policy-driver.boc")
        results = {}
        cases = [
            ("initialize", None, policy(), 0),
            ("initial_sequence", None, policy(sequence=1), 1999),
            ("advance", policy(), policy(sequence=1), 0),
            ("same_sequence", policy(), policy(), 1999),
            ("rollback_sequence", policy(sequence=2), policy(sequence=1), 1999),
            ("delete", policy(), None, 1999),
            ("retire", policy(), policy(sequence=1, retired=2), 0),
            ("revive", policy(retired=2), policy(sequence=1), 1999),
            ("schedule", policy(), policy(sequence=1, deadline=native.NOW + 10), 0),
            (
                "retain_deadline",
                policy(deadline=native.NOW + 10),
                policy(sequence=1, deadline=native.NOW + 10),
                0,
            ),
            (
                "advance_deadline",
                policy(deadline=native.NOW + 10),
                policy(sequence=1, deadline=native.NOW),
                0,
            ),
            (
                "postpone",
                policy(deadline=native.NOW),
                policy(sequence=1, deadline=native.NOW + 10),
                1999,
            ),
            ("remove_deadline", policy(deadline=native.NOW), policy(sequence=1), 1999),
            ("change_network", policy(), policy(sequence=1, network=124), 1999),
            ("change_spec", policy(), policy(sequence=1, spec=SPEC + 1), 1999),
            ("max_sequence", policy(sequence=(1 << 64) - 1), policy(), 1999),
        ]
        malformed = {
            "version": policy(tag=0xA2),
            "unknown_bit": policy(retired=4),
            "zero_deadline": policy(deadline=0),
            "unknown_suite": policy(schedule={2: Cell().uint(1, 32)}),
            "second_schedule": policy(schedule={1: Cell().uint(1, 32), 2: Cell().uint(1, 32)}),
            "short_deadline": policy(schedule={1: Cell().uint(1, 31)}),
            "long_deadline": policy(schedule={1: Cell().uint(1, 33)}),
            "deadline_ref": policy(schedule={1: Cell().uint(1, 32).ref(Cell())}),
            "short_record": Cell().uint(0xA1, 8),
            "trailing_bit": Cell(bits=policy().bits + "0", refs=policy().refs),
            "trailing_ref": Cell(bits=policy().bits, refs=[Cell()]),
        }
        for name, bad in malformed.items():
            cases.append(("malformed_" + name, policy(), bad, 1999))
        for name, old, new, expected in cases:
            results[name] = transact(code, old, new, expected=expected)
        for name, current, expected in [
            ("primary_live", policy(), 0),
            ("primary_retired", policy(retired=2), 1813),
            ("before_deadline", policy(deadline=native.NOW + 1), 0),
            ("at_deadline", policy(deadline=native.NOW), 1813),
            ("after_deadline", policy(deadline=native.NOW - 1), 1813),
            ("missing", None, 1820),
            ("wrong_network", policy(network=124), 1820),
            ("wrong_spec", policy(spec=SPEC + 1), 1820),
        ]:
            results[name] = transact(code, current, operation=1, expected=expected)
            results["rescue_" + name] = transact(code, current, operation=2)
        for parameter in (9, 10):
            results[f"delete_membership_{parameter}"] = transact(
                code, policy(), None, parameter=parameter, expected=1999
            )
            results[f"remove_membership_{parameter}"] = transact(
                code, policy(), make_dict({47: Cell()}, 32), parameter=parameter, expected=1999
            )
            results[f"keep_membership_{parameter}"] = transact(
                code, policy(), make_dict({48: Cell()}, 32), parameter=parameter
            )
        results["bootstrap_without_membership"] = transact(
            code, None, policy(), expected=1999, memberships=False
        )
        results["replacement_without_membership"] = transact(
            code, policy(), policy(sequence=1), expected=1999, memberships=False
        )
        mutations = [
            (
                "bootstrap_membership",
                "if (found) { valid = entry.slice_empty?(); }",
                "valid = true;",
                lambda c: transact(c, None, policy(), expected=1999, memberships=False),
            ),
            (
                "clear_bits",
                "& ((retired & old_retired) == old_retired)",
                "",
                lambda c: transact(c, policy(retired=2), policy(sequence=1), expected=1999),
            ),
            (
                "remove_deadline",
                "& ((old_deadline == 0) | ((deadline != 0) & (deadline <= old_deadline)))",
                "",
                lambda c: transact(
                    c, policy(deadline=native.NOW), policy(sequence=1), expected=1999
                ),
            ),
            (
                "sequence",
                "(sequence > old_sequence)",
                "(sequence >= old_sequence)",
                lambda c: transact(c, policy(), policy(), expected=1999),
            ),
            (
                "primary_gate",
                "throw_if(auth_policy::retired, (retired & 2) | ((deadline != 0) & (now() >= deadline)));",
                "",
                lambda c: transact(c, policy(retired=2), operation=1, expected=1813),
            ),
        ]
        killed = {}
        for name, old, new, test in mutations:
            mutant = compile_driver(work, args.output / (name + ".boc"), (old, new))
            try:
                test(mutant)
            except AssertionError as error:
                assert "got 0:" in str(error), str(error)
                killed[name] = str(error)
            else:
                raise AssertionError("mutation survived: " + name)
            test(code)
        report = {
            "scope": "FunC policy reader and actual governance install_param; node/genesis and full-wallet integration pending",
            "cases": len(results),
            "results": results,
            "mutations": killed,
            "spec_hash": f"{SPEC:064x}",
        }
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()

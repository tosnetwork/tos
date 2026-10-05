"""Full V5R1 action semantics required by V5R2; this does not certify an R2 wallet.

Executes the repository's V5R1 contract, checks its frozen SDK bytecode identity,
and exhausts all send-mode bytes plus action-list boundaries. Mutations compile
successfully and must violate a specific behavioral expectation.
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402
from native import account_data, active_account, compile_contract, internal, outgoing  # noqa: E402
from test_auth import CODES, MODULE, TARGET, Account  # noqa: E402


def sdk_code():
    source = (ROOT / "tosctl/src/node-control/contracts/src/wallet/wallet_contract.rs").read_text()
    found = re.findall(r'pub const V5R1_CODE_B64: &str =\s*"([^"]+)";', source)
    assert len(found) == 1
    return from_boc(base64.b64decode(found[0]))


def actions(account, count=1, mode=3):
    out = internal(account.address, TARGET, Cell(), value=1_000_000_000)
    result = Cell()
    for _ in range(count):
        result = Cell().uint(0x0EC3C86D, 32).uint(mode, 8).ref(result).ref(out)
    return result


def execute(code, make_actions, expected):
    CODES["wallet-func"] = code
    a = Account("wallet-func", mode=2)
    a.shard = active_account(a.address, code, a.data, balance=1_000_000_000_000_000)
    try:
        before = a.data.hash
        payload = make_actions(a)
        request = a.envelope(a.request(payload=payload))
        # Large batches must reach action validation, not fail for insufficient gas.
        r = a.e.send(a.shard, internal(MODULE, a.address, request, value=100_000_000_000))
        assert r["success"], r
        d = r["details"]
        assert d["exit"] == expected, f"expected exit {expected}, got {d['exit']}: {d}"
        state, _ = account_data(from_boc(r["shard_account"]))
        if expected:
            assert state.hash == before, "rejected actions changed wallet authority/counters"
        else:
            assert d["action"] is None or d["action"]["success"], d
            assert not d["aborted"], d
            assert state.hash != before, "accepted execution did not consume counters"
        messages = outgoing(from_boc(r["transaction"]))
        # Rejections can bounce the funded input. They must never emit a target payment.
        for message in messages:
            header = message.slice()
            flags = header.uint(4)
            header.addr()
            destination = header.addr()
            assert (flags & 1) if expected else destination == TARGET
        return {"exit": d["exit"], "gas": d["gas"], "messages": len(messages)}
    finally:
        a.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    code = compile_contract("wallet-v5-code.fc", args.output / "v5r1.boc")
    frozen = sdk_code()
    assert code.hash == frozen.hash, "V5R1 shared-engine extraction changed deployed code identity"
    results = {}
    allowed = []
    for mode in range(256):
        expected = 137 if not mode & 2 else 1811 if mode & 44 or mode & 192 == 192 else 0
        result = execute(code, lambda a, m=mode: actions(a, mode=m), expected)
        results[f"mode_{mode}"] = result
        if expected == 0:
            allowed.append(mode)
            assert result["messages"] == 1, (mode, result)
    assert allowed == [2, 3, 18, 19, 66, 67, 82, 83, 130, 131, 146, 147]
    for count in [0, 1, 254, 255, 256]:
        expected = 147 if count > 255 else 0
        result = execute(code, lambda a, n=count: actions(a, count=n), expected)
        if not expected:
            assert result["messages"] == count
        results[f"count_{count}"] = result
    malformed = {
        "setcode": (lambda a: Cell().uint(0xAD4DE08E, 32).ref(Cell()).ref(Cell()), 9),
        "reserve": (lambda a: Cell().uint(0x36E6B809, 32).uint(0, 8).ref(Cell()), 9),
        "tail_ref": (lambda a: Cell().ref(Cell()), 9),
        "extra_bits": (lambda a: Cell(bits=actions(a).bits + "0", refs=actions(a).refs), 147),
        "missing_message": (lambda a: Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()), 147),
    }
    for name, (payload, expected) in malformed.items():
        results[name] = execute(code, payload, expected)
    helper = ROOT / "crypto/smartcont/wallet-v5-action-list.fc"
    source = helper.read_text()
    mutations = [
        (
            "ignore_errors",
            "    throw_if(v5_action::external_requires_ignore_errors, is_external & (count_trailing_zeroes(cs.preload_bits(7)) > 0));",
            lambda a: actions(a, mode=0),
            137,
        ),
        (
            "action_cap",
            "  throw_unless(v5_action::invalid_c5, count <= 255);",
            lambda a: actions(a, count=256),
            147,
        ),
        (
            "unsafe_mode",
            "    throw_if(v5_action::bad_operation, (mode & 44) != 0); ;; bits 2, 3 and 5",
            lambda a: actions(a, mode=35),
            1811,
        ),
    ]
    killed = {}
    for name, guard, payload, expected in mutations:
        assert source.count(guard) == 1, name
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            for file in ["wallet-v5-code.fc", "auth-extension.fc"]:
                shutil.copy2(ROOT / "crypto/smartcont" / file, work / file)
            (work / helper.name).write_text(source.replace(guard, ""))
            mutant = compile_contract(
                str(work / "wallet-v5-code.fc"), args.output / f"mutant-{name}.boc"
            )
            try:
                execute(mutant, payload, expected)
            except AssertionError as error:
                assert f"expected exit {expected}, got 0" in str(error), (name, str(error))
                killed[name] = str(error)
            else:
                raise AssertionError(f"{name}: protection deletion survived")
    # Restore and exercise the guards again after mutation runs.
    for _, _, payload, expected in mutations:
        execute(code, payload, expected)
    report = {
        "scope": "V5R1 baseline and shared action engine only; not complete V5R2",
        "code_hash": code.hash.hex(),
        "sdk_code_unchanged": True,
        "allowed_strict_send_modes": allowed,
        "cases": len(results),
        "results": results,
        "mutations": killed,
        "source_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
    }
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()

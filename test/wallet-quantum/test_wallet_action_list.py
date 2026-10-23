"""Quantum action-path coverage plus separately labelled external-only helper coverage."""

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell  # noqa: E402
from test_receiver_auth import ACCOUNT, TARGET, request  # noqa: E402
from test_wallet import compile_fixture, run  # noqa: E402


def actions(count=1, mode=3):
    tail = Cell()
    message = native.internal(ACCOUNT, TARGET, Cell(), value=1_000_000_000)
    for _ in range(count):
        tail = Cell().uint(0x0EC3C86D, 32).uint(mode, 8).ref(tail).ref(message)
    return tail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    out = parser.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    results = {}
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        code, _, _, module, root, data = compile_fixture(out, work)

        def execute(code, action_list, expected):
            body = Cell().uint(0x45584543, 32).ref(action_list)
            return run(code, data, module, request(root=root, body=body), expected)

        allowed = []
        for mode in range(256):
            expected = 137 if not mode & 2 else 1811 if mode & 44 or mode & 192 == 192 else 0
            _, _, count = execute(code, actions(mode=mode), expected)
            if expected == 0:
                allowed.append(mode)
                assert count == 1, (mode, count)
            results[f"mode_{mode}"] = expected
        assert allowed == [2, 3, 18, 19, 66, 67, 82, 83, 130, 131, 146, 147]
        for count in [0, 1, 254, 255, 256]:
            expected = 147 if count > 255 else 0
            _, _, sent = execute(code, actions(count=count), expected)
            if not expected:
                assert sent == count, (count, sent)
            results[f"count_{count}"] = expected
        for label, malformed, expected in [
            ("setcode", Cell().uint(0xAD4DE08E, 32).ref(Cell()).ref(Cell()), 9),
            ("reserve", Cell().uint(0x36E6B809, 32).uint(0, 8).ref(Cell()), 9),
            ("tail_ref", Cell().ref(Cell()), 9),
            ("extra_bits", Cell(bits=actions().bits + "0", refs=actions().refs), 147),
            ("missing_message", Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()), 147),
        ]:
            execute(code, malformed, expected)
            results[label] = expected

        helper = work / "wallet-action-list.fc"
        source = helper.read_text()
        mutations = [
            (
                "ignore_errors",
                "    throw_if(wallet_action::external_requires_ignore_errors, is_external & (count_trailing_zeroes(cs.preload_bits(7)) > 0));",
                actions(mode=0),
                137,
            ),
            (
                "action_cap",
                "  throw_unless(wallet_action::invalid_c5, count <= 255);",
                actions(count=256),
                147,
            ),
            (
                "unsafe_mode",
                "    throw_if(wallet_action::bad_operation, (mode & 44) != 0); ;; bits 2, 3 and 5",
                actions(mode=35),
                1811,
            ),
        ]
        killed = {}
        for name, guard, action_list, expected in mutations:
            assert source.count(guard) == 1, name
            helper.write_text(source.replace(guard, ""))
            mutant = native.compile_contract(str(work / "driver.fc"), out / f"mutant-{name}.boc")
            try:
                execute(mutant, action_list, expected)
            except AssertionError as error:
                assert f"expected exit {expected}, got 0" in str(error), str(error)
                killed[name] = str(error)
            else:
                raise AssertionError(f"{name}: missing guard survived")
            finally:
                helper.write_text(source)
            execute(code, action_list, expected)

        # This caller tests helper branches, not a Quantum external-message path.
        fixture = work / "external-helper.fc"
        fixture.write_text(
            '#include "wallet-action-list.fc";\n() recv_internal(slice body) impure { set_c5_actions(verify_c5_actions(body~load_ref(), false)); }\n'
        )
        helper_code = native.compile_contract(str(fixture), out / "external-helper.boc")
        # The external restriction differs from internal helper validation.
        # Compile distinct entry points and exercise a funded action phase for both.
        helper_cases = {}
        for external in [False, True]:
            fixture.write_text(
                '#include "wallet-action-list.fc";\n() recv_internal(slice body) impure { set_c5_actions(verify_c5_actions(body~load_ref(), '
                + ("true" if external else "false")
                + ")); }\n"
            )
            helper_code = native.compile_contract(str(fixture), out / f"helper-{external}.boc")
            emulator = native.Emulator(16)
            try:
                shard = native.active_account(ACCOUNT, helper_code, Cell(), balance=10**15)
                response = emulator.send(
                    shard,
                    native.internal(
                        (0, 101), ACCOUNT, Cell().ref(actions(mode=0)), value=100_000_000_000
                    ),
                )
                assert response["success"], response
                expected = 137 if external else 0
                assert response["details"]["exit"] == expected, response["details"]
                helper_cases[str(external)] = expected
            finally:
                emulator.close()
        report = dict(
            scope="funded Quantum receiver with fixture module/vault; external-only cases are helper coverage",
            code_hash=code.hash.hex(),
            cases=len(results),
            results=results,
            mutations=killed,
            helper_cases=helper_cases,
            source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        )
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            f"{len(results)} Quantum action cases; {len(killed)} mutations; {len(helper_cases)} helper cases PASS"
        )


if __name__ == "__main__":
    main()

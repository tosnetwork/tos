"""The codec comparator rejects both-side wrong claims and damaged record populations."""

import copy
import re
import unittest

import gas_credit
import varuint_codec as codec

REPLAY_COMMANDS = (
    "cargo test --manifest-path tosctl/src/Cargo.toml --locked --release -p chain_block --lib native_varuint",
    'cmake --build build --target test-varuint-codec --parallel "$(nproc)"',
    "cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p chain_block --example varuint-codec",
    "python3 test/executor-parity/test_varuint_codec.py",
    "python3 test/executor-parity/varuint_codec.py --native build/emulator/test-varuint-codec --rust tosctl/src/target/release/examples/varuint-codec --output result/varuint-codec",
    "cmp result/storage-encoding.rejected.tsv tosctl/src/block/src/tests/data/storage_stat/storage-encoding-rejected.tsv",
    "cargo test --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_vm --test test_config",
    'cmake --build build --target test-vm-endstate --parallel "$(nproc)"',
    "cargo build --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_vm --example vm-endstate",
    "mkdir -p result/vm-varuint",
    "python3 test/rescue-fee-gate/vm_varuint_scenarios.py --write result/vm-varuint/inputs.tsv",
    "build/crypto/pq/test-vm-endstate result/vm-varuint/inputs.tsv > result/vm-varuint/native.tsv",
    "python3 test/rescue-fee-gate/vm_varuint_scenarios.py --check result/vm-varuint/native.tsv",
    "tosctl/src/target/release/examples/vm-endstate result/vm-varuint/inputs.tsv > result/vm-varuint/rust.tsv",
    "python3 test/rescue-fee-gate/vm_endstate_compare.py result/vm-varuint/native.tsv result/vm-varuint/rust.tsv",
    "cargo test --manifest-path tosctl/src/Cargo.toml --locked --release -p tos_executor --lib native_runtime_credit",
    "python3 test/executor-parity/gas_credit.py --native build/emulator/libemulator.so --rust tosctl/src/target/release/libtos_emulator.so --output result/gas-credit",
)
FINAL_COMMANDS = (
    tuple(
        f"cmp artifacts/epoch-replay-x86-64/varuint-codec/{name} artifacts/epoch-replay-arm64/varuint-codec/{name}"
        for name in ("inputs.tsv", "native.stdout", "rust.stdout")
    )
    + tuple(
        f"cmp artifacts/epoch-replay-x86-64/vm-varuint/{name} artifacts/epoch-replay-arm64/vm-varuint/{name}"
        for name in ("inputs.tsv", "native.tsv", "rust.tsv")
    )
    + tuple(
        f"cmp artifacts/epoch-replay-x86-64/gas-credit/{kind}/outcomes.json artifacts/epoch-replay-arm64/gas-credit/{kind}/outcomes.json"
        for kind in ("native", "rust")
    )
)


def workflow_contract(text):
    for arch in ("x86-64", "arm64"):
        assert re.search(r"(?m)^          - arch: " + re.escape(arch) + r"$", text)
    for name, required in (
        ("Preserve native transaction storage accounting and live caches", REPLAY_COMMANDS),
        ("Require both results and report the first differing field", FINAL_COMMANDS),
    ):
        blocks = re.split(r"(?m)(?=^      - )", text)
        selected = [block for block in blocks if block.startswith(f"      - name: {name}\n")]
        assert len(selected) == 1, "missing or duplicate codec step"
        block = selected[0]
        assert "        if:" not in block and "continue-on-error:" not in block
        assert "        run: |\n" in block
        script = block.split("        run: |\n", 1)[1]
        assert "set +e" not in script and "|| true" not in script
        commands = {line[10:] for line in script.splitlines() if line.startswith("          ")}
        assert set(required) <= commands, "missing executable codec obligation"


class VaruintComparatorTests(unittest.TestCase):
    def test_runtime_credit_report_controls(self):
        rows = []
        for name, _, _, _, expected in gas_credit.cases():
            row = dict(
                name=name,
                outcome=expected,
                inputs=dict(config="a" * 64, shard="b" * 64, message="c" * 64),
            )
            if expected == "accepted":
                row.update(transaction="d" * 64, account="e" * 64, shard_account="f" * 64)
            rows.append(row)
        gas_credit.compare_reports(rows, rows)
        for field in ("outcome", "transaction", "account", "shard_account", "inputs"):
            damaged = copy.deepcopy(rows)
            target = next(row for row in damaged if row["outcome"] == "accepted")
            if field == "inputs":
                target["inputs"]["config"] = "0" * 64
            else:
                target[field] = "encode-rejected" if field == "outcome" else "0" * 64
            with self.assertRaises(AssertionError):
                gas_credit.compare_reports(rows, damaged)
        for damaged in (rows[:-1], rows[::-1], rows + rows[:1]):
            with self.assertRaises(AssertionError):
                gas_credit.compare_reports(damaged, damaged)
        damaged = copy.deepcopy(rows)
        next(row for row in damaged if row["outcome"] == "accepted")["outcome"] = "encode-rejected"
        with self.assertRaises(AssertionError):
            gas_credit.compare_reports(damaged, damaged)

    def test_all_authored_types_and_boundaries(self):
        rows = codec.cases()
        self.assertEqual(len(rows), 330)
        self.assertEqual({row["n"] for row in rows}, {3, 7, 16, 32})
        good = codec.expected_output()
        codec.compare_outputs(good, good)
        for row in rows:
            if row["op"] == "write" and row["data"] == "-1":
                self.assertEqual(row["expected"][1:], ["0", "-", "-", "-"])

    def test_every_result_field_is_checked(self):
        good = codec.expected_output()
        rows = good.decode().splitlines()
        ordinal = next(i for i, line in enumerate(rows) if line.split("\t")[1] == "1")
        for field, replacement in enumerate(("wrong-name", "0", "999", "0" * 64, "0")):
            with self.subTest(field=field):
                damaged = list(rows)
                values = damaged[ordinal].split("\t")
                self.assertNotEqual(values[field], replacement)
                values[field] = replacement
                damaged[ordinal] = "\t".join(values)
                raw = ("\n".join(damaged) + "\n").encode()
                with self.assertRaisesRegex(AssertionError, "native/Rust"):
                    codec.compare_outputs(good, raw)
                with self.assertRaisesRegex(AssertionError, "authored"):
                    codec.compare_outputs(raw, raw)

    def test_population_order_and_line_integrity(self):
        good = codec.expected_output()
        rows = good.splitlines(keepends=True)
        for damaged in (
            b"".join(rows[1:]),
            good + rows[0],
            b"".join(reversed(rows)),
            good.rstrip(b"\n"),
            good.replace(b"\n", b"\r\n"),
        ):
            with self.assertRaises(AssertionError):
                codec.compare_outputs(good, damaged)

    def test_epoch_workflow_keeps_each_codec_obligation(self):
        text = (codec.ROOT / ".github/workflows/epoch-replay.yml").read_text()
        workflow_contract(text)
        for command in (*REPLAY_COMMANDS, *FINAL_COMMANDS):
            target = "          " + command + "\n"
            self.assertEqual(text.count(target), 1)
            with self.subTest(command=command), self.assertRaises(AssertionError):
                workflow_contract(text.replace(target, "          # " + command + "\n"))
        for arch in ("x86-64", "arm64"):
            with self.subTest(arch=arch), self.assertRaises(AssertionError):
                workflow_contract(text.replace(f"          - arch: {arch}\n", ""))

    def test_output_bound_precedes_parsing(self):
        with self.assertRaisesRegex(AssertionError, "byte limit"):
            codec.compare_outputs(b"x" * (codec.MAX_OUTPUT + 1), b"")


if __name__ == "__main__":
    unittest.main()

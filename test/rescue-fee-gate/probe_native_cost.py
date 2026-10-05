"""Cross-VM native cost floor; deliberately NOT a complete admission verifier.

Run with the normal rescue signer/compiler environment and two driver paths.
Only existing CDATASIZE and PQCHECKSIG_SUITE instructions are executed. No
registration, credit, tariff or signature-check bypass is introduced.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import test_rescue_e2e as loop
from probe_bounded_admission import header


def nodes(root):
    found = set()

    def visit(cell):
        if cell.hash in found:
            return
        found.add(cell.hash)
        for ref in cell.refs:
            visit(ref)

    visit(root)
    return found


def run_driver(path, scenarios):
    result = subprocess.run([str(path), str(scenarios)], capture_output=True, text=True, check=True)
    rows = {}
    for line in result.stdout.splitlines():
        name, exit_code, gas, value = line.split("\t")
        if name in rows:
            raise RuntimeError("duplicate driver row")
        rows[name] = tuple(map(int, (exit_code, gas, value)))
    return result.stdout, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    loop.RescueLoopTests.setUpClass()
    test = None
    try:
        test = loop.RescueLoopTests("test_rescue_lock_through_the_fee_vault")
        test.setUp()
        req = loop.request(loop.RESCUE, loop.K_LOCK, loop.Cell().uint(loop.LOCK, 32).uint(1, 8))
        slh = loop.slot.chain(test.sign.slh(loop.digest(req)))
        payload = loop.Cell().uint(loop.SUB1, 32).ref(req).ref(slh)
        intent = (
            loop.Cell()
            .uint(0x46454532, 32)
            .sint(loop.GLOBAL_ID, 32)
            .addr(loop.slot.VAULT)
            .uint(test.leaf, 32)
            .uint(loop.NOW + 600, 32)
            .coins(loop.slot.MAX_VALUE)
            .uint(1, 8)
            .ref(payload)
            .ref(header(test.fee.public))
        )
        fee_signature = test.fee.sign_at(test.leaf, intent.hash)
        body = loop.slot.body(intent, fee_signature)
        message = loop.slot.external(loop.slot.VAULT, body)
        key = loop.slot.chain(test.fee.public)
        count = len(nodes(message))
        test.assertEqual(count, 95)
        # Programs take pre-populated stacks. Their cost intentionally omits
        # all field parsing, identity checks, fee opcodes and state persistence.
        verify = "f93102"
        scan_drop = "f941303030"  # CDATASIZE; DROP DROP DROP
        scan_count = "f9413030"  # CDATASIZE; drop refs/bits, retain cell count
        verify_stack = [body.refs[1], body.refs[2], body.refs[3], key, 4]
        scenarios = []
        expected = {}

        def add(name, code, stack, exit_code, value, budget=30_000):
            def field(x):
                return f"int:{x}" if isinstance(x, int) else x.boc().hex()

            scenarios.append("\t".join([name, "16", str(budget), code, *map(field, stack)]))
            expected[name] = (exit_code, value)

        add("verify-valid", verify, verify_stack, 0, -1)
        corrupt = fee_signature[:-1] + bytes([fee_signature[-1] ^ 1])
        invalid_stack = [body.refs[1], body.refs[2], loop.slot.chain(corrupt), key, 4]
        invalid_body = (
            loop.Cell().ref(intent).ref(body.refs[1]).ref(body.refs[2]).ref(invalid_stack[2])
        )
        invalid_message = loop.slot.external(loop.slot.VAULT, invalid_body)
        add("verify-invalid", verify, invalid_stack, 0, 0)
        add("full-count", scan_count, [message, 128], 0, count)
        add("full-count-exact", scan_count, [message, count], 0, count)
        add("full-count-one-short", scan_count, [message, count - 1], 8, 99)
        add("scan-verify", scan_drop + verify, [*verify_stack, message, 128], 0, -1)
        add(
            "scan-verify-credit", scan_drop + verify, [*verify_stack, message, 128], -14, 99, 10_000
        )
        add("scan-verify-invalid", scan_drop + verify, [*invalid_stack, invalid_message, 128], 0, 0)
        add(
            "both-scans-verify",
            scan_drop * 2 + verify,
            [*verify_stack, payload, 72, message, 128],
            0,
            -1,
        )
        # Semantic failure controls: removing verification accepts the invalid
        # signature; removing scanning accepts an intentionally too-small bound.
        add("removed-verifier-accepts-invalid", "30303030307f", invalid_stack, 0, -1)
        add(
            "with-input-bound-rejects",
            scan_drop + verify,
            [*verify_stack, message, count - 1],
            8,
            99,
        )
        add(
            "removed-input-bound-accepts",
            "3030" + verify,
            [*verify_stack, message, count - 1],
            0,
            -1,
        )
        path = args.output / "native-cost-scenarios.tsv"
        path.write_text("\n".join(scenarios) + "\n")
        cpp_text, cpp = run_driver(args.cpp, path)
        rust_text, rust = run_driver(args.rust, path)
        (args.output / "native-cost-cpp.tsv").write_text(cpp_text)
        (args.output / "native-cost-rust.tsv").write_text(rust_text)
        test.assertEqual(set(cpp), set(expected))
        test.assertEqual(set(rust), set(expected))
        for name, (exit_code, value) in expected.items():
            for rows in (cpp, rust):
                test.assertEqual((rows[name][0], rows[name][2]), (exit_code, value), name)
        test.assertEqual(cpp, rust, "native operation exit/gas/value parity")

        # The transaction executors already use these host-side counters for
        # external import fees. Only successful, complete counts can be reused.
        def graph_bits(root):
            visited = set()

            def walk(cell):
                if cell.hash in visited:
                    return 0
                visited.add(cell.hash)
                return len(cell.bits) + sum(walk(ref) for ref in cell.refs)

            return walk(root)

        leaf = loop.Cell().uint(7, 8)
        shared = loop.Cell().uint(3, 8).ref(leaf).ref(leaf)
        inline = loop.Cell().uint(8, 4).addr(loop.slot.VAULT).coins(0).uint(0, 1).uint(0, 1)
        inline.bits += body.bits
        inline.refs.extend(body.refs)
        host_cases = {}
        for name, graph in {"external": message, "inline_body": inline, "shared": shared}.items():
            cells = len(nodes(graph)) - 1
            bits = graph_bits(graph) - len(graph.bits)
            for suffix, cell_limit, bit_limit, accepted in [
                ("exact", cells, bits, True),
                ("bits-short", cells, bits - 1, False),
                *([("cells-short", cells - 1, bits, False)] if cells > 1 else []),
            ]:
                values = []
                for driver in (args.cpp, args.rust):
                    value = json.loads(
                        subprocess.check_output(
                            [
                                str(driver),
                                "--storage",
                                graph.boc().hex(),
                                str(cell_limit),
                                str(bit_limit),
                            ],
                            text=True,
                        )
                    )
                    test.assertEqual(value["accepted"], accepted, (name, suffix, value))
                    if accepted:
                        test.assertEqual((value["cells"], value["bits"]), (cells, bits))
                    values.append(value)
                host_cases[f"{name}-{suffix}"] = {"cpp": values[0], "rust": values[1]}
        tariff = json.loads(
            subprocess.check_output([str(args.cpp), "--tariff", test.fee.public.hex()], text=True)
        )
        charged_compute = (
            tariff["base_gas"] + tariff["worst_compressions"] * tariff["per_compression_gas"]
        )
        signature_key_nodes = nodes(slh) | nodes(body.refs[3]) | nodes(key)
        signature_floor = len(signature_key_nodes) * tariff["cell_load_gas"] + charged_compute
        full_floor = len(nodes(message) | nodes(key)) * tariff["cell_load_gas"] + charged_compute
        test.assertGreater(signature_floor, 10_000)
        test.assertGreaterEqual(cpp["scan-verify"][1], full_floor)
        receipt = {
            "scope": "native scan plus HSS only; not an admission implementation or hardware benchmark",
            "global_version": 16,
            "external_credit": 10_000,
            "cross_vm_scenarios": len(cpp),
            "exact_exit_gas_value_parity": True,
            "host_import_counter_cases": host_cases,
            "tariff": tariff,
            "verification_compute_charge": charged_compute,
            "signature_and_key_distinct_cells": len(signature_key_nodes),
            "signature_and_key_cold_load_floor": signature_floor,
            "full_message_and_key_distinct_cells": len(nodes(message) | nodes(key)),
            "full_graph_cold_load_floor": full_floor,
            "rows": {
                name: {"exit": row[0], "gas": row[1], "value": row[2]} for name, row in cpp.items()
            },
            "source_hashes": {
                str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in [
                    Path(__file__),
                    loop.slot.ROOT / "test/rescue-fee-gate/native-cost.cpp",
                    loop.slot.ROOT / "tosctl/src/vm/examples/fee-native-cost.rs",
                    loop.slot.ROOT / "crypto/vm/pqops.h",
                    loop.slot.ROOT / "crypto/pq/lms-fee.cpp",
                    loop.slot.ROOT / "tosctl/src/block/src/accounts.rs",
                ]
            },
            "artifact_hashes": {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in [
                    path,
                    args.output / "native-cost-cpp.tsv",
                    args.output / "native-cost-rust.tsv",
                ]
            },
        }
        print(json.dumps(receipt, indent=2))
    finally:
        if test is not None:
            test.doCleanups()
        loop.RescueLoopTests.tearDownClass()


if __name__ == "__main__":
    main()

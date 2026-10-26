"""Sensitivity controls using actual Rust outputs, never generated positive roots."""

import argparse
import hashlib
import json
import platform
import tempfile
from pathlib import Path

import compare_rust as compare


def main():
    parser = argparse.ArgumentParser(
        description="Mutate actual replay artifacts to prove strict verification."
    )
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).parent / "corpus/manifest.json"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest_path = args.manifest
    architecture = platform.machine()
    other_architecture = {"x86_64": "aarch64", "aarch64": "x86_64"}[architecture]
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    receipt_path = args.receipt
    receipt = json.loads(receipt_path.read_bytes())
    actual = receipt_path.with_suffix(".roots.tsv").read_bytes()
    validation = (manifest, hashlib.sha256(manifest_bytes).hexdigest(), receipt["topology_sha256"])
    compare.check_artifact(receipt_path, architecture, *validation)
    results = [dict(control="actual-artifact", result="accepted")]
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / "receipt.json"
        roots_path = path.with_suffix(".roots.tsv")

        def reject(name, metadata, data, architecture, reason):
            path.write_text(json.dumps(metadata))
            roots_path.write_bytes(data)
            try:
                compare.check_artifact(path, architecture, *validation)
            except ValueError as e:
                assert reason in str(e), (name, e)
                results.append(dict(control=name, result="rejected", reason=str(e)))
            else:
                raise AssertionError(name + " accepted")

        reject(
            "wrong-architecture",
            receipt,
            actual,
            other_architecture,
            "receipt architecture differs",
        )
        wrong = dict(receipt, transactions=575)
        reject("false-total", wrong, actual, architecture, "receipt transactions differs")
        wrong = dict(receipt, manifest_sha256="0" * 64)
        reject("different-manifest", wrong, actual, architecture, "manifest_sha256 differs")
        lines = actual.decode().splitlines()
        row = lines[0].split("\t")
        row[6] = "0" * 64
        lines[0] = "\t".join(row)
        changed = ("\n".join(lines) + "\n").encode()
        reject("roots-digest-mismatch", receipt, changed, architecture, "output digest differs")
        wrong = dict(receipt, rust_output_sha256=hashlib.sha256(changed).hexdigest())
        reject(
            "forged-equal-with-rehashed-wrong-root",
            wrong,
            changed,
            architecture,
            "differs from complete parity",
        )
        missing = ("\n".join(actual.decode().splitlines()[:-1]) + "\n").encode()
        wrong = dict(receipt, rust_output_sha256=hashlib.sha256(missing).hexdigest())
        reject(
            "missing-row-with-rehashed-output",
            wrong,
            missing,
            architecture,
            "missing/extra Rust output rows",
        )
        # The chain pins Account and transaction roots. A same-width changed
        # ShardAccount root must additionally fail the cross-output comparison.
        shard_lines = actual.decode().splitlines()
        shard_row = shard_lines[0].split("\t")
        shard_row[8] = "0" * 64
        shard_lines[0] = "\t".join(shard_row)
        changed_shard = ("\n".join(shard_lines) + "\n").encode()
        changed_receipt = dict(
            receipt, rust_output_sha256=hashlib.sha256(changed_shard).hexdigest()
        )
        path.write_text(json.dumps(changed_receipt))
        roots_path.write_bytes(changed_shard)
        modified = compare.check_artifact(path, architecture, *validation)
        original = compare.check_artifact(receipt_path, architecture, *validation)
        try:
            compare.compare_results(original, modified)
        except ValueError as error:
            assert "cross-architecture rust_output_sha256 differs" in str(error)
            results.append(
                dict(
                    control="changed-ShardAccount-comparison", result="rejected", reason=str(error)
                )
            )
        else:
            raise AssertionError("changed ShardAccount accepted by comparison")
    with args.output.open("x") as output:
        output.write(json.dumps(results, indent=2) + "\n")
    print(f"PASS: real {architecture} roots accepted; seven artifact mutations rejected")


if __name__ == "__main__":
    main()

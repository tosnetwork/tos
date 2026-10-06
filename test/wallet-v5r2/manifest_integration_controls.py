"""Show compiled-code manifest rejection checks detect a bypass in the fixture adapter."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads(args.fixture.read_text())
    source = ROOT / "tosctl/src/node-control/contracts/examples/v5r2_genesis_encode.rs"
    original = source.read_text()
    anchor = "&encoded, code()?, bytes(expected)?"
    assert original.count(anchor) == 1

    def build(label):
        result = subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--example",
                "v5r2_genesis_encode",
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        (args.output / f"{label}-build.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stderr[-3000:]

    def check(label, mutated=False):
        payload = fixture["input"]
        result = subprocess.run(
            [str(args.driver.resolve())],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        response = json.loads(result.stdout)
        for field in ("wallet_init", "module_init", "vault_init", "config_hash"):
            assert response[field] == fixture["output"][field], field
        manifest = json.loads(response["recovery_manifest"])
        records = {}
        for field in ("wallet_state_init", "module_state_init", "vault_state_init", "wallet_code"):
            changed = dict(manifest)
            changed[field] = "ff" * 32
            altered = dict(payload, recovery_manifest=json.dumps(changed))
            result = subprocess.run(
                [str(args.driver.resolve())],
                input=json.dumps(altered),
                capture_output=True,
                text=True,
                timeout=60,
            )
            records[field] = {"exit": result.returncode, "stderr": result.stderr}
            if mutated:
                assert result.returncode == 0, "bypass did not exercise manifest acceptance"
            else:
                assert result.returncode != 0 and "manifest" in result.stderr, (
                    "adapter accepted tampered manifest",
                    field,
                )
        (args.output / f"{label}.json").write_text(json.dumps(records, indent=2) + "\n")
        return records

    try:
        build("baseline")
        check("baseline")
        source.write_text(
            original.replace(anchor, "&prepared.to_json()?, code()?, bytes(expected)?")
        )
        build("bypass")
        try:
            check("bypass-must-fail")
        except AssertionError as error:
            assert "adapter accepted tampered manifest" in str(error), str(error)
            (args.output / "failure-witness.txt").write_text(str(error) + "\n")
        else:
            raise AssertionError("manifest adapter bypass escaped detection")
        check("bypass-accepted-inputs", mutated=True)
    finally:
        source.write_text(original)
        build("restored")
        check("restored")
    print("Manifest adapter bypass detected; restored compiled-code reconstruction passes")


if __name__ == "__main__":
    main()

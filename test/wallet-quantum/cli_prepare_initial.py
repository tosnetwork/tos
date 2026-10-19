"""Verify real CLI public initial bundles against SDK fixtures and refusal before writes."""

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads(args.fixture.read_text())["input"]
    for field in ("recovery_derivation", "recovery_manifest", "expected_wallet", "existing_wallet"):
        fixture.pop(field, None)
    enrollment = {
        key: fixture[key]
        for key in (
            "global_id",
            "network",
            "wallet_id",
            "primary_key",
            "rescue_key",
            "fee_tree_id",
            "fee_public_key",
        )
    }
    enrollment.update(
        fee_epoch0=fixture["epoch0"],
        policy="RESCUE_READY",
        derivation=dict(
            account_index=5,
            key_generation=7,
            primary_seed_profile="raw-master-32-v1",
            rescue_seed_profile="raw-master-32-v1",
            fee_seed_profile="raw-master-32-v1",
        ),
    )
    results = {}
    with tempfile.TemporaryDirectory(prefix="pq-prepare-initial-") as temporary:
        directory = Path(temporary)
        inputs = directory / "enrollment.json"
        common = ["--enrollment-file", str(inputs)]
        for role in ("wallet", "module", "vault"):
            code = directory / (role + ".boc")
            code.write_bytes(bytes.fromhex(fixture[role + "_code"]))
            common += [f"--{role}-code", str(code), f"--{role}-code-hash", fixture[role + "_pin"]]

        def run(label, value, output, success, command=None):
            inputs.write_text(json.dumps(value))
            result = subprocess.run(
                [
                    str(args.cli.resolve()),
                    "wallet",
                    "pq-prepare-initial",
                    *(common if command is None else command),
                    "--output-dir",
                    str(output),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            (args.output / f"{label}.stdout").write_text(result.stdout)
            (args.output / f"{label}.stderr").write_text(result.stderr)
            assert (result.returncode == 0) == success, (
                "CLI preparation outcome",
                label,
                result.stderr,
            )
            results[label] = {"exit": result.returncode, "expected_success": success}
            return result

        for policy, number in (("RESCUE_READY", 1), ("SLH_REQUIRED", 2)):
            enrollment["policy"] = policy
            output = directory / policy
            result = run(policy, enrollment, output, True)
            report = json.loads(result.stdout)
            assert report["status"] == "initial_wallet_prepared" and report["workchain"] == 0
            data = dict(fixture, policy=number)
            expected = subprocess.run(
                [str(args.genesis_driver.resolve())],
                input=json.dumps(data),
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert expected.returncode == 0, expected.stderr
            expected = json.loads(expected.stdout)
            manifest = json.loads((output / "recovery-manifest.json").read_text())
            assert manifest["policy"] == policy, "CLI prepared wrong rescue policy"
            for role in ("wallet", "module", "vault"):
                assert (output / f"{role}-state-init.boc").read_bytes().hex() == expected[
                    role + "_init"
                ], "CLI prepared different StateInit"
                assert report[role] == manifest[role + "_state_init"]
            assert report["fee_config_hash"] == expected["config_hash"]
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            run(policy + "-duplicate", enrollment, output, False)
            assert before == {p.name: p.read_bytes() for p in output.iterdir()}, (
                "CLI changed existing bundle"
            )
        for field, value in (
            ("policy", "ED25519"),
            ("primary_key", "00"),
            ("secret_seed", "forbidden"),
        ):
            changed = copy.deepcopy(enrollment)
            changed[field] = value
            output = directory / ("invalid-" + field)
            run("invalid-" + field, changed, output, False)
            assert not output.exists(), "invalid enrollment wrote output directory"
        output = directory / "wrong-pin"
        changed = common.copy()
        changed[changed.index("--wallet-code-hash") + 1] = "ff" * 32
        run("wrong-pin", enrollment, output, False, changed)
        assert not output.exists(), "wrong code pin wrote output directory"
        partial = directory / "partial"
        partial.mkdir()
        (partial / "marker").write_text("preserve")
        run("partial", enrollment, partial, False)
        assert [p.name for p in partial.iterdir()] == ["marker"]
        assert (partial / "marker").read_text() == "preserve"
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} initial preparation CLI outcomes passed")


if __name__ == "__main__":
    main()

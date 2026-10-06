"""Exercise initial-manifest recovery through the actual CLI with public mnemonic fixtures."""

import argparse
import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    vectors = json.loads(
        (ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json").read_text()
    )
    vector = vectors["vectors"][1]
    payload = json.loads(args.fixture.read_text())["input"]
    for field in ("recovery_derivation", "recovery_manifest", "expected_wallet", "existing_wallet"):
        payload.pop(field, None)
    payload["network"] = vectors["context"]["network_hex"]
    results = {}

    def driver(data):
        result = subprocess.run(
            [str(args.genesis_driver.resolve())],
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    def replace(cmd, flag, value):
        cmd = cmd.copy()
        cmd[cmd.index(flag) + 1] = str(value)
        return cmd

    with tempfile.TemporaryDirectory(prefix="pq-initial-recovery-") as temporary:
        directory = Path(temporary)

        def protected(name, data):
            path = directory / name
            path.write_bytes(data)
            path.chmod(0o600)
            return str(path)

        subprocess.run(
            [
                os.environ["MLDSA_TOOL"],
                "keygen",
                vector["derived"]["ML-DSA-44"],
                str(directory / "primary.pub"),
                str(directory / "public-fixture.secret"),
            ],
            check=True,
            capture_output=True,
        )
        payload["primary_key"] = (directory / "primary.pub").read_bytes().hex()
        payload["rescue_key"] = subprocess.check_output(
            [os.environ["SLH_TOOL"], "keygen", vector["derived"]["SLH-DSA-SHA2-128s"]], text=True
        ).split()[0]
        basic = driver(payload)
        # Derive the expected identity outside the supplied recovery manifest.
        import sys

        sys.path.insert(0, str(ROOT / "test/auth-extensions"))
        from cells import from_boc

        payload["expected_wallet"] = from_boc(bytes.fromhex(basic["wallet_init"])).hash.hex()
        payload["recovery_derivation"] = dict(
            account_index=5,
            key_generation=7,
            primary_seed_profile="tos-native-mnemonic-v1",
            rescue_seed_profile="tos-native-mnemonic-v1",
            fee_seed_profile="raw-master-32-v1",
        )
        output = driver(payload)
        manifest = json.loads(output["recovery_manifest"])
        common = [
            "--network-tag",
            payload["network"],
            "--global-id",
            "42",
            "--account-index",
            "5",
            "--key-generation",
            "7",
            "--expected-wallet",
            payload["expected_wallet"],
            "--record-id",
            "initial.key",
            "--mnemonic-file",
            protected("words", vector["phrase"].encode()),
            "--password-file",
            protected("password", vector["password"].encode()),
            "--vault-key-file",
            protected("encryption", b"77" * 32),
        ]
        for role in ("wallet", "module", "vault"):
            common += [
                f"--{role}-code",
                protected(role + ".boc", bytes.fromhex(payload[role + "_code"])),
                f"--{role}-code-hash",
                payload[role + "_pin"],
            ]
        for role in ("primary", "rescue"):
            vault = directory / (role + ".json")
            manifest_path = directory / (role + "-manifest.json")
            manifest_path.write_text(json.dumps(manifest))
            cmd = common + [
                "--role",
                role,
                "--expected-public-key",
                payload[role + "_key"],
                "--vault-file",
                str(vault),
                "--recovery-manifest",
                str(manifest_path),
            ]

            def run(label, command, success, witness=None):
                result = subprocess.run(
                    [str(args.cli.resolve()), "wallet", "pq-restore-initial", *command],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                (args.output / f"{role}-{label}.stdout").write_text(result.stdout)
                (args.output / f"{role}-{label}.stderr").write_text(result.stderr)
                assert (result.returncode == 0) == success, (
                    "CLI initial recovery outcome",
                    label,
                    result.stderr,
                )
                if witness:
                    assert witness in result.stderr, (
                        "CLI initial recovery lost preflight",
                        label,
                        result.stderr,
                    )
                results[f"{role}-{label}"] = {
                    "exit": result.returncode,
                    "expected_success": success,
                }
                return result

            for field in ("account_index", "key_generation", role + "_seed_profile"):
                changed = copy.deepcopy(manifest)
                changed["derivation"][field] = (
                    "raw-master-32-v1" if field.endswith("profile") else 0
                )
                manifest_path.write_text(json.dumps(changed))
                run(
                    field,
                    cmd,
                    False,
                    "recovery input profile mismatch"
                    if field.endswith("profile")
                    else "recovered key differs",
                )
                assert not vault.exists() and not Path(str(vault) + ".lock").exists(), (
                    "manifest mismatch opened custody"
                )
            manifest_path.write_text(json.dumps(manifest))
            absent = replace(cmd, "--mnemonic-file", directory / "absent-secret")
            run(
                "trusted-wallet",
                replace(absent, "--expected-wallet", "ff" * 32),
                False,
                "trusted enrollment",
            )
            run("code-pin", replace(absent, "--wallet-code-hash", "ff" * 32), False, "code")
            manifest_path.write_bytes(b" " * (16 * 1024 + 1))
            run("manifest-size", absent, False, "public recovery input size limit")
            manifest_path.write_text(json.dumps(manifest))
            oversized = protected("oversized-code", b"x" * (256 * 1024 + 1))
            run(
                "code-size",
                replace(absent, "--wallet-code", oversized),
                False,
                "public recovery input size limit",
            )
            assert not vault.exists() and not Path(str(vault) + ".lock").exists(), (
                "invalid public inputs opened custody"
            )
            result = run("restore", cmd, True)
            report = json.loads(result.stdout)
            assert (
                report["public_key"] == payload[role + "_key"]
                and report["status"] == "key_record_restored"
            )
            assert vector["phrase"] not in result.stdout + result.stderr
            before = vault.read_bytes()
            run("duplicate", cmd, False)
            assert vault.read_bytes() == before, "duplicate changed initial custody"
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} initial-manifest CLI outcomes passed")


if __name__ == "__main__":
    main()

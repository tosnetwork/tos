"""Exercise the real PQ restore CLI using public mnemonic fixtures and temporary encrypted Vaults."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=["all", "preflight", "password", "inputs"], default="all")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = json.loads(
        (ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json").read_text()
    )
    results = {}

    def protected(path, data):
        path.write_bytes(data)
        path.chmod(0o600)
        return str(path)

    def run(label, command, expected, witness, pass_fds=()):
        result = subprocess.run(
            [str(args.cli.resolve()), "wallet", "pq-restore-key", *command],
            capture_output=True,
            text=True,
            timeout=180,
            pass_fds=pass_fds,
        )
        (args.output / f"{label}.stdout").write_text(result.stdout)
        (args.output / f"{label}.stderr").write_text(result.stderr)
        assert (result.returncode == 0) == expected, (
            witness,
            result.returncode,
            result.stderr[-2000:],
        )
        results[label] = {"exit": result.returncode, "expected_success": expected}
        return result

    def replace(command, flag, value):
        command = command.copy()
        command[command.index(flag) + 1] = str(value)
        return command

    for index, vector in enumerate(fixtures["vectors"]):
        for role, label in [("primary", "ML-DSA-44"), ("rescue", "SLH-DSA-SHA2-128s")]:
            if args.case in ("preflight", "inputs") and (index, role) != (0, "primary"):
                continue
            if args.case == "password" and (index, role) != (1, "rescue"):
                continue
            name = f"{index}-{role}"
            directory = args.output / name
            directory.mkdir()
            seed = vector["derived"][label]
            if role == "primary":
                subprocess.run(
                    [
                        os.environ["MLDSA_TOOL"],
                        "keygen",
                        seed,
                        str(directory / "public.bin"),
                        str(directory / "public-test-secret.bin"),
                    ],
                    check=True,
                    capture_output=True,
                )
                key = (directory / "public.bin").read_bytes().hex()
            else:
                key = subprocess.check_output(
                    [os.environ["SLH_TOOL"], "keygen", seed], text=True
                ).split()[0]
            vault = directory / "vault.json"
            command = [
                "--vault-file",
                str(vault),
                "--record-id",
                "pq.restored",
                "--role",
                role,
                "--expected-public-key",
                key,
                "--network-tag",
                fixtures["context"]["network_hex"],
                "--global-id",
                "42",
                "--account-index",
                "5",
                "--key-generation",
                "7",
                "--mnemonic-file",
                protected(directory / "mnemonic", vector["phrase"].encode()),
                "--password-file",
                protected(directory / "password", vector["password"].encode()),
                "--vault-key-file",
                protected(directory / "encryption-key", b"77" * 32),
            ]
            if args.case in ("all", "inputs") and (index, role) == (0, "primary"):
                absent = replace(command, "--mnemonic-file", directory / "absent-secret")
                invalids = [
                    (
                        "record-id",
                        replace(absent, "--record-id", ""),
                        "record ID must not be empty",
                    ),
                    (
                        "key-width",
                        replace(absent, "--expected-public-key", key[:-2]),
                        "wrong public-key width",
                    ),
                    (
                        "network-width",
                        replace(absent, "--network-tag", "01"),
                        "network tag must be 32 bytes",
                    ),
                ]
                duplicate_fd = command.copy()
                for flag in ("--mnemonic-file", "--password-file"):
                    at = duplicate_fd.index(flag)
                    del duplicate_fd[at : at + 2]
                duplicate_fd += ["--mnemonic-fd", "1", "--password-fd", "1"]
                invalids.append(
                    (
                        "duplicate-fd",
                        duplicate_fd,
                        "secret inputs require distinct file descriptors",
                    )
                )
                for invalid_name, invalid, expected_error in invalids:
                    failure = run(invalid_name, invalid, False, "CLI accepted invalid public input")
                    assert expected_error in failure.stderr, f"CLI lost {invalid_name} preflight"
                    assert not vault.exists() and not Path(str(vault) + ".lock").exists()
                if args.case == "inputs":
                    continue
            if args.case != "password":
                wrong_key = bytes([bytes.fromhex(key)[0] ^ 1]) + bytes.fromhex(key)[1:]
                run(
                    f"{name}-wrong-key",
                    replace(command, "--expected-public-key", wrong_key.hex()),
                    False,
                    "CLI accepted wrong enrolled key",
                )
                assert not vault.exists() and not Path(str(vault) + ".lock").exists(), (
                    "CLI opened custody before enrollment validation"
                )
                if args.case == "preflight":
                    continue
            result = run(
                f"{name}-restore", command, True, "CLI rejected valid exact-password recovery"
            )
            output = json.loads(result.stdout)
            assert output["status"] == "key_record_restored" and output["public_key"] == key
            assert vector["phrase"] not in result.stdout + result.stderr, "CLI disclosed mnemonic"
            ciphertext = vault.read_bytes()
            assert vector["phrase"].encode() not in ciphertext and seed.encode() not in ciphertext
            assert vault.stat().st_mode & 0o777 == 0o600
            if args.case == "password":
                continue
            run(f"{name}-duplicate", command, False, "CLI overwrote existing record")
            assert vault.read_bytes() == ciphertext, "duplicate restore changed Vault"
            wrong_master = protected(directory / "wrong-encryption-key", b"88" * 32)
            run(
                f"{name}-wrong-encryption-key",
                replace(command, "--vault-key-file", wrong_master),
                False,
                "CLI accepted wrong Vault encryption key",
            )
            assert vault.read_bytes() == ciphertext
            invalid = replace(command, "--role", "ed25519")
            run(f"{name}-classical-role", invalid, False, "CLI accepted classical role")
            (directory / "mnemonic").chmod(0o644)
            new_vault = directory / "unsafe-input.json"
            run(
                f"{name}-unsafe-file",
                replace(command, "--vault-file", new_vault),
                False,
                "CLI accepted exposed mnemonic file",
            )
            assert not new_vault.exists() and not Path(str(new_vault) + ".lock").exists()
            (directory / "mnemonic").chmod(0o600)
            if (index, role) == (0, "primary"):
                with (directory / "mnemonic").open("rb") as mnemonic:
                    via_fd = replace(command, "--vault-file", directory / "fd-vault.json")
                    position = via_fd.index("--mnemonic-file")
                    via_fd[position : position + 2] = ["--mnemonic-fd", str(mnemonic.fileno())]
                    run(
                        "inherited-fd",
                        via_fd,
                        True,
                        "CLI refused protected inherited FD",
                        (mnemonic.fileno(),),
                    )
    assert results, "CLI harness ran no cases"
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} actual CLI restore outcomes verified ({args.case})")


if __name__ == "__main__":
    main()

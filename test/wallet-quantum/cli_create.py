"""Exercise PQ key creation and recovery using disposable unfunded custody only."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=["all", "backup", "duplicate"], default="all")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}

    def run(name, action, command, success):
        result = subprocess.run(
            [str(args.cli.resolve()), "wallet", action, *command],
            capture_output=True,
            text=True,
            timeout=180,
        )
        (args.output / f"{name}.stdout").write_text(result.stdout)
        (args.output / f"{name}.stderr").write_text(result.stderr)
        assert (result.returncode == 0) == success, (
            f"CLI creation outcome {name}",
            result.stderr[-2000:],
        )
        results[name] = {"exit": result.returncode, "expected_success": success}
        return result

    def replace(command, flag, value):
        command = command.copy()
        command[command.index(flag) + 1] = str(value)
        return command

    with tempfile.TemporaryDirectory(prefix="pq-create-test-") as name:
        root = Path(name)
        encryption = root / "encryption-key"
        encryption.write_bytes(b"77" * 32)
        encryption.chmod(0o600)
        for role in ("primary", "rescue"):
            if args.case != "all" and role != "primary":
                continue
            directory = root / role
            directory.mkdir()
            vault, backup = directory / "vault.json", directory / "mnemonic"
            command = [
                "--vault-file",
                str(vault),
                "--record-id",
                "pq.new",
                "--role",
                role,
                "--mnemonic-backup-file",
                str(backup),
                "--network-tag",
                "01" * 32,
                "--global-id",
                "42",
                "--account-index",
                "5",
                "--key-generation",
                "7",
                "--vault-key-file",
                str(encryption),
            ]
            if args.case in ("all", "backup"):
                sentinel = b"existing backup must survive"
                backup.write_bytes(sentinel)
                backup.chmod(0o600)
                run(f"{role}-existing-backup", "pq-create-key", command, False)
                assert backup.read_bytes() == sentinel, "CLI overwrote recovery backup"
                assert not vault.exists(), "CLI persisted key despite failed backup"
                backup.unlink()
                if args.case == "backup":
                    continue
            created = run(f"{role}-create", "pq-create-key", command, True)
            output = json.loads(created.stdout)
            assert output["status"] == "key_record_created"
            words = backup.read_bytes()
            assert len(words.split()) == 24, "new PQ key did not use 24 words"
            assert backup.stat().st_mode & 0o777 == 0o600
            assert words.decode() not in created.stdout + created.stderr, (
                "creation disclosed mnemonic"
            )
            assert words not in vault.read_bytes(), "Vault contains plaintext mnemonic"
            original_vault = vault.read_bytes()
            duplicate_backup = directory / "duplicate-mnemonic"
            run(
                f"{role}-duplicate",
                "pq-create-key",
                replace(command, "--mnemonic-backup-file", duplicate_backup),
                False,
            )
            assert not duplicate_backup.exists(), "duplicate creation generated a new backup"
            assert vault.read_bytes() == original_vault and backup.read_bytes() == words
            if args.case == "duplicate":
                continue
            restore = [
                "--vault-file",
                str(directory / "recovered.json"),
                "--record-id",
                "pq.recovered",
                "--role",
                role,
                "--expected-public-key",
                output["public_key"],
                "--network-tag",
                "01" * 32,
                "--global-id",
                "42",
                "--account-index",
                "5",
                "--key-generation",
                "7",
                "--mnemonic-file",
                str(backup),
                "--vault-key-file",
                str(encryption),
            ]
            recovered = run(f"{role}-recover-backup", "pq-restore-key", restore, True)
            assert json.loads(recovered.stdout)["public_key"] == output["public_key"]
            assert words.decode() not in recovered.stdout + recovered.stderr
    assert results
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(
        f"{len(results)} actual CLI creation outcomes verified ({args.case}); ephemeral secrets removed"
    )


if __name__ == "__main__":
    main()

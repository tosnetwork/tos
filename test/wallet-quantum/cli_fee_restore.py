"""Exercise fee recovery through the actual CLI with public native mnemonic data."""

import argparse
import copy
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cli", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--public-tree", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--skip-rebuild", action="store_true")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads(
        (ROOT / "tosctl/src/wallet-pq-signer/tests/fixtures/native-fee-recovery.json").read_text()
    )
    payload = json.loads(args.fixture.read_text())["input"]
    results = {}
    cli = str(args.cli.resolve())
    with tempfile.TemporaryDirectory(prefix="fee-cli-public-test-") as temp:
        directory = Path(temp)

        def protected(name, data):
            path = directory / name
            path.write_bytes(data)
            path.chmod(0o600)
            return str(path)

        code = []
        for name in ("wallet", "module", "vault"):
            code += [
                f"--{name}-code",
                protected(name + ".boc", bytes.fromhex(payload[name + "_code"])),
                f"--{name}-code-hash",
                payload[name + "_pin"],
            ]
        enrollment = {k: payload[k] for k in ("wallet_id", "primary_key", "rescue_key")}
        enrollment.update(
            global_id=42,
            network="01" * 32,
            policy="SLH_REQUIRED",
            fee_tree_id=fixture["tree_id_hex"],
            fee_public_key=fixture["public_key_hex"],
            fee_epoch0=1000,
            derivation=dict(
                account_index=5,
                key_generation=7,
                primary_seed_profile="raw-master-32-v1",
                rescue_seed_profile="raw-master-32-v1",
                fee_seed_profile="tos-native-mnemonic-v1",
            ),
        )
        enrolled = protected("enrollment.json", json.dumps(enrollment).encode())
        prepared = directory / "prepared"
        result = subprocess.run(
            [
                cli,
                "wallet",
                "pq-prepare-initial",
                "--enrollment-file",
                enrolled,
                "--output-dir",
                str(prepared),
                *code,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        wallet = json.loads(result.stdout)["wallet"]
        manifest = json.loads((prepared / "recovery-manifest.json").read_text())
        manifest_path = Path(protected("manifest.json", json.dumps(manifest).encode()))
        cache = directory / "public-tree.cache"
        with cache.open("wb") as out:
            out.write(b"TOSFT001" + bytes.fromhex(fixture["public_key_hex"]))
            with args.public_tree.open("rb") as tree:
                import shutil

                shutil.copyfileobj(tree, out)
        base = [
            cli,
            "wallet",
            "pq-restore-fee-initial",
            *code,
            "--expected-wallet",
            wallet,
            "--recovery-manifest",
            str(manifest_path),
            "--record-id",
            "fee.initial",
            "--fee-tree-cache",
            str(cache),
            "--mnemonic-file",
            protected("words", fixture["phrase"].encode()),
            "--password-file",
            protected("password", fixture["password"].encode()),
            "--vault-key-file",
            protected("vault-key", b"77" * 32),
        ]

        def replace(command, flag, value):
            command = command.copy()
            command[command.index(flag) + 1] = str(value)
            return command

        def run(name, command, success, vault=None, witness=None):
            if vault is None:
                vault = directory / (name + ".vault")
            command = command + ["--vault-file", str(vault)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            (args.output / (name + ".stdout")).write_text(result.stdout)
            (args.output / (name + ".stderr")).write_text(result.stderr)
            assert (result.returncode == 0) == success, (
                f"{name}: unexpected CLI status: {result.stderr}"
            )
            if witness:
                assert witness in result.stderr, (name, result.stderr)
            if success:
                status = json.loads(result.stdout)
                assert status["status"] == "fee_key_record_restored"
                assert status["public_key"] == fixture["public_key_hex"]
                assert status["initial_wallet"] == wallet
            elif name != "duplicate":
                assert not vault.exists(), f"{name}: rejected recovery created Vault"
                assert not Path(str(vault) + ".lock").exists(), (
                    f"{name}: rejected recovery opened custody"
                )
            results[name] = {"exit": result.returncode, "expected_success": success}
            return vault

        run(
            "wrong-wallet",
            replace(base, "--expected-wallet", "ff" * 32),
            False,
            None,
            "manifest wallet differs",
        )
        run("wrong-code", replace(base, "--wallet-code-hash", "ff" * 32), False)
        for field, value in [
            ("account_index", 6),
            ("key_generation", 8),
            ("fee_seed_profile", "raw-master-32-v1"),
        ]:
            changed = copy.deepcopy(manifest)
            changed["derivation"][field] = value
            manifest_path.write_text(json.dumps(changed))
            run("metadata-" + field, base, False)
        manifest_path.write_text(json.dumps(manifest))
        run(
            "wrong-password",
            replace(
                base, "--password-file", protected("trimmed", fixture["password"].strip().encode())
            ),
            False,
        )
        run(
            "bad-mnemonic",
            replace(base, "--mnemonic-file", protected("bad-words", b"bad words")),
            False,
        )
        duplicate_fd = base.copy()
        for flag in ("--mnemonic-file", "--password-file"):
            at = duplicate_fd.index(flag)
            del duplicate_fd[at : at + 2]
        duplicate_fd += ["--mnemonic-fd", "1", "--password-fd", "1"]
        run(
            "duplicate-fd",
            duplicate_fd,
            False,
            witness="secret inputs require distinct file descriptors",
        )
        unsafe_words = Path(protected("unsafe-words", fixture["phrase"].encode()))
        unsafe_words.chmod(0o644)
        run("unsafe-mnemonic", replace(base, "--mnemonic-file", unsafe_words), False)
        with cache.open("r+b") as f:
            f.seek(68 + (1 << 20) * 32)
            original_byte = f.read(1)
            f.seek(68 + (1 << 20) * 32)
            f.write(bytes([original_byte[0] ^ 1]))
        run("bad-cache", base, False)
        with args.public_tree.open("rb") as original:
            original.seek((1 << 20) * 32)
            first = original.read(1)
        with cache.open("r+b") as f:
            f.seek(68 + (1 << 20) * 32)
            f.write(first)
        saved = directory / "verified-cache"
        vault = run("cached", base + ["--write-fee-tree-cache", str(saved)], True)
        before = vault.read_bytes()
        run("duplicate", base, False, vault)
        assert vault.read_bytes() == before
        run("existing-cache-output", base + ["--write-fee-tree-cache", str(saved)], False)
        if not args.skip_rebuild:
            no_cache = base.copy()
            index = no_cache.index("--fee-tree-cache")
            del no_cache[index : index + 2]
            rebuilt = directory / "rebuilt-cache"
            run("rebuild", no_cache + ["--write-fee-tree-cache", str(rebuilt)], True)
            assert rebuilt.read_bytes() == cache.read_bytes(), (
                "CLI rebuilt a different fee tree cache"
            )
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} fee CLI recovery outcomes verified")


if __name__ == "__main__":
    main()

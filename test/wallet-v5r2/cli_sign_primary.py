"""Real encrypted CLI PRIMARY signing; mocked proofs and native module signature execution."""

import argparse
import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from cli_inspect_initial import VERIFIER

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cli = [str(args.cli.resolve()), "wallet"]
    vectors = json.loads(
        (ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json").read_text()
    )
    vector = vectors["vectors"][1]
    payload = json.loads(args.fixture.read_text())["input"]
    for key in ("recovery_manifest", "recovery_derivation", "existing_wallet", "expected_wallet"):
        payload.pop(key, None)
    payload["network"] = vectors["context"]["network_hex"]
    results = {}
    with tempfile.TemporaryDirectory(prefix="pq-primary-cli-") as tmp:
        root = Path(tmp)

        def file(name, data):
            p = root / name
            p.write_bytes(data)
            p.chmod(0o600)
            return str(p)

        subprocess.run(
            [
                os.environ["MLDSA_TOOL"],
                "keygen",
                vector["derived"]["ML-DSA-44"],
                str(root / "primary.pub"),
                str(root / "PUBLIC-TEST-ONLY.secret"),
            ],
            check=True,
        )
        payload["primary_key"] = (root / "primary.pub").read_bytes().hex()

        def genesis(data):
            r = subprocess.run(
                [str(args.genesis_driver.resolve())],
                input=json.dumps(data),
                text=True,
                capture_output=True,
                timeout=60,
            )
            assert r.returncode == 0, r.stderr
            return json.loads(r.stdout)

        initial = genesis(payload)
        payload["expected_wallet"] = from_boc(bytes.fromhex(initial["wallet_init"])).hash.hex()
        payload["recovery_derivation"] = dict(
            account_index=5,
            key_generation=7,
            primary_seed_profile="tos-native-mnemonic-v1",
            rescue_seed_profile="raw-master-32-v1",
            fee_seed_profile="raw-master-32-v1",
        )
        output = genesis(payload)
        manifest = json.loads(output["recovery_manifest"])
        keyfile = file("encryption", b"77" * 32)
        custody = [
            "--vault-file",
            str(root / "vault.json"),
            "--record-id",
            "primary",
            "--vault-key-file",
            keyfile,
        ]
        restore = subprocess.run(
            cli
            + [
                "pq-restore-key",
                *custody,
                "--role",
                "primary",
                "--expected-public-key",
                payload["primary_key"],
                "--network-tag",
                payload["network"],
                "--global-id",
                str(payload["global_id"]),
                "--account-index",
                "5",
                "--key-generation",
                "7",
                "--mnemonic-file",
                file("words", vector["phrase"].encode()),
                "--password-file",
                file("password", vector["password"].encode()),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert restore.returncode == 0, restore.stderr
        verifier = root / "verifier"
        verifier.write_text(f"#!{sys.executable}\n" + VERIFIER)
        verifier.chmod(0o700)
        anchor = dict(
            kind="zerostate",
            workchain=-1,
            shard="8000000000000000",
            seqno=0,
            root_hash="00" * 32,
            file_hash="00" * 32,
        )
        config = dict(
            executable=str(verifier),
            anchor_file=file("anchor.json", json.dumps(anchor).encode()),
            material_dir=str(root),
            live_state_file=str(root / "live.json"),
            live_max_age_seconds=60,
            timeout_seconds=10,
            min_interval_ms=0,
        )
        common = [
            "--recovery-manifest",
            file("manifest.json", json.dumps(manifest).encode()),
            "--expected-wallet",
            payload["expected_wallet"],
            "--proof-config",
            file("config.json", json.dumps(config).encode()),
        ]
        accounts, codes, data, addresses = {}, {}, {}, {}
        for role in ("wallet", "module", "vault"):
            codes[role] = from_boc(bytes.fromhex(payload[role + "_code"]))
            data[role] = from_boc(bytes.fromhex(output[role + "_data"]))
            identity = from_boc(bytes.fromhex(output[role + "_init"])).hash.hex()
            addresses[role] = (0, int(identity, 16))
            account = native.active_account(addresses[role], codes[role], data[role]).refs[0]
            common += [
                f"--{role}-code",
                file(role + ".boc", codes[role].boc()),
                f"--{role}-code-hash",
                payload[role + "_pin"],
            ]
            accounts["0:" + identity] = dict(
                exists=True,
                active=True,
                address="0:" + identity,
                state_boc=base64.b64encode(account.boc()).decode(),
                state_hash=account.hash.hex(),
                balance="100000000000",
                code_hash=codes[role].hash.hex(),
                data_hash=data[role].hash.hex(),
                last_trans_lt=0,
                last_trans_hash="00" * 32,
                gen_utime=0,
                shard_block=dict(
                    workchain=0,
                    shard="8000000000000000",
                    seqno=8,
                    root_hash="44" * 32,
                    file_hash="55" * 32,
                ),
            )

        def policy(retired=0):
            return (
                Cell()
                .uint(0xA1, 8)
                .uint(int(payload["network"], 16), 256)
                .uint(0, 64)
                .uint(retired, 16)
                .uint(0, 1)
                .uint(
                    int("5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0", 16), 256
                )
            )

        message = native.internal(addresses["wallet"], (0, 789), Cell(), value=1_000_000_000)
        actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(message)
        actionfile = file("actions.boc", actions.boc())
        for mode in (
            "valid",
            "retired",
            "missing_policy",
            "expired",
            "unsafe_actions",
            "wrong_record",
            "duplicate",
        ):
            chosen = policy(2 if mode == "retired" else 0)
            scenario = dict(
                mode="valid",
                accounts=copy.deepcopy(accounts),
                config_params=[]
                if mode == "missing_policy"
                else [
                    dict(
                        index=48,
                        cell_hash=chosen.hash.hex(),
                        boc=base64.b64encode(chosen.boc()).decode(),
                    )
                ],
            )
            (root / "scenario.json").write_text(json.dumps(scenario))
            deadline = int(time.time()) + (-1 if mode == "expired" else 600)
            destination = root / ("valid" if mode == "duplicate" else mode)
            command = cli + [
                "pq-sign-primary-initial",
                *common,
                *custody,
                "--actions",
                actionfile,
                "--valid-until",
                str(deadline),
                "--output-dir",
                str(destination),
            ]
            if mode == "unsafe_actions":
                bad = Cell().uint(0x0EC3C86D, 32).uint(0, 8).ref(Cell()).ref(message)
                command[command.index("--actions") + 1] = file("unsafe.boc", bad.boc())
            if mode == "wrong_record":
                command[command.index("--record-id") + 1] = "absent"
            before = (
                {p.name: p.read_bytes() for p in destination.iterdir()}
                if destination.exists()
                else {}
            )
            r = subprocess.run(command, capture_output=True, text=True, timeout=90)
            (args.output / (mode + ".stdout")).write_text(r.stdout)
            (args.output / (mode + ".stderr")).write_text(r.stderr)
            assert (r.returncode == 0) == (mode == "valid"), (mode, r.stderr)
            results[mode] = dict(exit=r.returncode)
            if mode == "valid":
                report = json.loads(r.stdout)
                submission = from_boc((destination / "submission.boc").read_bytes())
                request = submission.refs[0]
                assert report["auth_digest"] == Cell().raw(b"TOS-AUTH").ref(request).hash.hex()
                assert report["actions_hash"] == actions.hash.hex()
                assert request.refs[0].refs[0].hash == actions.hash
                assert report["submission_hash"] == submission.hash.hex()
                (args.output / "submission.boc").write_bytes(submission.boc())
                # Execute the actual randomized signature against the compiled module.
                native.NOW = int(time.time())
                original = native.config

                def config(*pos, **kw):
                    entries = read_dict(original(*pos, **kw), 32)
                    entries[48] = Cell().ref(policy())
                    return make_dict(entries, 32)

                with patch.object(native, "config", config):
                    emu = native.Emulator(global_version=17)
                try:
                    shard = native.active_account(
                        addresses["module"], codes["module"], data["module"]
                    )
                    tx = emu.send(
                        shard,
                        native.internal(
                            addresses["vault"],
                            addresses["module"],
                            submission,
                            value=10_000_000_000,
                        ),
                    )
                    assert (
                        tx["success"]
                        and tx["details"]["compute_success"]
                        and not tx["details"]["aborted"]
                    ), tx
                    emitted = native.outgoing(from_boc(tx["transaction"]))
                    assert len(emitted) == 1, "signed module did not forward authorization"
                    (args.output / "module-transaction.json").write_text(json.dumps(tx, indent=2))
                    results[mode]["module_signature_execution"] = tx["details"]
                    sig = submission.refs[1]
                    corrupt = Cell(sig.bits[:-1] + str(1 - int(sig.bits[-1])), sig.refs)
                    broken = Cell(submission.bits, [request, corrupt])
                    negative = emu.send(
                        shard,
                        native.internal(
                            addresses["vault"], addresses["module"], broken, value=10_000_000_000
                        ),
                    )
                    assert negative["success"] and not negative["details"]["compute_success"], (
                        negative
                    )
                    results[mode]["corrupt_signature_exit"] = negative["details"]["exit"]
                finally:
                    emu.close()
            else:
                assert not r.stdout.strip()
                if mode in ("retired", "missing_policy", "expired", "unsafe_actions"):
                    assert not destination.exists(), "refused preflight opened output/custody"
                if mode == "retired":
                    assert "primary suite retired" in r.stderr
                if mode == "duplicate":
                    assert before == {p.name: p.read_bytes() for p in destination.iterdir()}
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(
        f"{len(results)} primary signing CLI outcomes passed; native module accepts signature and rejects corruption"
    )


if __name__ == "__main__":
    main()

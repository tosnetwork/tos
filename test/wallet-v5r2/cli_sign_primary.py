"""Real encrypted CLI PRIMARY signing and native recipient delivery; mocked proofs."""

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


def check_execution(result, before, message, label="wallet"):
    assert result["success"], "native transaction did not execute"
    details = result["details"]
    assert (
        details.get("compute_success")
        and not details.get("aborted")
        and (details.get("action") is None or details["action"]["success"])
    ), f"{label} transaction did not complete"
    transaction = from_boc(result["transaction"])
    incoming = transaction.refs[0].slice().maybe()
    assert incoming is not None and incoming.hash == message.hash, (
        "transaction input differs from emitted message"
    )
    update = transaction.refs[1].slice()
    assert update.uint(8) == 0x72
    assert update.uint(256) == int.from_bytes(before.refs[0].hash, "big"), (
        "transaction old account mismatch"
    )
    after = from_boc(result["shard_account"])
    assert update.uint(256) == int.from_bytes(after.refs[0].hash, "big"), (
        "transaction new account mismatch"
    )
    update.end()
    return native.outgoing(transaction)


def check_recipient(result, before, message):
    check_execution(result, before, message, "recipient")
    state, balance = native.account_data(from_boc(result["shard_account"]))
    assert state.hash == Cell().uint(1, 32).hash and balance > 1_000_000_000, (
        "recipient state did not record payment"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rescue-lock", action="store_true")
    parser.add_argument("--fee-session-tree", type=Path)
    parser.add_argument("--fee-session-pop", action="store_true")
    parser.add_argument("--fee-pop-receipts", action="store_true")
    parser.add_argument("--fee-session-prepare", action="store_true")
    args = parser.parse_args()
    if args.fee_session_prepare:
        assert args.fee_session_tree and not args.fee_session_pop and not args.fee_pop_receipts
    if args.fee_pop_receipts:
        args.fee_session_pop = True
    if args.fee_session_pop:
        assert args.fee_session_tree, "POP test needs the native fee tree"
    if args.fee_session_tree:
        args.rescue_lock = True
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
    if args.fee_session_tree:
        fee_vector = json.loads(
            (
                ROOT / "tosctl/src/wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
            ).read_text()
        )
        assert payload["network"] == fee_vector["context"]["network_hex"]
        payload["fee_public_key"] = fee_vector["public_key_hex"]
        payload["fee_tree_id"] = fee_vector["tree_id_hex"]
        # Real clock and fixed one-hour protocol slots: leave setup time before
        # crossing the first boundary while retaining the same CLI process.
        payload["epoch0"] = int(time.time()) - 3600 + 45
    signing_role = "rescue" if args.rescue_lock else "primary"
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
        if args.rescue_lock:
            payload["rescue_key"] = subprocess.check_output(
                [os.environ["SLH_TOOL"], "keygen", vector["derived"]["SLH-DSA-SHA2-128s"]],
                text=True,
            ).split()[0]

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

        # The mnemonic vector uses a different network than the recorded fixture.
        # Compile the wallet's immutable network/module/vault bindings for it.
        wallet_source = root / "network-wallet.fc"
        wallet_source.write_text(
            f'#include "{os.path.relpath(ROOT / "crypto/smartcont/wallet-v5r2-code.fc", root.resolve())}";\n'
            + f'cell compiled_vault() asm "B{{{payload["vault_code"]}}} B>boc PUSHREF";\n'
            + f"int r2wallet_network() inline {{ return 0x{payload['network']}; }}\n"
            + f"int r2wallet_module_hash() inline {{ return 0x{payload['module_pin']}; }}\n"
            + "cell r2wallet_vault_code() inline { return compiled_vault(); }\n"
        )
        try:
            wallet_code = native.compile_contract(
                str(wallet_source), args.output / "network-wallet.boc"
            )
        except subprocess.CalledProcessError as error:
            raise AssertionError(error.stderr.decode()) from error
        payload["wallet_code"] = wallet_code.boc().hex()
        payload["wallet_pin"] = wallet_code.hash.hex()
        initial = genesis(payload)
        payload["expected_wallet"] = from_boc(bytes.fromhex(initial["wallet_init"])).hash.hex()
        payload["recovery_derivation"] = dict(
            account_index=5,
            key_generation=7,
            primary_seed_profile="tos-native-mnemonic-v1",
            rescue_seed_profile="tos-native-mnemonic-v1"
            if args.rescue_lock
            else "raw-master-32-v1",
            fee_seed_profile="tos-native-mnemonic-v1"
            if args.fee_session_tree
            else "raw-master-32-v1",
        )
        output = genesis(payload)
        manifest = json.loads(output["recovery_manifest"])
        keyfile = file("encryption", b"77" * 32)
        custody = [
            "--vault-file",
            str(root / "vault.json"),
            "--record-id",
            signing_role,
            "--vault-key-file",
            keyfile,
        ]
        restore_command = cli + [
            "pq-restore-key",
            *custody,
            "--role",
            signing_role,
            "--expected-public-key",
            payload[signing_role + "_key"],
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
        ]
        restore = subprocess.run(restore_command, capture_output=True, text=True, timeout=180)
        assert restore.returncode == 0, restore.stderr
        if args.fee_session_pop:
            primary_command = list(restore_command)
            for option, value in [
                ("--role", "primary"),
                ("--record-id", "primary"),
                ("--expected-public-key", payload["primary_key"]),
            ]:
                primary_command[primary_command.index(option) + 1] = value
            restored_primary = subprocess.run(
                primary_command, capture_output=True, text=True, timeout=180
            )
            assert restored_primary.returncode == 0, restored_primary.stderr
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

        if args.fee_session_tree:
            from cli_fee_session_sign import check_signing_session

            check_signing_session(
                args, root, common, accounts, config, payload, codes, data, addresses
            )
            return

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

        recipient_source = root / "recipient.fc"
        recipient_source.write_text(
            "() recv_internal(slice body) impure { "
            "throw_unless(1777, get_data().begin_parse().preload_uint(32) == 0); "
            "set_data(begin_cell().store_uint(1, 32).end_cell()); }\n"
        )
        recipient_code = native.compile_contract(
            str(recipient_source), args.output / "recipient.boc"
        )
        recipient_data = Cell().uint(0, 32)
        recipient_address = (
            0,
            int.from_bytes(native.state_init(recipient_code, recipient_data).hash, "big"),
        )
        message = native.internal(
            addresses["wallet"], recipient_address, Cell(), value=1_000_000_000
        )
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
            if args.rescue_lock and mode == "unsafe_actions":
                continue
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
                "pq-lock-primary-initial" if args.rescue_lock else "pq-sign-primary-initial",
                *common,
                *custody,
                "--actions",
                actionfile,
                "--valid-until",
                str(deadline),
                "--output-dir",
                str(destination),
            ]
            if args.rescue_lock:
                idx = command.index("--actions")
                del command[idx : idx + 2]
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
            success = mode == "valid" or (
                args.rescue_lock and mode in ("retired", "missing_policy")
            )
            assert (r.returncode == 0) == success, (mode, r.stderr)
            results[mode] = dict(exit=r.returncode)
            if success:
                report = json.loads(r.stdout)
                submission = from_boc((destination / "submission.boc").read_bytes())
                request = submission.refs[0]
                assert report["auth_digest"] == Cell().raw(b"TOS-AUTH").ref(request).hash.hex()
                if args.rescue_lock:
                    from cli_lock_primary import execute_lock

                    results[mode].update(
                        execute_lock(
                            submission,
                            report,
                            codes,
                            data,
                            addresses,
                            None if mode == "missing_policy" else chosen,
                            args.output,
                            mode,
                        )
                    )
                    continue
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
                            (0, 987),
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
                    wallet_before = native.active_account(
                        addresses["wallet"], codes["wallet"], data["wallet"]
                    )
                    executed = emu.send(wallet_before, emitted[0])
                    (args.output / "wallet-transaction.json").write_text(
                        json.dumps(executed, indent=2)
                    )
                    payment = check_execution(executed, wallet_before, emitted[0])
                    assert len(payment) == 1, "wallet did not emit the approved payment"
                    header = payment[0].slice()
                    header.uint(4)
                    assert header.addr() == addresses["wallet"]
                    assert header.addr() == recipient_address
                    assert header.coins() == 1_000_000_000
                    recipient_before = native.active_account(
                        recipient_address, recipient_code, recipient_data, balance=1_000_000_000
                    )
                    delivered = emu.send(recipient_before, payment[0])
                    check_recipient(delivered, recipient_before, payment[0])
                    (args.output / "wallet-transaction.json").write_text(
                        json.dumps(executed, indent=2)
                    )
                    (args.output / "recipient-transaction.json").write_text(
                        json.dumps(delivered, indent=2)
                    )
                    results[mode]["wallet_execution"] = executed["details"]
                    results[mode]["recipient_delivery"] = delivered["details"]
                    results[mode]["payment_hash"] = payment[0].hash.hex()
                    # Successful wallet actions do not prove recipient execution.
                    refusing_before = native.active_account(
                        recipient_address, recipient_code, Cell().uint(1, 32), balance=1_000_000_000
                    )
                    refused = emu.send(refusing_before, payment[0])
                    assert refused["success"] and refused["details"]["exit"] == 1777
                    try:
                        check_recipient(refused, refusing_before, payment[0])
                        raise AssertionError("recipient failure was classified as delivery")
                    except AssertionError as error:
                        assert str(error) == "recipient transaction did not complete", error
                    # Reusing a valid receipt for another payment must also fail.
                    try:
                        check_recipient(delivered, recipient_before, message)
                        raise AssertionError("unrelated input was classified as delivery")
                    except AssertionError as error:
                        assert str(error) == "transaction input differs from emitted message", error
                    results[mode]["recipient_refusal_exit"] = refused["details"]["exit"]
                    results[mode]["unrelated_receipt_rejected"] = True
                    fee_forward = emu.send(
                        shard,
                        native.internal(
                            addresses["vault"],
                            addresses["module"],
                            submission,
                            value=10_000_000_000,
                        ),
                    )
                    assert fee_forward["success"] and fee_forward["details"]["compute_success"]
                    fee_messages = native.outgoing(from_boc(fee_forward["transaction"]))
                    assert len(fee_messages) == 1
                    fee_rejected = emu.send(wallet_before, fee_messages[0])
                    assert fee_rejected["success"] and fee_rejected["details"]["exit"] == 1818, (
                        "PRIMARY charged rescue fee vault"
                    )
                    assert (
                        native.account_data(from_boc(fee_rejected["shard_account"]))[0].hash
                        == data["wallet"].hash
                    )
                    results[mode]["rescue_fee_payer_rejected"] = fee_rejected["details"]["exit"]
                    (args.output / "primary-fee-payer-refusal.json").write_text(
                        json.dumps(fee_rejected, indent=2)
                    )
                    (args.output / "recipient-refusal.json").write_text(
                        json.dumps(refused, indent=2)
                    )
                    sig = submission.refs[1]
                    corrupt = Cell(sig.bits[:-1] + str(1 - int(sig.bits[-1])), sig.refs)
                    broken = Cell(submission.bits, [request, corrupt])
                    negative = emu.send(
                        shard,
                        native.internal(
                            (0, 987), addresses["module"], broken, value=10_000_000_000
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
    label = "SLH lock" if args.rescue_lock else "primary signing"
    print(
        f"{len(results)} {label} CLI outcomes passed; native execution and refusal controls passed"
    )


if __name__ == "__main__":
    main()

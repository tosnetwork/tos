"""Real cross-slot CLI fee signing and cached restart retry; proof acquisition is mocked."""

import base64
import json
import os
import selectors
import shutil
import subprocess
import time
from unittest.mock import patch

import cli_sign_primary as shared

native, Cell, from_boc = shared.native, shared.Cell, shared.from_boc


def check_signing_session(args, root, common, accounts, config, payload, codes, data, addresses):
    vector = json.loads(
        (
            shared.ROOT / "tosctl/src/wallet-pq-signer/tests/fixtures/native-fee-recovery.json"
        ).read_text()
    )
    cache = root / "tree.cache"
    with cache.open("wb") as output:
        output.write(b"TOSFT001" + bytes.fromhex(vector["public_key_hex"]))
        with args.fee_session_tree.open("rb") as source:
            shutil.copyfileobj(source, output)

    def secret(name, value):
        path = root / name
        path.write_bytes(value)
        path.chmod(0o600)
        return str(path)

    restore_args = []
    for i in range(0, len(common), 2):
        if common[i] != "--proof-config":
            restore_args += common[i : i + 2]
    restore = subprocess.run(
        [
            str(args.cli.resolve()),
            "wallet",
            "pq-restore-fee-initial",
            *restore_args,
            "--vault-file",
            str(root / "fee-vault.json"),
            "--record-id",
            "fee",
            "--fee-tree-cache",
            str(cache),
            "--mnemonic-file",
            secret("fee-words", vector["phrase"].encode()),
            "--password-file",
            secret("fee-password", vector["password"].encode()),
            "--vault-key-file",
            str(root / "encryption"),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    (args.output / "fee-restore.stderr").write_text(restore.stderr)
    assert restore.returncode == 0, restore.stderr
    journal = root / "journal"
    journal.mkdir(mode=0o700)
    scenario = dict(mode="valid", accounts=accounts)
    (root / "scenario.json").write_text(json.dumps(scenario))
    (root / "config.json").write_text(json.dumps(config))
    command = [
        str(args.cli.resolve()),
        "wallet",
        "pq-fee-session-initial",
        *common,
        "--journal-dir",
        str(journal),
        "--fee-tree-cache",
        str(cache),
        "--fee-vault-file",
        str(root / "fee-vault.json"),
        "--fee-record-id",
        "fee",
        "--fee-vault-key-file",
        str(root / "encryption"),
        "--rescue-vault-file",
        str(root / "vault.json"),
        "--rescue-record-id",
        "rescue",
        "--rescue-vault-key-file",
        str(root / "encryption"),
    ]
    reports = []
    process = None
    selector = None
    errors = []

    def start(label):
        nonlocal process, selector
        err = (args.output / (label + ".stderr")).open("w")
        errors.append(err)
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        assert read()["status"] == "fee_session_open"

    def read():
        assert selector.select(timeout=90), "fee session response timed out"
        line = process.stdout.readline()
        assert line, "fee session exited before response"
        value = json.loads(line)
        reports.append(value)
        return value

    def request(value):
        process.stdin.write(json.dumps(value).encode() + b"\n")
        process.stdin.flush()
        return read()

    def stop():
        nonlocal process, selector
        process.stdin.write(b'{"command":"quit"}\n')
        process.stdin.flush()
        assert process.wait(timeout=10) == 0
        selector.close()
        process = None

    try:
        start("initial")
        boundary = payload["epoch0"] + 3600
        assert int(time.time()) < boundary, "fixture setup missed real recovery boundary"
        initial = request(dict(command="status"))
        assert initial["status"] == "request_refused" and "WaitUntil" in initial["reason"]
        before = (journal / "fee-reservations").read_bytes()
        while int(time.time()) <= boundary:
            time.sleep(min(1, max(0.01, boundary + 1 - time.time())))
        available = request(dict(command="status"))
        assert available["status"] == "leaf_available" and available["leaf"] == 4, available
        signed_dir = root / "signed"
        lock_request = dict(
            command="lock",
            valid_for_seconds=600,
            value_nanotos="5000000000",
            output_dir=str(signed_dir),
        )
        crash = os.environ.get("TOS_TEST_FEE_EXPORT_CRASH") == "1"
        message_bytes = None
        result = None
        if crash:
            process.stdin.write(json.dumps(lock_request).encode() + b"\n")
            process.stdin.flush()
            assert process.wait(timeout=90) == 73, "injected export crash was not reached"
            selector.close()
            process = None
            assert not (signed_dir / "message.boc").exists(), "crash occurred after export"
        else:
            result = request(lock_request)
            assert result["status"] == "fee_message_cached" and result["leaf"] == 4, result
            message_bytes = (signed_dir / "message.boc").read_bytes()
        assert (signed_dir / "pending-intent.boc").exists(), (
            "cached signature lost its persisted intent"
        )
        intent_bytes = (signed_dir / "pending-intent.boc").read_bytes()
        after = (journal / "fee-reservations").read_bytes()
        assert len(after) > len(before), "fee signing did not durably reserve a leaf"
        if not crash:
            assert request(dict(command="status"))["leaf"] == 5
            stop()
            # Lose exported message/report, retain the pre-sign intent and journal/cache.
            (signed_dir / "message.boc").unlink()
            (signed_dir / "binding.json").unlink()
        start("restarted")
        blocked = request(dict(command="status"))
        assert blocked["status"] == "request_refused" and "WaitUntil" in blocked["reason"]
        retry_dir = root / "retry"
        retried = request(
            dict(
                command="retry",
                intent=str(signed_dir / "pending-intent.boc"),
                output_dir=str(retry_dir),
            )
        )
        assert retried["status"] == "fee_message_cached", retried
        recovered = (retry_dir / "message.boc").read_bytes()
        if message_bytes is not None:
            assert recovered == message_bytes, "cached restart retry changed external bytes"
        message_bytes = recovered
        assert (retry_dir / "pending-intent.boc").read_bytes() == intent_bytes
        assert (journal / "fee-reservations").read_bytes() == after, "retry consumed another leaf"
        root_message = from_boc(message_bytes)
        assert root_message.hash.hex() == retried["message_hash"]
        if result is not None:
            assert root_message.hash.hex() == result["message_hash"]
        (args.output / "message.boc").write_bytes(message_bytes)
        (args.output / "pending-intent.boc").write_bytes(intent_bytes)
        # Execute this exact CLI message through native fee -> module -> wallet.
        native.NOW = int(time.time())
        original = native.config

        def config_with_credit(credit):
            entries = shared.read_dict(original(17), 32)
            price = entries[21].refs[0]
            prefix = 136 if int(price.bits[:8], 2) == 0xD1 else 0
            assert int(price.bits[prefix : prefix + 8], 2) == 0xDE
            offset = prefix + 8 + 64 * 3
            entries[21] = Cell().ref(
                Cell(price.bits[:offset] + f"{credit:064b}" + price.bits[offset + 64 :], price.refs)
            )
            return shared.make_dict(entries, 32)

        with patch.object(native, "config", lambda *a, **k: config_with_credit(10000)):
            limited = native.Emulator(global_version=17)
        vault_before = native.active_account(addresses["vault"], codes["vault"], data["vault"])
        try:
            rejected = limited.send(vault_before, root_message)
            assert not rejected["success"] and rejected.get("vm_exit_code") == -14, rejected
        finally:
            limited.close()
        with patch.object(native, "config", lambda *a, **k: config_with_credit(20000)):
            emu = native.Emulator(global_version=17)
        try:
            paid = emu.send(vault_before, root_message)
            fee_messages = shared.check_execution(paid, vault_before, root_message, "fee vault")
            assert len(fee_messages) == 1
            module_before = native.active_account(
                addresses["module"], codes["module"], data["module"]
            )
            relayed = emu.send(module_before, fee_messages[0])
            wallet_messages = shared.check_execution(
                relayed, module_before, fee_messages[0], "module"
            )
            assert len(wallet_messages) == 1
            wallet_before = native.active_account(
                addresses["wallet"], codes["wallet"], data["wallet"]
            )
            locked = emu.send(wallet_before, wallet_messages[0])
            assert not shared.check_execution(locked, wallet_before, wallet_messages[0])
            wallet_after, _ = native.account_data(from_boc(locked["shard_account"]))
            authority = wallet_after.refs[0].slice()
            assert authority.uint(8) == 4 and authority.uint(2) == 2 and authority.uint(16) & 2
            assert authority.uint(64) == 2, "fee-funded SLH lock did not advance authority epoch"
            vault_after = from_boc(paid["shard_account"])
            vault_data, balance = native.account_data(vault_after)
            counter = vault_data.slice()
            assert counter.uint(8) == 3 and counter.uint(32) == 5
            record = accounts["0:" + payload["expected_wallet"]]  # Ensure enrollment still exists.
            assert record["active"]
            record = accounts[f"0:{addresses['vault'][1]:064x}"]
            record.update(
                state_boc=base64.b64encode(vault_after.refs[0].boc()).decode(),
                state_hash=vault_after.refs[0].hash.hex(),
                data_hash=vault_data.hash.hex(),
                balance=str(balance),
            )
            (root / "scenario.json").write_text(json.dumps(scenario))
            consumed = request(
                dict(
                    command="retry",
                    intent=str(signed_dir / "pending-intent.boc"),
                    output_dir=str(root / "consumed"),
                )
            )
            assert (
                consumed["status"] == "request_refused" and "already consumed" in consumed["reason"]
            ), consumed
            assert not (root / "consumed").exists()
            assert (journal / "fee-reservations").read_bytes() == after
            for label, tx in [
                ("default-credit", rejected),
                ("fee", paid),
                ("module", relayed),
                ("wallet", locked),
            ]:
                (args.output / (label + ".json")).write_text(json.dumps(tx, indent=2))
        finally:
            emu.close()
        stop()
        (args.output / "results.json").write_text(
            json.dumps(
                dict(
                    reports=reports,
                    real_slot_boundary=boundary,
                    exact_restart_retry=not crash,
                    abrupt_export_crash_recovered=crash,
                    retry_journal_unchanged=True,
                    native_default_credit_rejected=True,
                    native_diagnostic_credit=20000,
                    fee=paid["details"],
                    module=relayed["details"],
                    wallet=locked["details"],
                    scope="real native signing and local execution with mock proof acquisition; not production admission or live finality",
                ),
                indent=2,
            )
            + "\n"
        )
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if selector is not None:
            selector.close()
        for err in errors:
            err.close()
    print(
        "Cross-slot fee CLI signing, lost-output restart retry, native funded lock and consumed retry refusal passed"
    )


if __name__ == "__main__":
    shared.main()

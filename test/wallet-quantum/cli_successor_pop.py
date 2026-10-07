"""Prepared successor accounts, independent custody and funded dual POP in one flow."""

import base64
import json
import os
import selectors
import shutil
import subprocess
import time
from unittest.mock import patch

import cli_sign_primary as shared
from cli_pop_receipt import check_receipts

native, Cell, from_boc = shared.native, shared.Cell, shared.from_boc


def check_successor_pops(
    args,
    root,
    common,
    template,
    manifest,
    pin,
    successor,
    states,
    paid,
    prepared,
    original_addresses,
    source_request=None,
):
    vector = json.loads((args.successor_fee_fixture / "native-fee-recovery.json").read_text())
    scenario_path = root / "scenario.json"
    scenario = json.loads(scenario_path.read_text())
    record_template = dict(scenario["accounts"][f"0:{original_addresses['module'][1]:064x}"])
    addresses = {
        name: (0, int.from_bytes(from_boc(bytes.fromhex(successor[name + "_init"])).hash, "big"))
        for name in ["module", "vault"]
    }
    codes = {name: from_boc(bytes.fromhex(template[name + "_code"])) for name in addresses}
    data = {name: from_boc(bytes.fromhex(successor[name + "_data"])) for name in addresses}

    def update(address, state):
        record = dict(record_template)
        contents, balance = native.account_data(state)
        history = state.slice()
        last_hash, last_lt = history.uint(256), history.uint(64)
        code = (
            codes["vault"]
            if address in [addresses["vault"], original_addresses["vault"]]
            else codes["module"]
        )
        address = f"0:{address[1]:064x}"
        record.update(
            address=address,
            state_boc=base64.b64encode(state.refs[0].boc()).decode(),
            state_hash=state.refs[0].hash.hex(),
            data_hash=contents.hash.hex(),
            balance=str(balance),
            last_trans_lt=last_lt,
            last_trans_hash=f"{last_hash:064x}",
        )
        # Code is checked from the authenticated raw Account as well as metadata.
        record["code_hash"] = code.hash.hex()
        scenario["accounts"][address] = record
        scenario_path.write_text(json.dumps(scenario))

    for name, result in [("vault", paid), ("module", prepared)]:
        update(original_addresses[name], from_boc(result["shard_account"]))
    for name in addresses:
        update(addresses[name], states[name])

    def secret(name, value):
        path = root / name
        path.write_bytes(value)
        path.chmod(0o600)
        return str(path)

    words = secret("successor-words", vector["phrase"].encode())
    password = secret("successor-password", vector["password"].encode())
    encryption = str(root / "encryption")
    signer_vault = str(root / "successor-signers.json")
    fee_vault = str(root / "successor-fee.json")
    cache = root / "successor-tree.cache"
    with cache.open("wb") as target:
        target.write(b"TOSFT001" + bytes.fromhex(vector["public_key_hex"]))
        with (args.successor_fee_fixture / "PUBLIC-TEST-ONLY-tree").open("rb") as source:
            shutil.copyfileobj(source, target)
    cli = [str(args.cli.resolve()), "wallet"]
    for role in ["primary", "rescue"]:
        command = cli + [
            "pq-restore-key",
            "--vault-file",
            signer_vault,
            "--record-id",
            role,
            "--role",
            role,
            "--vault-key-file",
            encryption,
            "--expected-public-key",
            template[role + "_key"],
            "--network-tag",
            template["network"],
            "--global-id",
            str(template["global_id"]),
            "--account-index",
            str(vector["context"]["account_index"]),
            "--key-generation",
            str(vector["context"]["key_generation"]),
            "--mnemonic-file",
            words,
            "--password-file",
            password,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr
    restore_args = []
    for i in range(0, len(common), 2):
        if common[i] not in [
            "--proof-config",
            "--max-age-seconds",
            "--installed-successor-manifest",
            "--expected-installed-template-wallet",
            "--fee-history",
        ]:
            restore_args += common[i : i + 2]
    restore_args[restore_args.index("--recovery-manifest") + 1] = str(manifest)
    restore_args[restore_args.index("--expected-wallet") + 1] = pin
    result = subprocess.run(
        cli
        + [
            "pq-restore-fee-initial",
            *restore_args,
            "--vault-file",
            fee_vault,
            "--record-id",
            "fee",
            "--vault-key-file",
            encryption,
            "--fee-tree-cache",
            str(cache),
            "--mnemonic-file",
            words,
            "--password-file",
            password,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    journal = root / "successor-journal"
    journal.mkdir(mode=0o700)
    route = ["--successor-manifest", str(manifest), "--expected-template-wallet", pin]
    command = cli + [
        "pq-fee-session-initial",
        *common,
        *route,
        "--journal-dir",
        str(journal),
        "--fee-tree-cache",
        str(cache),
        "--fee-vault-file",
        fee_vault,
        "--fee-record-id",
        "fee",
        "--fee-vault-key-file",
        encryption,
        "--rescue-vault-file",
        signer_vault,
        "--rescue-record-id",
        "rescue",
        "--rescue-vault-key-file",
        encryption,
        "--primary-vault-file",
        signer_vault,
        "--primary-record-id",
        "primary",
        "--primary-vault-key-file",
        encryption,
    ]
    err = (args.output / "successor-session.stderr").open("w")
    process = None
    selector = selectors.DefaultSelector()
    if args.fee_session_migration:
        custody = {}
        for i in range(command.index("--journal-dir"), len(command), 2):
            custody[command[i][2:].replace("-", "_")] = command[i + 1]
        attached_manifest = str(manifest)
        if getattr(args, "fee_session_rotation", False):
            from cli_rotation_session import PATH_ARGUMENTS

            for field in custody:
                if "--" + field.replace("_", "-") in PATH_ARGUMENTS:
                    custody[field] = os.path.relpath(custody[field], args.rotation_session_cwd)
            attached_manifest = os.path.relpath(manifest, args.rotation_session_cwd)
            if getattr(args, "expect_rotation_capacity_refusal", False):
                from cli_rotation_session import check_full_journal_attachment_refusal

                try:
                    check_full_journal_attachment_refusal(
                        args,
                        source_request,
                        dict(
                            command="attach_successor",
                            successor_manifest=attached_manifest,
                            expected_template_wallet=pin,
                            custody=custody,
                        ),
                        root / "journal" / "fee-reservations",
                        journal / "fee-reservations",
                    )
                finally:
                    selector.close()
                    err.close()
                return
            from cli_rotation_session import check_full_history_refusal

            check_full_history_refusal(
                args,
                source_request,
                dict(
                    command="attach_successor",
                    successor_manifest=attached_manifest,
                    expected_template_wallet=pin,
                    custody=custody,
                ),
                root / "journal" / "fee-reservations",
                None,
                "attach",
            )
            assert not (journal / "fee-reservations").exists(), (
                "full-history attachment opened successor journal"
            )
        attached = source_request(
            dict(
                command="attach_successor",
                successor_manifest=attached_manifest,
                expected_template_wallet=pin,
                custody=custody,
            )
        )
        assert attached["status"] == "successor_session_attached", attached
        duplicate = source_request(
            dict(
                command="attach_successor",
                successor_manifest=attached_manifest,
                expected_template_wallet=pin,
                custody=custody,
            )
        )
        assert (
            duplicate["status"] == "request_refused" and "already attached" in duplicate["reason"]
        )
        competing = subprocess.run(
            command, input=b'{"command":"quit"}\n', capture_output=True, timeout=30
        )
        (args.output / "successor-competing.stderr").write_bytes(competing.stderr)
        assert (
            competing.returncode != 0
            and b"Resource temporarily unavailable" in competing.stderr
            and b"fee_session_open" not in competing.stdout
        ), "attached successor journal did not exclude another process"
    else:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err
        )
        selector.register(process.stdout, selectors.EVENT_READ)
    emu = None
    reports = []

    def read():
        assert selector.select(timeout=90), "successor session response timeout"
        line = process.stdout.readline()
        assert line, "successor session exited before response"
        result = json.loads(line)
        reports.append(result)
        return result

    def request(value):
        if args.fee_session_migration:
            result = source_request(dict(command="successor", request=value))
            reports.append(result)
            return result
        process.stdin.write(json.dumps(value).encode() + b"\n")
        process.stdin.flush()
        return read()

    try:
        if process is not None:
            assert read()["status"] == "fee_session_open"
        before = (journal / "fee-reservations").read_bytes()
        refused = request(
            dict(
                command="lock",
                valid_for_seconds=600,
                value_nanotos="5000000000",
                output_dir=str(root / "forbidden-successor-lock"),
            )
        )
        assert (
            refused["status"] == "request_refused" and "possession proofs only" in refused["reason"]
        ), "successor authority preflight gate missing"
        assert (journal / "fee-reservations").read_bytes() == before
        boundary = template["epoch0"] + 3600
        assert int(time.time()) < boundary, "successor setup missed real recovery boundary"
        waiting = request(dict(command="status"))
        assert waiting["status"] == "request_refused" and "WaitUntil" in waiting["reason"]
        if getattr(args, "fee_session_rotation", False):
            args.rotation_clock.advance(60)
            scenario.pop("checkpoint_time", None)
            scenario_path.write_text(json.dumps(scenario))
        while int(time.time()) <= boundary:
            time.sleep(min(1, max(0.01, boundary + 1 - time.time())))
        assert request(dict(command="status"))["leaf"] == 4
        wrong_bits = data["module"].bits
        wrong_data = Cell(
            wrong_bits[:304] + ("0" if wrong_bits[304] == "1" else "1") + wrong_bits[305:],
            data["module"].refs,
        )
        wrong_state = native.active_account(addresses["module"], codes["module"], wrong_data)
        update(addresses["module"], wrong_state)
        invalid_output = root / "wrong-successor-module"
        refused = request(
            dict(
                command="pop",
                role="primary",
                valid_for_seconds=600,
                value_nanotos="5000000000",
                output_dir=str(invalid_output),
            )
        )
        assert refused["status"] == "request_refused", "successor POP accepted changed module data"
        assert "differs from enrolled deployment" in refused["reason"], refused
        assert not invalid_output.exists() and (journal / "fee-reservations").read_bytes() == before
        update(addresses["module"], states["module"])
        native.NOW = int(time.time())
        original_config = native.config

        def diagnostic(*a, **k):
            entries = shared.read_dict(original_config(17), 32)
            price = entries[21].refs[0]
            prefix = 136 if int(price.bits[:8], 2) == 0xD1 else 0
            offset = prefix + 8 + 64 * 3
            entries[21] = Cell().ref(
                Cell(price.bits[:offset] + f"{20000:064b}" + price.bits[offset + 64 :], price.refs)
            )
            return shared.make_dict(entries, 32)

        with patch.object(native, "config", diagnostic):
            emu = native.Emulator(global_version=17)
        receipts, challenges = [], set()
        roles = (
            ["primary", "rescue"]
            if getattr(args, "fee_session_rotation", False)
            else ["primary", "rescue", "primary"]
        )
        for index, role in enumerate(roles):
            output = root / f"successor-pop-{index}"
            signed = request(
                dict(
                    command="pop",
                    role=role,
                    valid_for_seconds=600,
                    value_nanotos="5000000000",
                    output_dir=str(output),
                )
            )
            assert signed["status"] == "fee_message_cached" and signed["leaf"] == 4 + index, signed
            assert signed["vault"] == f"0:{addresses['vault'][1]:064x}", (
                "POP used original fee route"
            )
            challenge = from_boc((output / "pop-request.boc").read_bytes())
            assert challenge.hash not in challenges, "successor repeated a POP challenge"
            challenges.add(challenge.hash)
            saved = (journal / "fee-reservations").read_bytes()
            retry = root / f"successor-retry-{index}"
            retried = request(
                dict(
                    command="retry",
                    intent=str(output / "pending-intent.boc"),
                    output_dir=str(retry),
                )
            )
            assert retried["status"] == "fee_message_cached"
            assert (retry / "message.boc").read_bytes() == (output / "message.boc").read_bytes()
            assert (journal / "fee-reservations").read_bytes() == saved
            message = from_boc((output / "message.boc").read_bytes())
            for name, filename in [("vault", "fee"), ("module", "module")]:
                assert (
                    from_boc((output / f"{filename}-observed-account.boc").read_bytes()).hash
                    == states[name].refs[0].hash
                )
            paid = emu.send(states["vault"], message)
            forwarded = shared.check_execution(paid, states["vault"], message, "successor fee")
            assert len(forwarded) == 1
            proved = emu.send(states["module"], forwarded[0])
            assert not shared.check_execution(
                proved, states["module"], forwarded[0], "successor POP"
            ), "successor POP emitted authority"
            module_data, _ = native.account_data(from_boc(proved["shard_account"]))
            assert module_data.hash == data["module"].hash
            receipts.append(dict(output=output, paid=paid, proved=proved, role=role))
            for name, outcome in [("vault", paid), ("module", proved)]:
                states[name] = from_boc(outcome["shard_account"])
                update(addresses[name], states[name])
                (args.output / f"successor-pop-{index}-{name}.json").write_text(
                    json.dumps(outcome, indent=2)
                )
            (args.output / f"successor-pop-{index}-message.boc").write_bytes(message.boc())
        continuation = None
        if args.fee_session_migration:
            from cli_migration_session import check_migration

            def continuation(url):
                return check_migration(
                    args,
                    root,
                    source_request,
                    request,
                    receipts,
                    url,
                    emu,
                    scenario_path,
                    original_addresses,
                    successor,
                    journal,
                    rotation_context=dict(
                        common=common,
                        template=template,
                        manifest=manifest,
                        pin=pin,
                        states=states,
                        addresses=addresses,
                        codes=codes,
                        data=data,
                        command=command,
                        custody=custody,
                    )
                    if getattr(args, "fee_session_rotation", False)
                    else None,
                )

        check_receipts(
            args,
            root,
            common + route,
            receipts,
            addresses,
            codes,
            data,
            successor=True,
            continuation=continuation,
        )
        (args.output / "successor-template.json").write_bytes(manifest.read_bytes())
        (args.output / "successor-session-reports.json").write_text(json.dumps(reports, indent=2))
        print(
            f"Prepared successor, independent custody, {len(roles)} funded POPs and authenticated receipts passed"
        )
    finally:
        if emu is not None:
            emu.close()
        if process is not None and process.poll() is None:
            process.stdin.write(b'{"command":"quit"}\n')
            process.stdin.flush()
            assert process.wait(timeout=10) == 0
        selector.close()
        err.close()

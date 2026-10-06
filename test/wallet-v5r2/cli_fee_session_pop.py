"""Fee-funded native PRIMARY/RESCUE POPs, followed by an actual wallet lock."""

import base64
import json
import time
from unittest.mock import patch

import cli_sign_primary as shared

native, Cell, from_boc = shared.native, shared.Cell, shared.from_boc


def check_pop_flow(args, root, request, journal, payload, codes, data, addresses):
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

    with patch.object(native, "config", lambda *a, **k: config_with_credit(20000)):
        emu = native.Emulator(global_version=17)
    with patch.object(native, "config", lambda *a, **k: config_with_credit(10000)):
        limited = native.Emulator(global_version=17)
    vault_before = native.active_account(addresses["vault"], codes["vault"], data["vault"])
    module_before = native.active_account(addresses["module"], codes["module"], data["module"])
    challenges = set()
    outcomes = []
    try:
        for offset, role in enumerate(["primary", "rescue", "primary"]):
            output = root / f"pop-{offset}"
            result = request(
                dict(
                    command="pop",
                    role=role,
                    valid_for_seconds=600,
                    value_nanotos="5000000000",
                    output_dir=str(output),
                )
            )
            assert result["status"] == "fee_message_cached", f"POP signing refused: {result}"
            assert result["leaf"] == 4 + offset
            pop = from_boc((output / "pop-request.boc").read_bytes())
            intent = from_boc((output / "pending-intent.boc").read_bytes())
            assert intent.refs[0].refs[0].hash == pop.hash, "fee payload changed retained POP"
            envelope = intent.slice()
            assert envelope.uint(32) == 0x46454534
            envelope.uint(136)
            assert envelope.uint(8) == 2, "POP used an authorization fee class"
            fields = pop.slice()
            assert fields.uint(32) == 0x504F5033
            fields.uint(32)
            fields.uint(256)
            assert fields.uint(8) == (1 if role == "primary" else 2), "POP signed the wrong role"
            challenge = fields.uint(256)
            assert challenge and challenge not in challenges, "POP reused a possession challenge"
            challenges.add(challenge)
            before_retry = (journal / "fee-reservations").read_bytes()
            retry = root / f"pop-retry-{offset}"
            retried = request(
                dict(
                    command="retry",
                    intent=str(output / "pending-intent.boc"),
                    output_dir=str(retry),
                )
            )
            assert retried["status"] == "fee_message_cached", retried
            message_bytes = (output / "message.boc").read_bytes()
            assert (retry / "message.boc").read_bytes() == message_bytes
            assert (journal / "fee-reservations").read_bytes() == before_retry
            message = from_boc(message_bytes)
            assert message.hash.hex() == result["message_hash"] == retried["message_hash"]
            rejected = limited.send(vault_before, message)
            assert not rejected["success"] and rejected.get("vm_exit_code") == -14, rejected
            paid = emu.send(vault_before, message)
            forwarded = shared.check_execution(paid, vault_before, message, "fee vault")
            assert len(forwarded) == 1
            proved = emu.send(module_before, forwarded[0])
            assert not shared.check_execution(proved, module_before, forwarded[0], "POP module"), (
                "POP emitted wallet authority"
            )
            module_after, _ = native.account_data(from_boc(proved["shard_account"]))
            assert module_after.hash == data["module"].hash, (
                "POP changed module authorization state"
            )
            vault_before = from_boc(paid["shard_account"])
            module_before = from_boc(proved["shard_account"])
            fee_data, balance = native.account_data(vault_before)
            counter = fee_data.slice()
            assert counter.uint(8) == 3 and counter.uint(32) == 5 + offset
            # Mock proof source advances to the account actually produced by the VM.
            scenario = json.loads((root / "scenario.json").read_text())
            account = scenario["accounts"][f"0:{addresses['vault'][1]:064x}"]
            account.update(
                state_boc=base64.b64encode(vault_before.refs[0].boc()).decode(),
                state_hash=vault_before.refs[0].hash.hex(),
                data_hash=fee_data.hash.hex(),
                balance=str(balance),
            )
            (root / "scenario.json").write_text(json.dumps(scenario))
            consumed = request(
                dict(
                    command="retry",
                    intent=str(output / "pending-intent.boc"),
                    output_dir=str(root / f"consumed-{offset}"),
                )
            )
            assert (
                consumed["status"] == "request_refused" and "already consumed" in consumed["reason"]
            )
            assert (journal / "fee-reservations").read_bytes() == before_retry
            for label, receipt in [("fee", paid), ("module", proved), ("default-credit", rejected)]:
                (args.output / f"pop-{offset}-{label}.json").write_text(
                    json.dumps(receipt, indent=2)
                )
            (args.output / f"pop-{offset}-message.boc").write_bytes(message_bytes)
            outcomes.append(
                dict(
                    role=role,
                    leaf=result["leaf"],
                    message_hash=message.hash.hex(),
                    challenge=f"{challenge:064x}",
                    no_authority_emitted=True,
                )
            )
        locked_dir = root / "after-pop-lock"
        signed = request(
            dict(
                command="lock",
                valid_for_seconds=600,
                value_nanotos="5000000000",
                output_dir=str(locked_dir),
            )
        )
        assert signed["status"] == "fee_message_cached" and signed["leaf"] == 7, signed
        message = from_boc((locked_dir / "message.boc").read_bytes())
        paid = emu.send(vault_before, message)
        forwarded = shared.check_execution(paid, vault_before, message, "fee vault")
        assert len(forwarded) == 1
        relayed = emu.send(module_before, forwarded[0])
        forwarded_wallet = shared.check_execution(relayed, module_before, forwarded[0], "module")
        assert len(forwarded_wallet) == 1
        wallet_before = native.active_account(addresses["wallet"], codes["wallet"], data["wallet"])
        locked = emu.send(wallet_before, forwarded_wallet[0])
        for label, receipt in [("fee", paid), ("module", relayed), ("wallet", locked)]:
            (args.output / f"post-pop-lock-{label}.json").write_text(json.dumps(receipt, indent=2))
        assert locked["success"], locked
        assert not shared.check_execution(locked, wallet_before, forwarded_wallet[0])
        wallet_after, _ = native.account_data(from_boc(locked["shard_account"]))
        authority = wallet_after.refs[0].slice()
        assert authority.uint(8) == 4 and authority.uint(2) == 2 and authority.uint(16) & 2
        assert authority.uint(64) == 2
        for label, receipt in [("fee", paid), ("module", relayed), ("wallet", locked)]:
            (args.output / f"post-pop-lock-{label}.json").write_text(json.dumps(receipt, indent=2))
        (args.output / "pop-results.json").write_text(
            json.dumps(
                dict(
                    outcomes=outcomes,
                    subsequent_lock_leaf=7,
                    diagnostic_credit=20000,
                    scope="Mock proof acquisition, real encrypted native signatures and local VM execution; POP grants no authority; not production admission or live finality",
                ),
                indent=2,
            )
            + "\n"
        )
    finally:
        emu.close()
        limited.close()
    print("3 fresh fee-funded POPs and subsequent native wallet lock passed")


if __name__ == "__main__":
    shared.main()

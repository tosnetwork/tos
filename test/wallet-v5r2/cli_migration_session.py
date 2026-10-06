"""Joint journal session: funded successor POPs through actual wallet migration."""

import base64
import json
import time

import cli_sign_primary as shared

Cell, from_boc, native = shared.Cell, shared.from_boc, shared.native


def check_migration(
    args,
    root,
    source_request,
    successor_request,
    receipts,
    url,
    emu,
    scenario_path,
    original_addresses,
    successor,
    successor_journal,
):
    def files(item):
        folder = item["output"]
        return dict(
            pop_request=str(folder / "pop-request.boc"),
            external_message=str(folder / "message.boc"),
            fee_before_account=str(folder / "fee-observed-account.boc"),
            module_before_account=str(folder / "module-observed-account.boc"),
        )

    scenario = json.loads(scenario_path.read_text())
    scenario["checkpoint_time"] = int(time.time())
    scenario_path.write_text(json.dumps(scenario))
    output = root / "migration"
    evidence = dict(
        primary_pop=files(receipts[0]),
        rescue_pop=files(receipts[1]),
        history=dict(transaction_rpc_url=url, history_limit=8, timeout_seconds=5),
        valid_for_seconds=600,
        value_nanotos="5000000000",
        output_dir=str(output),
    )
    old_journal = root / "journal" / "fee-reservations"
    new_journal = successor_journal / "fee-reservations"
    old_before, new_before = old_journal.read_bytes(), new_journal.read_bytes()
    refused = {}
    for name, change, expected in [
        ("duplicate_role", dict(primary_pop=files(receipts[1])), "one POP for each key"),
        (
            "wrong_challenge",
            dict(
                primary_pop=dict(files(receipts[0]), pop_request=str(root / "wrong-challenge.boc"))
            ),
            "challenge differs",
        ),
        (
            "history_budget",
            dict(history=dict(evidence["history"], history_limit=1)),
            "history budget exhausted",
        ),
    ]:
        destination = root / ("migration-" + name)
        report = source_request(
            dict(command="migrate", evidence=dict(evidence, **change, output_dir=str(destination)))
        )
        assert report["status"] == "request_refused" and expected in report["reason"], (
            f"migration accepted {name}: {report}"
        )
        assert not destination.exists(), f"migration touched output before {name} refusal"
        assert old_journal.read_bytes() == old_before and new_journal.read_bytes() == new_before
        refused[name] = report
    signed = source_request(dict(command="migrate", evidence=evidence))
    assert signed["status"] == "fee_message_cached" and signed["leaf"] == 5, signed
    assert signed["vault"] == f"0:{original_addresses['vault'][1]:064x}", (
        "migration used successor fee route"
    )
    assert new_journal.read_bytes() == new_before, "migration consumed successor readiness leaf"
    assert (output / "pending-intent.boc").is_file(), (
        "migration fee signature exported without retained intent"
    )
    old_after = old_journal.read_bytes()
    retry = root / "migration-retry"
    retried = source_request(
        dict(command="retry", intent=str(output / "pending-intent.boc"), output_dir=str(retry))
    )
    assert retried["status"] == "fee_message_cached", retried
    assert (retry / "message.boc").read_bytes() == (output / "message.boc").read_bytes()
    assert old_journal.read_bytes() == old_after and new_journal.read_bytes() == new_before

    # Burn the remaining successor slot leaf without broadcasting it. On-chain
    # capacity remains unchanged, but another migration must respect local state.
    burned = successor_request(
        dict(
            command="pop",
            role="primary",
            valid_for_seconds=600,
            value_nanotos="5000000000",
            output_dir=str(root / "unbroadcast-successor-pop"),
        )
    )
    assert burned["status"] == "fee_message_cached" and burned["leaf"] == 7, burned
    burned_state = new_journal.read_bytes()
    refused_output = root / "migration-local-exhaustion"
    exhausted = source_request(
        dict(command="migrate", evidence=dict(evidence, output_dir=str(refused_output)))
    )
    assert exhausted["status"] == "request_refused" and "WaitUntil" in exhausted["reason"], (
        "migration ignored local successor reservations"
    )
    assert not refused_output.exists() and old_journal.read_bytes() == old_after
    assert new_journal.read_bytes() == burned_state
    refused["local_exhaustion"] = exhausted

    def observed(name):
        value = scenario["accounts"][f"0:{original_addresses[name][1]:064x}"]
        return (
            Cell()
            .uint(int(value["last_trans_hash"], 16), 256)
            .uint(value["last_trans_lt"], 64)
            .ref(from_boc(base64.b64decode(value["state_boc"])))
        )

    message = from_boc((output / "message.boc").read_bytes())
    paid = emu.send(observed("vault"), message)
    forwarded = shared.check_execution(paid, observed("vault"), message, "migration fee")
    assert len(forwarded) == 1
    authorized = emu.send(observed("module"), forwarded[0])
    forwarded = shared.check_execution(
        authorized, observed("module"), forwarded[0], "migration module"
    )
    assert len(forwarded) == 1
    installed = emu.send(observed("wallet"), forwarded[0])
    assert not shared.check_execution(
        installed, observed("wallet"), forwarded[0], "migration wallet"
    )
    wallet_data, _ = native.account_data(from_boc(installed["shard_account"]))
    auth = wallet_data.refs[0]
    assert auth.refs[0].hash == from_boc(bytes.fromhex(successor["module_init"])).hash
    assert auth.refs[1].hash == from_boc(bytes.fromhex(successor["metadata"])).hash
    previous_data, _ = native.account_data(observed("wallet"))
    previous_auth = previous_data.refs[0]
    assert auth.bits[:26] == previous_auth.bits[:26], "migration changed mode or retirement"
    assert int(auth.bits[26:90], 2) == int(previous_auth.bits[26:90], 2) + 1
    assert int(auth.bits[90:218], 2) == 0, "migration did not reset role counters"
    current = from_boc(installed["shard_account"])
    current_data, balance = native.account_data(current)
    history = current.slice()
    last_hash, last_lt = history.uint(256), history.uint(64)
    record = scenario["accounts"][f"0:{original_addresses['wallet'][1]:064x}"]
    record.update(
        state_boc=base64.b64encode(current.refs[0].boc()).decode(),
        state_hash=current.refs[0].hash.hex(),
        data_hash=current_data.hash.hex(),
        balance=str(balance),
        last_trans_hash=f"{last_hash:064x}",
        last_trans_lt=last_lt,
    )
    scenario_path.write_text(json.dumps(scenario))
    old_route = source_request(
        dict(
            command="lock",
            valid_for_seconds=600,
            value_nanotos="5000000000",
            output_dir=str(root / "stale-source-lock"),
        )
    )
    assert (
        old_route["status"] == "request_refused"
        and "installed module/fee tuple mismatch" in old_route["reason"]
    ), "old enrollment still signed after migration"
    assert old_journal.read_bytes() == old_after
    refused["old_enrollment"] = old_route
    for name, value in (("fee", paid), ("module", authorized), ("wallet", installed)):
        (args.output / f"migration-{name}.json").write_text(json.dumps(value, indent=2))
    for path in output.iterdir():
        (args.output / ("migration-" + path.name)).write_bytes(path.read_bytes())
    (args.output / "migration-reports.json").write_text(
        json.dumps(dict(signed=signed, refusals=refused), indent=2)
    )
    print(
        "Joint sessions, dual funded POPs, exact migration retry and native wallet installation passed"
    )

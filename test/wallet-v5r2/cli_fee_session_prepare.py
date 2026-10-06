"""Persistent fee session prepares both successor accounts in the native VM."""

import base64
import hmac
import json
import os
import subprocess
import time
from unittest.mock import patch

import cli_sign_primary as shared

native, Cell, from_boc = shared.native, shared.Cell, shared.from_boc


def check_preparation(args, root, request, journal, payload, codes, data, addresses, common):
    original = json.loads(args.fixture.read_text())["input"]
    template = dict(payload)
    template.pop("expected_wallet", None)
    derivation = template.pop("recovery_derivation")
    for name in ("primary_key", "rescue_key", "fee_public_key", "fee_tree_id"):
        template[name] = original[name]
    template["policy"] = 2
    if args.successor_fee_fixture:
        vectors = json.loads(
            (
                shared.ROOT / "tosctl/src/tos-native-mnemonic/tests/fixtures/native-pq.json"
            ).read_text()
        )
        vector = vectors["vectors"][0]
        fee_vector = json.loads(
            (args.successor_fee_fixture / "native-fee-recovery.json").read_text()
        )
        context = fee_vector["context"]
        derivation = dict(
            derivation,
            account_index=context["account_index"],
            key_generation=context["key_generation"],
        )

        def derived(label, size):
            label = label.encode()
            info = bytes([1, len(label)]) + label + bytes.fromhex(template["network"])
            info += context["global_id"].to_bytes(4, "big", signed=True)
            info += context["account_index"].to_bytes(4, "big")
            info += context["key_generation"].to_bytes(4, "big")
            prk = hmac.digest(
                b"TOS-WALLET-DUALROOT-KDF-v1", bytes.fromhex(vector["master_hex"]), "sha256"
            )
            first = hmac.digest(prk, info + b"\x01", "sha256")
            return (first + hmac.digest(prk, first + info + b"\x02", "sha256"))[:size].hex()

        subprocess.run(
            [
                os.environ["MLDSA_TOOL"],
                "keygen",
                derived("ML-DSA-44", 32),
                str(root / "successor.pub"),
                str(root / "PUBLIC-TEST-ONLY-successor.secret"),
            ],
            check=True,
        )
        template["primary_key"] = (root / "successor.pub").read_bytes().hex()
        template["rescue_key"] = subprocess.check_output(
            [os.environ["SLH_TOOL"], "keygen", derived("SLH-DSA-SHA2-128s", 48)], text=True
        ).split()[0]
        template["fee_public_key"] = fee_vector["public_key_hex"]
        template["fee_tree_id"] = fee_vector["tree_id_hex"]
        template["epoch0"] = int(time.time()) - 3600 + 45
        for name in ["primary_key", "rescue_key", "fee_public_key"]:
            assert template[name] != payload[name], "successor reused source key"

    def genesis(value):
        run = subprocess.run(
            [str(args.genesis_driver.resolve())],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            timeout=60,
        )
        assert run.returncode == 0, run.stderr
        return json.loads(run.stdout)

    initial = genesis(template)
    pin = from_boc(bytes.fromhex(initial["wallet_init"])).hash.hex()
    enrolled = genesis(dict(template, expected_wallet=pin, recovery_derivation=derivation))
    manifest = root / "successor-template.json"
    manifest.write_text(enrolled["recovery_manifest"])
    successor = genesis(dict(template, existing_wallet=payload["expected_wallet"]))
    chosen = (
        Cell()
        .uint(0xA1, 8)
        .uint(int(payload["network"], 16), 256)
        .uint(0, 64)
        .uint(0, 16)
        .uint(0, 1)
        .uint(int("5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0", 16), 256)
    )
    scenario_path = root / "scenario.json"
    scenario = json.loads(scenario_path.read_text())
    scenario["config_params"] = [
        dict(index=48, cell_hash=chosen.hash.hex(), boc=base64.b64encode(chosen.boc()).decode())
    ]
    scenario_path.write_text(json.dumps(scenario))
    output = root / "prepared"
    operation = dict(
        command="prepare",
        successor_manifest=str(manifest),
        expected_template_wallet=pin,
        module_nanotos="10000000000",
        vault_nanotos="20000000000",
        valid_for_seconds=600,
        value_nanotos="50000000000",
        output_dir=str(output),
    )
    before = (journal / "fee-reservations").read_bytes()
    failures = {}
    if args.expect_fee_reuse_refusal:
        refused = request(operation)
        assert (
            refused["status"] == "request_refused"
            and "reuses active LMS public key" in refused["reason"]
        ), f"preparation accepted reused active LMS key: {refused}"
        assert not output.exists() and (journal / "fee-reservations").read_bytes() == before
        (args.output / "reused-fee-key-refusal.json").write_text(json.dumps(refused, indent=2))
        print("Reused active LMS key refused before output, custody and reservation")
        return
    for label, change in [
        ("wrong_template", dict(expected_template_wallet="ff" * 32)),
        ("zero_module", dict(module_nanotos="0")),
        ("overflow", dict(module_nanotos=str(2**128 - 1), vault_nanotos="1")),
        ("insufficient_funding", dict(value_nanotos="30000000000")),
    ]:
        target = root / label
        refused = request(dict(operation, **change, output_dir=str(target)))
        assert refused["status"] == "request_refused", f"preparation accepted {label}"
        assert not target.exists(), f"preparation touched output before rejecting {label}"
        assert (journal / "fee-reservations").read_bytes() == before
        failures[label] = refused
    # READY must respect current PRIMARY retirement. REQUIRED preparation must
    # remain available even when ConfigParam 48 cannot be supplied.
    ready = dict(template, policy=1)
    ready_genesis = genesis(ready)
    ready_pin = from_boc(bytes.fromhex(ready_genesis["wallet_init"])).hash.hex()
    ready_enrolled = genesis(dict(ready, expected_wallet=ready_pin, recovery_derivation=derivation))
    ready_file = root / "ready-template.json"
    ready_file.write_text(ready_enrolled["recovery_manifest"])
    retired = (
        Cell()
        .uint(0xA1, 8)
        .uint(int(payload["network"], 16), 256)
        .uint(0, 64)
        .uint(2, 16)
        .uint(0, 1)
        .uint(int("5e4380aedc95f8cb72de55f7506de0269b47c03ad1d1ed0e5184c332544262c0", 16), 256)
    )
    scenario["config_params"] = [
        dict(index=48, cell_hash=retired.hash.hex(), boc=base64.b64encode(retired.boc()).decode())
    ]
    scenario_path.write_text(json.dumps(scenario))
    for label in ["ready_retired", "ready_missing_policy"]:
        if label == "ready_missing_policy":
            scenario["config_params"] = []
            scenario_path.write_text(json.dumps(scenario))
        target = root / label
        result = request(
            dict(
                operation,
                successor_manifest=str(ready_file),
                expected_template_wallet=ready_pin,
                output_dir=str(target),
            )
        )
        assert result["status"] == "request_refused", f"preparation accepted {label}"
        assert not target.exists() and (journal / "fee-reservations").read_bytes() == before
        failures[label] = result
    if getattr(args, "fee_session_rotation", False):
        from cli_rotation_session import check_full_history_refusal

        destination = root / "full-history-prepare"
        check_full_history_refusal(
            args,
            request,
            dict(operation, output_dir=str(destination)),
            journal / "fee-reservations",
            destination,
            "prepare",
        )
    expected_leaf = (
        request(dict(command="status"))["leaf"]
        if getattr(args, "fee_session_rotation", False)
        else 4
    )
    signed = request(operation)
    assert signed["status"] == "fee_message_cached" and signed["leaf"] == expected_leaf, (
        f"REQUIRED preparation depended on PRIMARY policy: {signed}"
    )
    after = (journal / "fee-reservations").read_bytes()
    assert len(after) > len(before), "preparation did not reserve a fee leaf"
    intent = from_boc((output / "pending-intent.boc").read_bytes())
    envelope = intent.slice()
    assert envelope.uint(32) == 0x46454534
    envelope.uint(136)
    assert envelope.uint(8) == 3, "preparation used wrong fee class"
    retained = from_boc((output / "preparation-request.boc").read_bytes())
    assert intent.refs[0].refs[0].hash == retained.hash, "preparation changed retained request"
    for name in ["module", "vault"]:
        exported = from_boc((output / f"successor-{name}-init.boc").read_bytes())
        assert exported.hash == from_boc(bytes.fromhex(successor[f"{name}_init"])).hash
    retry = root / "prepare-retry"
    retried = request(
        dict(command="retry", intent=str(output / "pending-intent.boc"), output_dir=str(retry))
    )
    assert retried["status"] == "fee_message_cached", retried
    assert (retry / "message.boc").read_bytes() == (output / "message.boc").read_bytes()
    assert (journal / "fee-reservations").read_bytes() == after

    native.NOW = int(time.time())
    original_config = native.config

    def config(credit):
        entries = shared.read_dict(original_config(17), 32)
        price = entries[21].refs[0]
        prefix = 136 if int(price.bits[:8], 2) == 0xD1 else 0
        offset = prefix + 8 + 64 * 3
        entries[21] = Cell().ref(
            Cell(price.bits[:offset] + f"{credit:064b}" + price.bits[offset + 64 :], price.refs)
        )
        return shared.make_dict(entries, 32)

    def observed(name):
        value = scenario["accounts"][f"0:{addresses[name][1]:064x}"]
        return (
            Cell()
            .uint(int(value["last_trans_hash"], 16), 256)
            .uint(value["last_trans_lt"], 64)
            .ref(from_boc(base64.b64decode(value["state_boc"])))
        )

    message = from_boc((output / "message.boc").read_bytes())
    with patch.object(native, "config", lambda *a, **k: config(10000)):
        limited = native.Emulator(global_version=17)
    with patch.object(native, "config", lambda *a, **k: config(20000)):
        emu = native.Emulator(global_version=17)
    try:
        rejected = limited.send(observed("vault"), message)
        assert not rejected["success"] and rejected.get("vm_exit_code") == -14
        paid = emu.send(observed("vault"), message)
        forwarded = shared.check_execution(paid, observed("vault"), message, "preparation fee")
        assert len(forwarded) == 1
        prepared = emu.send(observed("module"), forwarded[0])
        deployments = shared.check_execution(
            prepared, observed("module"), forwarded[0], "preparation module"
        )
        assert len(deployments) == 2, "preparation did not emit both deployments"
        unchanged, _ = native.account_data(from_boc(prepared["shard_account"]))
        assert unchanged.hash == data["module"].hash, "preparation changed current authority"
        deployed_states = {}
        for name, deployment, amount in zip(["module", "vault"], deployments, [10**10, 2 * 10**10]):
            target = from_boc(bytes.fromhex(successor[f"{name}_init"]))
            fields = deployment.slice()
            fields.uint(4)
            assert fields.addr() == addresses["module"]
            assert fields.addr() == (0, int.from_bytes(target.hash, "big"))
            assert fields.coins() == amount and deployment.refs[0].hash == target.hash
            empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
            deployed = emu.send(empty, deployment)
            assert not shared.check_execution(deployed, empty, deployment, f"successor {name}")
            final, balance = native.account_data(from_boc(deployed["shard_account"]))
            assert (
                final.hash == from_boc(bytes.fromhex(successor[f"{name}_data"])).hash
                and balance > 0
            )
            deployed_states[name] = from_boc(deployed["shard_account"])
            (args.output / f"prepare-deployed-{name}.json").write_text(
                json.dumps(deployed, indent=2)
            )
        for name, value in [("fee", paid), ("module", prepared), ("default-credit", rejected)]:
            (args.output / f"prepare-{name}.json").write_text(json.dumps(value, indent=2))
        for path in output.iterdir():
            (args.output / ("prepare-" + path.name)).write_bytes(path.read_bytes())
        (args.output / "prepare-controls.json").write_text(json.dumps(failures, indent=2))
        print("6 preparation refusals, exact retry and both native successor deployments passed")
        if args.successor_fee_fixture:
            from cli_successor_pop import check_successor_pops

            check_successor_pops(
                args,
                root,
                common,
                template,
                manifest,
                pin,
                successor,
                deployed_states,
                paid,
                prepared,
                addresses,
                source_request=request,
            )

    finally:
        emu.close()
        limited.close()

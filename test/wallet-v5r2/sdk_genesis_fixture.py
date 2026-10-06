"""Compare SDK genesis cells and actually deploy all three accounts from StateInit."""

import json
import subprocess

import native
from cells import Cell, from_boc


def encode(
    driver,
    out,
    *,
    wallet,
    module,
    vault,
    primary,
    rescue,
    fee_key,
    expected,
    policy=1,
    tree_id=456,
    existing_wallet=None,
):
    payload = dict(
        wallet_code=wallet.boc().hex(),
        module_code=module.boc().hex(),
        vault_code=vault.boc().hex(),
        wallet_pin=wallet.hash.hex(),
        module_pin=module.hash.hex(),
        vault_pin=vault.hash.hex(),
        global_id=42,
        network=f"{123:064x}",
        wallet_id=42,
        primary_key=primary.hex(),
        rescue_key=rescue.hex(),
        policy=policy,
        fee_tree_id=f"{tree_id:064x}",
        fee_public_key=fee_key.hex(),
        epoch0=native.NOW - 2 * 3600 - 10,
    )
    if existing_wallet is not None:
        payload["existing_wallet"] = f"{existing_wallet:064x}"
    if existing_wallet is None:
        # Public fixture declarations only; these keys are not derived from a backup.
        payload["recovery_derivation"] = dict(
            account_index=5,
            key_generation=7,
            primary_seed_profile="raw-master-32-v1",
            rescue_seed_profile="raw-master-32-v1",
            fee_seed_profile="raw-master-32-v1",
        )
        payload["expected_wallet"] = expected["wallet_init"].hash.hex()
    result = subprocess.run(
        [str(driver.resolve())], input=json.dumps(payload), capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    if existing_wallet is None:
        manifest = json.loads(response["recovery_manifest"])
        assert manifest["wallet_state_init"] == payload["expected_wallet"]
        controls = []
        for field in ("wallet_state_init", "module_state_init", "vault_state_init", "wallet_code"):
            changed = dict(manifest)
            changed[field] = "ff" * 32
            altered = dict(payload, recovery_manifest=json.dumps(changed))
            rejected = subprocess.run(
                [str(driver.resolve())], input=json.dumps(altered), capture_output=True, text=True
            )
            assert rejected.returncode != 0 and "manifest" in rejected.stderr, field
            controls.append(field)
        # A valid manifest cannot choose its own independent enrollment identity.
        altered = dict(
            payload, recovery_manifest=response["recovery_manifest"], expected_wallet="ff" * 32
        )
        rejected = subprocess.run(
            [str(driver.resolve())], input=json.dumps(altered), capture_output=True, text=True
        )
        assert rejected.returncode != 0 and "trusted enrollment" in rejected.stderr
        controls.append("independent_wallet")
        response["manifest_rejections"] = controls
    actual = {name: from_boc(bytes.fromhex(response[name])) for name in expected}
    for name, cell in expected.items():
        assert actual[name].hash == cell.hash, name
    assert (
        response["config_hash"]
        == f"{expected['vault_data'].slice().uint(296) & ((1 << 256) - 1):064x}"
    )
    out.write_text(json.dumps({"input": payload, "output": response}, indent=2) + "\n")
    return actual


def deploy(e, out, cells):
    out.mkdir(parents=True, exist_ok=True)
    accounts = {}
    for name, value in [("module", 10**12), ("wallet", 10**15), ("vault", 10**15)]:
        init, data = cells[name + "_init"], cells[name + "_data"]
        address = (0, int.from_bytes(init.hash, "big"))
        message = (
            Cell()
            .uint(4, 4)
            .addr((0, 999))
            .addr(address)
            .coins(value)
            .uint(0, 1)
            .coins(0)
            .coins(0)
            .uint(0, 64)
            .uint(native.NOW, 32)
            .uint(1, 1)
            .uint(1, 1)
            .uint(1, 1)
            .ref(init)
            .ref(Cell())
        )
        empty = Cell().uint(0, 320).ref(Cell().uint(0, 1))
        result = e.send(empty, message)
        (out / f"{name}.json").write_text(json.dumps(result, indent=2) + "\n")
        assert result["success"] and result["details"]["exit"] == 0
        assert not result["details"]["aborted"]
        assert not native.outgoing(from_boc(result["transaction"]))
        account = from_boc(result["shard_account"])
        actual, balance = native.account_data(account)
        assert actual.hash == data.hash and 0 < balance < value
        accounts[name] = account
    return accounts

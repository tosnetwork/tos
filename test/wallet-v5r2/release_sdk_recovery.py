"""Deploy SDK enrollment and recover with native journal-backed fee signatures.

Uses unchanged generated ConfigParams for both transaction executors. Trusted
local fixture times/keys are public test data, not production custody evidence.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--examples", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    examples = args.examples.resolve()
    raw = args.config.read_bytes()
    command = [
        sys.executable,
        ROOT / "test/wallet-v5r2/fee_tx_parity.py",
        "--chain-config",
        args.config.resolve(),
        "--driver",
        examples / "pq-tx-parity",
        "--genesis-driver",
        examples / "v5r2_genesis_encode",
        "--fee-driver",
        examples / "v5r2_fee_encode",
        "--preparation-driver",
        examples / "v5r2_prepare_encode",
        "--cache-driver",
        examples / "lms_fee_cache_fixture",
        "--prepare",
        "--recovery",
        "--output",
        out / "transactions",
    ]
    env = dict(os.environ, TOS_TEST_REQUIRE_NATIVE_FEE="1")
    with (out / "transactions.log").open("w") as log:
        result = subprocess.run(
            list(map(str, command)), cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT
        )
    assert result.returncode == 0, "SDK recovery transactions failed"
    folder = out / "transactions"
    parity = json.loads((folder / "parity.json").read_text())
    assert parity["success"] and parity["expected_transactions"] == 67
    assert parity["observed_transactions"] == 67 and not parity["differences"]
    assert (folder / "config.boc").read_bytes() == raw
    native = folder / "native"
    cache = json.loads((native / "sdk-cache/summary.json").read_text())
    assert cache["backend_kind"] == "native-lms"
    assert cache["signer_calls"] == 1 and cache["restart_retry_signer_calls"] == 0
    assert all(
        cache[name]
        for name in (
            "retry_bytes_identical",
            "wrong_intent_rejected",
            "wrong_public_key_rejected",
            "restart_signing_blocked",
            "corrupted_backend_rejected_and_leaf_burned",
        )
    )
    recovery = json.loads((native / "recovery-summary.json").read_text())
    assert recovery["recipient_received"] and recovery["sdk_cached_signatures"] == 6
    assert recovery["funded_pop_roles"] == [1, 2] and not recovery["primary_auth_signing_used"]
    genesis = json.loads((native / "sdk-genesis.json").read_text())
    for name in ("wallet", "module", "vault"):
        receipt = json.loads((native / "genesis-deployment" / (name + ".json")).read_text())
        assert receipt["success"] and receipt["details"]["exit"] == 0
        assert receipt["details"]["compute_success"] and not receipt["details"]["aborted"]
    signature_count = 0
    for session in ("sdk-old", "sdk-new"):
        for path in (native / "recovery" / session).glob("*-sign.json"):
            record = json.loads(path.read_text())
            request, signed = record["request"], record["result"]
            signature_count += 1
            assert signed["backend_kind"] == "native-lms" and signed["backend_calls"] == 1
            assert (
                signed["route"]["global_id"]
                == genesis["input"]["global_id"]
                == request["global_id"]
            )
            assert signed["route"]["network"] == genesis["input"]["network"] == request["network"]
            assert request["vm_version"] == 18
    assert signature_count == 6, "missing persistent native signing evidence"
    assert args.config.read_bytes() == raw
    report = dict(
        passed=True,
        command=list(map(str, command)),
        exit=result.returncode,
        config_sha256=hashlib.sha256(raw).hexdigest(),
        parity=parity,
        recovery=recovery,
        cache=cache,
        identity={name: genesis["input"][name] for name in ("global_id", "network", "wallet_id")},
        scope=__doc__,
    )
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

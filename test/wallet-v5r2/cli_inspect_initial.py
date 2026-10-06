"""Exercise CLI proof orchestration with a mock local verifier, not cryptographic proofs."""

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402
from native import active_account  # noqa: E402

# The executable is explicitly provisioned as trusted by this test. It echoes
# request binding and supplies synthetic evidence around real compiled fixtures.
VERIFIER = r"""
import hashlib, json, pathlib, sys, time
args = sys.argv
root = pathlib.Path(args[args.index("--material") + 1])
request_bytes = pathlib.Path(args[args.index("--request") + 1]).read_bytes()
request = json.loads(request_bytes)
scenario = json.loads((root / "scenario.json").read_text())
anchor = json.loads(pathlib.Path(args[args.index("--anchor") + 1]).read_text())
with (root / "requests.jsonl").open("a") as f:
    f.write(json.dumps(request) + "\n")
if scenario["mode"] == "refusal":
    print(json.dumps({"status": "refused", "reason": "test refusal"}))
    sys.exit(1)
now = int(time.time())
account = scenario["accounts"][request["account"]]
account["gen_utime"] = now - (120 if scenario["mode"] == "stale_account" else 0)
target = dict(workchain=-1, shard="8000000000000000", seqno=7,
    root_hash="11"*32, file_hash="22"*32, gen_utime=now)
# Fix both observations to the first read's time even if a second ticks over.
stamp = root / "stamp"
if request["mode"] == "live":
    stamp.write_text(str(now))
target["gen_utime"] = int(stamp.read_text())
if scenario["mode"] == "other_checkpoint" and request["mode"] == "historical":
    target["root_hash"] = "33"*32
out = dict(status="verified", interface="tos-proof-verify/1", mode=request["mode"],
    anchor=anchor, target=target, account=account,
    request_sha256=hashlib.sha256(request_bytes).hexdigest())
if scenario["mode"] == "wrong_request":
    out["request_sha256"] = "ff"*32
if request["mode"] == "live":
    out["live"] = dict(now=now, age_seconds=now-target["gen_utime"],
        max_age_seconds=request["max_age_seconds"])
print(json.dumps(out))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    fixture = json.loads(args.fixture.read_text())
    inputs, outputs = fixture["input"], fixture["output"]
    results = {}
    with tempfile.TemporaryDirectory(prefix="pq-inspect-") as tmp:
        root = Path(tmp)
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
        (root / "anchor.json").write_text(json.dumps(anchor))
        config = dict(
            executable=str(verifier),
            anchor_file=str(root / "anchor.json"),
            material_dir=str(root),
            live_state_file=str(root / "live.json"),
            live_max_age_seconds=60,
            timeout_seconds=10,
            min_interval_ms=0,
        )
        manifest = outputs["recovery_manifest"]
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        (root / "manifest.json").write_text(json.dumps(manifest))
        common = [
            "--recovery-manifest",
            str(root / "manifest.json"),
            "--expected-wallet",
            manifest["wallet_state_init"],
            "--proof-config",
            str(root / "config.json"),
        ]
        accounts = {}
        for role in ("wallet", "module", "vault"):
            code = from_boc(bytes.fromhex(inputs[role + "_code"]))
            data = from_boc(bytes.fromhex(outputs[role + "_data"]))
            init = from_boc(bytes.fromhex(outputs[role + "_init"]))
            address = (0, int.from_bytes(init.hash, "big"))
            account = active_account(address, code, data, balance=100_000_000_000).refs[0]
            (root / (role + ".boc")).write_bytes(code.boc())
            common += [
                f"--{role}-code",
                str(root / (role + ".boc")),
                f"--{role}-code-hash",
                inputs[role + "_pin"],
            ]
            accounts[f"0:{init.hash.hex()}"] = dict(
                exists=True,
                active=True,
                address=f"0:{init.hash.hex()}",
                state_boc=base64.b64encode(account.boc()).decode(),
                state_hash=account.hash.hex(),
                balance="100000000000",
                code_hash=code.hash.hex(),
                data_hash=data.hash.hex(),
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
        for mode in (
            "valid",
            "refusal",
            "wrong_request",
            "other_checkpoint",
            "stale_account",
            "wrong_wallet_pin",
            "loose_age",
            "module_data",
        ):
            scenario = dict(mode=mode, accounts=json.loads(json.dumps(accounts)))
            command = common.copy()
            conf = dict(config)
            if mode == "wrong_wallet_pin":
                command[command.index("--expected-wallet") + 1] = "ff" * 32
            if mode == "loose_age":
                conf["live_max_age_seconds"] = 61
            if mode == "module_data":
                address = "0:" + manifest["module_state_init"]
                data = Cell().uint(0, 8)
                code = from_boc(bytes.fromhex(inputs["module_code"]))
                account = active_account(
                    (0, int(manifest["module_state_init"], 16)), code, data, balance=100_000_000_000
                ).refs[0]
                scenario["accounts"][address].update(
                    state_boc=base64.b64encode(account.boc()).decode(),
                    state_hash=account.hash.hex(),
                    data_hash=data.hash.hex(),
                )
            (root / "config.json").write_text(json.dumps(conf))
            (root / "scenario.json").write_text(json.dumps(scenario))
            (root / "requests.jsonl").write_text("")
            result = subprocess.run(
                [str(args.cli.resolve()), "wallet", "pq-inspect-initial", *command],
                capture_output=True,
                text=True,
                timeout=45,
            )
            (args.output / (mode + ".stdout")).write_text(result.stdout)
            (args.output / (mode + ".stderr")).write_text(result.stderr)
            assert (result.returncode == 0) == (mode == "valid"), (mode, result.stderr)
            requests = [
                json.loads(line) for line in (root / "requests.jsonl").read_text().splitlines()
            ]
            if mode == "valid":
                report = json.loads(result.stdout)
                assert report["status"] == "initial_wallet_pair_proven"
                assert report["wallet"] == "0:" + manifest["wallet_state_init"]
                assert report["module"] == "0:" + manifest["module_state_init"]
                assert report["seqno"] == 0 and report["primary_nonce"] == 0
                assert len(requests) == 2 and requests[0]["mode"] == "live"
                assert requests[1]["mode"] == "historical"
                assert requests[1]["target"] == report["checkpoint"]
            else:
                assert not result.stdout.strip(), "refusal emitted a success report"
                if mode in ("wrong_wallet_pin", "loose_age"):
                    assert not requests, "local invalid input invoked verifier"
                if mode == "module_data":
                    assert "deployed module data mismatch" in result.stderr
            results[mode] = dict(exit=result.returncode, requests=len(requests))
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} initial inspection CLI outcomes passed (mock verifier boundary only)")


if __name__ == "__main__":
    main()

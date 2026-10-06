"""Use Rust SDK AUTH bytes in the real funded recovery and dual-executor suite."""

import argparse
import inspect
import json
import runpy
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
import native  # noqa: E402
import test_receiver_auth  # noqa: E402
from cells import from_boc  # noqa: E402
from test_rescue_e2e import digest  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-signer", type=Path)
    parser.add_argument("--genesis-driver", type=Path)
    parser.add_argument("--fee-driver", type=Path)
    parser.add_argument("--preparation-driver", type=Path)
    parser.add_argument("--pop-driver", type=Path)
    parser.add_argument("--pop-role", type=int, choices=(1, 2))
    parser.add_argument("--auth-driver", type=Path, required=True)
    parser.add_argument("--cache-driver", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    original = test_receiver_auth.request
    calls = []

    def request(*pos, **kw):
        expected = original(*pos, **kw)
        binding = inspect.signature(original).bind(*pos, **kw)
        binding.apply_defaults()
        fields = binding.arguments
        assert fields["account"][0] == 0
        body = expected.refs[0]
        refs = body.refs
        replacement = fields["kind"] == 1 and bool(refs)
        if replacement:
            refs = refs[0].refs
        payload = dict(
            global_id=fields["global_id"],
            network=f"{fields['network']:064x}",
            account=f"{fields['account'][1]:064x}",
            module=f"{fields['root']:064x}",
            epoch=fields["epoch"],
            nonce=fields["nonce"],
            deadline=fields["deadline"],
            proven_time=fields["deadline"] - 600,
            role=fields["role"],
            kind=fields["kind"],
            refs=[ref.boc().hex() for ref in refs],
            replacement=replacement,
        )
        # Time here is fixture data only; the adapter does not verify chain proofs.
        assert payload["proven_time"] >= native.NOW
        result = subprocess.run(
            [str(args.auth_driver.resolve())],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
        )
        assert result.returncode == 0, result.stderr
        encoded = json.loads(result.stdout)
        actual = from_boc(bytes.fromhex(encoded["request"]))
        assert actual.hash == expected.hash
        assert encoded["digest"] == digest(expected).hex()
        context = (
            b"TOS-AUTH-V2-ML-DSA-44-v1" if fields["role"] == 1 else b"TOS-AUTH-SLH-DSA-SHA2-128S-v1"
        )
        assert encoded["context"] == context.hex()
        calls.append({"input": payload, "output": encoded})
        return actual

    argv = [
        "fee_tx_parity.py",
        "--driver",
        str(args.driver),
        "--cache-driver",
        str(args.cache_driver),
        "--output",
        str(out),
    ]
    if args.genesis_driver:
        argv += ["--genesis-driver", str(args.genesis_driver)]
        if not args.pop_role:
            argv += ["--migration-gate"]
    if args.fee_driver:
        argv += ["--fee-driver", str(args.fee_driver)]
    if args.preparation_driver:
        assert args.pop_role is None
        argv += ["--preparation-driver", str(args.preparation_driver)]
    argv += ["--pop-role", str(args.pop_role)] if args.pop_role else ["--prepare", "--recovery"]
    with ExitStack() as stack:
        if args.native_signer:
            from native_signer_fixture import NativeSignerFixture

            native_signer = NativeSignerFixture(args.native_signer)
            native_signer.install(stack)
        if args.pop_driver:
            import test_pop
            from sdk_pop_fixture import PopEncoder

            pop_encoder = PopEncoder(args.pop_driver, test_pop.signed)
            stack.enter_context(patch.object(test_pop, "signed", pop_encoder.signed))
        stack.enter_context(patch.object(test_receiver_auth, "request", request))
        stack.enter_context(patch.object(sys, "argv", argv))
        runpy.run_path(str(Path(__file__).with_name("fee_tx_parity.py")), run_name="__main__")
    if args.genesis_driver and not args.pop_role:
        recovery = json.loads((out / "native/recovery-summary.json").read_text())
        assert recovery["proven_wallet_migration_gate"] is True
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).with_name("recorded_migration_gate.py")),
                "--fixtures",
                str(out / "native"),
                "--output",
                str(out / "native/recovery/sdk-migration.boc"),
                "--verify-execution",
            ],
            check=True,
        )
    assert [call["input"]["kind"] for call in calls] == ([0] if args.pop_role else [0, 3, 4, 0])
    if args.pop_driver:
        assert [call["input"]["role"] for call in pop_encoder.calls] == (
            [args.pop_role] if args.pop_role else [2, 2, 1]
        )
        (out / "sdk-pop.json").write_text(json.dumps(pop_encoder.calls, indent=2) + "\n")
    (out / "sdk-auth.json").write_text(json.dumps(calls, indent=2) + "\n")
    if args.native_signer:
        assert native_signer.calls, "native signer was not exercised"
        (out / "native-wallet-signatures.json").write_text(
            json.dumps(native_signer.calls, indent=2) + "\n"
        )
    print("SDK wire bytes match Python and execute in both VMs")


if __name__ == "__main__":
    main()

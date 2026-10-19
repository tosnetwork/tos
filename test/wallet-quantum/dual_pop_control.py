"""Corrupt a funded successor primary POP and require migration to stop."""

import argparse
import json
import os
import runpy
import sys
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
import funded_recovery  # noqa: E402
from cells import Cell  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-signer", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    for name in ["PUBLIC-TEST-ONLY-lms-tree", "PUBLIC-TEST-ONLY-successor-tree"]:
        os.link(args.baseline / "native" / name, out / name)
    original = funded_recovery.run

    def corrupt(e, directory, **kwargs):
        constructor = kwargs["primary_pop"]

        def primary(now):
            body = constructor(now)
            signature = body.refs[1]
            changed = Cell(
                bits=("1" if signature.bits[0] == "0" else "0") + signature.bits[1:],
                refs=signature.refs,
            )
            return Cell(bits=body.bits, refs=[body.refs[0], changed])

        kwargs["primary_pop"] = primary
        return original(e, directory, **kwargs)

    with ExitStack() as stack:
        from native_signer_fixture import NativeSignerFixture

        signer = NativeSignerFixture(args.native_signer)
        signer.install(stack)
        stack.enter_context(patch.object(funded_recovery, "run", corrupt))
        stack.enter_context(
            patch.object(
                sys,
                "argv",
                [
                    "test_fee_delivery.py",
                    "--prepare",
                    "--recovery",
                    "--credit-probe",
                    "--output",
                    str(out),
                ],
            )
        )
        try:
            runpy.run_path(
                str(Path(__file__).with_name("test_fee_delivery.py")), run_name="__main__"
            )
        except AssertionError as error:
            assert "successor-primary-pop-module" in str(error), str(error)
        else:
            raise AssertionError("corrupt primary POP completed migration")
    fee = json.loads((out / "recovery/successor-primary-pop-fee.json").read_text())
    module = json.loads((out / "recovery/successor-primary-pop-module.json").read_text())
    assert fee["success"] and fee["details"]["exit"] == 0 and not fee["details"]["aborted"]
    assert module["success"] and module["details"]["exit"] == 1808 and module["details"]["aborted"]
    assert not (out / "recovery/migrate-wallet.json").exists()
    (out / "control.json").write_text(
        json.dumps(
            {
                "fee_exit": 0,
                "module_exit": 1808,
                "migration_attempted": False,
                "scope": "Actual native rejection of a corrupt primary POP under a valid funded envelope; diagnostic credit only",
            },
            indent=2,
        )
        + "\n"
    )
    print("Corrupt primary POP rejected after valid fee delivery; migration not attempted")


if __name__ == "__main__":
    main()

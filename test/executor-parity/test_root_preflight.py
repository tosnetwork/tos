"""Later malformed typed inputs must fail before any root transaction output."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/rel02"), str(ROOT / "test/auth-extensions")]
from cells import Cell, from_boc  # noqa: E402
from transaction_roots import run_rust  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    configuration = args.fixtures / "ext-accept-config.boc"
    good = (args.fixtures / "ext-accept-roots.tsv").read_text().splitlines()[1]
    reports = []
    for kind in ("Account", "Message"):
        fields = good.split("\t")
        if kind == "Account":
            original = from_boc(bytes.fromhex(fields[3]))
            fields[3] = Cell(bits=original.bits, refs=[Cell()]).boc().hex()
        else:
            fields[4] = Cell().boc().hex()
        inputs = args.output / f"bad-{kind}.tsv"
        inputs.write_text("#pq-tx-roots-v1\n" + good + "\n" + "\t".join(fields) + "\n")
        label = "bad-" + kind
        try:
            run_rust.execute(
                [
                    str(args.driver.resolve()),
                    str(configuration.resolve()),
                    str(inputs.resolve()),
                    "16",
                    "--roots",
                ],
                args.output,
                label,
            )
        except ValueError as error:
            diagnostic = str(error)
            assert "failed (exit 1;" in diagnostic
            assert "invalid root input record 1" in diagnostic
            assert f"invalid original {kind} during root preflight" in diagnostic
        else:
            raise AssertionError(f"malformed {kind} was accepted")
        assert (args.output / f"{label}.stdout").read_bytes() == b"", (
            "transaction output before complete typed preflight",
            kind,
        )
        reports.append(dict(kind=kind, rejected=True, stdout_rows=0))
    (args.output / "summary.json").write_text(json.dumps(reports, indent=2) + "\n")
    print("PASS: later malformed Account and Message rejected before any transaction output")


if __name__ == "__main__":
    main()

"""Measure private function-extraction experiments without changing production source."""

import argparse
import json
import os
import runpy
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def transform(source, variant):
    if variant.startswith("bounds"):
        start = source.index("  ;; Fee-relative class bounds:")
        end = source.index("  throw_unless(2010, (amount >= floor)", start)
        declaration = "(int, int, int) r2fee_bounds(int kind, int setup_module, int setup_vault)"
        call = "  var (floor, ceiling, reserve) = r2fee_bounds(kind, setup_module, setup_vault);\n"
        result = "  return (floor, ceiling, reserve);\n"
    else:
        start = source.index("  slice ps = r2fee_child(payload);")
        end = source.index("  r2fee_address(module);", start)
        declaration = (
            "(int, int) r2fee_payload(int kind, cell payload, slice prefix, int pop_parties)"
        )
        call = "  var (setup_module, setup_vault) = r2fee_payload(kind, payload, prefix, pop_parties);\n"
        result = "  return (setup_module, setup_vault);\n"
    modifier = "inline" if variant == "bounds-inline" else "inline_ref"
    helper = declaration + " impure " + modifier + " {\n" + source[start:end] + result + "}\n\n"
    source = source[:start] + call + source[end:]
    position = source.index("() recv_internal(")
    return source[:position] + helper + source[position:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=("bounds", "bounds-inline", "payload"), required=True)
    parser.add_argument("--route", choices=("auth", "pop", "prepare"), required=True)
    parser.add_argument("--trees", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for tree in ("PUBLIC-TEST-ONLY-lms-tree", "PUBLIC-TEST-ONLY-successor-tree"):
        if not (args.output / tree).exists():
            os.link(args.trees / tree, args.output / tree)
    original = ROOT / "crypto/smartcont/wallet-v5r2-fee-vault.fc"
    source = original.read_text()
    candidate = transform(source, args.variant)
    (args.output / "candidate.fc").write_text(candidate)
    copy = shutil.copyfile

    def copy_candidate(src, dst, **kwargs):
        if Path(src).resolve() == original:
            Path(dst).write_text(candidate)
            return dst
        return copy(src, dst, **kwargs)

    argv = ["test_fee_delivery.py", "--credit-probe", "--gas-trace", "--output", str(args.output)]
    argv += {"auth": [], "pop": ["--pop-role", "2"], "prepare": ["--prepare"]}[args.route]
    sys.path.insert(0, str(Path(__file__).parent))
    with patch.object(shutil, "copyfile", copy_candidate), patch.object(sys, "argv", argv):
        runpy.run_path(str(Path(__file__).with_name("test_fee_delivery.py")), run_name="__main__")
    assert original.read_text() == source, "experiment modified production source"
    result = json.loads((args.output / "credit-probe.json").read_text())
    print(json.dumps({"variant": args.variant, "route": args.route, "probe": result}))


if __name__ == "__main__":
    main()

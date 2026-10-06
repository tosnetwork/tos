"""Measure private compiler-layout experiments without changing production source."""

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
    if variant == "verify-before-budget":
        check = (
            "  throw_unless(2007, lms_check_fee_hash(cell_hash(intent), leaf, signature, key));\n"
        )
        anchor = "  ;; Fee-relative class bounds:"
        assert source.count(check) == source.count(anchor) == 1
        # All binding, budget and signature checks remain before ACCEPT. This
        # experiment changes rejection work ordering and is not adoption approval.
        return source.replace(check, "").replace(anchor, check + anchor)
    if variant == "literal-request-tags":
        helpers = """(slice, int) r2fee_pop_tag(slice s) asm "x{504f5033} SDBEGINSQ";
(slice, int) r2fee_prepare_tag(slice s) asm "x{50525033} SDBEGINSQ";
"""
        anchor = "const int r2fee::max_cells"
        assert source.count(anchor) == 1
        source = source.replace(anchor, helpers + anchor)
        for name, tag in [("pop", "504f5033"), ("prepare", "50525033")]:
            old = f"    throw_unless(2012, request~load_uint(32) == 0x{tag});"
            assert source.count(old) == 1
            source = source.replace(
                old,
                f"    (request, int tag_ok) = r2fee_{name}_tag(request);\n    throw_unless(2012, tag_ok);",
            )
        return source
    if variant == "bounds-payload":
        return transform(transform(source, "bounds"), "payload")
    if variant == "late-send":
        # Retain all admission checks; reconstruct send-only values after ACCEPT
        # so the compiler need not preserve them throughout fee/signature checks.
        source = source.replace("  slice immutable = ds;\n", "")
        source = source.replace(
            "  accept_message();\n",
            """  accept_message();
  slice immutable = get_data().begin_parse().skip_bits(40);
  slice parties = immutable.skip_bits(256 + 32);
  module = parties~load_msg_addr();
  payload = intent.begin_parse().preload_ref();
""",
        )
        return source
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


def prepare_output(output):
    # Retained evidence must never be silently replaced by a repeat experiment.
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("admission experiment requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--variant",
        choices=(
            "bounds",
            "bounds-inline",
            "payload",
            "late-send",
            "bounds-payload",
            "verify-before-budget",
            "literal-request-tags",
        ),
        required=True,
    )
    parser.add_argument("--route", choices=("auth", "pop", "prepare"), required=True)
    parser.add_argument("--trees", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare_output(args.output)
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

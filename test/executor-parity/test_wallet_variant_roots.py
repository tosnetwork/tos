"""Mutate actual wallet artifacts, including coherently wrong claimed roots."""

import argparse
import copy
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from wallet_variant_roots import (
    FAMILIES,
    ROOT,
    json_value,
    profiles,
    read,
    run_files,
    validate_run,
    wallet_expected,
)

CONTROLS = (
    "missing",
    "extra",
    "reordered",
    "transaction-root",
    "account-root",
    "shard-root",
    "coherent-native",
    "native-missing",
    "configuration",
    "source",
    "harness",
    "profile",
    "candidate",
    "dirty",
    "case-population",
    "receipt-field",
    "oversize",
    *(f"input-{index}" for index in range(9)),
)


def controls(directory, family, source, *, allow_dirty=False):
    signatures, counts = validate_run(directory, family, source, allow_dirty=allow_dirty)
    results = []
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        for name in run_files(family):
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / name, target)
        originals = {}

        def write(name, raw):
            path = work / name
            originals.setdefault(name, path.read_bytes())
            path.write_bytes(raw)

        def write_json(name, value):
            write(name, (json.dumps(value) + "\n").encode())

        def run_check():
            return validate_run(work, family, source, allow_dirty=allow_dirty)

        assert run_check() == (signatures, counts)
        prefix = "configuration-0/"
        input_name = prefix + "wallet-variant-roots.tsv"
        inputs = read(work / input_name).decode().splitlines()
        output_name = prefix + "wallet-variant-root-driver.stdout"
        outputs = read(work / output_name).decode().splitlines()
        native_name = prefix + "wallet-variant-root-native.json"
        oracles = json_value(read(work / native_name))
        first = next(i for i, row in enumerate(oracles) if row["success"])
        for kind in CONTROLS:
            witness = ""
            if kind in {"missing", "extra", "reordered"}:
                changed = inputs.copy()
                if kind == "missing":
                    changed.pop()
                elif kind == "extra":
                    changed.append(changed[-1])
                else:
                    changed[1], changed[2] = changed[2], changed[1]
                write(input_name, ("\n".join(changed) + "\n").encode())
                witness = (
                    "wallet call order" if kind == "reordered" else "wallet linked record count"
                )
            elif kind.endswith("-root"):
                changed = outputs.copy()
                row = changed[first].split("\t")
                row[{"transaction-root": 2, "account-root": 3, "shard-root": 4}[kind]] = "0" * 64
                changed[first] = "\t".join(row)
                write(output_name, ("\n".join(changed) + "\n").encode())
                witness = "wallet root output changed"
            elif kind == "coherent-native":
                changed = copy.deepcopy(oracles)
                other = next(
                    row
                    for row in oracles
                    if row["success"] and row["transaction"] != changed[first]["transaction"]
                )
                changed[first] = copy.deepcopy(other)
                write_json(native_name, changed)
                derived = [
                    "\t".join(wallet_expected(line.split("\t")[0], oracle))
                    for line, oracle in zip(inputs[1:], changed, strict=True)
                ]
                for name in (output_name, prefix + "wallet-variant-root-expected.tsv"):
                    write(name, ("\n".join(derived) + "\n").encode())
                witness = "wallet native baseline outcome or roots changed"
            elif kind == "native-missing":
                write_json(native_name, oracles[:-1])
                witness = "wallet oracle population"
            elif kind == "configuration":
                from cells import Cell, make_dict, read_dict
                from root_cells import from_boc

                name = prefix + "config.boc"
                cfg = from_boc(read(work / name))
                entries = read_dict(cfg.refs[0], 32)
                assert 200 not in entries
                entries[200] = Cell().ref(Cell().uint(1, 1))
                write(name, Cell(bits=cfg.bits).ref(make_dict(entries, 32)).boc())
                witness = "wallet configuration wire changed"
            elif kind.startswith("input-"):
                changed = inputs.copy()
                row = changed[1].split("\t")
                column = int(kind.split("-")[1])
                row[column] = "changed" if column == 0 else row[column] + "0"
                changed[1] = "\t".join(row)
                write(input_name, ("\n".join(changed) + "\n").encode())
                witness = "wallet call order" if column == 0 else "wallet original input changed"
            elif kind == "case-population":
                name = "native/results.json" if family == "preparation" else "native/report.json"
                value = json_value(read(work / name))
                if family == "preparation":
                    value.pop(next(iter(value)))
                else:
                    value["cases"].pop()
                write_json(name, value)
                witness = "wallet native cases"
            elif kind == "oversize":
                write(input_name, b"x" * (2 * 1024 * 1024 + 1))
                witness = "wallet-variant artifact size limit"
            else:
                name = "wallet-variant-receipt.json"
                value = json_value(read(work / name))
                field, replacement, witness = {
                    "source": ("source", "0" * 40, "wallet receipt source"),
                    "harness": ("harness_sha256", "0" * 64, "wallet harness source"),
                    "profile": ("profile_sha256", "0" * 64, "wallet input profile receipt"),
                    "candidate": ("recorded_profile", True, "wallet producer did not pass"),
                    "dirty": ("source_diff_sha256", "0" * 64, "wallet source had tracked changes"),
                    "receipt-field": ("unexpected", True, "wallet receipt fields"),
                }[kind]
                value[field] = replacement
                write_json(name, value)
            try:
                # Even author-mode checks must exercise the dirty-source guard.
                validate_run(work, family, source, allow_dirty=allow_dirty and kind != "dirty")
            except AssertionError as error:
                assert witness in str(error), (family, kind, witness, str(error))
                results.append(dict(mutation=kind, rejected=True, witness=witness))
            else:
                raise AssertionError(f"wallet mutation survived: {family}/{kind}")
            for name, raw in originals.items():
                (work / name).write_bytes(raw)
            originals.clear()
            assert run_check() == (signatures, counts), (
                "wallet controls failed to restore artifacts"
            )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="Author exploration only")
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    profiles()
    results = {
        family: controls(args.artifacts / family, family, source, allow_dirty=args.allow_dirty)
        for family in FAMILIES
    }
    value = dict(source=source, passed=True, mutations=results)
    args.output.write_text(json.dumps(value, indent=2) + "\n")
    print("PASS:", sum(map(len, results.values())), "actual wallet artifact mutations rejected")


if __name__ == "__main__":
    main()

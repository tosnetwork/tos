"""Require module population and oracle checks to reject damaged real artifacts."""

# ruff: noqa: E402
import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "test/falcon-auth"))
from linked_roots import MODULE_CODES, compare_module_architectures
from native import Cell, Emulator, from_boc
from transaction_roots import expected_row


def changed_native(artifacts, family, kind):
    fields = (artifacts / f"{family}-roots.tsv").read_text().splitlines()[2].split("\t")
    original = from_boc(bytes.fromhex(fields[3]))
    if kind == "profile":
        account = original.refs[0]
        # A real ordinary contract outside this profile, not a malformed BOC.
        account = Cell(bits=account.bits, refs=[Cell().raw(b"\xf8\x00"), *account.refs[1:]])
        shard = Cell(bits=original.bits, refs=[account])
    else:
        account = original.refs[0]
        storage = account.slice()
        assert storage.uint(1)
        storage.addr()
        storage.varuint(7)
        storage.varuint(7)
        if storage.uint(3) == 1:
            storage.uint(256)
        storage.uint(32)
        if storage.uint(1):
            storage.coins()
        offset = len(account.bits) - len(storage.bits)
        # Account storage end LT must exceed the ShardAccount transaction start LT.
        account = Cell(
            bits=account.bits[:offset] + f"{2:064b}" + account.bits[offset + 64 :],
            refs=account.refs,
        )
        shard = Cell().uint(1, 256).uint(1, 64).ref(account)
    configuration = from_boc((artifacts / f"{family}-config.boc").read_bytes())
    emulator = Emulator.from_config(configuration.refs[0])
    try:
        emulator.lib.transaction_emulator_set_unixtime.restype = ctypes.c_bool
        assert emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, int(fields[1]))
        emulator.lt = int(fields[2]) - 1_000_000
        result = emulator.send(shard, from_boc(bytes.fromhex(fields[4])))
    finally:
        emulator.close()
    assert result["success"] is True, ("native control setup did not execute", kind, result)
    fields[3] = shard.boc().hex()
    oracle = {key: result[key] for key in ("success", "transaction", "shard_account")}
    return "\t".join(fields), oracle, "\t".join(expected_row(fields[0], oracle))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--family", choices=tuple(MODULE_CODES), required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    args = parser.parse_args()
    os.environ["EMULATOR_PATH"] = str(args.emulator.resolve())
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    family = args.family
    controls = {
        kind: changed_native(args.artifacts, family, kind) for kind in ("profile", "predecessor")
    }
    (args.artifacts / f"{family}-root-control-native.json").write_text(
        json.dumps(controls, indent=2) + "\n"
    )
    cases = {
        "missing": "linked record count mismatch",
        "extra": "linked record count mismatch",
        "reordered": "linked population order changed",
        "roots": "linked root mismatch",
        "native": "invalid linked native outcome",
        "time": "native time mismatch",
        "config": "unexpected linked v16 config",
        "source": "stale module source",
        "receipt": "stale module receipt",
        "producer": "module producer failed",
        "profile": "module profile code mismatch",
        "predecessor": "unexpected module predecessor",
    }
    for kind, diagnostic in cases.items():
        with tempfile.TemporaryDirectory(prefix="module-root-control-") as temp:
            sides = [Path(temp) / side / "transactions" for side in ("left", "right")]
            for side in sides:
                side.mkdir(parents=True)
                (side.parent / "commit.txt").write_text(source + "\n")
                for item in args.artifacts.glob(f"{family}-*"):
                    if item.is_file():
                        shutil.copyfile(item, side / item.name)
                shutil.copyfile(args.artifacts / "tx-parity.json", side / "tx-parity.json")
                paths = [
                    side / f"{family}-{name}"
                    for name in ("roots.tsv", "root-driver.stdout", "root-expected.tsv")
                ]
                raw = side / f"{family}-root-native.json"
                receipt = side / f"{family}-root-receipt.json"
                if kind in ("missing", "extra", "roots"):
                    for path in paths[1:]:
                        rows = path.read_text().splitlines()
                        if kind == "missing":
                            rows.pop()
                        elif kind == "extra":
                            rows.append(rows[-1])
                        else:
                            fields = rows[3].split("\t")
                            fields[2] = "0" * 64
                            rows[3] = "\t".join(fields)
                        path.write_text("\n".join(rows) + "\n")
                elif kind == "reordered":
                    for path in paths:
                        rows = path.read_text().splitlines()
                        rows[-1], rows[-2] = rows[-2], rows[-1]
                        path.write_text("\n".join(rows) + "\n")
                    rows = json.loads(raw.read_text())
                    rows[-1], rows[-2] = rows[-2], rows[-1]
                    raw.write_text(json.dumps(rows))
                elif kind in controls:
                    original, oracle, expected = controls[kind]
                    for path, index, replacement in [
                        (paths[0], 2, original),
                        (paths[1], 1, expected),
                        (paths[2], 1, expected),
                    ]:
                        rows = path.read_text().splitlines()
                        rows[index] = replacement
                        path.write_text("\n".join(rows) + "\n")
                    rows = json.loads(raw.read_text())
                    rows[1] = oracle
                    raw.write_text(json.dumps(rows))
                elif kind == "native":
                    rows = json.loads(raw.read_text())
                    rows[0]["success"] = False
                    raw.write_text(json.dumps(rows))
                elif kind == "time":
                    rows = paths[0].read_text().splitlines()
                    fields = rows[1].split("\t")
                    fields[1] = str(int(fields[1]) + 1)
                    rows[1] = "\t".join(fields)
                    paths[0].write_text("\n".join(rows) + "\n")
                elif kind == "config":
                    path = side / f"{family}-config.boc"
                    path.write_bytes(b"wrong-config")
                    report = json.loads(receipt.read_text())
                    report["configuration_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    receipt.write_text(json.dumps(report))
                elif kind == "source":
                    (side.parent / "commit.txt").write_text("0" * 40)
                elif kind == "receipt":
                    report = json.loads(receipt.read_text())
                    report["source_commit"] = "0" * 40
                    receipt.write_text(json.dumps(report))
                elif kind == "producer":
                    report = json.loads((side / "tx-parity.json").read_text())
                    report["success"] = False
                    (side / "tx-parity.json").write_text(json.dumps(report))
            try:
                compare_module_architectures(*sides, family, source)
            except AssertionError as error:
                assert diagnostic in str(error), (kind, diagnostic, error)
            else:
                raise AssertionError(f"{kind}: damaged module artifacts survived")
    compare_module_architectures(args.artifacts, args.artifacts, family, source)
    print(
        f"PASS: {family} twelve controls and restored local artifacts (not architecture evidence)"
    )


if __name__ == "__main__":
    main()

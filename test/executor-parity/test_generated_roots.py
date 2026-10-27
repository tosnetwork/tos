"""Actual generated-config native controls; coherent wrong artifacts on both sides."""

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

sys.path.extend(
    str(Path(__file__).resolve().parents[2] / path)
    for path in ("test/auth-extensions", "test/wallet-quantum")
)

from cells import Cell, make_dict, read_dict
from fee_tx_parity import transcript
from generated_bundle import CONTROL_CASES, FOLDERS
from generated_roots import POST, RELEASE, ROOT, validate
from native import Emulator, transaction_details
from root_cells import from_boc
from transaction_roots import expected_row


def write_lines(path, lines):
    path.write_text("\n".join(lines) + "\n")


def rederive(directory, family, lines, oracles, raw):
    (directory / "config.boc").write_bytes(raw)
    write_lines(directory / f"{family}-roots.tsv", ["#pq-tx-roots-v1", *lines])
    expected = [
        "\t".join(expected_row(line.split("\t")[0], oracle))
        for line, oracle in zip(lines, oracles, strict=True)
    ]
    for suffix in ("-root-driver.stdout", "-root-expected.tsv"):
        write_lines(directory / (family + suffix), expected)
    (directory / f"{family}-root-native.json").write_text(json.dumps(oracles) + "\n")
    legacy, native = [], []
    for line, oracle in zip(lines, oracles, strict=True):
        name, now, lt, shard, message, *_ = line.split("\t")
        name = name.split(":", 1)[1]
        legacy.append(
            "\t".join(
                [name, now, lt, from_boc(bytes.fromhex(shard)).refs[0].boc().hex(), message, "-"]
            )
        )
        result = dict(oracle)
        if result["success"]:
            result["details"] = transaction_details(from_boc(result["transaction"]))
        native.append(transcript(name, result))
    write_lines(directory / "scenarios.tsv", legacy)
    for name in ("native.tsv", "rust.tsv"):
        write_lines(directory / name, native)
    receipt_path = directory / f"{family}-receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["configuration_sha256"] = hashlib.sha256(raw).hexdigest()
    receipt_path.write_text(json.dumps(receipt))
    path = directory / "result.json"
    report = json.loads(path.read_text())
    report["config_sha256"] = hashlib.sha256(raw).hexdigest()
    if family == RELEASE:
        report["config_root"] = from_boc(raw).refs[0].hash.hex()
        for row, oracle in zip(report["cases"], oracles, strict=True):
            row["gas"] = transaction_details(from_boc(oracle["transaction"]))["gas"]
    else:
        for row, oracle in zip(report["measurements"], oracles, strict=True):
            row["exit"] = (
                transaction_details(from_boc(oracle["transaction"]))["exit"]
                if oracle["success"]
                else oracle["vm_exit_code"]
            )
            if oracle["success"]:
                row["gas"] = transaction_details(from_boc(oracle["transaction"]))["gas"]
    path.write_text(json.dumps(report))


def runtime_control(directory, family, kind):
    lines = (directory / f"{family}-roots.tsv").read_text().splitlines()[1:]
    root = from_boc((directory / "config.boc").read_bytes())
    if kind == "config":
        entries = read_dict(root.refs[0], 32)
        assert 200 not in entries
        entries[200] = Cell().ref(Cell().uint(1, 1))
        root = Cell(bits=root.bits, refs=[make_dict(entries, 32)])
    records, changed = [], []
    for index, line in enumerate(lines):
        fields = line.split("\t")
        shard = from_boc(bytes.fromhex(fields[3]))
        message = from_boc(bytes.fromhex(fields[4]))
        if kind == "code":
            account = shard.refs[0]
            code = account.refs[0]
            code = Cell(bits="00000000" + code.bits, refs=code.refs)
            shard = Cell(
                bits=shard.bits, refs=[Cell(bits=account.bits, refs=[code, *account.refs[1:]])]
            )
        emulator = Emulator.from_config(root.refs[0], vm_log_verbosity=0)
        try:
            emulator.lib.transaction_emulator_set_unixtime.restype = ctypes.c_bool
            assert emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, int(fields[1]))
            emulator.lt = int(fields[2]) - 1_000_000
            native = emulator.send(shard, message)
        finally:
            emulator.close()
        if family == POST and index < 2:
            assert native["success"] is False and native["external_not_accepted"] is True
            assert native["vm_exit_code"] == (0 if index == 0 else -14), (
                "native control setup changed refusal"
            )
        else:
            assert native["success"] is True, (
                "native control setup failed",
                family,
                kind,
                index,
                native,
            )
        fields[3] = shard.boc().hex()
        changed.append("\t".join(fields))
        records.append(
            {
                key: native[key]
                for key in (
                    "success",
                    "transaction",
                    "shard_account",
                    "external_not_accepted",
                    "vm_exit_code",
                    "error",
                )
                if key in native
            }
        )
    return changed, records, root.boc()


def controls(directory, family, source):
    original_lines = (directory / f"{family}-roots.tsv").read_text().splitlines()[1:]
    original_oracles = json.loads((directory / f"{family}-root-native.json").read_text())
    alternatives = {kind: runtime_control(directory, family, kind) for kind in ("config", "code")}
    (directory / f"{family}-native-controls.json").write_text(
        json.dumps(
            {
                kind: {"lines": lines, "native": oracles, "configuration": raw.hex()}
                for kind, (lines, oracles, raw) in alternatives.items()
            }
        )
        + "\n"
    )
    for kind in CONTROL_CASES:
        diagnostic = {
            "missing": "generated record count mismatch",
            "extra": "generated record count mismatch",
            "reordered": "generated population order changed",
            "roots": "generated root mismatch",
            "boc": "generated native BOC missing",
            "rejection-exit": "generated external rejection mismatch"
            if family == POST
            else "generated native classification mismatch",
            "native": "generated external classification mismatch"
            if family == POST
            else "generated native classification mismatch",
            "rejection": "generated external rejection mismatch"
            if family == POST
            else "generated native classification mismatch",
            "rejection-message": "generated original message mismatch",
            "time": "generated time/LT mismatch",
            "lt": "generated time/LT mismatch",
            "context": "generated execution context mismatch",
            "code": "generated probe code mismatch",
            "workchain": "generated address/workchain mismatch",
            "config": "unexpected generated configuration",
            "source": "stale generated source",
            "producer": "generated producer report mismatch",
        }[kind]
        with tempfile.TemporaryDirectory(prefix="generated-control-") as temporary:
            for side in ("left", "right"):
                target = Path(temporary) / side
                shutil.copytree(directory, target)
                lines = list(original_lines)
                oracles = json.loads(json.dumps(original_oracles))
                if kind in alternatives:
                    rederive(target, family, *alternatives[kind])
                elif kind in ("missing", "extra", "roots"):
                    for suffix in ("-root-driver.stdout", "-root-expected.tsv"):
                        path = target / (family + suffix)
                        values = path.read_text().splitlines()
                        if kind == "missing":
                            values.pop()
                        elif kind == "extra":
                            values.append(values[-1])
                        else:
                            fields = values[-1].split("\t")
                            fields[2] = "0" * 64
                            values[-1] = "\t".join(fields)
                        write_lines(path, values)
                elif kind == "reordered":
                    lines[0], lines[1] = lines[1], lines[0]
                    write_lines(target / f"{family}-roots.tsv", ["#pq-tx-roots-v1", *lines])
                elif kind == "boc":
                    del oracles[2 if family == POST else 0]["transaction"]
                    (target / f"{family}-root-native.json").write_text(json.dumps(oracles))
                elif kind in ("native", "rejection", "rejection-exit"):
                    if family == POST:
                        if kind == "native":
                            oracles[0]["success"] = True
                        elif kind == "rejection-exit":
                            del oracles[0]["vm_exit_code"]
                        else:
                            oracles[0]["vm_exit_code"] = -14
                            rederive(
                                target, family, lines, oracles, (target / "config.boc").read_bytes()
                            )
                    else:
                        oracles[0] = dict(success=False, external_not_accepted=True, vm_exit_code=0)
                    (target / f"{family}-root-native.json").write_text(json.dumps(oracles))
                elif kind in ("time", "lt", "context", "workchain", "rejection-message"):
                    fields = lines[0].split("\t")
                    if kind in ("time", "lt"):
                        fields[1 if kind == "time" else 2] = str(
                            int(fields[1 if kind == "time" else 2]) + 1
                        )
                    elif kind == "context":
                        fields[8] = "1"
                    elif kind == "workchain":
                        shard = from_boc(bytes.fromhex(fields[3]))
                        account = shard.refs[0]
                        fields[3] = (
                            Cell(
                                bits=shard.bits,
                                refs=[
                                    Cell(
                                        bits=account.bits[:4] + "1" * 8 + account.bits[12:],
                                        refs=account.refs,
                                    )
                                ],
                            )
                            .boc()
                            .hex()
                        )
                    else:
                        message = from_boc(bytes.fromhex(fields[4]))
                        fields[4] = (
                            Cell(bits=message.bits, refs=[Cell().uint(0, 1).uint(2, 32)])
                            .boc()
                            .hex()
                        )
                    lines[0] = "\t".join(fields)
                    rederive(target, family, lines, oracles, (target / "config.boc").read_bytes())
                elif kind == "source":
                    path = target / f"{family}-receipt.json"
                    value = json.loads(path.read_text())
                    value["source"] = "0" * 40
                    path.write_text(json.dumps(value))
                else:
                    path = target / "result.json"
                    value = json.loads(path.read_text())
                    value["passed"] = False
                    path.write_text(json.dumps(value))
                try:
                    validate(target, family, source)
                except AssertionError as error:
                    assert diagnostic in str(error), (family, kind, diagnostic, error)
                else:
                    raise AssertionError(f"{family}/{kind}: damaged generated artifacts survived")
    validate(directory, family, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--post", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.environ["EMULATOR_PATH"] = str(args.emulator.resolve())
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    for directory, family in ((args.release, RELEASE), (args.post, POST)):
        controls(directory, family, source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            dict(
                source=source,
                passed=True,
                families={family: list(CONTROL_CASES) for family in FOLDERS},
            ),
            indent=2,
        )
        + "\n"
    )
    print(
        "PASS: thirty-four generated-config actual-artifact controls, both-side damage, restored originals"
    )


if __name__ == "__main__":
    main()

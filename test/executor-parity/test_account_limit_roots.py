"""Real account-ceiling oracle mutations, including coherent wrong populations."""

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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT / "test/falcon-auth"))
import account_limit_context
from linked_roots import compare_account_limit_architectures
from native import Cell, Emulator
from root_cells import from_boc
from transaction_roots import expected_row

FAMILY = "account-limit-v16"


def runtime_control(artifacts, kind):
    lines = (artifacts / f"{FAMILY}-roots.tsv").read_text().splitlines()[1:]
    config = (artifacts / f"{FAMILY}-config.boc").read_bytes()
    if kind == "config":
        with patch.object(account_limit_context, "ORDINARY_CEILING", 65537):
            dictionary = account_limit_context.configuration(16)
        config = Cell(bits=from_boc(config).bits).ref(dictionary).boc()
    changes = []
    for index in range(4) if kind == "config" else [0 if kind == "action" else 1]:
        fields = lines[index].split("\t")
        shard, message = from_boc(bytes.fromhex(fields[3])), from_boc(bytes.fromhex(fields[4]))
        account = shard.refs[0]
        if kind == "code":
            account = Cell(bits=account.bits, refs=[Cell().raw(b"\xf8\x00"), *account.refs[1:]])
            shard = Cell(bits=shard.bits, refs=[account])
        elif kind == "workchain":
            account = Cell(bits=account.bits[:4] + "0" * 8 + account.bits[12:], refs=account.refs)
            shard = Cell(bits=shard.bits, refs=[account])
            envelope = message.slice()
            envelope.uint(4)
            envelope.addr()
            offset = len(message.bits) - len(envelope.bits) + 3
            message = Cell(
                bits=message.bits[:offset] + "0" * 8 + message.bits[offset + 8 :], refs=message.refs
            )
        elif kind == "action":
            payload = Cell().uint(0, 8)
            for _ in range(3):
                payload = Cell().uint(0, 8).ref(payload)
            message = Cell(bits=message.bits, refs=[Cell().ref(payload)])
        emulator = Emulator.from_config(from_boc(config).refs[0])
        try:
            emulator.lib.transaction_emulator_set_unixtime.restype = ctypes.c_bool
            assert emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, int(fields[1]))
            emulator.lt = int(fields[2]) - 1_000_000
            result = emulator.send(shard, message)
        finally:
            emulator.close()
        assert result["success"] is True, (
            "native account-limit control setup failed",
            kind,
            result,
        )
        fields[3], fields[4] = shard.boc().hex(), message.boc().hex()
        oracle = {key: result[key] for key in ("success", "transaction", "shard_account")}
        changes.append(
            (index, "\t".join(fields), oracle, "\t".join(expected_row(fields[0], oracle)))
        )
    return config, changes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    args = parser.parse_args()
    os.environ["EMULATOR_PATH"] = str(args.emulator.resolve())
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    controls = {
        kind: runtime_control(args.artifacts, kind)
        for kind in ("config", "code", "workchain", "action")
    }
    saved = {
        kind: {"config": config.hex(), "changes": changes}
        for kind, (config, changes) in controls.items()
    }
    (args.artifacts / f"{FAMILY}-control-native.json").write_text(
        json.dumps(saved, indent=2) + "\n"
    )
    cases = {
        "config": "unexpected linked v16 config",
        "code": "account-limit probe mismatch",
        "workchain": "account-limit workchain mismatch",
        "action": "account-limit action mismatch",
        "missing": "linked record count mismatch",
        "extra": "linked record count mismatch",
        "reordered": "linked population order changed",
        "roots": "linked root mismatch",
        "native": "invalid linked native outcome",
        "time": "native time mismatch",
        "source": "stale account-limit source",
        "producer": "account-limit legacy report changed",
    }
    for kind, diagnostic in cases.items():
        with tempfile.TemporaryDirectory(prefix="account-limit-control-") as temp:
            sides = [Path(temp) / side / "account-limit" for side in ("left", "right")]
            for side in sides:
                side.mkdir(parents=True)
                (side.parent / "commit.txt").write_text(source + "\n")
                for name in ("account-limit-parity.json", "source-commit.txt"):
                    shutil.copyfile(args.artifacts / name, side / name)
                for path in args.artifacts.glob(f"{FAMILY}-*"):
                    if path.is_file():
                        shutil.copyfile(path, side / path.name)
                inputs = side / f"{FAMILY}-roots.tsv"
                outputs = [
                    side / f"{FAMILY}-{suffix}"
                    for suffix in ("root-driver.stdout", "root-expected.tsv")
                ]
                raw = side / f"{FAMILY}-root-native.json"
                if kind in controls:
                    config, changes = controls[kind]
                    (side / f"{FAMILY}-config.boc").write_bytes(config)
                    receipt = side / f"{FAMILY}-root-receipt.json"
                    value = json.loads(receipt.read_text())
                    value["configuration_sha256"] = hashlib.sha256(config).hexdigest()
                    receipt.write_text(json.dumps(value))
                    for index, original, oracle, expected in changes:
                        for path, row, text in [
                            (inputs, index + 1, original),
                            *[(p, index, expected) for p in outputs],
                        ]:
                            lines = path.read_text().splitlines()
                            lines[row] = text
                            path.write_text("\n".join(lines) + "\n")
                        records = json.loads(raw.read_text())
                        records[index] = oracle
                        raw.write_text(json.dumps(records))
                elif kind in ("missing", "extra", "roots"):
                    for path in outputs:
                        lines = path.read_text().splitlines()
                        if kind == "missing":
                            lines.pop()
                        elif kind == "extra":
                            lines.append(lines[-1])
                        else:
                            fields = lines[3].split("\t")
                            fields[2] = "0" * 64
                            lines[3] = "\t".join(fields)
                        path.write_text("\n".join(lines) + "\n")
                elif kind == "reordered":
                    for path in (inputs, *outputs):
                        lines = path.read_text().splitlines()
                        lines[-1], lines[-2] = lines[-2], lines[-1]
                        path.write_text("\n".join(lines) + "\n")
                    records = json.loads(raw.read_text())
                    records[-1], records[-2] = records[-2], records[-1]
                    raw.write_text(json.dumps(records))
                elif kind == "native":
                    records = json.loads(raw.read_text())
                    records[0]["success"] = False
                    raw.write_text(json.dumps(records))
                elif kind == "time":
                    lines = inputs.read_text().splitlines()
                    fields = lines[1].split("\t")
                    fields[1] = str(int(fields[1]) + 1)
                    lines[1] = "\t".join(fields)
                    inputs.write_text("\n".join(lines) + "\n")
                elif kind == "source":
                    (side.parent / "commit.txt").write_text("0" * 40)
                else:
                    (side / "account-limit-parity.json").write_text(
                        '{"cases":12,"accepted":12,"refused":0}'
                    )
            try:
                compare_account_limit_architectures(*sides, source)
            except AssertionError as error:
                assert diagnostic in str(error), (kind, diagnostic, error)
            else:
                raise AssertionError(f"{kind}: damaged account-limit artifacts survived")
    compare_account_limit_architectures(args.artifacts, args.artifacts, source)
    print(
        "PASS: twelve account-limit controls and restored local artifacts (not architecture evidence)"
    )


if __name__ == "__main__":
    main()

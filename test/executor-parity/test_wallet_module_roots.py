"""Tamper real fresh/replay Module artifacts at the independently checked boundary."""

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
    str(Path(__file__).resolve().parents[1] / name)
    for name in ("auth-extensions", "wallet-quantum", "falcon-auth")
)

from cells import Cell, make_dict, read_dict
from fee_tx_parity import transcript
from native import Emulator, outgoing, transaction_details
from root_cells import from_boc
from transaction_roots import expected_row
from wallet_module_roots import ROOT, calls, fixtures, validate_run


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n")


def native_alternative(directory, kind):
    """Run coherent alternate inputs in C++; never infer validity from rejection."""
    folder = directory / "configuration-0"
    config = from_boc((folder / "config.boc").read_bytes())
    inputs = (folder / "wallet-module-roots.tsv").read_text().splitlines()[1:]
    oracles = json.loads((folder / "wallet-module-root-native.json").read_text())
    if kind == "native-config":
        entries = read_dict(config.refs[0], 32)
        # Change an unused value without adding a dictionary branch: another
        # branch can add100 gas to policy lookup and alter relayed message fees.
        original = entries[0].refs[0]
        changed = original.bits[:-1] + ("0" if original.bits[-1] == "1" else "1")
        entries[0] = Cell(bits=entries[0].bits, refs=[Cell(bits=changed)])
        address = changed if config.bits == original.bits else config.bits
        config = Cell(bits=address, refs=[make_dict(entries, 32)])
    for ordinal, line in enumerate(inputs):
        if kind == "native-code" and ordinal != 2:
            continue
        fields = line.split("\t")
        shard = from_boc(bytes.fromhex(fields[3]))
        if kind == "native-code":
            account = shard.refs[0]
            code = account.refs[0]
            alternate = Cell(bits="00000000" + code.bits, refs=code.refs)
            shard = Cell(
                bits=shard.bits, refs=[Cell(bits=account.bits, refs=[alternate, account.refs[1]])]
            )
            fields[3] = shard.boc().hex()
        emulator = Emulator.from_config(config.refs[0], vm_log_verbosity=0)
        try:
            emulator.lib.transaction_emulator_set_unixtime.restype = ctypes.c_bool
            assert emulator.lib.transaction_emulator_set_unixtime(emulator.ptr, int(fields[1]))
            emulator.lt = int(fields[2]) - 1_000_000
            result = emulator.send(shard, from_boc(bytes.fromhex(fields[4])))
        finally:
            emulator.close()
        assert result["success"] is True, ("native alternate setup failed", kind, ordinal, result)
        expected = fixtures()[0]["modes"][
            json.loads((directory / "wallet-module-receipt.json").read_text())["mode"]
        ]["groups"][0]["rows"][ordinal]
        assert result["details"]["exit"] == expected["exit"], (
            "native alternate changed class",
            kind,
            ordinal,
        )
        if kind == "native-code":
            assert result["details"]["compute_success"] is True
        else:
            assert [message.hash for message in outgoing(from_boc(result["transaction"]))] == [
                message.hash for message in outgoing(from_boc(oracles[ordinal]["transaction"]))
            ], "native alternate changed relay inputs"
        inputs[ordinal] = "\t".join(fields)
        oracles[ordinal] = {key: result[key] for key in ("success", "transaction", "shard_account")}
    return config.boc(), inputs, oracles


def rederive(directory, alternative):
    raw, inputs, oracles = alternative
    folder = directory / "configuration-0"

    def rows(path, value):
        path.write_text("\n".join(value) + "\n")

    (folder / "config.boc").write_bytes(raw)
    rows(folder / "wallet-module-roots.tsv", ["#pq-tx-roots-v1", *inputs])
    write_json(folder / "wallet-module-root-native.json", oracles)
    expected = [
        "\t".join(expected_row(line.split("\t")[0], oracle))
        for line, oracle in zip(inputs, oracles, strict=True)
    ]
    for name in ("wallet-module-root-expected.tsv", "wallet-module-root-driver.stdout"):
        rows(folder / name, expected)
    legacy, detailed = [], []
    for line, oracle in zip(inputs, oracles, strict=True):
        name, now, lt, shard, message, *_ = line.split("\t")
        plain = name.split(":", 1)[1]
        legacy.append(
            "\t".join(
                [plain, now, lt, from_boc(bytes.fromhex(shard)).refs[0].boc().hex(), message, "-"]
            )
        )
        detailed.append(
            transcript(
                plain, dict(oracle, details=transaction_details(from_boc(oracle["transaction"])))
            )
        )
    rows(folder / "scenarios.tsv", legacy)
    for name in ("native.tsv", "rust.tsv"):
        rows(folder / name, detailed)
    path = directory / "parity.json"
    report = json.loads(path.read_text())
    report["groups"][0]["configuration"] = from_boc(raw).refs[0].hash.hex()
    if report["generated_config_sha256"] is not None:
        report["generated_config_sha256"] = hashlib.sha256(raw).hexdigest()
    write_json(path, report)
    path = directory / "native/results.json"
    report = json.loads(path.read_text())
    report["cases"]["primary"]["recipient"] = transaction_details(
        from_boc(oracles[2]["transaction"])
    )
    if report["chain_config_sha256"] is not None:
        report["chain_config_sha256"] = hashlib.sha256(raw).hexdigest()
    write_json(path, report)


def controls(directory, mode, source, recorded, alternatives=None):
    validate_run(directory, mode, source, recorded)
    checks = {
        "missing-row": "row population",
        "same-wrong-root": "root mismatch",
        "time": "time/LT",
        "context": "context",
        "reordered": "row order",
        "call-identity": "signature call identity",
        "signature-message": "signature/message mismatch",
        "recipient-control": "recipient control",
        "receipt": "receipt/source",
        "legacy": "legacy outcome",
        "native-report": "native report cases",
    }
    if alternatives is not None:
        checks.update({"native-config": "configuration identity", "native-code": "code identity"})
    for kind, diagnostic in checks.items():
        with tempfile.TemporaryDirectory(prefix="wallet-module-control-") as temporary:
            target = Path(temporary) / "run"
            shutil.copytree(directory, target, ignore=shutil.ignore_patterns("recorded-replay"))
            folder = target / "configuration-0"
            path = folder / "wallet-module-roots.tsv"
            lines = path.read_text().splitlines()
            if kind in ("native-config", "native-code"):
                rederive(target, alternatives[kind])
            elif kind == "missing-row":
                path.write_text("\n".join(lines[:-1]) + "\n")
            elif kind in ("time", "context"):
                fields = lines[1].split("\t")
                fields[1 if kind == "time" else 5] = "1"
                lines[1] = "\t".join(fields)
                path.write_text("\n".join(lines) + "\n")
            elif kind == "reordered":
                lines[1], lines[2] = lines[2], lines[1]
                path.write_text("\n".join(lines) + "\n")
            elif kind == "same-wrong-root":
                for suffix in ("-root-driver.stdout", "-root-expected.tsv"):
                    result = folder / ("wallet-module" + suffix)
                    rows = result.read_text().splitlines()
                    fields = rows[0].split("\t")
                    fields[2] = "0" * 64
                    rows[0] = "\t".join(fields)
                    result.write_text("\n".join(rows) + "\n")
            elif kind in ("call-identity", "signature-message"):
                path = target / "native/native-wallet-signatures.json"
                value = json.loads(path.read_text())
                if kind == "call-identity":
                    value[0]["purpose"] = "unexpected"
                else:
                    signature = value[0]["signature"]
                    value[0]["signature"] = f"{int(signature[:2], 16) ^ 1:02x}" + signature[2:]
                    # Fixed replay rejects even earlier at the fixed-signature check.
                    if recorded:
                        diagnostic = "recorded signature mismatch"
                write_json(path, value)
            elif kind == "recipient-control":
                path = target / "recipient-control.json"
                value = json.loads(path.read_text())
                value["exit"] = 0
                write_json(path, value)
            elif kind == "receipt":
                path = target / "wallet-module-receipt.json"
                value = json.loads(path.read_text())
                value["source"] = "0" * 40
                write_json(path, value)
            elif kind == "native-report":
                path = target / "native/results.json"
                value = json.loads(path.read_text())
                value["cases"]["primary"]["module"]["gas"] += 1
                write_json(path, value)
            elif kind == "legacy":
                (folder / "rust.tsv").write_text("incorrect\n")
            try:
                validate_run(target, mode, source, recorded)
            except AssertionError as error:
                assert diagnostic in str(error), (kind, diagnostic, str(error))
            else:
                raise AssertionError(f"wallet-module control escaped: {kind}")
    # Fixed signatures must not quietly become optional, reordered, or extended.
    rows = json.loads((directory / "native/native-wallet-signatures.json").read_text())
    for changed in (rows[:-1], [*rows, rows[0]], [rows[1], rows[0], *rows[2:]]):
        try:
            calls(changed, mode, recorded=recorded)
        except AssertionError as error:
            assert "signature call" in str(error)
        else:
            raise AssertionError("wallet-module signature sequence escaped")
    assert len(fixtures()[0]["modes"][mode]["calls"]) == 7
    return len(checks) + 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--mode", choices=("candidate", "diagnostic"), required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emulator", type=Path, required=True)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    os.environ["EMULATOR_PATH"] = str(args.emulator.resolve())
    counts = []
    for directory, recorded in (
        (args.artifacts, False),
        (args.artifacts / "recorded-replay", True),
    ):
        alternatives = {
            kind: native_alternative(directory, kind) for kind in ("native-config", "native-code")
        }
        write_json(
            directory / "wallet-module-native-controls.json",
            {
                kind: dict(configuration=raw.hex(), inputs=inputs, native=oracles)
                for kind, (raw, inputs, oracles) in alternatives.items()
            },
        )
        counts.append(controls(directory, args.mode, source, recorded, alternatives))
    fresh, recorded = counts
    count = fresh + recorded
    if args.output:
        value = (
            json.loads(args.output.read_text())
            if args.output.exists()
            else dict(source=source, modes={})
        )
        assert value["source"] == source
        value["modes"][args.mode] = dict(fresh=fresh, recorded=recorded)
        write_json(args.output, value)
    print(f"{count} wallet-module artifact controls passed: {args.mode}")


if __name__ == "__main__":
    main()

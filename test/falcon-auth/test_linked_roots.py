"""Damage real linked artifacts; require specific final-comparison failures."""

import argparse
import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from linked_roots import ROOT, compare_architectures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    cases = [
        ("missing", "root output", "linked record count mismatch"),
        ("same-wrong-roots", "root output", "linked root mismatch"),
        ("dropped-capture", "population", "linked population count changed"),
        ("reordered-capture", "population", "linked population order changed"),
        ("same-wrong-time", "context", "native time mismatch"),
        ("same-wrong-predecessor", "context", "native predecessor mismatch"),
        ("bad-native", "oracle", "invalid linked native outcome"),
        ("partial", "receipt", "partial linked population"),
        ("exclusions", "receipt", "linked exclusions changed"),
        ("same-wrong-config", "context", "unexpected linked v16 config"),
        ("stale-source", "source", "stale linked source"),
        ("failed-producer", "producer", "linked producer failed"),
    ]
    for name, _, diagnostic in cases:
        with tempfile.TemporaryDirectory(prefix="linked-root-control-") as temp:
            sides = [Path(temp) / "left", Path(temp) / "right"]
            for side in sides:
                side.mkdir()
                (side / "receipts").mkdir()
                for folder, pattern in (("", "two-hop-*"), ("receipts", "receipt-*")):
                    for item in (args.artifacts / folder).glob(pattern):
                        if item.is_file():
                            shutil.copyfile(item, side / folder / item.name)
                for item in ("commit.txt", "e2e.json"):
                    shutil.copyfile(args.artifacts / item, side / item)
                path = side / "two-hop-root-receipt.json"
                receipt = json.loads(path.read_text())
                files = [
                    side / "two-hop-roots.tsv",
                    side / "two-hop-root-driver.stdout",
                    side / "two-hop-root-expected.tsv",
                ]
                if name == "missing":
                    p = files[1]
                    p.write_text("\n".join(p.read_text().splitlines()[:-1]) + "\n")
                elif name == "same-wrong-roots":
                    for p in files[1:]:
                        rows = p.read_text().splitlines()
                        fields = rows[100].split("\t")
                        fields[2] = "0" * 64
                        rows[100] = "\t".join(fields)
                        p.write_text("\n".join(rows) + "\n")
                elif name in ("dropped-capture", "reordered-capture"):
                    for p in files:
                        rows = p.read_text().splitlines()
                        if name == "dropped-capture":
                            rows.pop()
                        else:
                            # Keep the schema header in place.
                            rows[-1], rows[-2] = rows[-2], rows[-1]
                        p.write_text("\n".join(rows) + "\n")
                    p = side / "two-hop-root-native.json"
                    rows = json.loads(p.read_text())
                    if name == "dropped-capture":
                        rows.pop()
                        receipt["rows"] -= 1
                        receipt["captured_attempts"] -= 1
                        path.write_text(json.dumps(receipt))
                    else:
                        rows[-1], rows[-2] = rows[-2], rows[-1]
                    p.write_text(json.dumps(rows))
                elif name in ("same-wrong-time", "same-wrong-predecessor"):
                    p = files[0]
                    rows = p.read_text().splitlines()
                    index = 917 if name == "same-wrong-time" else 1
                    fields = rows[index + 1].split("\t")
                    if name == "same-wrong-time":
                        fields[1] = "1780000000"
                    else:
                        from cells import Cell, from_boc

                        original = from_boc(bytes.fromhex(fields[3]))
                        fields[3] = Cell().uint(0, 320).ref(original.refs[0]).boc().hex()
                    rows[index + 1] = "\t".join(fields)
                    p.write_text("\n".join(rows) + "\n")
                elif name == "bad-native":
                    p = side / "two-hop-root-native.json"
                    rows = json.loads(p.read_text())
                    rows[0]["success"] = False
                    p.write_text(json.dumps(rows))
                elif name == "partial":
                    receipt["full"] = False
                    path.write_text(json.dumps(receipt))
                elif name == "exclusions":
                    receipt["exclusions"] = {}
                    path.write_text(json.dumps(receipt))
                elif name == "same-wrong-config":
                    from linked_roots import configuration
                    from native import Cell, config

                    value = Cell(bits=configuration().bits).ref(config(17)).boc()
                    (side / "two-hop-config.boc").write_bytes(value)
                    receipt["configuration_sha256"] = hashlib.sha256(value).hexdigest()
                    path.write_text(json.dumps(receipt))
                elif name == "stale-source":
                    (side / "commit.txt").write_text("0" * 40)
                elif name == "failed-producer":
                    (side / "e2e.json").write_text('{"success":false}')
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    compare_architectures(*sides, source)
            except AssertionError as error:
                assert diagnostic in str(error), (name, diagnostic, error)
            else:
                raise AssertionError(f"{name}: damaged linked artifacts survived")
    compare_architectures(args.artifacts, args.artifacts, source)
    print(
        "PASS: twelve real-artifact controls rejected; restored local artifacts pass (not architecture evidence)"
    )


if __name__ == "__main__":
    main()

"""Attribute the governance answer change to the configuration policy addition."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAME = "Test_Toslib_GovernanceProposalFiftScriptRegression_default"
OLD = "2d5c00270f3abb0304318dd8d481eaa29d031f02d73a0c307e94e770bd8ad593"
NEW = "064b5a65380b0b6fdfec7dfc2e179941437859d28e6abcd48a807bc946fe6f17"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--prior-config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--case", choices=("governance", "zerostate"), default="governance")
    args = p.parse_args()
    name, old_hash, new_hash = NAME, OLD, NEW
    if args.case == "zerostate":
        name = "Test_Toslib_GenZerostateFiftRegression_default"
        old_hash = "814401c531cb039224d39721bf01472dc50545236d1c8e2820cfecda5f3aa381"
        new_hash = "79a896e7d1cd99bb34ff86174cf417d428f3be62ce2cd1c5f422efc4c4156efd"
    args.output.mkdir(parents=True, exist_ok=False)
    generated = args.build / "crypto/smartcont/auto/config-code.fif"
    original = generated.read_bytes()
    answers = (ROOT / "test/regression-tests.ans").read_text()
    lines = [line for line in answers.splitlines() if line.startswith(name + " ")]
    assert len(lines) == 1 and lines[0].split()[1] in (old_hash, new_hash)
    old_answers = answers.replace(lines[0], name + " " + old_hash)
    new_answers = answers.replace(lines[0], name + " " + new_hash)
    work = args.output / "private-source"
    work.mkdir()
    for source in (ROOT / "crypto/smartcont").glob("*.fc"):
        shutil.copyfile(source, work / source.name)
    shutil.copyfile(args.prior_config, work / "config-code.fc")
    previous_asm = args.output / "previous-config.fif"
    result = subprocess.run(
        [
            str((args.build / "crypto/func").resolve()),
            "-PS",
            "-o",
            str(previous_asm.resolve()),
            str((work / "stdlib.fc").resolve()),
            str((work / "config-code.fc").resolve()),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    (args.output / "compile.log").write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stderr

    def run(label, record, expect_pass, got=None):
        path = args.output / (label + ".ans")
        path.write_text(record)
        result = subprocess.run(
            [
                str((args.build / "test-smartcont").resolve()),
                "--filter",
                name.removeprefix("Test_Toslib_").removesuffix("_default"),
                "--regression",
                str(path.resolve()),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        if expect_pass:
            assert result.returncode == 0 and "1 test(s) passed" in log, log[-4000:]
        else:
            assert (
                result.returncode != 0 and name + " changed:" in log and "[got:" + got + "]" in log
            ), log[-4000:]
        return result.returncode

    receipts = {}
    try:
        receipts["current_old_record"] = run("current-old", old_answers, False, new_hash)
        generated.write_bytes(previous_asm.read_bytes())
        receipts["previous_old_record"] = run("previous-old", old_answers, True)
        receipts["previous_new_record"] = run("previous-new", new_answers, False, old_hash)
    finally:
        generated.write_bytes(original)
        receipts["restored_new_record"] = run("restored-new", new_answers, True)
    assert generated.read_bytes() == original

    def summary(label):
        return dict(
            line.split("=", 1)
            for line in (args.output / (label + ".cache") / "WA").read_text().splitlines()
        )

    old, new = summary("previous-new"), summary("current-old")
    changed = [key for key in old if old[key] != new[key]]
    assert old.keys() == new.keys(), (old, new)
    if args.case == "governance":
        assert changed == ["config_upgrade_root_hash"], (old, new)
    else:
        assert {"zerostate.file_hash", "zerostate.root_hash"} <= set(changed)
        assert set(changed) <= {
            "zerostate.boc_size",
            "zerostate.file_hash",
            "zerostate.root_hash",
            "config-master.addr",
        }, (old, new)
    report = {
        "receipts": receipts,
        "old": old,
        "new": new,
        "changed": changed,
        "prior_config_sha256": hashlib.sha256(args.prior_config.read_bytes()).hexdigest(),
        "restored_asm_sha256": hashlib.sha256(original).hexdigest(),
    }
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        "Previous/current config controls passed; changed fields bounded; generated source restored"
    )


if __name__ == "__main__":
    main()

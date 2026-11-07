#!/usr/bin/env python3
"""Red/green controls for the Service Actor release check.

Usage: FUNC_BIN=... FIFT_BIN=... FUNC_PATH=... FIFT_PATH=... \
    python3 test/service-actor/release_mutations.py <checkout> <results.json>

Starts from a passing baseline, applies one mutation at a time, records the
exit status and final line of each check, and restores the mutated file
before the next control. Expected: (a) a flipped artifact byte fails both the
release test and the bytecode checker; (b) a changed source constant fails on
the code hash; (c) a wrong manifest size fails the manifest comparison; (d) the
same root cell in another BOC container fails the release test's byte
comparison while the root-hash checker alone still passes.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CHECKOUT = Path(sys.argv[1]).resolve()
OUTPUT = Path(sys.argv[2])
TEST = ["scripts/test-tos-service-actor-v1.sh"]
CHECKER = ["python3", "scripts/check-service-actor-bytecode.py"]
SDK = "tosctl/src/node-control/contracts/src/service_actor.rs"
results = []


def run(command):
    result = subprocess.run(command, cwd=CHECKOUT, capture_output=True, text=True)
    return result.returncode, (result.stdout + result.stderr).strip().splitlines()[-1:]


def record(control, command, extra=None):
    status, last = run(command)
    results.append(
        {
            "control": control,
            "command": " ".join(command),
            "exit": status,
            "last_line": last,
            **(extra or {}),
        }
    )


def control(name, path, mutate, commands):
    target = CHECKOUT / path
    original = target.read_bytes()
    mutated = mutate(original)
    if mutated == original:
        raise SystemExit(f"{name}: the mutation did not change {path}")
    try:
        target.write_bytes(mutated)
        for command in commands:
            record(
                name,
                command,
                {"mutated": path, "mutated_sha256": hashlib.sha256(mutated).hexdigest()},
            )
    finally:
        target.write_bytes(original)


def flip_artifact_character(raw):
    lines = raw.decode().splitlines(keepends=True)
    line = lines[10]
    replacement = "A" if line[20] != "A" else "B"
    lines[10] = line[:20] + replacement + line[21:]
    return "".join(lines).encode()


def alternate_container(boc):
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        (directory / "in.boc").write_bytes(boc)
        script = directory / "reserialize.fif"
        script.write_text(
            f'"{directory}/in.boc" file>B B>boc 0 boc+>B "{directory}/out.boc" B>file\n'
        )
        subprocess.run(
            [os.environ["FIFT_BIN"], "-I", str(CHECKOUT / "crypto/fift/lib"), "-s", str(script)],
            check=True,
        )
        return (directory / "out.boc").read_bytes()


record("baseline", TEST)
record("baseline", CHECKER)
control(
    "a-artifact-byte",
    "crypto/smartcont/tos-service-actor-v1.boc.base64",
    flip_artifact_character,
    [TEST, CHECKER],
)
control(
    "b-source-constant",
    "crypto/smartcont/service-actor-code.fc",
    lambda raw: raw.replace(
        b"const int ADMISSION_GAS_ALLOWANCE = 200000000;",
        b"const int ADMISSION_GAS_ALLOWANCE = 200000001;",
        1,
    ),
    [TEST],
)
control(
    "c-manifest-boc-bytes",
    "crypto/smartcont/tos-service-actor-v1.release.json",
    lambda raw: raw.replace(b'"boc_bytes": 4590', b'"boc_bytes": 4591', 1),
    [TEST],
)
embedded = base64.b64decode(
    re.search(r'SERVICE_ACTOR_CODE_B64: &str = "([^"]+)"', (CHECKOUT / SDK).read_text())[1]
)
alternate = alternate_container(embedded)
results.append(
    {
        "control": "d-alternate-container",
        "embedded_sha256": hashlib.sha256(embedded).hexdigest(),
        "alternate_sha256": hashlib.sha256(alternate).hexdigest(),
        "alternate_bytes": len(alternate),
    }
)
control(
    "d-sdk-alternate-container",
    SDK,
    lambda raw: raw.replace(base64.b64encode(embedded), base64.b64encode(alternate), 1),
    [TEST, CHECKER],
)
record("restored", TEST)
OUTPUT.write_text(json.dumps(results, indent=1) + "\n")
print(json.dumps(results, indent=1))

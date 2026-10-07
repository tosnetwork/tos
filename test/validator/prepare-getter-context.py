#!/usr/bin/env python3
"""Generate an isolated masterchain fixture for native getter-context checks."""

import argparse
import hashlib
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    build = args.build.resolve()
    reference = (source / "test/validator/getter-context-reference.h").read_text()
    start = reference.index("static td::Ref<vm::Tuple> prepare_vm_c7")
    end = reference.index("\n}", start) + 2
    digest = hashlib.sha256(reference[start:end].encode()).hexdigest()
    if digest != "4cc2b04ab23188d56d8c881e91a139ba2073970442b611d12581423a7aad34dc":
        raise SystemExit("independent context oracle differs from the frozen source")
    directory = build / "getter-context-data"
    directory.mkdir(exist_ok=True)
    # Public descriptors suffice: this fixture executes getters, never signs blocks.
    manifest = b"".join(
        bytes([index]) * 32 + bytes([index + 4]) * 32 + bytes([index + 8]) * 1312
        for index in range(1, 5)
    )
    (directory / "validator-pq.pub").write_bytes(manifest)
    (directory / "zerostate.boc").unlink(missing_ok=True)
    environment = dict(os.environ, SOURCE_DATE_EPOCH="1789434000")
    include = ":".join(
        str(path)
        for path in (
            source / "crypto/fift/lib",
            build / "crypto/smartcont",
            source / "crypto/smartcont",
        )
    )
    result = subprocess.run(
        [
            str(build / "crypto/create-state"),
            "-I",
            include,
            str(source / "crypto/smartcont/gen-zerostate.fif"),
        ],
        cwd=directory,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if (
        result.returncode
        or "Error interpreting" in result.stdout + result.stderr
        or not (directory / "zerostate.boc").is_file()
    ):
        raise SystemExit(f"fixture generation failed: {result.stdout}\n{result.stderr}")
    print("GETTER_CONTEXT_FIXTURE_READY")


if __name__ == "__main__":
    main()

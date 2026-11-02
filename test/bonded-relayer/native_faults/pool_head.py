#!/usr/bin/env python3
"""Obtain an operator-pinned native pool head before paginating untrusted RPC."""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path

from control import configuration, write_new
from native_process import NativeRPC, PinnedProgram


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--backend", type=Path, required=True)
    parser.add_argument("--backend-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = configuration(args.config)
    if config["release"].global_id != 3:
        parser.error("isolated local network only")
    program = PinnedProgram(
        args.backend, args.backend_sha256, Path(config["state_dir"]), timeout=30
    )
    try:
        head = NativeRPC(program).call(
            "pool_head", {"release": dataclasses.asdict(config["release"])}
        )
        if head["scope"] != config["release"].scope or head["pool"] != config["release"].pool:
            raise RuntimeError("native pool scope mismatch")
        write_new(args.out, {"provider_sha256": args.backend_sha256, "head": head})
    finally:
        program.close()


if __name__ == "__main__":
    main()

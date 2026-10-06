#!/usr/bin/env python3
"""Admit an installed generator only after a protected resource query succeeds."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

CONTRACT = "crypto/smartcont/tos-shielded-pool-v1.fc"
FIXTURE = "tools/shielded-pool-circuit/fixtures/groth16-development.json"
GENERATOR = "tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"


def validate(output, contract, fixture):
    response = json.loads(output)
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise ValueError("generator resource request failed (exit zero is not success)")
    result = response["result"]
    if (result.get("schema") != "tos.local-pq-runtime-resources.v1"
            or result.get("pool_source") != contract
            or result.get("development_fixture") != fixture):
        raise ValueError("generator was not built from these contract/fixture bytes; rebuild")
    expected_vk = json.loads(fixture)["verifying_key"]["hex"]
    if (result.get("verifying_key_hex") != expected_vk
            or len(bytes.fromhex(expected_vk)) != 1248):
        raise ValueError("generator development verifying key differs")
    for name in ("deposit_gas_ceiling", "transact_gas_ceiling"):
        matches = re.findall(rf'int {name}\(\) asm "(\d+) PUSHINT', contract)
        if len(matches) != 1 or type(result.get(name)) is not int or result[name] != int(matches[0]):
            raise ValueError(f"generator {name} differs from the contract")
    return result


def quote_path(path):
    # Unit properties use quoted words and expand specifiers. Do not let a path
    # split the inaccessible list or introduce a systemd specifier.
    value = str(Path(path).resolve())
    if any(ord(c) < 32 for c in value):
        raise ValueError("control character in installation path")
    return json.dumps(value.replace("%", "%%"), ensure_ascii=False)


def check(dest, repo, build):
    dest, repo, build = (Path(p).resolve() for p in (dest, repo, build))
    for hidden in (repo, build):
        if dest == hidden or hidden in dest.parents:
            raise ValueError("snapshot must be outside hidden source/build roots")
    contract, fixture = (repo / CONTRACT).read_text(), (repo / FIXTURE).read_text()
    command = ["systemd-run", "--quiet", "--collect", "--wait", "--pipe",
               "--property=ProtectHome=true", "--property=RuntimeMaxSec=60",
               "--property=MemoryMax=1G", "--property=CPUQuota=100%",
               "--property=WorkingDirectory=" + str(dest / "src").replace("%", "%%"),
               "--property=InaccessiblePaths=" + " ".join(quote_path(p) for p in (repo, build)),
               "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=/nonexistent",
               str(dest / "src" / GENERATOR)]
    process = subprocess.run(command, input='{"operation":"resources"}\n',
                             capture_output=True, text=True, timeout=75, check=False)
    if process.returncode:
        raise ValueError(f"protected generator resource query failed: {process.stderr[-1000:]}")
    validate(process.stdout, contract, fixture)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dest", type=Path)
    parser.add_argument("repo", type=Path)
    parser.add_argument("build", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("protected snapshot admission requires root/systemd")
    check(args.dest, args.repo, args.build)


if __name__ == "__main__":
    main()

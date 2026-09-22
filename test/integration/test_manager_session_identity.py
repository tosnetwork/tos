#!/usr/bin/env python3
"""Observe ValidatorManagerImpl deriving a group session from a real zerostate.

This is deliberately a process integration test, not another call to the shared
session helper.  Each run starts validator-engine and lets its real manager/DB
startup path unpack the generated zerostate and create the validator group.  A
third control run separates the governing global_id from node-local launch
coordinates: changing the port and data directory must not change the session,
while changing global_id with those launch coordinates held fixed must change it.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import re
import time
from pathlib import Path

from nacl.signing import SigningKey
from tostester.install import Install
from tostester.key import Key
from tostester.network import Network, StartOptions

GROUP_CREATED = re.compile(
    r"Created validator group \(-1,8000000000000000\)\.0:(?P<session>[A-Za-z0-9+/]{43}=)"
)
FIXED_VALIDATOR_SEED = bytes.fromhex(
    "8a4d6f7c12e03b9a21c517d4a0ee349d7f614ce9b52d03f078bb5928cfe1a630"
)
FIXED_PQ_SEED = bytes.fromhex("f6d2e94c3810b5236a7fcd9081264be75139d80a2cf45e6b938701af24bd5c68")
FIXED_VALIDATOR_ID = bytes.fromhex(
    "3b1c8dc4bde09875f033a46d29e761bc95e2f408ba167dc5308fb34e6a91c257"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=28600)
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


async def wait_for_group(log_path: Path, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            match = GROUP_CREATED.search(log_path.read_text(errors="replace"))
            if match is not None:
                return base64.b64decode(match.group("session"), validate=True).hex().upper()
        await asyncio.sleep(0.1)
    raise TimeoutError(f"manager did not create a validator group; log={log_path}")


async def observe_session(
    install: Install,
    directory: Path,
    base_port: int,
    global_id: int,
    timeout: float,
) -> str:
    directory.mkdir()
    validator_key = Key(SigningKey(FIXED_VALIDATOR_SEED))
    async with Network(install, directory, base_port=base_port) as network:
        network.config.global_id = global_id
        dht = network.create_dht_node()
        node = network.create_full_node(validator_key=validator_key)
        node.make_initial_pq_validator(FIXED_VALIDATOR_ID, FIXED_PQ_SEED)
        node.announce_to(dht)
        for key_file in directory.glob("node*/keyring/*"):
            key_file.chmod(0o600)
        await dht.run(StartOptions(threads=1, verbosity=3))
        await node.run(StartOptions(threads=2, verbosity=3))
        return await wait_for_group(node.log_path, timeout)


async def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    artifact_dir = args.artifact_dir.resolve()
    if artifact_dir.exists():
        raise ValueError(f"artifact directory already exists: {artifact_dir}")
    artifact_dir.mkdir(parents=True)
    install = Install(args.build_dir.resolve(), repo_root)

    first_global_id = -239
    second_global_id = -238
    first = await observe_session(
        install, artifact_dir / "global-minus-239", args.base_port, first_global_id, args.timeout
    )
    second = await observe_session(
        install,
        artifact_dir / "global-minus-238",
        args.base_port + 100,
        second_global_id,
        args.timeout,
    )
    local_coordinate_control = await observe_session(
        install,
        artifact_dir / "control-global-minus-239",
        args.base_port + 100,
        first_global_id,
        args.timeout,
    )
    summary = {
        "first_global_id": first_global_id,
        "first_session_id": first,
        "second_global_id": second_global_id,
        "second_session_id": second,
        "local_coordinate_control_global_id": first_global_id,
        "local_coordinate_control_session_id": local_coordinate_control,
    }
    (artifact_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if first != local_coordinate_control:
        raise RuntimeError(
            "MANAGER_SESSION_IDENTITY_LOCAL_INPUT_FAILURE: changing the node-local port and "
            "data directory changed the manager-created group session "
            f"({first} != {local_coordinate_control})"
        )
    if first == second:
        raise RuntimeError(
            "MANAGER_SESSION_IDENTITY_FAILURE: changing zerostate global_id did not change "
            f"the manager-created group session ({first})"
        )
    print(
        "MANAGER_SESSION_IDENTITY_OK: real ValidatorManagerImpl startup observed "
        f"global_id={first_global_id} session={first} and "
        f"global_id={second_global_id} session={second}; changing only node-local launch "
        f"coordinates preserved session={local_coordinate_control}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except (RuntimeError, TimeoutError, ValueError) as error:
        print(error)
        raise SystemExit(1) from error

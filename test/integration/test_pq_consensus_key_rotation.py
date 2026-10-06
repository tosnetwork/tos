#!/usr/bin/env python3
"""A real validator engine holding two post-quantum consensus keys at once.

One validator, booted on a chain whose genesis set lists its key A. The node also holds
key B, valid for stakes from a later election date: the state a node is in during a
consensus key rotation, after B was added and before A was retired. Three runs:

  rotation  A and B held. The group for the set listing A is created and produces
            masterchain blocks (signed with A); a stake for B's election is signed with
            B, a stake for an earlier election with A, and a named key overrides the
            schedule only inside its window. The console lists both keys, refuses to
            drop A while the running set lists it, drops B, adds B back while the node
            runs, refuses a key that would make the schedule ambiguous, and the node is
            still producing blocks afterwards. config.json follows every change.
  missing   Only B held, the set lists A: no group is created, no block is produced, and
            the node does not count itself a validator of the set (as with one key).
  expired   A held but expired, B held: A is not loaded and is not used for anything, so
            the outcome is the same as `missing`.

The same one-validator fixture as the unsafe-rotation refusal test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import subprocess
import time
from pathlib import Path

from nacl.signing import SigningKey
from test_manager_session_identity import (
    FIXED_PQ_SEED,
    FIXED_VALIDATOR_ID,
    FIXED_VALIDATOR_SEED,
)
from test_pq_unsafe_rotation_refusal import GROUP_CREATED, successful_masterchain_stats
from tosapi import tos_api
from toslib.errors import RemoteError
from tostester.install import Install
from tostester.key import Key
from tostester.network import Network, StartOptions

SUCCESSOR_SEED = bytes.fromhex("5e" * 32)
THIRD_SEED = bytes.fromhex("7c" * 32)
# The first election date the successor signs stakes for. Any date works: the node
# checks windows, not whether an election at that date exists.
SUCCESSOR_FROM = 2_000_000_000


class Failure(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=29100)
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


def place_key(install: Install, path: Path, seed: bytes) -> tuple[bytes, bytes]:
    """Import a seed with the production tool; return its key id and public key."""
    result = subprocess.run(
        [str(install.pq_consensus_key_exe), "import", str(path)],
        input=seed.hex() + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise Failure(f"could not place {path}: {result.stderr.strip()}")
    key_id = re.search(r"^key_id\s+([0-9a-f]{64})$", result.stdout, re.M)
    public = re.search(r"^public\s+([0-9a-f]{2624})$", result.stdout, re.M)
    if key_id is None or public is None:
        raise Failure("the key tool did not report the key identity")
    return bytes.fromhex(key_id.group(1)), bytes.fromhex(public.group(1))


async def wait_for_blocks(node, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.log_path.exists():
            log = node.log_path.read_text(errors="replace")
            if GROUP_CREATED.search(log) and successful_masterchain_stats(node.session_log_path):
                return "blocks"
        await asyncio.sleep(0.2)
    return "timeout"


def successful_stats(node) -> int:
    return len(re.findall(r'"success":\s*true', node.session_log_path.read_text(errors="replace")))


async def stake(node, election: int, key_id: bytes | None = None):
    common = dict(
        election_date=election,
        max_factor=0x10000,
        adnl_addr=node.validator_key.id,
        stake_owner=bytes([0x77]) * 32,
    )
    if key_id is None:
        request = tos_api.Engine_validator_createPqStakeAuthorizationRequest(**common)
    else:
        request = tos_api.Engine_validator_createPqStakeAuthorizationWithKeyRequest(
            **common, key_id=key_id
        )
    return request.parse_result(await node.engine_console.request(request))


async def refused(coroutine, phrase: str, why: str) -> None:
    try:
        await coroutine
    except RemoteError as error:
        if phrase not in error.message:
            raise Failure(f"{why} was refused for another reason: {error.message!r}")
        return
    raise Failure(f"{why} was not refused")


async def list_keys(node) -> list:
    request = tos_api.Engine_validator_getPqConsensusKeysRequest()
    result = request.parse_result(await node.engine_console.request(request))
    if result.validator_id != FIXED_VALIDATOR_ID:
        raise Failure("the console listed another validator")
    return result.keys


def disk_keys(node) -> dict:
    return json.loads((node.directory / "config.json").read_text())["extraconfig"]["pq_consensus"]


async def boot(install: Install, directory: Path, base_port: int, configure) -> tuple:
    directory.mkdir()
    network = Network(install, directory, base_port=base_port)
    await network.__aenter__()
    network.config.global_id = -239
    dht = network.create_dht_node()
    node = network.create_full_node(validator_key=Key(SigningKey(FIXED_VALIDATOR_SEED)))
    node.make_initial_pq_validator(FIXED_VALIDATOR_ID, FIXED_PQ_SEED)
    node.announce_to(dht)
    for key_file in directory.glob("node*/keyring/*"):
        key_file.chmod(0o600)
    keys = configure(node)
    await dht.run(StartOptions(threads=1, verbosity=3))
    await node.run(StartOptions(threads=2, verbosity=3))
    return network, node, keys


async def rotation(install: Install, directory: Path, base_port: int, timeout: float) -> dict:
    def configure(node):
        a_file = node.directory / "pq-consensus.seed"
        a_id, a_public = place_key(install, node.directory / "pq-a-copy.seed", FIXED_PQ_SEED)
        (node.directory / "pq-a-copy.seed").unlink()
        b_file = node.directory / "pq-consensus-next.seed"
        b_id, b_public = place_key(install, b_file, SUCCESSOR_SEED)
        c_file = node.directory / "pq-consensus-third.seed"
        c_id, _ = place_key(install, c_file, THIRD_SEED)
        node._local_config.extraconfig.pq_consensus.keys = [
            tos_api.Engine_validator_pqConsensusKey(
                consensus_key_file=str(b_file), valid_from=SUCCESSOR_FROM, expire_at=0
            )
        ]
        return dict(
            a_file=a_file,
            a_id=a_id,
            a_public=a_public,
            b_file=b_file,
            b_id=b_id,
            b_public=b_public,
            c_file=c_file,
            c_id=c_id,
        )

    network, node, k = await boot(install, directory, base_port, configure)
    try:
        if await wait_for_blocks(node, timeout) != "blocks":
            raise Failure("a node holding A and B produced no block for the set listing A")
        log = node.log_path.read_text(errors="replace")
        for name in ("a_id", "b_id"):
            if k[name].hex() not in log:
                raise Failure(f"the node did not log custody of key {name[0].upper()}")

        # The stake for B's election is signed with B; one for an earlier election with A.
        for_b = await stake(node, SUCCESSOR_FROM)
        if (
            for_b.key_id != k["b_id"]
            or for_b.public_key != k["b_public"]
            or for_b.validator_id != FIXED_VALIDATOR_ID
        ):
            raise Failure(f"the stake for B's election was not signed with B: {for_b.key_id.hex()}")
        for_a = await stake(node, SUCCESSOR_FROM - 1)
        if for_a.key_id != k["a_id"] or for_a.public_key != k["a_public"]:
            raise Failure(
                f"the stake for an earlier election was not signed with A: {for_a.key_id.hex()}"
            )
        if for_a.signature == for_b.signature:
            raise Failure("two keys produced one signature")
        named = await stake(node, SUCCESSOR_FROM, k["a_id"])
        if named.key_id != k["a_id"]:
            raise Failure("a stake naming A was not signed with A")
        await refused(
            stake(node, SUCCESSOR_FROM - 1, k["b_id"]),
            "valid only from",
            "naming B before its window",
        )
        await refused(
            stake(node, SUCCESSOR_FROM, k["c_id"]),
            "not held",
            "naming a key the node does not hold",
        )

        listed = await list_keys(node)
        if [(key.key_id, key.valid_from) for key in listed] != [
            (k["a_id"], 0),
            (k["b_id"], SUCCESSOR_FROM),
        ]:
            raise Failure(f"the console listed other keys: {listed!r}")

        # A is what the running set lists: it stays. B is listed by no set: it may go.
        delete = tos_api.Engine_validator_delPqConsensusKeyRequest
        await refused(node.engine_console.request(delete(key_id=k["a_id"])), "listed", "dropping A")
        await node.engine_console.request(delete(key_id=k["b_id"]))
        if [key.key_id for key in await list_keys(node)] != [k["a_id"]]:
            raise Failure("dropping B did not leave A alone")
        on_disk = disk_keys(node)
        if on_disk["consensus_key_file"] != str(k["a_file"]) or on_disk.get("keys", []) != []:
            raise Failure(f"config.json was not rewritten to the single key: {on_disk!r}")
        await refused(
            node.engine_console.request(delete(key_id=k["a_id"])),
            "last consensus key",
            "dropping the last key",
        )
        await refused(stake(node, SUCCESSOR_FROM, k["b_id"]), "not held", "naming a dropped key")

        # B comes back while the node runs, and signs B's election again.
        add = tos_api.Engine_validator_addPqConsensusKeyRequest
        added = add(consensus_key_file=str(k["b_file"]), valid_from=SUCCESSOR_FROM, expire_at=0)
        info = added.parse_result(await node.engine_console.request(added))
        if info.key_id != k["b_id"]:
            raise Failure("adding B at runtime reported another key")
        if (await stake(node, SUCCESSOR_FROM)).key_id != k["b_id"]:
            raise Failure("a key added at runtime does not sign its election")
        on_disk = disk_keys(node)
        if on_disk["keys"] != [
            {
                "@type": "engine.validator.pqConsensusKey",
                "consensus_key_file": str(k["b_file"]),
                "valid_from": SUCCESSOR_FROM,
                "expire_at": 0,
            }
        ]:
            raise Failure(f"config.json does not hold the added key: {on_disk!r}")
        await refused(
            node.engine_console.request(
                add(consensus_key_file=str(k["c_file"]), valid_from=SUCCESSOR_FROM, expire_at=0)
            ),
            "same election date",
            "a key valid from B's date",
        )
        await refused(
            node.engine_console.request(
                add(consensus_key_file=str(k["b_file"]), valid_from=SUCCESSOR_FROM + 5, expire_at=0)
            ),
            "configured twice",
            "B's file a second time",
        )
        await refused(
            node.engine_console.request(
                add(consensus_key_file="pq-consensus-third.seed", valid_from=7, expire_at=0)
            ),
            "absolute",
            "a relative key path",
        )

        # And through all of it, the group for the set listing A kept producing blocks.
        stats_before = successful_stats(node)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(1.0)
            if successful_stats(node) > stats_before:
                break
        else:
            raise Failure("the node stopped producing blocks after the key changes")
        return {"decision": "rotation_ok", "log_path": str(node.log_path)}
    finally:
        await network.__aexit__(None, None, None)


async def without_a(
    install: Install, directory: Path, base_port: int, timeout: float, expired_a: bool
) -> dict:
    def configure(node):
        b_file = node.directory / "pq-consensus-next.seed"
        b_id, _ = place_key(install, b_file, SUCCESSOR_SEED)
        pq = node._local_config.extraconfig.pq_consensus
        if expired_a:
            # A is configured, and its window closed long ago.
            pq.keys = [
                tos_api.Engine_validator_pqConsensusKey(
                    consensus_key_file=pq.consensus_key_file, valid_from=0, expire_at=1000
                ),
                tos_api.Engine_validator_pqConsensusKey(
                    consensus_key_file=str(b_file), valid_from=1, expire_at=0
                ),
            ]
            pq.consensus_key_file = ""
        else:
            pq.consensus_key_file = str(b_file)
            pq.keys = []
        return dict(b_id=b_id)

    network, node, k = await boot(install, directory, base_port, configure)
    try:
        outcome = await wait_for_blocks(node, timeout)
        log = node.log_path.read_text(errors="replace")
        if outcome != "timeout" or GROUP_CREATED.search(log):
            raise Failure("a node without the key the set lists created a group")
        if k["b_id"].hex() not in log:
            raise Failure("the node did not come up holding B")
        if expired_a and "expired at 1000 and is not loaded" not in log:
            raise Failure("the expired key was not reported as not loaded")
        # It is not a validator of the set, so it cannot vote as one; and it can still
        # authorize B's stake, because that consults no set.
        if (await stake(node, SUCCESSOR_FROM)).key_id != k["b_id"]:
            raise Failure("a node outside the set could not sign its next stake")
        return {"decision": "no_group", "log_path": str(node.log_path)}
    finally:
        await network.__aexit__(None, None, None)


async def main() -> int:
    args = parse_args()
    artifact_dir = args.artifact_dir.resolve()
    if artifact_dir.exists():
        raise ValueError(f"artifact directory already exists: {artifact_dir}")
    artifact_dir.mkdir(parents=True)
    root = Path(__file__).resolve().parents[2]
    install = Install(args.build_dir.resolve(), root)
    results = {}
    try:
        results["rotation"] = await rotation(
            install, artifact_dir / "rotation", args.base_port, args.timeout
        )
        results["missing"] = await without_a(
            install,
            artifact_dir / "missing",
            args.base_port + 100,
            args.timeout / 3,
            expired_a=False,
        )
        results["expired"] = await without_a(
            install,
            artifact_dir / "expired",
            args.base_port + 200,
            args.timeout / 3,
            expired_a=True,
        )
    except Failure as failure:
        print(f"PQ_CONSENSUS_KEY_ROTATION_FAILED {failure}")
        print(json.dumps(results, indent=2))
        return 1
    print(json.dumps(results, indent=2))
    print("PQ_CONSENSUS_KEY_ROTATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

#!/usr/bin/env python3
"""A real validator engine holding several post-quantum consensus keys at once.

One validator, booted on a chain whose genesis set lists its key A. Seven runs:

  rotation           A and B held (B valid for stakes from a later election). The group
                     for the set listing A produces blocks; the stake for B's election is
                     signed with B, an earlier one with A; a named key overrides the
                     schedule only inside its window. The console refuses to drop A while
                     the running set lists it, drops B, adds B back while the node runs,
                     refuses ambiguous, duplicate and relative-path keys, and reports a
                     change whose directory flush failed as not confirmed durable.
                     config.json follows every change; blocks keep coming.
  missing            Only B held: no group (as with one key).
  expired            A held but expired, B held: A is not loaded; no group.
  expired_successor  A held, B configured but expired before the restart: the stake B
                     was scheduled for is refused, never signed with A.
  concurrent         Two deletes at once that would together leave no key, and two adds
                     at once that would together exceed the capacity: exactly one of
                     each succeeds.
  hard_deadline      A, listed and signing, expires while its group runs: no block or
                     signature after the deadline, logged as an expired key, and no other
                     key signs in its place.
  misspelt           A window field the engine does not know (`validFrom`) stops the node
                     at start instead of being defaulted and rewritten away.

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

import tostester.network as network_module
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
    parser.add_argument(
        "--only", action="append", help="run only this scenario (repeatable); default: all"
    )
    parser.add_argument(
        "--fsync-shim",
        type=Path,
        help="LD_PRELOAD library that fails directory fsync on demand "
        "(default: BUILD_DIR/crypto/pq/libtest-fsync-dir-failure-shim.so)",
    )
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


def key_entry(path, valid_from: int, expire_at: int = 0):
    return tos_api.Engine_validator_pqConsensusKey(
        consensus_key_file=str(path), valid_from=valid_from, expire_at=expire_at
    )


def set_keys(node, entries) -> None:
    """State several keys the way the engine writes them: in `keys` alone."""
    pq = node._local_config.extraconfig.pq_consensus
    pq.consensus_key_file = ""
    pq.keys = entries


def disk_entry(path, valid_from: int, expire_at: int = 0) -> dict:
    return {
        "@type": "engine.validator.pqConsensusKey",
        "consensus_key_file": str(path),
        "valid_from": valid_from,
        "expire_at": expire_at,
    }


async def boot(
    install: Install, directory: Path, base_port: int, configure, env: dict | None = None
) -> tuple:
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
    await node.run(StartOptions(threads=2, verbosity=3, env=env or {}))
    return network, node, keys


async def rotation(
    install: Install, directory: Path, base_port: int, timeout: float, shim: Path
) -> dict:
    trigger = directory / "fail-directory-fsync"

    def configure(node):
        a_file = node.directory / "pq-consensus.seed"
        a_id, a_public = place_key(install, node.directory / "pq-a-copy.seed", FIXED_PQ_SEED)
        (node.directory / "pq-a-copy.seed").unlink()
        b_file = node.directory / "pq-consensus-next.seed"
        b_id, b_public = place_key(install, b_file, SUCCESSOR_SEED)
        c_file = node.directory / "pq-consensus-third.seed"
        c_id, _ = place_key(install, c_file, THIRD_SEED)
        set_keys(node, [key_entry(a_file, 0), key_entry(b_file, SUCCESSOR_FROM)])
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

    # The directory flush of the node's configuration can be made to fail on demand:
    # while `trigger` exists, fsync on a directory fails in this process.
    env = {"LD_PRELOAD": str(shim), "TOS_TEST_FAIL_DIR_FSYNC_WHEN": str(trigger)}
    network, node, k = await boot(install, directory, base_port, configure, env)
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
        if on_disk["consensus_key_file"] != "" or on_disk["keys"] != [
            disk_entry(k["a_file"], 0),
            disk_entry(k["b_file"], SUCCESSOR_FROM),
        ]:
            raise Failure(f"config.json does not hold both keys in the list form: {on_disk!r}")
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

        # A change whose directory flush fails is reported as not confirmed durable,
        # though the new configuration is in place.
        trigger.write_text("")
        try:
            await refused(
                node.engine_console.request(
                    add(
                        consensus_key_file=str(k["c_file"]),
                        valid_from=SUCCESSOR_FROM + 10,
                        expire_at=0,
                    )
                ),
                "not confirmed durable",
                "a change whose directory flush failed",
            )
        finally:
            trigger.unlink()
        if [key.key_id for key in await list_keys(node)] != [k["a_id"], k["b_id"], k["c_id"]]:
            raise Failure("a change with a failed directory flush was not applied")
        if disk_entry(k["c_file"], SUCCESSOR_FROM + 10) not in disk_keys(node)["keys"]:
            raise Failure("a change with a failed directory flush is not in the configuration")
        await node.engine_console.request(delete(key_id=k["c_id"]))

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
            set_keys(node, [key_entry(pq.consensus_key_file, 0, 1000), key_entry(b_file, 1)])
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


async def expired_successor(
    install: Install, directory: Path, base_port: int, timeout: float
) -> dict:
    """A restart after the successor B expired: A must not sign in B's place."""

    def configure(node):
        a_file = node.directory / "pq-consensus.seed"
        b_file = node.directory / "pq-consensus-next.seed"
        b_id, _ = place_key(install, b_file, SUCCESSOR_SEED)
        a_id, _ = place_key(install, node.directory / "pq-a-copy.seed", FIXED_PQ_SEED)
        (node.directory / "pq-a-copy.seed").unlink()
        set_keys(node, [key_entry(a_file, 0), key_entry(b_file, 1, 2)])
        return dict(a_id=a_id, b_id=b_id)

    network, node, k = await boot(install, directory, base_port, configure)
    try:
        if await wait_for_blocks(node, timeout) != "blocks":
            raise Failure("A, unexpired and listed, produced no block")
        log = node.log_path.read_text(errors="replace")
        if "expired at 2 and is not loaded" not in log:
            raise Failure("the expired successor was not reported as not loaded")
        await refused(
            stake(node, SUCCESSOR_FROM),
            "(expired and not loaded) expired at 2",
            "the stake the expired successor was scheduled for",
        )
        if (await stake(node, 0)).key_id != k["a_id"]:
            raise Failure("an election before the successor's window was not signed with A")
        # A is the only unexpired key: removing it would leave a configuration the node
        # refuses at its next start, so the console refuses it before asking any set.
        await refused(
            node.engine_console.request(
                tos_api.Engine_validator_delPqConsensusKeyRequest(key_id=k["a_id"])
            ),
            "every configured consensus key has expired",
            "removing the only unexpired key",
        )
        return {"decision": "refused_not_substituted", "log_path": str(node.log_path)}
    finally:
        await network.__aexit__(None, None, None)


async def concurrent(install: Install, directory: Path, base_port: int, timeout: float) -> dict:
    """Two key changes at once cannot together break a limit either alone respects."""
    seeds = [bytes([0x30 + index]) * 32 for index in range(10)]

    def configure(node):
        files = [node.directory / f"pq-k{index}.seed" for index in range(len(seeds))]
        ids = [place_key(install, path, seed)[0] for path, seed in zip(files, seeds, strict=True)]
        # Two keys, neither listed by the running set (it lists A, which is not held).
        set_keys(node, [key_entry(files[0], 0), key_entry(files[1], 100)])
        return dict(files=files, ids=ids)

    network, node, k = await boot(install, directory, base_port, configure)
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                await list_keys(node)
                break
            except Exception:  # the console is not up yet
                await asyncio.sleep(1.0)
        delete = tos_api.Engine_validator_delPqConsensusKeyRequest
        add = tos_api.Engine_validator_addPqConsensusKeyRequest

        # Deleting both at once: each alone leaves one key; both would leave none.
        outcomes = await asyncio.gather(
            node.engine_console.request(delete(key_id=k["ids"][0])),
            node.engine_console.request(delete(key_id=k["ids"][1])),
            return_exceptions=True,
        )
        if sum(1 for outcome in outcomes if not isinstance(outcome, Exception)) != 1:
            raise Failure(f"two concurrent deletes did not leave exactly one key: {outcomes!r}")
        if len(await list_keys(node)) != 1 or len(disk_keys(node).get("keys", [])) > 1:
            raise Failure("concurrent deletes left another number of keys")
        held = (await list_keys(node))[0]
        held_index = k["ids"].index(held.key_id)

        # Fill to one below capacity one by one, then add two at once: only one fits.
        next_index = 2
        while len(await list_keys(node)) < 7:
            await node.engine_console.request(
                add(
                    consensus_key_file=str(k["files"][next_index]),
                    valid_from=1000 + next_index,
                    expire_at=0,
                )
            )
            next_index += 1
        candidates = [index for index in range(len(seeds)) if index >= next_index][:2]
        outcomes = await asyncio.gather(
            *(
                node.engine_console.request(
                    add(
                        consensus_key_file=str(k["files"][index]),
                        valid_from=2000 + index,
                        expire_at=0,
                    )
                )
                for index in candidates
            ),
            return_exceptions=True,
        )
        if sum(1 for outcome in outcomes if not isinstance(outcome, Exception)) != 1:
            raise Failure(
                f"two concurrent adds at capacity did not add exactly one key: {outcomes!r}"
            )
        on_disk = disk_keys(node)["keys"]
        if len(await list_keys(node)) != 8 or len(on_disk) != 8:
            raise Failure(
                f"concurrent adds left {len(on_disk)} keys configured, not the capacity of 8"
            )
        return {
            "decision": "serialized",
            "kept_after_deletes": held_index,
            "log_path": str(node.log_path),
        }
    finally:
        await network.__aexit__(None, None, None)


async def hard_deadline(install: Install, directory: Path, base_port: int, timeout: float) -> dict:
    """A, listed and signing, expires while its group runs: signing stops at the deadline."""
    expire_at = int(time.time()) + int(timeout * 0.8)

    def configure(node):
        a_file = node.directory / "pq-consensus.seed"
        b_file = node.directory / "pq-consensus-next.seed"
        b_id, _ = place_key(install, b_file, SUCCESSOR_SEED)
        a_id, _ = place_key(install, node.directory / "pq-a-copy.seed", FIXED_PQ_SEED)
        (node.directory / "pq-a-copy.seed").unlink()
        set_keys(node, [key_entry(a_file, 0, expire_at), key_entry(b_file, SUCCESSOR_FROM)])
        return dict(a_id=a_id, b_id=b_id)

    network, node, k = await boot(install, directory, base_port, configure)
    try:
        if await wait_for_blocks(node, timeout) != "blocks":
            raise Failure("A produced no block before its deadline")
        if (await stake(node, 1)).key_id != k["a_id"]:
            raise Failure("A did not sign before its deadline")
        while time.time() < expire_at + 2:
            await asyncio.sleep(0.5)
        frozen = successful_stats(node)
        await asyncio.sleep(10)
        if successful_stats(node) != frozen:
            raise Failure("blocks were still produced after the only listed key expired")
        log = node.log_path.read_text(errors="replace")
        if "(the consensus key has expired)" not in log:
            raise Failure("the expired key's refused signatures were not logged as such")
        await refused(stake(node, 1, k["a_id"]), "expired", "a stake named with expired A")
        # B is never signed with for the set listing A, and the schedule does not hand A's
        # elections to B either.
        await refused(stake(node, 1), "expired", "a stake A was scheduled for")
        return {"decision": "stopped_at_deadline", "log_path": str(node.log_path)}
    finally:
        await network.__aexit__(None, None, None)


async def misspelt(install: Install, directory: Path, base_port: int, timeout: float) -> dict:
    """A window field the engine does not know stops the node instead of being defaulted."""
    original = network_module._write_model

    def write_with_misspelt_field(file: Path, model) -> None:
        data = json.loads(model.to_json())
        binding = (data.get("extraconfig") or {}).get("pq_consensus")
        if file.name != "config.json" or not binding:
            original(file, model)
            return
        binding["keys"][1]["validFrom"] = SUCCESSOR_FROM
        file.write_text(json.dumps(data))

    def configure(node):
        a_file = node.directory / "pq-consensus.seed"
        b_file = node.directory / "pq-consensus-next.seed"
        place_key(install, b_file, SUCCESSOR_SEED)
        set_keys(node, [key_entry(a_file, 0), key_entry(b_file, 5)])
        return {}

    network_module._write_model = write_with_misspelt_field
    try:
        network, node, _ = await boot(install, directory, base_port, configure)
    finally:
        network_module._write_model = original
    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = node.log_path.read_text(errors="replace") if node.log_path.exists() else ""
            if "validFrom is not a field" in log:
                break
            await asyncio.sleep(0.5)
        else:
            raise Failure("a misspelt window field did not stop the node")
        if GROUP_CREATED.search(node.log_path.read_text(errors="replace")):
            raise Failure("a node with a misspelt window field created a group")
        if "validFrom" not in (node.directory / "config.json").read_text():
            raise Failure("the refused configuration was rewritten")
        return {"decision": "refused_at_start", "log_path": str(node.log_path)}
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
    shim = (
        args.fsync_shim or args.build_dir / "crypto/pq/libtest-fsync-dir-failure-shim.so"
    ).resolve()
    if not shim.is_file():
        print(f"PQ_CONSENSUS_KEY_ROTATION_FAILED no directory-fsync shim at {shim}")
        return 1
    results = {}
    only = set(args.only or [])

    def wanted(name: str) -> bool:
        return not only or name in only

    try:
        port = args.base_port
        if wanted("rotation"):
            results["rotation"] = await rotation(
                install, artifact_dir / "rotation", port, args.timeout, shim
            )
        if wanted("missing"):
            results["missing"] = await without_a(
                install, artifact_dir / "missing", port + 100, args.timeout / 3, expired_a=False
            )
        if wanted("expired"):
            results["expired"] = await without_a(
                install, artifact_dir / "expired", port + 200, args.timeout / 3, expired_a=True
            )
        if wanted("expired_successor"):
            results["expired_successor"] = await expired_successor(
                install, artifact_dir / "expired-successor", port + 300, args.timeout
            )
        if wanted("concurrent"):
            results["concurrent"] = await concurrent(
                install, artifact_dir / "concurrent", port + 400, args.timeout
            )
        if wanted("hard_deadline"):
            results["hard_deadline"] = await hard_deadline(
                install, artifact_dir / "hard-deadline", port + 500, args.timeout
            )
        if wanted("misspelt"):
            results["misspelt"] = await misspelt(
                install, artifact_dir / "misspelt", port + 600, args.timeout
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

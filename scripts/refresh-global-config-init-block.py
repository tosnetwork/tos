#!/usr/bin/env python3
"""Write a copy of a global config whose init block follows native state selection.

A client or a new node proves its way forward from the global config's
validator.init_block, through every key block after it. Nodes collect old key
blocks with the rest of their archive, so a global config that still starts
from the zero state stops working for newcomers once the early key blocks are
gone. A network's published global config therefore has to be refreshed to a
recent key block, at least as often as the shortest archive retention among
its public lite servers.

This script reads the chain from one node's JSON-RPC and writes the refreshed
copy:

  getMasterchainInfo   the node's zero state and its last masterchain block
  getBlockHeader       walk key blocks backwards and read their timestamps
  lookupBlock          independently check each key block's full id

It refuses unless:

  * the input names a well-formed masterchain zero state, and the node's zero
    state is exactly that one (workchain, seqno 0, root hash and file hash);
  * every block id the node returns is a well-formed masterchain id, and the
    two answers for the key block (lookupBlock and getBlockHeader) agree on
    its full id;
  * the chosen block's header says it is a key block, and every header read
    (the last block's included) carries the global id the operator expects;
  * a key block at the height of the last block is that same block;
  * the new init block is not older than the one the input already has, and
    if it is at the same height it is the same block (full id, not height).

The newest eligible key block starts a new 2^17-second period relative to its
predecessor (the initial key block has no predecessor), is at least one hour
old, and has more than eight hours of persistent-state life remaining. Expiry
is gen_utime + 2^(18 + trailing_zero_bits(gen_utime / 2^17)), as in the node.
Selection uses timestamps only: it does not probe snapshot availability.

The node is trusted, not checked: nothing here verifies a proof. Point it at a
node you operate and have already compared, on the full block id, with a
second node you trust. The refreshed file is an input to a release; it is
authenticated by what the release does with it (digest and attestation), not
by this script.

Usage:
  refresh-global-config-init-block.py --rpc URL --global-id N IN OUT
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

MASTERCHAIN = -1
MASTERCHAIN_SHARD = -(2**63)
HASH_BYTES = 32
RPC_TIMEOUT_SECONDS = 20
PERSISTENT_STATE_PERIOD = 1 << 17
SYNC_BLOCKS_BEFORE = 3600
MIN_BOOTSTRAP_SECONDS = 8 * 3600
MAX_UNIX_TIME = (1 << 32) - 1
MAX_KEY_BLOCKS = 4096

Rpc = Callable[..., Any]


class RefreshError(Exception):
    pass


def http_rpc(url: str) -> Rpc:
    """A JSON-RPC 2.0 caller for `url`. Proxies from the environment are ignored:
    the answer must come from the node that was named."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(method: str, **params: Any) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        request = urllib.request.Request(
            url, body.encode(), {"Content-Type": "application/json"}, method="POST"
        )
        try:
            with opener.open(request, timeout=RPC_TIMEOUT_SECONDS) as response:
                answer = json.load(response)
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise RefreshError(f"{method}: request to {url} failed: {error}") from error
        if not isinstance(answer, dict):
            raise RefreshError(f"{method}: the node answered {answer!r}, not a JSON-RPC object")
        if answer.get("error") is not None or "result" not in answer:
            raise RefreshError(f"{method}: {answer.get('error', answer)}")
        return answer["result"]

    return call


def require_hash(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise RefreshError(f"{what} is {value!r}, not a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise RefreshError(f"{what} {value!r} is not valid base64") from error
    if len(raw) != HASH_BYTES:
        raise RefreshError(f"{what} decodes to {len(raw)} bytes, not {HASH_BYTES}")
    # One spelling per hash, so comparisons below are comparisons of bytes.
    return base64.b64encode(raw).decode()


def require_int(value: Any, what: str) -> int:
    # The node writes shards as decimal strings and seqnos as numbers; a
    # boolean or a float is never a block coordinate.
    if isinstance(value, bool):
        raise RefreshError(f"{what} is {value!r}, not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError as error:
            raise RefreshError(f"{what} is {value!r}, not an integer") from error
    raise RefreshError(f"{what} is {value!r}, not an integer")


def masterchain_id(value: Any, what: str) -> dict[str, Any]:
    """A full masterchain block id in the global config's spelling."""
    if not isinstance(value, dict):
        raise RefreshError(f"{what} is {value!r}, not a block id")
    workchain = require_int(value.get("workchain"), f"{what}.workchain")
    shard = require_int(value.get("shard"), f"{what}.shard")
    seqno = require_int(value.get("seqno"), f"{what}.seqno")
    if workchain != MASTERCHAIN or shard != MASTERCHAIN_SHARD:
        raise RefreshError(
            f"{what} is ({workchain},{shard}), not the masterchain ({MASTERCHAIN},{MASTERCHAIN_SHARD})"
        )
    if seqno < 0 or seqno >= 2**32:
        raise RefreshError(f"{what}.seqno {seqno} is out of range")
    return {
        "workchain": workchain,
        "shard": shard,
        "seqno": seqno,
        "root_hash": require_hash(value.get("root_hash"), f"{what}.root_hash"),
        "file_hash": require_hash(value.get("file_hash"), f"{what}.file_hash"),
    }


def require_object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RefreshError(f"{what} is {value!r}, not an object")
    return value


def check_global_id(header: dict[str, Any], seqno: int, global_id: int) -> None:
    header_global_id = require_int(header.get("global_id"), f"global_id of block {seqno}")
    if header_global_id != global_id:
        raise RefreshError(
            f"block {seqno} carries global id {header_global_id}, expected {global_id}"
        )


def header_of(rpc: Rpc, seqno: int) -> tuple[dict[str, Any], dict[str, Any]]:
    header = require_object(
        rpc("getBlockHeader", workchain=MASTERCHAIN, shard=str(MASTERCHAIN_SHARD), seqno=seqno),
        f"getBlockHeader({seqno})",
    )
    block = masterchain_id(header.get("id"), f"getBlockHeader({seqno}).id")
    if block["seqno"] != seqno:
        raise RefreshError(f"getBlockHeader({seqno}) answered block {block['seqno']}")
    return header, block


def block_time(header: dict[str, Any], seqno: int) -> int:
    timestamp = require_int(header.get("gen_utime"), f"gen_utime of block {seqno}")
    if not 0 < timestamp <= MAX_UNIX_TIME:
        raise RefreshError(f"gen_utime of block {seqno} is outside the nonzero uint32 range")
    return timestamp


def persistent_state_expiry(timestamp: int) -> int:
    """The expiry used by the node's persistent_state_ttl, without wrapping."""
    period = timestamp // PERSISTENT_STATE_PERIOD
    if period == 0:
        raise RefreshError("persistent-state timestamp precedes the first period")
    trailing_zeroes = (period & -period).bit_length() - 1
    expiry = timestamp + (1 << (18 + trailing_zeroes))
    if expiry > MAX_UNIX_TIME:
        raise RefreshError("persistent-state expiry exceeds the uint32 time range")
    return expiry


def eligible_persistent_state(created: int, previous: int | None, *, now: int) -> tuple[bool, str]:
    if previous is not None and previous > created:
        raise RefreshError("previous key block is newer than its successor")
    if (
        previous is not None
        and created // PERSISTENT_STATE_PERIOD == previous // PERSISTENT_STATE_PERIOD
    ):
        return False, "not the first key block of its persistent-state period"
    if created > now:
        return (
            False,
            f"block was created {created - now}s after this host's clock; check time synchronization",
        )
    if created + SYNC_BLOCKS_BEFORE > now:
        return False, "key block is less than one hour old"
    if persistent_state_expiry(created) <= now + MIN_BOOTSTRAP_SECONDS:
        return (
            False,
            f"persistent state expires within the requested {MIN_BOOTSTRAP_SECONDS}s download window",
        )
    return True, "persistent state meets the startup selection policy"


def refreshed(config: dict[str, Any], rpc: Rpc, *, global_id: int) -> dict[str, Any]:
    """Select the newest key block meeting the native startup policy."""
    validator = require_object(config.get("validator"), "validator")
    zero_state = masterchain_id(validator.get("zero_state"), "validator.zero_state")
    if zero_state["seqno"] != 0:
        raise RefreshError(f"validator.zero_state has seqno {zero_state['seqno']}, not 0")
    current = None
    if validator.get("init_block") is not None:
        current = masterchain_id(validator.get("init_block"), "validator.init_block")
    current_seqno = current["seqno"] if current is not None else 0
    if current is not None and current_seqno == 0 and current != zero_state:
        raise RefreshError(
            "the config's zero-state init block and zero state differ in their hashes"
        )

    info = require_object(rpc("getMasterchainInfo"), "getMasterchainInfo")
    node_zero = masterchain_id(info.get("init"), "getMasterchainInfo.init")
    if node_zero["seqno"] != 0:
        raise RefreshError(f"the node's zero state has seqno {node_zero['seqno']}, not 0")
    for field in ("root_hash", "file_hash"):
        if node_zero[field] != zero_state[field]:
            raise RefreshError(
                f"the node's zero state {field} {node_zero[field]} is not the config's "
                f"{zero_state[field]}: the node belongs to another network"
            )
    last = masterchain_id(info.get("last"), "getMasterchainInfo.last")

    last_header, last_block = header_of(rpc, last["seqno"])
    if last_block != last:
        raise RefreshError(
            f"getBlockHeader({last['seqno']}) and getMasterchainInfo disagree on the last block"
        )
    # Every header the node returns must belong to the expected network, the
    # zero-state path included.
    check_global_id(last_header, last["seqno"], global_id)
    if last_header.get("is_key_block") is True:
        key_seqno = last["seqno"]
    else:
        key_seqno = require_int(last_header.get("prev_key_block_seqno"), "prev_key_block_seqno")
    if key_seqno < 0 or key_seqno > last["seqno"]:
        raise RefreshError(f"prev_key_block_seqno {key_seqno} is outside 0..{last['seqno']}")
    if key_seqno < current_seqno:
        raise RefreshError(
            f"the node's latest key block {key_seqno} is older than the config's init block "
            f"{current_seqno}; the node is behind or on another chain"
        )

    def checked_key(seqno: int) -> tuple[dict[str, Any], dict[str, Any]]:
        looked_up = masterchain_id(
            rpc(
                "lookupBlock",
                workchain=MASTERCHAIN,
                shard=str(MASTERCHAIN_SHARD),
                seqno=seqno,
            ),
            f"lookupBlock({seqno})",
        )
        key_header, key_block = header_of(rpc, seqno)
        if key_block != looked_up:
            raise RefreshError(
                f"lookupBlock and getBlockHeader disagree on the full id of block {seqno}"
            )
        if key_header.get("is_key_block") is not True:
            raise RefreshError(f"block {seqno} is not a key block")
        check_global_id(key_header, seqno, global_id)
        # The last block was already identified in full; a key block at the
        # same height must be that very block, not another one at that height.
        if seqno == last["seqno"] and looked_up != last:
            raise RefreshError(
                f"block {seqno} as looked up is not the last block getMasterchainInfo named"
            )
        # Check the existing anchor even when its state is not available.
        if current is not None and seqno == current_seqno and looked_up != current:
            raise RefreshError(
                f"the config's init block {current_seqno} and the node's block at that height "
                f"differ in their hashes; the node is on another chain or the config is wrong"
            )
        previous = require_int(key_header.get("prev_key_block_seqno"), "prev_key_block_seqno")
        if previous < 0 or previous >= seqno:
            raise RefreshError(
                f"prev_key_block_seqno {previous} does not precede key block {seqno}"
            )
        block_time(key_header, seqno)
        return key_header, looked_up

    skipped: list[str] = []
    checked = 0
    pending = None
    while key_seqno > 0 and key_seqno >= current_seqno:
        if checked >= MAX_KEY_BLOCKS:
            raise RefreshError(
                f"no usable snapshot within {MAX_KEY_BLOCKS} key blocks; check the source"
            )
        checked += 1
        key_header, looked_up = checked_key(key_seqno) if pending is None else pending
        previous = require_int(key_header["prev_key_block_seqno"], "prev_key_block_seqno")
        pending = checked_key(previous) if previous > 0 else None
        previous_time = block_time(pending[0], previous) if pending is not None else None
        available, reason = eligible_persistent_state(
            block_time(key_header, key_seqno),
            previous_time,
            now=int(time.time()),
        )
        if available:
            result = json.loads(json.dumps(config))
            result["validator"]["init_block"] = looked_up
            return result
        if len(skipped) < 8:
            skipped.append(f"{key_seqno}: {reason}")
        key_seqno = previous

    details = "; ".join(skipped) or "no persistent key block has been published yet"
    recovery = (
        " The existing init block is not rolled back; to repair an unusable newer anchor, "
        "refresh from the original trusted global config after verifying the source."
        if current_seqno > 0
        else ""
    )
    raise RefreshError(
        f"no eligible persistent key block at or after init block {current_seqno}: {details}. "
        "Wait for a qualifying persistent-state key block before refreshing." + recovery
    )


def write_new_file(path: Path, text: str) -> None:
    """Write `path`, which must not exist, through a temporary file and a rename."""
    if path.exists() or path.is_symlink():
        raise RefreshError(f"{path} already exists; it is never overwritten")
    directory = path.parent
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=directory)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        # link() fails if the name appeared in the meantime, where a rename
        # would silently replace it.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def main(argv: list[str] | None = None, rpc_factory: Callable[[str], Rpc] = http_rpc) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--rpc", required=True, help="JSON-RPC URL of a node you trust")
    parser.add_argument(
        "--global-id", type=int, required=True, help="the network's global id, from its zero state"
    )
    parser.add_argument("input", type=Path, help="the global config to refresh")
    parser.add_argument("output", type=Path, help="where to write the refreshed copy (new file)")
    args = parser.parse_args(argv)
    try:
        try:
            config = json.loads(args.input.read_text())
        except (OSError, ValueError) as error:
            raise RefreshError(f"cannot read {args.input}: {error}") from error
        config = require_object(config, str(args.input))
        result = refreshed(config, rpc_factory(args.rpc), global_id=args.global_id)
        write_new_file(args.output, json.dumps(result, indent=2) + "\n")
    except (RefreshError, OSError) as error:
        print(f"GLOBAL_CONFIG_REFRESH_REFUSED: {error}", file=sys.stderr)
        return 1
    block = result["validator"]["init_block"]
    print(
        f"init_block ({block['workchain']},{block['shard']},{block['seqno']}) "
        f"root_hash {block['root_hash']} file_hash {block['file_hash']} -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

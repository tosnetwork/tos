#!/usr/bin/env python3
"""Write a copy of a global config whose init block is the latest key block.

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
  getBlockHeader       is_key_block / prev_key_block_seqno of the last block,
                       then the header of the chosen key block itself
  lookupBlock          the chosen key block's full id

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
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

MASTERCHAIN = -1
MASTERCHAIN_SHARD = -(2**63)
HASH_BYTES = 32
RPC_TIMEOUT_SECONDS = 20

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


def refreshed(config: dict[str, Any], rpc: Rpc, *, global_id: int) -> dict[str, Any]:
    """The config with validator.init_block set to the node's latest key block."""
    validator = require_object(config.get("validator"), "validator")
    zero_state = masterchain_id(validator.get("zero_state"), "validator.zero_state")
    if zero_state["seqno"] != 0:
        raise RefreshError(f"validator.zero_state has seqno {zero_state['seqno']}, not 0")
    current = None
    if validator.get("init_block") is not None:
        current = masterchain_id(validator.get("init_block"), "validator.init_block")
    current_seqno = current["seqno"] if current is not None else 0

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

    if key_seqno == 0:
        init_block = dict(zero_state)
    else:
        looked_up = masterchain_id(
            rpc(
                "lookupBlock",
                workchain=MASTERCHAIN,
                shard=str(MASTERCHAIN_SHARD),
                seqno=key_seqno,
            ),
            f"lookupBlock({key_seqno})",
        )
        key_header, key_block = header_of(rpc, key_seqno)
        if key_block != looked_up:
            raise RefreshError(
                f"lookupBlock and getBlockHeader disagree on the full id of block {key_seqno}"
            )
        if key_header.get("is_key_block") is not True:
            raise RefreshError(f"block {key_seqno} is not a key block")
        check_global_id(key_header, key_seqno, global_id)
        # The last block was already identified in full; a key block at the
        # same height must be that very block, not another one at that height.
        if key_seqno == last["seqno"] and looked_up != last:
            raise RefreshError(
                f"block {key_seqno} as looked up is not the last block getMasterchainInfo named"
            )
        init_block = looked_up

    # Heights alone never decide: an existing init block at the same height must
    # be the same block, or the node and the config are on different chains.
    if current is not None and init_block["seqno"] == current["seqno"] and init_block != current:
        raise RefreshError(
            f"the config's init block {current['seqno']} and the node's block at that height "
            f"differ in their hashes; the node is on another chain or the config is wrong"
        )

    result = json.loads(json.dumps(config))
    result["validator"]["init_block"] = init_block
    return result


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

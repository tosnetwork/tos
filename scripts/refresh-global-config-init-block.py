#!/usr/bin/env python3
"""Write a global config anchored at the newest available bootstrap snapshot.

A client or a new node proves its way forward from the global config's
validator.init_block, through every key block after it. Nodes collect old key
blocks with the rest of their archive, so a global config that still starts
from the zero state stops working for newcomers once the early key blocks are
gone. A network's published global config therefore has to be refreshed to a
served persistent key block, before its state or catch-up archives expire.
Ordinary key blocks and snapshots still being serialized cannot bootstrap a
new node. Bootstrap sources must retain archives across the persistent-state
period, serialization delay, and the time newcomers need to catch up.

This script reads the chain from one node's JSON-RPC and writes the refreshed
copy:

  getMasterchainInfo   the node's zero state and its last masterchain block
  getBlockHeader       walk backwards through key-block headers
  lookupBlock          independently identify each candidate in full
  getBootstrapState    check the serving archive for the candidate's state,
                       shard states, required split parts and shard proofs

It refuses unless:

  * the input names a well-formed masterchain zero state, and the node's zero
    state is exactly that one (workchain, seqno 0, root hash and file hash);
  * every block id the node returns is a well-formed masterchain id, and the
    two answers for the key block (lookupBlock and getBlockHeader) agree on
    its full id;
  * the chosen block's header says it is a key block, and every header read
    (the last block's included) carries the global id the operator expects;
  * a key block at the height of the last block is that same block;
  * the complete snapshot is available and both its state and the source's
    archive retention have the requested remaining bootstrap time;
  * the new init block is not older than the one the input already has, and
    if it is at the same height it is the same block (full id, not height).

A candidate that is not ready is skipped and the walk moves to the previous
key block, except when the source reports that it is busy (`resource_limit`
or `timeout`): those say nothing about the snapshot, and the readiness method
admits only two scans at a time, so anyone can keep it busy. The same
candidate is asked again with bounded backoff, and the script refuses if the
source stays busy, rather than settle for an older anchor. `resource_limit`
also covers a snapshot that exceeds the source's scan budget; that never
clears, and the refusal says so. A candidate newer than this host's clock is
skipped with a message naming the clock difference: remaining validity
cannot be measured from a clock that is behind the source's blocks.

The node is trusted, not checked: nothing here verifies a proof. Point it at a
node you operate and have already compared, on the full block id, with a
second node you trust. The refreshed file is an input to a release; it is
authenticated by what the release does with it (digest and attestation), not
by this script. Availability is checked on that source, not on every peer.
A fresh node needs no extra flag: by default it walks the key blocks after the
anchor and chooses a persistent state itself. --skip-key-sync is optional and
makes it start exactly at this checked anchor instead. See
doc/validator-operator-guide.md for source retention and publication steps.

Usage:
  refresh-global-config-init-block.py --rpc URL --global-id N IN OUT
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
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
MIN_BOOTSTRAP_SECONDS = 8 * 3600
MAX_KEY_BLOCKS = 4096
# Readiness reasons that describe the source's load, not the snapshot.
BUSY_REASONS = frozenset({"resource_limit", "timeout"})
# Seconds to wait before each repeated readiness query of a busy source.
BUSY_RETRY_DELAYS = (2, 4, 8, 16, 30)

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


def bootstrap_available(
    rpc: Rpc,
    block: dict[str, Any],
    header: dict[str, Any],
    *,
    now: int | None,
    minimum_validity: int,
) -> tuple[bool, str]:
    """Check the exact serving snapshot and a conservative catch-up horizon."""
    seqno = block["seqno"]
    status = require_object(
        rpc("getBootstrapState", **{**block, "shard": str(MASTERCHAIN_SHARD)}),
        f"getBootstrapState({seqno})",
    )
    returned_id = masterchain_id(status.get("id"), f"getBootstrapState({seqno}).id")
    if returned_id != block:
        raise RefreshError(f"getBootstrapState({seqno}) answered a different full block id")
    if not isinstance(status.get("ready"), bool):
        raise RefreshError(f"getBootstrapState({seqno}).ready is not a boolean")
    reason = status.get("reason")
    if not isinstance(reason, str) or not reason:
        raise RefreshError(f"getBootstrapState({seqno}).reason is not a nonempty string")
    if not status["ready"]:
        return False, reason

    # A scan can outlive the requested remaining validity. Measure after the
    # readiness response, not when the scan began. Explicit `now` is for tests.
    if now is None:
        now = int(time.time())

    created = require_int(status.get("gen_utime"), f"getBootstrapState({seqno}).gen_utime")
    header_created = require_int(header.get("gen_utime"), f"gen_utime of block {seqno}")
    if created != header_created or created <= 0:
        raise RefreshError(f"getBootstrapState({seqno}) has an inconsistent snapshot timestamp")
    if created > now:
        # The remaining-time checks below would be measured from a clock that
        # is behind the chain; an older candidate may still qualify.
        return (
            False,
            f"block was created {created - now}s after this host's clock; "
            "check this host's time synchronization",
        )
    expires = require_int(status.get("expires_at"), f"getBootstrapState({seqno}).expires_at")
    if expires <= created:
        raise RefreshError(f"getBootstrapState({seqno}) has an invalid snapshot expiry")
    archive_ttl = status.get("archive_ttl")
    if isinstance(archive_ttl, bool) or not isinstance(archive_ttl, (int, float)):
        raise RefreshError(f"getBootstrapState({seqno}).archive_ttl is not a duration")
    try:
        finite = math.isfinite(archive_ttl)
    except OverflowError:
        finite = False
    if not finite or archive_ttl <= 0:
        raise RefreshError(f"getBootstrapState({seqno}).archive_ttl is not a positive duration")
    if expires <= now + minimum_validity:
        return False, f"snapshot expires within the requested {minimum_validity}s bootstrap window"
    # Do not count CellDB retention or delayed GC as promised archive retention.
    # Retaining a snapshot alone does not retain the blocks needed after it.
    if created + archive_ttl <= now + minimum_validity:
        return (
            False,
            f"archive retention cannot cover the requested {minimum_validity}s bootstrap window",
        )
    return True, reason


def bootstrap_available_when_idle(
    rpc: Rpc,
    block: dict[str, Any],
    header: dict[str, Any],
    *,
    now: int | None,
    minimum_validity: int,
    sleep: Callable[[float], None],
) -> tuple[bool, str]:
    """bootstrap_available, asked again while the source reports it is busy."""
    attempts = len(BUSY_RETRY_DELAYS) + 1
    reason = ""
    for attempt in range(attempts):
        available, reason = bootstrap_available(
            rpc, block, header, now=now, minimum_validity=minimum_validity
        )
        if available or reason not in BUSY_REASONS:
            return available, reason
        if attempt < len(BUSY_RETRY_DELAYS):
            delay = BUSY_RETRY_DELAYS[attempt]
            print(
                f"getBootstrapState({block['seqno']}): source busy ({reason}); "
                f"asking again in {delay}s",
                file=sys.stderr,
            )
            sleep(delay)
    raise RefreshError(
        f"getBootstrapState({block['seqno']}) answered {reason} {attempts} times: the source is "
        "busy, or the snapshot exceeds its scan budget, so the snapshot's readiness is unknown. "
        "An older anchor is not substituted; retry later or use a source that is not saturated."
    )


def refreshed(
    config: dict[str, Any],
    rpc: Rpc,
    *,
    global_id: int,
    minimum_validity: int = MIN_BOOTSTRAP_SECONDS,
    now: int | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Set validator.init_block to the newest complete, sufficiently retained snapshot."""
    if minimum_validity <= 0:
        raise RefreshError("minimum bootstrap validity must be positive")
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

    skipped: list[str] = []
    checked = 0
    while key_seqno > 0 and key_seqno >= current_seqno:
        if checked >= MAX_KEY_BLOCKS:
            raise RefreshError(
                f"no usable snapshot within {MAX_KEY_BLOCKS} key blocks; check the source"
            )
        checked += 1
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
        # Check the existing anchor even when its state is not available.
        if current is not None and key_seqno == current_seqno and looked_up != current:
            raise RefreshError(
                f"the config's init block {current_seqno} and the node's block at that height "
                f"differ in their hashes; the node is on another chain or the config is wrong"
            )
        available, reason = bootstrap_available_when_idle(
            rpc,
            looked_up,
            key_header,
            now=now,
            minimum_validity=minimum_validity,
            sleep=time.sleep if sleep is None else sleep,
        )
        if available:
            result = json.loads(json.dumps(config))
            result["validator"]["init_block"] = looked_up
            return result
        if len(skipped) < 8:
            skipped.append(f"{key_seqno}: {reason}")
        previous = require_int(key_header.get("prev_key_block_seqno"), "prev_key_block_seqno")
        if previous < 0 or previous >= key_seqno:
            raise RefreshError(
                f"prev_key_block_seqno {previous} does not precede key block {key_seqno}"
            )
        key_seqno = previous

    details = "; ".join(skipped) or "no persistent key block has been published yet"
    recovery = (
        " The existing init block is not rolled back; to repair an unusable newer anchor, "
        "refresh from the original trusted global config after verifying the source."
        if current_seqno > 0
        else ""
    )
    raise RefreshError(
        f"no available bootstrap snapshot at or after init block {current_seqno}: {details}. "
        "Wait for complete serialization, or use a bootstrap source with sufficient archives."
        + recovery
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
    parser.add_argument(
        "--minimum-validity",
        type=int,
        default=MIN_BOOTSTRAP_SECONDS,
        help="seconds of remaining snapshot and archive retention required (default: 28800)",
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
        result = refreshed(
            config,
            rpc_factory(args.rpc),
            global_id=args.global_id,
            minimum_validity=args.minimum_validity,
        )
        write_new_file(args.output, json.dumps(result, indent=2) + "\n")
    except (RefreshError, OSError) as error:
        print(f"GLOBAL_CONFIG_REFRESH_REFUSED: {error}", file=sys.stderr)
        return 1
    block = result["validator"]["init_block"]
    print(
        f"init_block ({block['workchain']},{block['shard']},{block['seqno']}) "
        f"root_hash {block['root_hash']} file_hash {block['file_hash']} -> {args.output}"
    )
    print(
        "This anchor's snapshot is served, so --skip-key-sync may start a fresh node exactly here; "
        "publish the config before its validity window closes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

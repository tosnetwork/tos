#!/usr/bin/env python3
"""Offline tests for scripts/refresh-global-config-init-block.py.

The node's JSON-RPC is replaced by a fake chain, so each test states exactly
which blocks exist. Refusal tests check the specific reason and that no output
file was written.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "refresh_global_config_init_block", HERE / "refresh-global-config-init-block.py"
)
assert SPEC is not None and SPEC.loader is not None
refresh = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = refresh
SPEC.loader.exec_module(refresh)
RefreshError = refresh.RefreshError

SHARD = -(2**63)
GLOBAL_ID = 1


def h(label: str) -> str:
    """A distinct, well-formed base64 hash per label."""
    return base64.b64encode(label.encode().ljust(32, b".")[:32]).decode()


ZERO = {"workchain": -1, "shard": SHARD, "seqno": 0, "root_hash": h("zr"), "file_hash": h("zf")}
OTHER_ZERO = {**ZERO, "root_hash": h("other-zr")}

GLOBAL_CONFIG = {
    "@type": "config.global",
    "dht": {"@type": "dht.config.global", "k": 6, "a": 3, "static_nodes": {"nodes": []}},
    "validator": {"@type": "validator.config.global", "zero_state": ZERO, "hardforks": []},
}


def rpc_id(seqno: int) -> dict[str, Any]:
    """A block id as the node's JSON-RPC writes it (shard as a decimal string)."""
    if seqno == 0:
        root, file = ZERO["root_hash"], ZERO["file_hash"]
    else:
        root, file = h(f"r{seqno}"), h(f"f{seqno}")
    return {
        "@type": "tos.blockIdExt",
        "workchain": -1,
        "shard": str(SHARD),
        "seqno": seqno,
        "root_hash": root,
        "file_hash": file,
    }


def config_id(seqno: int) -> dict[str, Any]:
    block = rpc_id(seqno)
    return {
        "workchain": -1,
        "shard": SHARD,
        "seqno": seqno,
        "root_hash": block["root_hash"],
        "file_hash": block["file_hash"],
    }


class FakeChain:
    """Masterchain blocks 0..last; `key_blocks` are the key blocks among them."""

    def __init__(self, last: int, key_blocks: set[int], zero: dict[str, Any] = ZERO) -> None:
        self.last = last
        self.key_blocks = key_blocks
        self.zero = zero
        self.global_id = GLOBAL_ID
        self.calls: list[tuple[str, dict[str, Any]]] = []
        # Hooks that let a test make one answer lie.
        self.lookup_override: dict[int, dict[str, Any]] = {}
        self.header_override: dict[int, dict[str, Any]] = {}

    def prev_key(self, seqno: int) -> int:
        earlier = [k for k in self.key_blocks if k < seqno]
        return max(earlier) if earlier else 0

    def __call__(self, method: str, **params: Any) -> Any:
        self.calls.append((method, params))
        if method == "getMasterchainInfo":
            return {
                "@type": "blocks.masterchainInfo",
                "last": rpc_id(self.last),
                "state_root_hash": h("state"),
                "init": {
                    **rpc_id(0),
                    "root_hash": self.zero["root_hash"],
                    "file_hash": self.zero["file_hash"],
                },
            }
        if params.get("workchain") != -1 or params.get("shard") != str(SHARD):
            raise RefreshError(f"{method} asked for a non-masterchain block: {params}")
        seqno = params["seqno"]
        if not 0 < seqno <= self.last:
            raise RefreshError(f"{method}: block {seqno} not found")
        if method == "lookupBlock":
            return self.lookup_override.get(seqno, rpc_id(seqno))
        if method == "getBlockHeader":
            header = {
                "@type": "blocks.header",
                "id": rpc_id(seqno),
                "global_id": self.global_id,
                "is_key_block": seqno in self.key_blocks,
                "prev_key_block_seqno": self.prev_key(seqno),
            }
            header.update(self.header_override.get(seqno, {}))
            return header
        raise RefreshError(f"unexpected method {method}")


class RefreshTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="refresh-global-config-"))
        self.input = self.tmp / "global-config.json"
        self.output = self.tmp / "refreshed.json"
        self.config = copy.deepcopy(GLOBAL_CONFIG)

    def tearDown(self) -> None:
        for path in sorted(self.tmp.rglob("*"), reverse=True):
            path.unlink()
        self.tmp.rmdir()

    def run_main(self, chain: FakeChain, global_id: int = GLOBAL_ID) -> tuple[int, str, str]:
        self.input.write_text(json.dumps(self.config))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = refresh.main(
                [
                    "--rpc",
                    "http://node.invalid:8081",
                    "--global-id",
                    str(global_id),
                    str(self.input),
                    str(self.output),
                ],
                rpc_factory=lambda url: chain,
            )
        return code, out.getvalue(), err.getvalue()

    def refreshed(self, chain: FakeChain) -> dict[str, Any]:
        code, _, err = self.run_main(chain)
        self.assertEqual(code, 0, err)
        return json.loads(self.output.read_text())

    def assert_refused(self, chain: FakeChain, reason: str, global_id: int = GLOBAL_ID) -> None:
        code, _, err = self.run_main(chain, global_id)
        self.assertEqual(code, 1, err)
        self.assertIn("GLOBAL_CONFIG_REFRESH_REFUSED", err)
        self.assertIn(reason, err)
        self.assertFalse(self.output.exists(), "a refusal must not write the output")

    # ---- success

    def test_init_block_becomes_the_previous_key_block(self) -> None:
        result = self.refreshed(FakeChain(last=120, key_blocks={40, 100}))
        self.assertEqual(result["validator"]["init_block"], config_id(100))
        expected = copy.deepcopy(GLOBAL_CONFIG)
        expected["validator"]["init_block"] = config_id(100)
        self.assertEqual(result, expected, "nothing but the init block changes")

    def test_last_block_that_is_a_key_block_is_used_itself(self) -> None:
        result = self.refreshed(FakeChain(last=100, key_blocks={40, 100}))
        self.assertEqual(result["validator"]["init_block"], config_id(100))

    def test_shard_is_written_as_a_signed_integer(self) -> None:
        result = self.refreshed(FakeChain(last=120, key_blocks={100}))
        self.assertIs(type(result["validator"]["init_block"]["shard"]), int)
        self.assertEqual(result["validator"]["init_block"]["shard"], -9223372036854775808)

    def test_chain_without_key_blocks_starts_from_the_zero_state(self) -> None:
        result = self.refreshed(FakeChain(last=12, key_blocks=set()))
        self.assertEqual(result["validator"]["init_block"], ZERO)

    def test_existing_older_init_block_is_replaced(self) -> None:
        self.config["validator"]["init_block"] = config_id(40)
        result = self.refreshed(FakeChain(last=120, key_blocks={40, 100}))
        self.assertEqual(result["validator"]["init_block"], config_id(100))

    def test_the_input_is_never_modified(self) -> None:
        self.refreshed(FakeChain(last=120, key_blocks={100}))
        self.assertEqual(json.loads(self.input.read_text()), GLOBAL_CONFIG)

    # ---- refusals

    def test_node_of_another_network_is_refused(self) -> None:
        self.assert_refused(
            FakeChain(last=120, key_blocks={100}, zero=OTHER_ZERO),
            "the node belongs to another network",
        )

    def test_zero_state_file_hash_mismatch_is_refused(self) -> None:
        self.assert_refused(
            FakeChain(last=120, key_blocks={100}, zero={**ZERO, "file_hash": h("other-zf")}),
            "zero state file_hash",
        )

    def test_wrong_global_id_is_refused(self) -> None:
        self.assert_refused(
            FakeChain(last=120, key_blocks={100}), "carries global id 1, expected 2", global_id=2
        )

    def test_block_that_is_not_a_key_block_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[100] = {"is_key_block": False}
        self.assert_refused(chain, "block 100 is not a key block")

    def test_lookup_and_header_disagreeing_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.lookup_override[100] = {**rpc_id(100), "root_hash": h("forked")}
        self.assert_refused(chain, "disagree on the full id of block 100")

    def test_last_block_disagreeing_with_its_header_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[120] = {"id": {**rpc_id(120), "file_hash": h("forked")}}
        self.assert_refused(chain, "disagree on the last block")

    def test_node_behind_the_config_is_refused(self) -> None:
        self.config["validator"]["init_block"] = config_id(100)
        self.assert_refused(
            FakeChain(last=90, key_blocks={40, 100}), "is older than the config's init block"
        )

    def test_non_masterchain_answer_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.lookup_override[100] = {**rpc_id(100), "workchain": 0}
        self.assert_refused(chain, "not the masterchain")

    def test_malformed_hash_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.lookup_override[100] = {**rpc_id(100), "root_hash": "AAAA"}
        self.assert_refused(chain, "decodes to 3 bytes")

    def test_prev_key_beyond_the_last_block_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[120] = {"prev_key_block_seqno": 121}
        self.assert_refused(chain, "outside 0..120")

    def test_config_without_a_masterchain_zero_state_is_refused(self) -> None:
        self.config["validator"]["zero_state"] = {**ZERO, "shard": 0}
        self.assert_refused(FakeChain(last=120, key_blocks={100}), "validator.zero_state")

    def test_existing_output_is_never_overwritten(self) -> None:
        self.output.write_text("keep")
        code, _, err = self.run_main(FakeChain(last=120, key_blocks={100}))
        self.assertEqual(code, 1)
        self.assertIn("is never overwritten", err)
        self.assertEqual(self.output.read_text(), "keep")

    def test_rpc_error_is_refused(self) -> None:
        def failing(method: str, **params: Any) -> Any:
            raise RefreshError(f"{method}: request failed")

        self.input.write_text(json.dumps(self.config))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = refresh.main(
                ["--rpc", "http://x", "--global-id", "1", str(self.input), str(self.output)],
                rpc_factory=lambda url: failing,
            )
        self.assertEqual(code, 1)
        self.assertIn("getMasterchainInfo: request failed", err.getvalue())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

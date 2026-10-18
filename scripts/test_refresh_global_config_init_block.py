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
from unittest import mock

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
NOW = 1_800_000_000


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
        # Overrides consumed one per getBlockHeader call, before header_override.
        self.header_sequence: dict[int, list[dict[str, Any]]] = {}
        self.init_seqno = 0

    def timestamp(self, seqno: int) -> int:
        keys = sorted(self.key_blocks)
        base = ((NOW - 12 * 3600) // (1 << 17)) * (1 << 17)
        preceding = [key for key in keys if key <= seqno]
        if not preceding:
            return base - (1 << 17)
        key = preceding[-1]
        return base + (keys.index(key) - len(keys) + 1) * (1 << 17) + 3600 + (seqno - key) * 60

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
                    "seqno": self.init_seqno,
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
                "gen_utime": self.timestamp(seqno),
            }
            header.update(self.header_override.get(seqno, {}))
            sequence = self.header_sequence.get(seqno)
            if sequence:
                header.update(sequence.pop(0))
            return header
        raise RefreshError(f"unexpected method {method}")


class RefreshTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="refresh-global-config-"))
        self.input = self.tmp / "global-config.json"
        self.output = self.tmp / "refreshed.json"
        self.config = copy.deepcopy(GLOBAL_CONFIG)
        clock = mock.patch("time.time", return_value=NOW)
        self.clock = clock.start()
        self.addCleanup(clock.stop)

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

    def test_chain_without_key_blocks_cannot_publish_a_bootstrap_snapshot(self) -> None:
        self.assert_refused(
            FakeChain(last=12, key_blocks=set()), "no persistent key block has been published yet"
        )

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

    def test_zero_state_path_checks_the_global_id(self) -> None:
        # No key block yet: the init block is the zero state, but the node's
        # headers must still carry the expected global id.
        self.assert_refused(
            FakeChain(last=12, key_blocks=set()), "carries global id 1, expected 2", global_id=2
        )

    def test_last_block_of_another_network_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[120] = {"global_id": 7}
        self.assert_refused(chain, "block 120 carries global id 7, expected 1")

    def test_node_zero_state_with_a_nonzero_seqno_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.init_seqno = 9
        self.assert_refused(chain, "the node's zero state has seqno 9, not 0")

    def test_same_height_init_block_with_other_hashes_is_refused(self) -> None:
        self.config["validator"]["init_block"] = {**config_id(100), "root_hash": h("other-100")}
        self.assert_refused(FakeChain(last=120, key_blocks={40, 100}), "differ in their hashes")

    def test_same_height_zero_state_init_block_with_other_hashes_is_refused(self) -> None:
        self.config["validator"]["init_block"] = {**ZERO, "file_hash": h("other-zf")}
        self.assert_refused(FakeChain(last=12, key_blocks=set()), "differ in their hashes")

    def test_same_init_block_is_kept(self) -> None:
        self.config["validator"]["init_block"] = config_id(100)
        result = self.refreshed(FakeChain(last=120, key_blocks={40, 100}))
        self.assertEqual(result["validator"]["init_block"], config_id(100))

    def test_key_block_at_the_last_height_must_be_the_last_block(self) -> None:
        # The first header of block 100 matches getMasterchainInfo; the second
        # answer and lookupBlock agree with each other on another block 100.
        chain = FakeChain(last=100, key_blocks={40, 100})
        other = {**rpc_id(100), "root_hash": h("other-100"), "file_hash": h("other-f100")}
        chain.lookup_override[100] = other
        chain.header_sequence[100] = [{}, {"id": other}]
        self.assert_refused(chain, "is not the last block getMasterchainInfo named")

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

    def test_only_metadata_methods_are_called(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(100))
        self.assertEqual(
            {method for method, _ in chain.calls},
            {"getMasterchainInfo", "getBlockHeader", "lookupBlock"},
        )

    def test_ordinary_key_block_is_skipped(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 80, 100})
        chain.header_override[80] = {"gen_utime": chain.timestamp(100)}
        chain.header_override[100] = {"gen_utime": chain.timestamp(100) + 60}
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(80))

    def test_period_boundary_uses_the_previous_key_block(self) -> None:
        boundary = ((NOW - 12 * 3600) // (1 << 17)) * (1 << 17)
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.header_override[40] = {"gen_utime": boundary - 1}
        chain.header_override[100] = {"gen_utime": boundary}
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(100))

    def test_same_period_is_not_a_boundary_even_for_nearby_seconds(self) -> None:
        boundary = ((NOW - 12 * 3600) // (1 << 17)) * (1 << 17)
        for previous, current in ((0, 1), (65535, 65536)):
            with self.subTest(previous=previous, current=current):
                self.output.unlink(missing_ok=True)
                chain = FakeChain(last=120, key_blocks={40, 100})
                chain.header_override[40] = {"gen_utime": boundary + previous}
                chain.header_override[100] = {"gen_utime": boundary + current}
                self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(40))

    def test_one_hour_age_boundary(self) -> None:
        for age, expected in ((3599, 40), (3600, 100), (3601, 100)):
            with self.subTest(age=age):
                self.output.unlink(missing_ok=True)
                chain = FakeChain(last=120, key_blocks={40, 100})
                chain.header_override[40] = {"gen_utime": 13728 * 131072 + 3600}
                chain.header_override[100] = {"gen_utime": NOW - age}
                self.assertEqual(
                    self.refreshed(chain)["validator"]["init_block"], config_id(expected)
                )

    def test_only_too_young_key_block_writes_nothing(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[100] = {"gen_utime": NOW - 3599}
        self.assert_refused(chain, "less than one hour old")

    def test_future_key_block_is_skipped(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.header_override[40] = {"gen_utime": 13728 * 131072 + 3600}
        chain.header_override[100] = {"gen_utime": NOW + 120}
        code, _, err = self.run_main(chain)
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(self.output.read_text())["validator"]["init_block"], config_id(40)
        )

    def test_only_future_key_block_writes_nothing(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[40] = {"gen_utime": 13728 * 131072 + 3600}
        chain.header_override[100] = {"gen_utime": NOW + 120}
        self.assert_refused(chain, "120s after this host's clock")

    def test_native_lifetime_vectors(self) -> None:
        for period, lifetime in (
            (1, 262144),
            (2, 524288),
            (3, 262144),
            (4, 1048576),
            (6, 524288),
            (8, 2097152),
            (12, 1048576),
        ):
            with self.subTest(period=period):
                timestamp = period * 131072 + 123
                self.assertEqual(refresh.persistent_state_expiry(timestamp), timestamp + lifetime)

    def test_expiry_must_exceed_eight_hours_at_selection(self) -> None:
        created = 13733 * 131072 + 60
        expiry = created + 262144
        for delta, expected in ((-1, 100), (0, 40), (1, 40)):
            with self.subTest(delta=delta):
                self.output.unlink(missing_ok=True)
                chain = FakeChain(last=120, key_blocks={40, 100})
                chain.header_override[40] = {"gen_utime": created - 131072}
                chain.header_override[100] = {"gen_utime": created}
                with mock.patch("time.time", return_value=expiry - 28800 + delta):
                    self.assertEqual(
                        self.refreshed(chain)["validator"]["init_block"], config_id(expected)
                    )

    def test_only_expiring_state_writes_nothing(self) -> None:
        created = 13733 * 131072 + 60
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[100] = {"gen_utime": created}
        with mock.patch("time.time", return_value=created + 262144 - 28800):
            self.assert_refused(chain, "expires within the requested 28800s")

    def test_remaining_life_is_checked_after_header_reads(self) -> None:
        created = 13733 * 131072 + 60
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.header_override[40] = {"gen_utime": created - 131072}
        chain.header_override[100] = {"gen_utime": created}

        def rpc(method: str, **params: Any) -> Any:
            answer = chain(method, **params)
            if method == "getBlockHeader" and params["seqno"] == 40:
                self.clock.return_value = created + 262144 - 28800
            return answer

        self.clock.return_value = created + 262144 - 28801
        self.assertEqual(self.refreshed(rpc)["validator"]["init_block"], config_id(40))

    def test_previous_key_header_is_checked_in_full(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.lookup_override[40] = {**rpc_id(40), "root_hash": h("fork")}
        self.assert_refused(chain, "disagree on the full id of block 40")

    def test_every_predecessor_must_be_a_key_block_of_the_expected_network(self) -> None:
        for changes, reason in (
            ({"is_key_block": False}, "block 40 is not a key block"),
            ({"global_id": 2}, "block 40 carries global id 2"),
        ):
            with self.subTest(changes=changes):
                chain = FakeChain(last=120, key_blocks={40, 100})
                chain.header_override[40] = changes
                self.assert_refused(chain, reason)

    def test_timestamp_is_nonzero_uint32(self) -> None:
        for value in (None, True, 0, -1, 1.5, 1 << 32):
            with self.subTest(value=value):
                chain = FakeChain(last=120, key_blocks={100})
                chain.header_override[100] = {"gen_utime": value}
                self.assert_refused(chain, "gen_utime of block 100")

    def test_older_key_block_cannot_have_a_later_timestamp(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.header_override[40] = {"gen_utime": chain.timestamp(100) + 1}
        self.assert_refused(chain, "previous key block is newer")

    def test_expiry_does_not_wrap(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[100] = {"gen_utime": (1 << 32) - 3601}
        with mock.patch("time.time", return_value=(1 << 32) - 1):
            self.assert_refused(chain, "expiry exceeds the uint32 time range")

    def test_unusable_newer_existing_anchor_is_not_rolled_back(self) -> None:
        self.config["validator"]["init_block"] = config_id(100)
        chain = FakeChain(last=120, key_blocks={40, 80, 100})
        chain.header_override[100] = {"gen_utime": chain.timestamp(80) + 60}
        self.assert_refused(chain, "existing init block is not rolled back")

    def test_backward_walk_cannot_loop_or_move_forward(self) -> None:
        for previous in (100, 120, -1):
            with self.subTest(previous=previous):
                chain = FakeChain(last=120, key_blocks={100})
                chain.header_override[100] = {"prev_key_block_seqno": previous}
                self.assert_refused(chain, "does not precede key block 100")

    def test_backward_walk_is_bounded(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 80, 100})
        for key in chain.key_blocks:
            chain.header_override[key] = {"gen_utime": NOW - 12 * 3600}
        with mock.patch.object(refresh, "MAX_KEY_BLOCKS", 2):
            self.assert_refused(chain, "no usable snapshot within 2 key blocks")


if __name__ == "__main__":
    unittest.main()

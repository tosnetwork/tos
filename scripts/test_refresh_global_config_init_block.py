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
        self.ready_blocks = set(key_blocks)
        self.bootstrap_override: dict[int, dict[str, Any]] = {}
        # Overrides consumed one per getBootstrapState call, after bootstrap_override.
        self.bootstrap_sequence: dict[int, list[dict[str, Any]]] = {}

    def timestamp(self, seqno: int) -> int:
        return NOW - 12 * 3600 - (self.last - seqno) * 60

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
        if method == "getBootstrapState":
            if (
                params.get("root_hash") != rpc_id(seqno)["root_hash"]
                or params.get("file_hash") != rpc_id(seqno)["file_hash"]
            ):
                raise RefreshError("readiness query is not bound to the full block id")
            ready = seqno in self.ready_blocks
            status = {
                "id": rpc_id(seqno),
                "ready": ready,
                "reason": "ready" if ready else "state_unavailable",
                "gen_utime": self.timestamp(seqno),
                "expires_at": self.timestamp(seqno) + 3 * 86400,
                "archive_ttl": 7 * 86400,
            }
            status.update(self.bootstrap_override.get(seqno, {}))
            sequence = self.bootstrap_sequence.get(seqno)
            if sequence:
                status.update(sequence.pop(0))
            # By default every required proof is in the anchor's own package.
            if "archive_expires_at" not in status and isinstance(status.get("gen_utime"), int):
                ttl = status.get("archive_ttl")
                if isinstance(ttl, int) and not isinstance(ttl, bool):
                    status["archive_expires_at"] = status["gen_utime"] + ttl
                else:
                    status["archive_expires_at"] = status["gen_utime"] + 7 * 86400
            return status
        raise RefreshError(f"unexpected method {method}")


class RefreshTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="refresh-global-config-"))
        self.input = self.tmp / "global-config.json"
        self.output = self.tmp / "refreshed.json"
        self.config = copy.deepcopy(GLOBAL_CONFIG)
        clock = mock.patch("time.time", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)
        # No test waits; each records the waits the script asked for.
        sleeper = mock.patch("time.sleep")
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)

    def sleeps(self) -> list[float]:
        return [call.args[0] for call in self.sleep.call_args_list]

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

    # ---- completed persistent snapshots, not merely recent key blocks

    def test_newest_unserved_key_blocks_fall_back_to_the_served_snapshot(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 80, 100})
        chain.ready_blocks = {40}
        chain.bootstrap_override[100] = {"reason": "snapshot_not_found"}
        result = self.refreshed(chain)
        self.assertEqual(result["validator"]["init_block"], config_id(40))
        probes = [params for method, params in chain.calls if method == "getBootstrapState"]
        self.assertEqual([p["seqno"] for p in probes], [100, 80, 40])
        for query in probes:
            self.assertEqual(query["root_hash"], rpc_id(query["seqno"])["root_hash"])
            self.assertEqual(query["file_hash"], rpc_id(query["seqno"])["file_hash"])

    def test_latest_persistent_snapshot_is_used_only_after_it_becomes_ready(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.ready_blocks = {40}
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(40))
        self.output.unlink()
        chain.ready_blocks.add(100)
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(100))

    def test_no_served_snapshot_writes_nothing(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.ready_blocks.clear()
        self.assert_refused(chain, "no available bootstrap snapshot")

    def test_missing_shard_parts_or_proofs_prevent_publication(self) -> None:
        for reason in ("state_unavailable", "proof_unavailable", "invalid_state", "resource_limit"):
            with self.subTest(reason=reason):
                chain = FakeChain(last=120, key_blocks={100})
                chain.bootstrap_override[100] = {"ready": False, "reason": reason}
                self.assert_refused(chain, reason)

    def test_unusable_newer_existing_anchor_is_not_rolled_back(self) -> None:
        self.config["validator"]["init_block"] = config_id(100)
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.ready_blocks = {40}
        self.assert_refused(chain, "refresh from the original trusted global config")
        self.assertNotIn(40, [p["seqno"] for m, p in chain.calls if m == "getBootstrapState"])

    def test_same_height_fork_is_rejected_even_when_snapshot_is_unavailable(self) -> None:
        self.config["validator"]["init_block"] = {**config_id(40), "file_hash": h("fork")}
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.ready_blocks.clear()
        self.assert_refused(chain, "differ in their hashes")

    def test_nearly_expired_snapshot_falls_back_to_a_longer_lived_one(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.bootstrap_override[100] = {"expires_at": NOW + refresh.MIN_BOOTSTRAP_SECONDS}
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(40))

    def test_snapshot_without_enough_catch_up_archive_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        created = NOW - 23 * 3600
        chain.header_override[100] = {"gen_utime": created}
        chain.bootstrap_override[100] = {"gen_utime": created, "archive_ttl": 86400}
        self.assert_refused(chain, "archive retention cannot cover")

    def test_older_shard_proof_package_bounds_the_archive_window(self) -> None:
        # Block 100's snapshot needs a shard block older than the anchor; its
        # proof sits in an older archive package that expires within the
        # window, although gen_utime + archive_ttl would still cover it.
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.bootstrap_override[100] = {
            "archive_expires_at": NOW + refresh.MIN_BOOTSTRAP_SECONDS - 60
        }
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(40))

    def test_only_snapshot_with_an_expiring_proof_package_writes_nothing(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"archive_expires_at": NOW + 3600}
        self.assert_refused(chain, "100: archive retention cannot cover")

    def test_archive_package_expiry_is_required(self) -> None:
        for value in (None, "soon", True, 0, -1, 1.5):
            with self.subTest(value=value):
                self.output.unlink(missing_ok=True)
                chain = FakeChain(last=120, key_blocks={100})
                chain.bootstrap_override[100] = {"archive_expires_at": value}
                self.assert_refused(chain, "getBootstrapState(100).archive_expires_at is ")

    def test_slow_readiness_response_cannot_spend_the_requested_validity(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"expires_at": NOW + refresh.MIN_BOOTSTRAP_SECONDS + 60}
        clock = [NOW]

        def rpc(method: str, **params: Any) -> Any:
            if method == "getBootstrapState":
                clock[0] += 3600
            return chain(method, **params)

        with mock.patch.object(refresh.time, "time", side_effect=lambda: clock[0]):
            self.assert_refused(rpc, "snapshot expires within")

    def test_explicit_download_budget_changes_required_retention(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"expires_at": NOW + 2 * 3600}
        with self.assertRaisesRegex(RefreshError, "snapshot expires within"):
            refresh.refreshed(self.config, chain, global_id=GLOBAL_ID)
        result = refresh.refreshed(self.config, chain, global_id=GLOBAL_ID, minimum_validity=3600)
        self.assertEqual(result["validator"]["init_block"], config_id(100))

    def test_readiness_answer_must_name_the_exact_candidate(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"id": {**rpc_id(100), "file_hash": h("wrong")}}
        self.assert_refused(chain, "answered a different full block id")

    def test_unavailable_readiness_answer_must_also_name_the_exact_candidate(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"id": rpc_id(40), "ready": False}
        self.assert_refused(chain, "answered a different full block id")

    def test_ready_is_a_boolean_not_a_truthy_value(self) -> None:
        for value in (1, "true", "false", None):
            with self.subTest(value=value):
                chain = FakeChain(last=120, key_blocks={100})
                chain.bootstrap_override[100] = {"ready": value}
                self.assert_refused(chain, ".ready is not a boolean")

    def test_snapshot_time_must_match_the_candidate_header(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"gen_utime": NOW - 1}
        self.assert_refused(chain, "inconsistent snapshot timestamp")

    def test_snapshot_newer_than_the_host_clock_is_skipped(self) -> None:
        # The host's clock is behind the source: the newest candidate cannot
        # be measured, but an older one already in the host's past can.
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.header_override[100] = {"gen_utime": NOW + 90}
        chain.bootstrap_override[100] = {"gen_utime": NOW + 90}
        self.assertEqual(self.refreshed(chain)["validator"]["init_block"], config_id(40))
        self.assertEqual(self.sleeps(), [])

    def test_only_snapshot_newer_than_the_host_clock_writes_nothing(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.header_override[100] = {"gen_utime": NOW + 90}
        chain.bootstrap_override[100] = {"gen_utime": NOW + 90}
        self.assert_refused(chain, "100: block was created 90s after this host's clock")

    # ---- a busy source is asked again, never replaced by an older anchor

    def test_busy_source_is_asked_again_until_it_answers(self) -> None:
        for reason in ("resource_limit", "timeout"):
            with self.subTest(reason=reason):
                self.sleep.reset_mock()
                chain = FakeChain(last=120, key_blocks={40, 100})
                busy = {"ready": False, "reason": reason}
                chain.bootstrap_sequence[100] = [busy, busy]
                result = self.refreshed(chain)
                self.output.unlink()
                self.assertEqual(result["validator"]["init_block"], config_id(100))
                probes = [p["seqno"] for m, p in chain.calls if m == "getBootstrapState"]
                self.assertEqual(probes, [100, 100, 100])
                self.assertEqual(self.sleeps(), list(refresh.BUSY_RETRY_DELAYS[:2]))

    def test_persistently_busy_source_is_refused_without_walking_back(self) -> None:
        for reason in ("resource_limit", "timeout"):
            with self.subTest(reason=reason):
                self.sleep.reset_mock()
                self.output.unlink(missing_ok=True)
                chain = FakeChain(last=120, key_blocks={40, 100})
                chain.bootstrap_override[100] = {"ready": False, "reason": reason}
                self.assert_refused(chain, f"getBootstrapState(100) answered {reason}")
                probes = [p["seqno"] for m, p in chain.calls if m == "getBootstrapState"]
                attempts = len(refresh.BUSY_RETRY_DELAYS) + 1
                self.assertEqual(probes, [100] * attempts, "an older anchor was probed")
                self.assertEqual(self.sleeps(), list(refresh.BUSY_RETRY_DELAYS))

    def test_busy_retries_are_bounded(self) -> None:
        self.assertEqual(refresh.BUSY_REASONS, {"resource_limit", "timeout"})
        self.assertLessEqual(sum(refresh.BUSY_RETRY_DELAYS), 120)
        self.assertTrue(all(delay > 0 for delay in refresh.BUSY_RETRY_DELAYS))

    def test_invalid_expiry_is_refused(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        chain.bootstrap_override[100] = {"expires_at": chain.timestamp(100)}
        self.assert_refused(chain, "invalid snapshot expiry")

    def test_invalid_archive_retention_is_refused(self) -> None:
        for value in (True, "604800", 0, -1, float("nan"), float("inf"), 10**400):
            with self.subTest(value=value):
                chain = FakeChain(last=120, key_blocks={100})
                chain.bootstrap_override[100] = {"archive_ttl": value}
                self.assert_refused(chain, ".archive_ttl is not")

    def test_backward_walk_cannot_loop_or_move_forward(self) -> None:
        for previous in (100, 120, -1):
            with self.subTest(previous=previous):
                chain = FakeChain(last=120, key_blocks={100})
                chain.ready_blocks.clear()
                chain.header_override[100] = {"prev_key_block_seqno": previous}
                self.assert_refused(chain, "does not precede key block 100")

    def test_backward_walk_is_bounded(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 80, 100})
        chain.ready_blocks = {40}
        with mock.patch.object(refresh, "MAX_KEY_BLOCKS", 2):
            self.assert_refused(chain, "no usable snapshot within 2 key blocks")

    def test_every_candidate_header_must_have_the_expected_global_id(self) -> None:
        chain = FakeChain(last=120, key_blocks={40, 100})
        chain.ready_blocks = {40}
        chain.header_override[40] = {"global_id": 2}
        self.assert_refused(chain, "block 40 carries global id 2, expected 1")

    def test_missing_readiness_method_cannot_fall_back_to_latest_key_block(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})

        def rpc(method: str, **params: Any) -> Any:
            if method == "getBootstrapState":
                raise RefreshError("getBootstrapState: method not found")
            return chain(method, **params)

        self.assert_refused(rpc, "getBootstrapState: method not found")

    def test_invalid_download_budget_is_refused_before_reading_the_node(self) -> None:
        chain = FakeChain(last=120, key_blocks={100})
        for value in (0, -1):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(RefreshError, "must be positive"),
            ):
                refresh.refreshed(self.config, chain, global_id=GLOBAL_ID, minimum_validity=value)
        self.assertEqual(chain.calls, [])


if __name__ == "__main__":
    unittest.main()

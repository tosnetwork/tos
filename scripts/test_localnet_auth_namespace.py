"""Explicit localnet AUTH namespace parsing and the pre-start configuration boundary."""

import asyncio
import contextlib
import importlib.util
import io
import os
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from tostester.zerostate import NetworkConfig, create_zerostate

TAG = "46" * 32


class ReachedNodeCreation(Exception):
    """Stop the harness before it launches or generates anything native."""


class BeforeNodeStart:
    def __init__(self):
        self.config = NetworkConfig()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def create_dht_node(self):
        raise ReachedNodeCreation


class LocalnetAuthNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("localnet-jsonrpc.py")
        spec = importlib.util.spec_from_file_location("localnet_auth_namespace", path)
        cls.localnet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.localnet)

    def test_frozen_v5r2_candidate_profile_and_conflicts(self):
        from tostester.zerostate import fee_schedule_for

        config = NetworkConfig()
        self.localnet.configure_v5r2_candidate(config, None)
        self.assertEqual(
            (config.global_version, config.global_id, config.auth_network_tag),
            (18, 1, bytes.fromhex("42" * 32)),
        )
        self.assertTrue(config.deployment_fee_schedule)
        self.assertTrue(config.v5r2_admission_candidate)
        self.assertIn("20000", fee_schedule_for(config)["gas_prices"])
        self.assertIn("10000", fee_schedule_for(config)["mc_gas_prices"])
        for tag, version in [(bytes.fromhex("43" * 32), None), (None, "19")]:
            with self.assertRaises(ValueError):
                self.localnet.configure_v5r2_candidate(NetworkConfig(), tag, version)
        self.assertTrue(self.parsed(["--v5r2-admission-candidate"]).v5r2_admission_candidate)
        self.assertFalse(self.parsed().v5r2_admission_candidate)

    def test_candidate_cli_reaches_frozen_config_before_node_creation(self):
        script = Path(__file__).with_name("localnet-jsonrpc.py")
        network = BeforeNodeStart()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {}, clear=True),
            patch.object(
                sys, "argv", [str(script), "--workdir", directory, "--v5r2-admission-candidate"]
            ),
            patch("tostester.network.Network", return_value=network),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(ReachedNodeCreation),
        ):
            runpy.run_path(str(script), run_name="__main__")
        self.assertEqual(network.config.global_version, 18)
        self.assertEqual(network.config.global_id, 1)
        self.assertEqual(network.config.auth_network_tag, bytes.fromhex("42" * 32))
        self.assertTrue(network.config.deployment_fee_schedule)
        self.assertTrue(network.config.v5r2_admission_candidate)

    def test_candidate_never_reuses_or_overwrites_saved_network(self):
        for reuse, existing in [(True, False), (False, True)]:
            with (
                tempfile.TemporaryDirectory() as directory,
                patch.object(self.localnet, "saved_network_exists", return_value=existing),
                patch.object(self.localnet.shutil, "rmtree") as remove,
                patch.object(self.localnet, "Network", side_effect=ReachedNodeCreation),
            ):
                try:
                    asyncio.run(
                        self.localnet.main(
                            "127.0.0.1:18545",
                            "127.0.0.1:18745",
                            1,
                            Path(directory),
                            1,
                            False,
                            None,
                            reuse,
                            2000,
                            None,
                            None,
                            True,
                        )
                    )
                except ValueError:
                    pass
                except ReachedNodeCreation:
                    self.fail("Candidate reached node setup while reusing existing state")
                else:
                    self.fail("Candidate reuse unexpectedly completed")
                remove.assert_not_called()

    def parsed(self, argv=(), env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            return self.localnet.parse_args(list(argv))

    def launch(self, workdir, tag, reuse=False):
        return self.localnet.main(
            "127.0.0.1:18545",
            "127.0.0.1:18745",
            1,
            workdir,
            1,
            False,
            None,
            reuse,
            2000,
            None,
            tag,
        )

    def capture_config(self, tag, version=None):
        network = BeforeNodeStart()
        env = {} if version is None else {"TOS_GLOBAL_VERSION": str(version)}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, env, clear=True),
            patch.object(self.localnet, "Network", return_value=network),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(ReachedNodeCreation),
        ):
            asyncio.run(self.launch(Path(directory) / "fresh", tag))
        return network.config

    def test_main_entrypoint_forwards_cli_and_environment_namespace(self):
        script = Path(__file__).with_name("localnet-jsonrpc.py")
        for arguments, namespace_env in [
            (["--auth-network-tag", TAG], {}),
            ([], {"TOS_AUTH_NETWORK_TAG": TAG}),
        ]:
            with self.subTest(source="CLI" if arguments else "environment"):
                network = BeforeNodeStart()
                with (
                    tempfile.TemporaryDirectory() as directory,
                    patch.dict(
                        os.environ, {"TOS_GLOBAL_VERSION": "19", **namespace_env}, clear=True
                    ),
                    patch.object(sys, "argv", [str(script), "--workdir", directory, *arguments]),
                    patch("tostester.network.Network", return_value=network),
                    contextlib.redirect_stdout(io.StringIO()),
                    self.assertRaises(ReachedNodeCreation),
                ):
                    runpy.run_path(str(script), run_name="__main__")
                self.assertEqual(network.config.global_version, 19)
                self.assertEqual(
                    network.config.auth_network_tag,
                    bytes.fromhex(TAG),
                    "the launcher entrypoint must forward the explicit namespace",
                )

    def test_default_namespace_and_version_remain_unactivated(self):
        args = self.parsed()
        self.assertIsNone(args.auth_network_tag)
        config = self.capture_config(args.auth_network_tag)
        self.assertEqual(config.global_version, 16)
        self.assertIsNone(config.auth_network_tag)

    def test_cli_and_environment_reach_config_before_any_node_is_created(self):
        for argv, env in [
            (["--auth-network-tag", TAG], {}),
            ([], {"TOS_AUTH_NETWORK_TAG": TAG}),
        ]:
            with self.subTest(source="CLI" if argv else "environment"):
                args = self.parsed(argv, env)
                config = self.capture_config(args.auth_network_tag, 19)
                self.assertEqual(config.global_version, 19)
                self.assertEqual(
                    config.auth_network_tag,
                    bytes.fromhex(TAG),
                    "explicit namespace must reach genesis configuration before node creation",
                )

    def test_cli_value_overrides_the_environment(self):
        args = self.parsed(["--auth-network-tag", "AB" * 32], {"TOS_AUTH_NETWORK_TAG": TAG})
        self.assertEqual(args.auth_network_tag, b"\xab" * 32)

    def test_malformed_cli_and_environment_inputs_are_rejected(self):
        for value in ["", "46" * 31, "46" * 33, "0x" + TAG, TAG + " ", "g" * 64]:
            for argv, env in [
                (["--auth-network-tag", value], {}),
                ([], {"TOS_AUTH_NETWORK_TAG": value}),
            ]:
                with self.subTest(value=value, source="CLI" if argv else "environment"):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(
                            SystemExit, msg="malformed namespace was accepted"
                        ) as error:
                            self.parsed(argv, env)
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn(
                        "AUTH network tag must be exactly 64 hexadecimal digits", stderr.getvalue()
                    )

    def test_version19_missing_namespace_still_fails_the_real_genesis_guard(self):
        config = self.capture_config(self.parsed().auth_network_tag, 19)
        with self.assertRaisesRegex(ValueError, "requires an explicit 32-byte AUTH network tag"):
            create_zerostate(None, Path("unused"), config, [])

    def test_version16_explicit_namespace_is_not_silently_activated(self):
        config = self.capture_config(self.parsed(["--auth-network-tag", TAG]).auth_network_tag)
        with self.assertRaisesRegex(ValueError, "requires Genesis version 17 or newer"):
            create_zerostate(None, Path("unused"), config, [])

    def test_reuse_refuses_to_imply_the_existing_namespace_was_changed(self):
        resume = AsyncMock()
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(self.localnet, "saved_network_exists", return_value=True),
            patch.object(self.localnet, "resume_saved_network", resume),
            self.assertRaisesRegex(ValueError, "--auth-network-tag only applies"),
        ):
            asyncio.run(self.launch(Path(directory), bytes.fromhex(TAG), reuse=True))
        resume.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()

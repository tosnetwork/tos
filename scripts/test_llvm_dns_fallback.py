#!/usr/bin/env python3
# Copyright 2026 TOS Network. SPDX-License-Identifier: GPL-3.0-only
"""No network or system hosts writes: test the CI resolver's fail-closed gates."""

import contextlib
import importlib.util
import io
import ipaddress
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "llvm_dns", Path(__file__).with_name("ensure-llvm-dns.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ADDRESS = "199.232.198.49"
ANSWER = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ADDRESS, 443))]


class ResolverTests(unittest.TestCase):
    def test_existing_resolution_is_preserved_without_a_probe_or_write(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(MODULE, "lookup", return_value=ANSWER),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            self.assertFalse(MODULE.ensure_dns())
            probe.assert_not_called()
            write.assert_not_called()

    def test_empty_system_answer_fails_without_a_probe(self):
        with (
            patch.object(MODULE, "lookup", return_value=[]),
            patch.object(MODULE, "probe_origin") as probe,
        ):
            with self.assertRaisesRegex(RuntimeError, "no addresses"):
                MODULE.ensure_dns()
            probe.assert_not_called()

    def test_nxdomain_is_not_bypassed(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(
                MODULE,
                "lookup",
                side_effect=[socket.gaierror(socket.EAI_NONAME, "unknown name"), ANSWER],
            ),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            with self.assertRaises(socket.gaierror):
                MODULE.ensure_dns()
            probe.assert_not_called()
            write.assert_not_called()

    def test_temporary_failure_uses_verified_origin_and_checks_effect(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(
                MODULE,
                "lookup",
                side_effect=[socket.gaierror(socket.EAI_AGAIN, "temporary"), ANSWER],
            ),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            self.assertTrue(MODULE.ensure_dns())
            probe.assert_called_once_with()
            write.assert_called_once_with(ADDRESS)

    def test_proxy_configuration_refuses_mapping(self):
        with (
            patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.invalid"}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(
                MODULE,
                "lookup",
                side_effect=[socket.gaierror(socket.EAI_AGAIN, "temporary"), ANSWER],
            ),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            with self.assertRaisesRegex(RuntimeError, "proxy"):
                MODULE.ensure_dns()
            probe.assert_not_called()
            write.assert_not_called()

    def test_failed_tls_probe_does_not_write(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(
                MODULE,
                "lookup",
                side_effect=[socket.gaierror(socket.EAI_AGAIN, "temporary"), ANSWER],
            ),
            patch.object(
                MODULE.subprocess,
                "check_output",
                side_effect=subprocess.CalledProcessError(60, ["curl"]),
            ) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.ensure_dns()
            self.assertEqual(probe.call_count, 1)
            write.assert_not_called()

    def test_unprivileged_fallback_does_not_probe_or_write(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=501),
            patch.object(
                MODULE,
                "lookup",
                side_effect=[socket.gaierror(socket.EAI_AGAIN, "temporary"), ANSWER],
            ),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS) as probe,
            patch.object(MODULE, "append_host") as write,
        ):
            with self.assertRaises(PermissionError):
                MODULE.ensure_dns()
            probe.assert_not_called()
            write.assert_not_called()

    def test_probe_requires_public_ip_and_preserves_tls_options(self):
        for value in ["127.0.0.1", "10.0.0.1", "224.0.0.1", "not an IP"]:
            with patch.object(MODULE.subprocess, "check_output", return_value=value):
                with self.assertRaises((RuntimeError, ipaddress.AddressValueError)):
                    MODULE.probe_origin()
        with patch.object(MODULE.subprocess, "check_output", return_value=ADDRESS) as curl:
            self.assertEqual(MODULE.probe_origin(), ADDRESS)
            command = curl.call_args.args[0]
            self.assertEqual(command[:2], ["curl", "--disable"])
            self.assertNotIn("--insecure", command)
            self.assertNotIn("-k", command)
            self.assertEqual(command[-1], "https://apt.llvm.org/")
            self.assertEqual(command[command.index("--doh-url") + 1], "https://1.1.1.1/dns-query")

    def test_ephemeral_opt_in_is_required_before_any_dns_work(self):
        with (
            patch("sys.argv", ["ensure-llvm-dns.py"]),
            patch.object(MODULE, "ensure_dns") as ensure,
        ):
            with self.assertRaises(SystemExit) as result:
                MODULE.main()
            self.assertEqual(result.exception.code, 2)
            ensure.assert_not_called()

    def test_unsafe_hosts_file_is_refused_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts"
            path.write_bytes(b"baseline\n")
            unsafe = SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_uid=0, st_nlink=1)
            with (
                patch.object(MODULE, "HOSTS_FILE", path),
                patch.object(MODULE.os, "fstat", return_value=unsafe),
            ):
                with self.assertRaisesRegex(RuntimeError, "protected"):
                    MODULE.append_host(ADDRESS)
            self.assertEqual(path.read_bytes(), b"baseline\n")

    def test_hosts_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"baseline\n")
            link = Path(directory) / "hosts"
            link.symlink_to(target)
            valid = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=1)
            with (
                patch.object(MODULE, "HOSTS_FILE", link),
                patch.object(MODULE.os, "fstat", return_value=valid),
            ):
                with self.assertRaises(OSError):
                    MODULE.append_host(ADDRESS)
            self.assertEqual(target.read_bytes(), b"baseline\n")

    def test_failed_system_recheck_is_not_reported_as_success(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(MODULE.os, "geteuid", return_value=0),
            patch.object(
                MODULE, "lookup", side_effect=[socket.gaierror(socket.EAI_AGAIN, "temporary"), []]
            ),
            patch.object(MODULE, "probe_origin", return_value=ADDRESS),
            patch.object(MODULE, "append_host"),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not adopt"):
                MODULE.ensure_dns()


def run_controls():
    global MODULE
    original = MODULE
    source = Path(__file__).with_name("ensure-llvm-dns.py").read_text()
    variants = [
        (
            "healthy",
            "return False",
            "pass",
            "existing_resolution_is_preserved_without_a_probe_or_write",
        ),
        ("empty", "if not lookup():", "if False:", "empty_system_answer_fails_without_a_probe"),
        (
            "nxdomain",
            "if error.errno != socket.EAI_AGAIN:",
            "if False:",
            "nxdomain_is_not_bypassed",
        ),
        (
            "proxy",
            "if any(os.environ.get(name) for name in PROXY_VARIABLES):",
            "if False:",
            "proxy_configuration_refuses_mapping",
        ),
        (
            "uid",
            "if os.geteuid() != 0:",
            "if False:",
            "unprivileged_fallback_does_not_probe_or_write",
        ),
        (
            "ip",
            "if not address.is_global or address.is_multicast or address.is_reserved:",
            "if False:",
            "probe_requires_public_ip_and_preserves_tls_options",
        ),
        (
            "tls",
            '"--ipv4",',
            '"--ipv4", "--insecure",',
            "probe_requires_public_ip_and_preserves_tls_options",
        ),
        (
            "hosts",
            "if (\n            not stat.S_ISREG(metadata.st_mode)\n"
            "            or metadata.st_uid != 0\n"
            "            or metadata.st_nlink != 1\n"
            "            or metadata.st_mode & 0o022\n        ):",
            "if False:",
            "unsafe_hosts_file_is_refused_without_writing",
        ),
        ("nofollow", "os.O_NOFOLLOW", "0", "hosts_symlink_is_not_followed"),
        (
            "recheck",
            "if address not in {entry[4][0] for entry in lookup()}:",
            "if False:",
            "failed_system_recheck_is_not_reported_as_success",
        ),
        (
            "optin",
            'action="store_true", required=True',
            'action="store_true", required=False',
            "ephemeral_opt_in_is_required_before_any_dns_work",
        ),
    ]
    try:
        for label, before, after, test in variants:
            if source.count(before) != 1:
                raise RuntimeError(f"Control {label} must change exactly one source site")
            mutant = ModuleType("llvm_dns_control")
            exec(
                compile(source.replace(before, after, 1), "<llvm-dns-control>", "exec"),
                mutant.__dict__,
            )
            MODULE = mutant
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = unittest.TextTestRunner(stream=output).run(
                    unittest.TestSuite([ResolverTests("test_" + test)])
                )
            if result.testsRun != 1 or len(result.failures) != 1 or result.errors or result.skipped:
                raise RuntimeError(
                    f"Control {label} did not produce one assertion failure: {output.getvalue()}"
                )
            if "AssertionError" not in result.failures[0][1]:
                raise RuntimeError(f"Control {label} failed for an unrelated reason")
            print(f"CONTROL {label}: expected assertion failure")
    finally:
        MODULE = original
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ResolverTests)
    )
    if not result.wasSuccessful() or result.testsRun != 12:
        raise RuntimeError("Restored baseline did not pass all 12 tests")


if __name__ == "__main__":
    if sys.argv[1:] == ["--controls"]:
        run_controls()
    else:
        unittest.main()

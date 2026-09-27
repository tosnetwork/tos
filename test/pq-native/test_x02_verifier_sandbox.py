#!/usr/bin/env python3
"""The Config34 verifier's U24 sandbox, controlled without running the verifier.

Host-only (needs /usr/bin/bwrap and the frozen U24 rootfs and runtime). Every control
uses the coordinator's exact sandbox argv and swaps only the payload command: a probe of
the bound paths, the pinned interpreter printing its version, an output flood, a hang.
Old red: launched directly (as 1863 did) the pinned interpreter starts, but on the host's
glibc 2.35 loader and libc, so it is not a U24 execution; in the sandbox it reports U24's 2.39.
Run: /usr/bin/python3 -I -B test/pq-native/test_x02_verifier_sandbox.py
"""

import json
import os
import subprocess
import tempfile
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOTFS = "/datax/n6-unit-agents/Z02/u24-rootfs"
PREFIX = "/datax/n6-unit-agents/Z02/u24-runtime-f1f912-v2"
VENV = "/datax/n6-unit-agents/Z02/u24-runtime-f1f912-recovery-v8"
INTERPRETER = PREFIX + "/python/bin/python3.14"  # the indexed, regular interpreter file
STDLIB = PREFIX + "/python/lib/python3.14"
SITE = VENV + "/venv/lib/python3.14/site-packages"
PROBE = "import os, platform; print(platform.python_version(), os.confstr('CS_GNU_LIBC_VERSION'))"


def coordinator():
    module = types.ModuleType("x02_four_node_sandbox_test")
    module.__file__ = str(REPO / "scripts/x02_four_node.py")
    exec(
        compile((REPO / "scripts/x02_four_node.py").read_bytes(), module.__file__, "exec"),
        module.__dict__,
    )
    return module


four_node = coordinator()
# The same roots as the Stage A binding draft: stdlib only, and the venv's site-packages.
BINDING = {
    "bwrap_path": "/usr/bin/bwrap",
    "rootfs_root": ROOTFS,
    "source_root": str(REPO),
    "runtime_roots": [STDLIB],
    "dependency_roots": [SITE],
    "interpreter": INTERPRETER,
}


@unittest.skipUnless(
    os.path.exists(ROOTFS) and os.path.exists("/usr/bin/bwrap"), "host U24 rootfs absent"
)
class VerifierSandbox(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir="/datax/cc-n6-20260925/x02-hf")
        self.output = Path(os.path.realpath(self.directory.name))
        (self.output / "artifacts").mkdir()
        (self.output / "artifacts" / "probe.boc").write_bytes(b"x")

    def tearDown(self):
        self.directory.cleanup()

    def run_payload(self, name, command, **limits):
        argv = four_node.verifier_sandbox_argv(BINDING, self.output, command)
        self.assertEqual(argv[: argv.index("--") + 1][-1], "--")
        return four_node.run_bounded(argv, self.output, name, **limits)

    def test_bound_paths_are_visible_read_only_and_the_network_is_absent(self):
        script = (
            "/usr/bin/test -r {s} && /usr/bin/test -r {a} && /usr/bin/test -x {i} && ! /usr/bin/touch {a}.w "
            "&& ! /usr/bin/touch {s}/w && [ $(/usr/bin/wc -l < /proc/net/dev) -le 3 ]".format(
                s=REPO / "scripts/x02_config34_proof.py",
                a=self.output / "artifacts/probe.boc",
                i=INTERPRETER,
            )
        )
        record = self.run_payload("paths", ["/bin/sh", "-c", script])
        self.assertEqual(
            (record["natural_exit"], record["sandbox_setup_failed"]),
            (0, False),
            (self.output / "paths.stderr.raw").read_text(),
        )

    def test_the_pinned_interpreter_runs_on_the_u24_loader(self):
        record = self.run_payload("interpreter", [INTERPRETER, "-I", "-B", "-c", PROBE])
        self.assertEqual(
            record["natural_exit"], 0, (self.output / "interpreter.stderr.raw").read_text()
        )
        self.assertEqual(
            (self.output / "interpreter.stdout.raw").read_text().split(),
            ["3.14.7", "glibc", "2.39"],
        )

    def test_without_the_interpreter_file_bind_the_sandbox_cannot_start_it(self):
        argv = four_node.verifier_sandbox_argv(
            BINDING, self.output, [INTERPRETER, "-I", "-c", "pass"]
        )
        at = argv.index(INTERPRETER)
        self.assertEqual(argv[at - 1 : at + 2], ["--ro-bind", INTERPRETER, INTERPRETER])
        old = argv[: at - 1] + argv[at + 2 :]  # the 15c32c0b argv, without the file bind
        record = four_node.run_bounded(old, self.output, "nobind")
        self.assertTrue(record["sandbox_setup_failed"])
        self.assertIn(b"execvp", (self.output / "nobind.stderr.raw").read_bytes())

    def test_dependency_roots_import_inside_the_sandbox(self):
        code = (
            f"import sys; sys.path[:0] = [{str(REPO / 'test/tostester/src')!r}, {SITE!r}]; "
            "import bitarray, pytosiq_core.boc.cell; print('imports ok')"
        )
        record = self.run_payload("imports", [INTERPRETER, "-I", "-B", "-c", code])
        self.assertEqual(
            record["natural_exit"], 0, (self.output / "imports.stderr.raw").read_text()
        )
        self.assertEqual((self.output / "imports.stdout.raw").read_text().strip(), "imports ok")

    def test_old_direct_host_launch_runs_on_the_host_libc_not_u24(self):
        result = subprocess.run(
            [INTERPRETER, "-I", "-B", "-c", PROBE], capture_output=True, timeout=30
        )
        self.assertEqual(result.returncode, 0)
        version = result.stdout.decode().split()
        self.assertEqual(version[:2], ["3.14.7", "glibc"])
        self.assertNotEqual(version[2], "2.39")
        self.assertEqual(version[2], os.confstr("CS_GNU_LIBC_VERSION").split()[1])

    def test_an_output_flood_stops_at_the_file_bound(self):
        record = self.run_payload(
            "flood", ["/bin/sh", "-c", "/usr/bin/head -c 3000000 /dev/zero"], max_bytes=1 << 16
        )
        self.assertTrue(record["capture_limit_reached"])
        self.assertEqual(record["stream_bytes"]["stdout"], 1 << 16)

    def test_a_hang_is_killed_as_a_group_at_the_timeout(self):
        record = self.run_payload(
            "hang", ["/bin/sh", "-c", "/bin/sleep 60 & /bin/sleep 60; wait"], timeout=2
        )
        self.assertTrue(record["timed_out"] and record["signalled"])
        with self.assertRaises(ProcessLookupError):
            os.killpg(record["pid"], 0)  # the whole group, including both sleeps, is gone
        self.assertEqual(
            json.loads((self.output / "hang.exit.raw").read_text()), record["natural_exit"]
        )

    def test_the_runner_itself_kills_the_whole_group_without_bwrap(self):
        # Inside the sandbox, bwrap's --die-with-parent and PID namespace also end the
        # payload; this shows the runner's own group kill, with no sandbox around it.
        record = four_node.run_bounded(
            ["/bin/sh", "-c", "/bin/sleep 60 & /bin/sleep 60; wait"], self.output, "bare", timeout=2
        )
        self.assertTrue(record["timed_out"])
        with self.assertRaises(ProcessLookupError):
            os.killpg(record["pid"], 0)

    def test_a_bwrap_setup_failure_is_not_a_verifier_outcome(self):
        binding = dict(BINDING, runtime_roots=[PREFIX, VENV, "/nonexistent-runtime-root"])
        argv = four_node.verifier_sandbox_argv(binding, self.output, ["/usr/bin/true"])
        record = four_node.run_bounded(argv, self.output, "setup")
        self.assertTrue(record["sandbox_setup_failed"])
        self.assertNotEqual(record["natural_exit"], 0)


if __name__ == "__main__":
    unittest.main()

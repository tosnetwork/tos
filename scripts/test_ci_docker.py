"""Exercise the container adapter with a recording daemon stub, not a real daemon."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "ghcr.io/tosnetwork/tos-builder@sha256:" + "a" * 64


class DockerAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="ci docker ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "ci").mkdir()
        (self.root / ".git").mkdir()
        (self.root / "bin").mkdir()
        shutil.copy2(ROOT / "ci/docker", self.root / "ci/docker")
        self.log = self.root / "docker-args"
        stub = self.root / "bin/docker"
        stub.write_text('#!/bin/sh\nprintf "%s\\0" "$@" > "$CI_DOCKER_LOG"\nexit "${DAEMON_EXIT:-0}"\n')
        stub.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": str(self.root / "bin") + os.pathsep + os.environ["PATH"],
            "TOS_CI_CACHE_DIR": str(self.root / "cache"),
            "CI_DOCKER_LOG": str(self.log),
            "CI_BUILD_JOBS": "8",
            "CI_DOCKER_MEMORY": "16g",
        }

    def invoke(self, image: str = IMAGE, task: str = "native", **env: str):
        self.log.unlink(missing_ok=True)
        return subprocess.run(
            [str(self.root / "ci/docker"), image, task],
            text=True, capture_output=True, check=False, env={**self.env, **env},
        )

    def test_immutable_image_and_resources_are_forwarded_without_privileged_mounts(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.log.read_text().split("\0")[:-1]
        self.assertIn(IMAGE, args)
        for flag, value in (("--cpus", "8"), ("--memory", "16g"), ("--cap-drop", "ALL")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--read-only", args)
        self.assertIn("--user", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--network", args)
        self.assertNotIn("/var/run/docker.sock", " ".join(args))
        self.assertIn("HOME=/tmp/tos-ci-home", args)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertEqual(args[-2:], ["--", "native"])

    def test_locally_built_immutable_image_id_is_accepted(self) -> None:
        image = "sha256:" + "b" * 64
        result = self.invoke(image)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(image, self.log.read_text().split("\0"))

    def test_mutable_image_and_unsupported_profiles_never_start_a_daemon(self) -> None:
        for image, task in (("image:latest", "native"), (IMAGE, "full"), (IMAGE, "native-registry")):
            with self.subTest(image=image, task=task):
                self.assertEqual(self.invoke(image, task).returncode, 2)
                self.assertFalse(self.log.exists())

    def test_invalid_limits_never_start_a_daemon(self) -> None:
        for env in ({"CI_BUILD_JOBS": "0"}, {"CI_DOCKER_MEMORY": "unlimited"}):
            self.assertEqual(self.invoke(**env).returncode, 2)
            self.assertFalse(self.log.exists())

    def test_daemon_failure_propagates(self) -> None:
        self.assertEqual(self.invoke(DAEMON_EXIT="23").returncode, 23)

    def test_linked_worktree_is_refused(self) -> None:
        (self.root / ".git").rmdir()
        (self.root / ".git").write_text("gitdir: /outside/checkout/.git/worktrees/ci\n")
        self.assertEqual(self.invoke().returncode, 2)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()

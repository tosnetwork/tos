#!/usr/bin/env python3
"""The node image can only be built for platforms the builder image is published for.

docker-ubuntu-image.yml builds Dockerfile once per architecture, and Dockerfile
starts FROM the builder tag that build-builder-image.yml publishes. When the
builder was published for amd64 only, the arm64 node image failed at release
time with "no match for platform in manifest". These checks keep the two lists
of architectures, the builder tag, the Ubuntu release and the per-architecture
tool pins in agreement, so that failure is caught by a source change instead of
by a release tag.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
UBUNTU = "24.04"
# Debian architecture names used by BuildKit (TARGETARCH) -> uv release names.
UV_ARCH = {"amd64": "x86_64", "arm64": "aarch64"}


def matrix_arches(workflow: Path) -> list[str]:
    return re.findall(r"^\s*- arch: (\S+)\s*$", workflow.read_text(), re.MULTILINE)


def matrix_runners(workflow: Path) -> dict[str, str]:
    text = workflow.read_text()
    pairs = re.findall(r"- arch: (\S+)\s*\n\s*runner: (\S+)", text)
    return dict(pairs)


class ContainerPlatformTests(unittest.TestCase):
    def setUp(self):
        self.builder_wf = WORKFLOWS / "build-builder-image.yml"
        self.node_wf = WORKFLOWS / "docker-ubuntu-image.yml"
        self.dockerfile = (ROOT / "Dockerfile").read_text()
        self.builder_dockerfile = (ROOT / "Dockerfile.builder").read_text()

    def test_builder_covers_every_node_image_architecture(self):
        builder = set(matrix_arches(self.builder_wf))
        node = set(matrix_arches(self.node_wf))
        self.assertTrue(node, "docker-ubuntu-image.yml builds no architecture")
        self.assertEqual(node - builder, set(), "node image architectures missing from the builder")

    def test_each_architecture_builds_on_a_native_runner(self):
        for workflow in (self.builder_wf, self.node_wf):
            for arch, runner in matrix_runners(workflow).items():
                with self.subTest(workflow=workflow.name, arch=arch):
                    expected = f"ubuntu-{UBUNTU}-arm" if arch == "arm64" else f"ubuntu-{UBUNTU}"
                    self.assertEqual(runner, expected)

    def test_node_image_builds_from_the_published_multi_arch_tag(self):
        published = re.search(r'imagetools create --tag "\$image:([^"]+)"', self.builder_wf.read_text())
        self.assertIsNotNone(published, "builder workflow publishes no index tag")
        tag = published.group(1)
        self.assertEqual(tag, f"ubuntu-{UBUNTU}")
        self.assertRegex(self.dockerfile, rf"(?m)^FROM ghcr\.io/\S+-builder:{re.escape(tag)} AS builder$")

    def test_builder_index_is_checked_for_both_architectures(self):
        self.assertIn('[ "$platforms" = "amd64,arm64" ]', self.builder_wf.read_text())
        self.assertEqual(sorted(matrix_arches(self.builder_wf)), ["amd64", "arm64"])

    def test_runtime_and_builder_use_the_same_ubuntu_release(self):
        self.assertRegex(self.dockerfile, rf"(?m)^FROM ubuntu:{UBUNTU}$")
        bases = re.findall(r"(?m)^FROM ubuntu:(\S+) AS (\S+)$", self.builder_dockerfile)
        self.assertEqual(bases, [(UBUNTU, "builder-24")])
        self.assertIn("target: builder-24", self.builder_wf.read_text())

    def test_every_builder_architecture_has_a_pinned_uv(self):
        pins = json.loads((ROOT / "scripts" / "build-tool-pins.json").read_text())
        for arch in matrix_arches(self.builder_wf):
            with self.subTest(arch=arch):
                uv = UV_ARCH[arch]
                self.assertIn(f"uv-{uv}", pins)
                self.assertIn(f"{arch}) UV_ARCH={uv} ;;", self.builder_dockerfile)
        self.assertNotRegex(self.builder_dockerfile, r"https://\S*astral-sh/uv")

    def test_no_workflow_runs_on_an_older_ubuntu(self):
        for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
            with self.subTest(workflow=workflow.name):
                self.assertNotRegex(workflow.read_text(), r"ubuntu-2[0-3]\.\d\d")


if __name__ == "__main__":
    unittest.main()

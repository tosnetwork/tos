"""The retired-escrow-v1 check can fail, and the deployment policy it relies on refuses.

Runs with the standard library only: python3 scripts/test_check_retired_escrow_v1.py
"""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tos_service_escrow_deploy_policy as policy  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "check_retired_escrow_v1", ROOT / "scripts/check-retired-escrow-v1.py"
)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

V1_BOC_PATH = "crypto/smartcont/tos-service-stablecoin-escrow-" + "v1.boc.base64"
V2_RELEASE = "crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json"


def v2_code_hash() -> str:
    return json.loads((ROOT / V2_RELEASE).read_text())["code_hash"]


def retired_boc_from_history() -> bytes | None:
    """The retired artifact as it was last committed, if history is available."""
    try:
        last = subprocess.run(
            ["git", "-C", str(ROOT), "rev-list", "-1", "HEAD", "--", V1_BOC_PATH],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        for revision in (f"{last}^", last):
            shown = subprocess.run(
                ["git", "-C", str(ROOT), "show", f"{revision}:{V1_BOC_PATH}"],
                capture_output=True,
            )
            if shown.returncode == 0:
                return shown.stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return None


class SyntheticTree(unittest.TestCase):
    """A minimal tree without .git, so the check walks the filesystem."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / "scripts").mkdir()
        (self.root / "scripts/deploy.py").write_text("print('escrow v2 only')\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_clean_tree_passes(self):
        self.assertEqual(check.scan_tree(self.root), [])

    def test_a_restored_v1_artifact_is_named_and_refused(self):
        (self.root / "crypto").mkdir()
        (self.root / "crypto/tos-service-stablecoin-escrow-v1.fc").write_text(";; restored\n")
        failures = check.scan_tree(self.root)
        self.assertTrue(any("named after the retired" in f for f in failures), failures)

    def test_tooling_that_names_v1_is_refused(self):
        for needle in check.FORBIDDEN_TEXT:
            with self.subTest(needle=needle):
                (self.root / "scripts/deploy.py").write_text(f"CODE = '{needle}'\n")
                self.assertTrue(check.scan_tree(self.root))

    def test_cmake_wiring_is_scanned(self):
        (self.root / "CMakeLists.txt").write_text(
            "add_custom_target(gen_tos_service_stablecoin_escrow_v1)\n"
        )
        self.assertTrue(check.scan_tree(self.root))

    def test_evidence_logs_are_exempt(self):
        evidence = self.root / "tools/node-health-monitor/evidence/raw"
        evidence.mkdir(parents=True)
        (evidence / "build.log.txt").write_text("Building tos-service-stablecoin-escrow-v1.cpp\n")
        self.assertEqual(check.scan_tree(self.root), [])

    def test_the_v1_boc_under_another_name_is_refused(self):
        boc = retired_boc_from_history()
        if boc is None:
            self.skipTest("the retired artifact is not reachable in this checkout's history")
        (self.root / "crypto").mkdir()
        (self.root / "crypto/innocent-escrow.boc.base64").write_bytes(boc)
        failures = check.scan_tree(self.root)
        self.assertTrue(any("under another name" in f for f in failures), failures)


class DeploymentPolicy(unittest.TestCase):
    def test_v1_code_is_refused_even_for_test_use(self):
        for non_production in (False, True):
            with self.assertRaisesRegex(policy.DeploymentRefused, "retired"):
                policy.check_escrow_deployment(
                    check.RETIRED_CODE_HASH, non_production=non_production
                )

    def test_unknown_code_is_refused(self):
        with self.assertRaisesRegex(policy.DeploymentRefused, "not the code of a supported"):
            policy.check_escrow_deployment("ab" * 32, non_production=True)

    def test_malformed_hash_is_refused(self):
        with self.assertRaises(policy.DeploymentRefused):
            policy.check_escrow_deployment("tvm-cell-sha256:xyz", non_production=True)

    def test_v2_is_refused_in_production_and_names_the_stranding_risk(self):
        with self.assertRaisesRegex(policy.DeploymentRefused, "stranded") as refused:
            policy.check_escrow_deployment(v2_code_hash(), non_production=False)
        self.assertIn(policy.NON_PRODUCTION_FLAG, str(refused.exception))

    def test_v2_is_allowed_with_the_non_production_acknowledgment(self):
        manifest = policy.check_escrow_deployment(v2_code_hash(), non_production=True)
        self.assertEqual(manifest["protocol"], "tos_service_stablecoin_escrow_v2")

    def test_a_deprecated_manifest_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            target = repo / V2_RELEASE
            target.parent.mkdir(parents=True)
            manifest = json.loads((ROOT / V2_RELEASE).read_text())
            manifest["status"] = "deprecated"
            target.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(policy.DeploymentRefused, "deprecated"):
                policy.check_escrow_deployment(v2_code_hash(), non_production=True, repo=repo)


class RepositoryCheck(unittest.TestCase):
    def test_this_repository_passes(self):
        self.assertEqual(check.scan_tree(ROOT), [])
        self.assertEqual(check.check_policy(ROOT), [])

    def test_the_policy_check_fails_when_the_deploy_script_stops_applying_it(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "scripts").mkdir()
            for name in ("tos_service_escrow_deploy_policy.py",):
                shutil.copy(ROOT / "scripts" / name, repo / "scripts" / name)
            (repo / V2_RELEASE).parent.mkdir(parents=True)
            shutil.copy(ROOT / V2_RELEASE, repo / V2_RELEASE)
            deploy = (ROOT / check.DEPLOY_SCRIPT).read_text()
            stripped = deploy.replace(
                "check_escrow_deployment(code_hash, non_production=args.non_production)\n", ""
            )
            self.assertNotEqual(stripped, deploy)
            (repo / check.DEPLOY_SCRIPT).write_text(stripped)
            self.assertTrue(check.check_policy(repo))


if __name__ == "__main__":
    unittest.main()

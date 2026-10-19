"""The escrow deployment policy refuses everything but the supported release,
and the deploy script applies it before it touches a network.

Escrow v2 is deployable only with the non-production acknowledgment, because a
payout the recipient's jetton wallet refuses can leave funds stranded. Code of
any other escrow, including the removed v1, is refused as unknown.

Runs with the standard library only: python3 scripts/test_tos_service_escrow_deploy_policy.py
"""

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tos_service_escrow_deploy_policy as policy  # noqa: E402

guard_spec = importlib.util.spec_from_file_location(
    "check_no_legacy_escrow", ROOT / "scripts/check-no-legacy-escrow.py"
)
guard = importlib.util.module_from_spec(guard_spec)
guard_spec.loader.exec_module(guard)

V2_RELEASE = "crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json"
DEPLOY_SCRIPT = "scripts/tos-service-stablecoin-escrow-deploy.py"
APPLY_POLICY = "check_escrow_deployment(code_hash, non_production=args.non_production)"
# Everything the deploy script does with the network or a key, which must all
# come after the policy has accepted the code.
NETWORK_OR_KEY_USE = (
    "json.loads(config_path.read_text())",
    "gate.read_private(",
    "gate.account_code(",
    "gate.send_wallet_message(",
    "rpc(endpoint",
)


ACKNOWLEDGMENT_FLAG = re.compile(
    r"parser\.add_argument\(\s*NON_PRODUCTION_FLAG,\s*dest=\"non_production\",\s*"
    r"action=\"store_true\","
)


def v2_code_hash() -> str:
    return json.loads((ROOT / V2_RELEASE).read_text())["code_hash"]


def deploy_script_problems(text: str) -> list[str]:
    """Why the deploy script would not apply the policy before using the network."""
    problems = []
    if "\ndef main():" not in text:
        return ["the deploy script has no main()"]
    flag_declared = ACKNOWLEDGMENT_FLAG.search(text)
    # Helpers defined above main() name the network too; only main() runs them.
    text = text.split("\ndef main():", 1)[1]
    applied = text.find(APPLY_POLICY)
    if applied < 0:
        return ["the deploy script does not apply the deployment policy"]
    if not flag_declared:
        problems.append(
            "the deploy script does not declare the non-production acknowledgment as an "
            "off-by-default flag setting args.non_production"
        )
    for use in NETWORK_OR_KEY_USE:
        position = text.find(use)
        if position < 0:
            problems.append(f"expected network or key use not found: {use}")
        elif position < applied:
            problems.append(f"the deploy script reaches {use} before applying the policy")
    return problems


class DeploymentPolicy(unittest.TestCase):
    def test_removed_v1_code_is_refused_even_for_test_use(self):
        for code_hash in guard.V1_CODE_HASHES:
            for non_production in (False, True):
                with self.subTest(code_hash=code_hash, non_production=non_production):
                    with self.assertRaisesRegex(policy.DeploymentRefused, "not the code of a"):
                        policy.check_escrow_deployment(code_hash, non_production=non_production)

    def test_unknown_code_is_refused(self):
        with self.assertRaisesRegex(policy.DeploymentRefused, "not the code of a supported"):
            policy.check_escrow_deployment("ab" * 32, non_production=True)

    def test_malformed_hash_is_refused(self):
        for value in ("tvm-cell-sha256:xyz", "", "ab" * 31, "zz" * 32):
            with self.subTest(value=value):
                with self.assertRaisesRegex(policy.DeploymentRefused, "malformed"):
                    policy.check_escrow_deployment(value, non_production=True)

    def test_v2_is_refused_in_production_and_names_the_stranding_risk(self):
        with self.assertRaisesRegex(policy.DeploymentRefused, "stranded") as refused:
            policy.check_escrow_deployment(v2_code_hash(), non_production=False)
        self.assertIn(policy.NON_PRODUCTION_FLAG, str(refused.exception))

    def test_v2_is_allowed_with_the_non_production_acknowledgment(self):
        manifest = policy.check_escrow_deployment(v2_code_hash(), non_production=True)
        self.assertEqual(manifest["protocol"], "tos_service_stablecoin_escrow_v2")

    def test_no_supported_release_is_production(self):
        for manifest_path, entry in policy.SUPPORTED_ESCROW_RELEASES.items():
            with self.subTest(manifest=manifest_path):
                self.assertIs(entry["production"], False)
                code_hash = json.loads((ROOT / manifest_path).read_text())["code_hash"]
                with self.assertRaises(policy.DeploymentRefused):
                    policy.check_escrow_deployment(code_hash, non_production=False)

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


class DeployScript(unittest.TestCase):
    def test_the_check_fails_when_the_flag_defaults_on(self):
        deploy = (ROOT / DEPLOY_SCRIPT).read_text()
        defaulted = deploy.replace('action="store_true",', 'action="store_false",', 1)
        self.assertNotEqual(defaulted, deploy)
        self.assertTrue(deploy_script_problems(defaulted))

    def test_the_deploy_script_applies_the_policy_first(self):
        self.assertEqual(deploy_script_problems((ROOT / DEPLOY_SCRIPT).read_text()), [])

    def test_the_check_fails_when_the_deploy_script_stops_applying_it(self):
        deploy = (ROOT / DEPLOY_SCRIPT).read_text()
        stripped = deploy.replace(f"    {APPLY_POLICY}\n", "")
        self.assertNotEqual(stripped, deploy)
        self.assertTrue(deploy_script_problems(stripped))

    def test_the_check_fails_when_the_policy_is_applied_after_the_network(self):
        deploy = (ROOT / DEPLOY_SCRIPT).read_text()
        moved = deploy.replace(f"    {APPLY_POLICY}\n", "").replace(
            "    endpoints = [", f"    {APPLY_POLICY}\n    endpoints = ["
        )
        self.assertNotEqual(moved, deploy)
        problems = deploy_script_problems(moved)
        self.assertTrue(any("before applying the policy" in p for p in problems), problems)

    def test_the_check_fails_when_the_acknowledgment_is_always_set(self):
        deploy = (ROOT / DEPLOY_SCRIPT).read_text()
        forced = deploy.replace(
            APPLY_POLICY, "check_escrow_deployment(code_hash, non_production=True)"
        )
        self.assertNotEqual(forced, deploy)
        self.assertTrue(deploy_script_problems(forced))


if __name__ == "__main__":
    unittest.main()

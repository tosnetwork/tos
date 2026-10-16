"""Protect the existing test bodies, reuse gates and cache settings from silent weakening."""

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "test/ci/efficiency-contract.json"
GATE = "steps.snapshot.outputs.run-tests == 'true'"


def read_steps(text, job):
    body = re.search(r"(?ms)^  " + re.escape(job) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text)[1]
    steps = {}
    for block in re.split(r"(?m)(?=^ {4,6}- (?:name:|uses:|if:))", body)[1:]:
        lines = block.splitlines()
        first = re.match(r"^( +)- ([\w-]+): ?(.*)$", lines[0])
        indent = len(first[1])
        props = {first[2]: first[3]}
        for index, line in enumerate(lines[1:], 1):
            match = re.match(r"^ {" + str(indent + 2) + r"}([\w-]+): ?(.*)$", line)
            if not match:
                continue
            key, value = match.groups()
            if key == "run" and value in ("|", ">"):
                commands = []
                for following in lines[index + 1 :]:
                    if following and not following.startswith(" " * (indent + 4)):
                        break
                    commands.append(following[indent + 4 :] if following else "")
                props[key] = ("\n" if value == "|" else " ").join(commands).rstrip() + "\n"
            else:
                props[key] = value + ("\n" if key == "run" else "")
        name = props.pop("name", "@if:" + str(props.get("if")))
        steps[name] = props
    return steps


def validate(root=ROOT):
    contract = json.loads((root / "test/ci/efficiency-contract.json").read_text())
    for row in contract["steps"]:
        text = (root / ".github/workflows" / row["workflow"]).read_text()
        step = read_steps(text, row["job"])[row["name"]]
        if hashlib.sha256(step["run"].encode()).hexdigest() != row["run_sha256"]:
            raise ValueError("Original test body changed: " + str(row["name"]))
        expected = row["original_if"]
        if row["deduplicated"]:
            expected = f"({expected}) && {GATE}" if expected else GATE
        if step.get("if") != expected:
            raise ValueError("Test skip rule changed: " + str(row["name"]))
    for filename in ["build-tos-linux-x86-64-shared.yml", "build-tos-linux-arm64-shared.yml"]:
        text = (root / ".github/workflows" / filename).read_text()
        if "branches: [main]" not in text or "  workflow_dispatch:\n" not in text:
            raise ValueError("Full main/manual build triggers lost")
        if (
            "uses: ./.github/actions/native-cache" not in text
            or "profile: main-shared" not in text
            or "max-size: 1G" not in text
        ):
            raise ValueError("Bounded compatible main cache missing")
        if "snapshot.outputs" in text:
            raise ValueError("Full main builds must never reuse a prior test result")
    for filename, jobs in {
        "build-tos-linux-x86-64-werror.yml": ["strict-build", "hygiene"],
        "auth-extension-validation.yml": ["authentication"],
        "quantum-readiness.yml": ["native"],
    }.items():
        text = (root / ".github/workflows" / filename).read_text()
        if "types: [opened, reopened, synchronize, ready_for_review]" not in text:
            raise ValueError("Automatic PR validation trigger lost")
        for job in jobs:
            steps = read_steps(text, job)
            gate = steps["Reuse only a proven identical Ready snapshot"]
            if gate.get("id") != "snapshot" or gate.get("if"):
                raise ValueError("Reuse decision must always run")
            for name in [
                "Record successful executed snapshot",
                "Retain successful snapshot evidence",
            ]:
                if steps[name].get("if") != "github.event_name == 'pull_request' && " + GATE:
                    raise ValueError("Only successful executed PR jobs may publish evidence")
    script = (root / "assembly/native/build-ubuntu-shared.sh").read_text()
    if (
        'export CCACHE_DIR="${CCACHE_DIR:-$HOME/.ccache}"' not in script
        or 'ccache -M "${CCACHE_MAXSIZE:-0}"' not in script
    ):
        raise ValueError("Inherited cache directory and bound must be honored")
    original = script.replace(
        '  export CCACHE_DIR="${CCACHE_DIR:-$HOME/.ccache}"\n  ccache -M "${CCACHE_MAXSIZE:-0}"',
        "  export CCACHE_DIR=~/.ccache\n  ccache -M 0",
    )
    if hashlib.sha256(original.encode()).hexdigest() != contract["original_assembly_sha256"]:
        raise ValueError("Build flags changed or cache bounds overwritten")
    return len(contract["steps"])


class EfficiencyTests(unittest.TestCase):
    def test_existing_validation_and_full_builds_remain(self):
        self.assertGreater(validate(), 20)

    def test_dropped_test_and_weakened_skip_rule_are_rejected(self):
        from unittest.mock import patch

        path = ROOT / ".github/workflows/auth-extension-validation.yml"
        text = path.read_text()
        original = Path.read_text
        for mutant in [
            text.replace(GATE, "false"),
            text.replace("python3 scripts/update-auth-contract-code.py --check", "true"),
        ]:

            def read(p, *args, **kwargs):
                return mutant if p == path else original(p, *args, **kwargs)

            with patch.object(Path, "read_text", read), self.assertRaises(ValueError):
                validate()

    def test_cache_override_cannot_revert_to_unbounded_legacy_settings(self):
        from unittest.mock import patch

        path = ROOT / "assembly/native/build-ubuntu-shared.sh"
        text = path.read_text()
        original = Path.read_text
        for mutant in [
            text.replace('ccache -M "${CCACHE_MAXSIZE:-0}"', "ccache -M 0"),
            text.replace(
                'export CCACHE_DIR="${CCACHE_DIR:-$HOME/.ccache}"', "export CCACHE_DIR=~/.ccache"
            ),
        ]:

            def read(p, *args, **kwargs):
                return mutant if p == path else original(p, *args, **kwargs)

            with (
                patch.object(Path, "read_text", read),
                self.assertRaisesRegex(ValueError, "must be honored"),
            ):
                validate()


if __name__ == "__main__":
    unittest.main()

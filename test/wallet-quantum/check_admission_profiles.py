"""Check retained AUTH/POP/preparation traces and require corrupted traces to fail."""

import argparse
import json
from pathlib import Path

from admission_profile import profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    reports = {}
    for name in ("auth", "pop", "prepare"):
        directory = args.artifacts / name
        receipt = json.loads((directory / "vault-result.json").read_text())
        probe = json.loads((directory / "credit-probe.json").read_text())
        assert receipt["success"] and receipt["details"]["exit"] == 0
        trace = receipt["vm_log"]
        initial, minimum = probe["downstream_diagnostic_credit"], probe["minimum_accept_credit"]
        result = profile(trace, initial, minimum)
        rejected = []
        for label, corrupted, bound in (
            ("missing_accept", trace.split("execute ACCEPT")[0], minimum),
            ("missing_verifier", trace.replace("execute LMSCHECKFEEHASH", "execute NOP"), minimum),
            ("incorrect_admission", trace, minimum - 1),
        ):
            try:
                profile(corrupted, initial, bound)
            except AssertionError:
                rejected.append(label)
            else:
                raise AssertionError(f"{name}: corrupted evidence accepted: {label}")
        assert len(rejected) == 3
        result["rejected_evidence_controls"] = rejected
        (directory / "gas-profile.json").write_text(json.dumps(result, indent=2) + "\n")
        reports[name] = result
    (args.artifacts / "profiles.json").write_text(json.dumps(reports, indent=2) + "\n")
    print("Three real admission profiles reconciled; nine corrupted-evidence controls rejected")


if __name__ == "__main__":
    main()

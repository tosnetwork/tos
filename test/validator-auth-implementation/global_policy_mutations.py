"""Remove each thing a zero-identity policy operation must establish.

The operation's effects are three that have to move together and one that is
easy to fake. The three are the policy, the activation that binds it and the
global nonce; a run producing any two leaves the registry describing a policy
nothing activates, or an activation for a policy that is not there.

The one that is easy to fake is the activation's checkpoint. Four nonzero
hashes in the right fields satisfy every structural check the state makes, so
the mutation that matters here does not corrupt them -- it stamps a *different
and perfectly legal* anchor. If that survives, the case was only proving the
fields were populated, which is not the property: the checkpoint has to be the
anchor of the governing snapshot that admitted this operation.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path("validator/auth/lifecycle.cpp")
BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-global-policy")

STAMP = """  change.activation.checkpoint_seqno_ = anchor.value().seqno_;
  change.activation.checkpoint_root_ = anchor.value().root_;
  change.activation.checkpoint_file_ = anchor.value().file_;
  change.activation.checkpoint_state_ = anchor.value().state_;
"""
# A legal anchor that is not the governing one: earlier than the effective
# height, four distinct nonzero hashes, every structural rule satisfied.
FOREIGN = """  change.activation.checkpoint_seqno_ = anchor.value().seqno_;
  change.activation.checkpoint_root_ = Hash{1};
  change.activation.checkpoint_file_ = Hash{2};
  change.activation.checkpoint_state_ = Hash{3};
"""
PREDECESSOR = """  if (update.previous_ != current.current_policy())
    return Error{"global-predecessor"};
"""
HEIGHT = """  if (policy.effective_from_ != update.effective_from_)
    return Error{"global-effective-coordinate"};
"""
REVISION = """  if (current_policy.revision_ == std::numeric_limits<std::uint64_t>::max() ||
      policy.revision_ != current_policy.revision_ + 1)
    return Error{"global-policy-revision"};
"""
CONFIGURATION = """  if (update.operation_ == 6)
    return Error{"global-configuration-unimplemented"};
"""
NONCE = """  change.global.next_nonce_ = update.nonce_ + 1;
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", default="48")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    mutations = [
        # The one this suite exists for.
        ("checkpoint-is-any-legal-anchor", "global-policy-checkpoint-is-governing-anchor", STAMP, FOREIGN, []),
        ("predecessor-unchecked", "global-policy-old-policy-cas-refused", PREDECESSOR, "", []),
        ("height-unchecked", "global-policy-wrong-effective-height-refused", HEIGHT, "", []),
        ("policy-revision-unchecked", "global-policy-activation-chain-revision-refused", REVISION, "", []),
        ("configuration-admitted", "global-policy-configuration-operation-refused", CONFIGURATION, "", []),
        # The nonce standing still, which would let one authorization be spent
        # twice for two different policies.
        ("nonce-does-not-advance", "global-policy-zero-nonce-advances", NONCE,
         "  change.global.next_nonce_ = global.next_nonce_;\n", []),
    ]

    def build() -> bool:
        return subprocess.run(["cmake", "--build", "build-p0", "--target", "test-p0-global-policy",
                               "-j" + args.jobs], capture_output=True, text=True, check=False).returncode == 0

    def outcomes() -> dict[str, bool]:
        result = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        return {line.split(" ", 1)[1]: line.startswith("CASE_PASS ")
                for line in result.stdout.splitlines() if line.startswith("CASE_")}

    def declared() -> set[str]:
        result = subprocess.run([str(BINARY)], capture_output=True, text=True, check=False)
        return {line.split(" ", 1)[1] for line in result.stdout.splitlines() if line.startswith("MANIFEST ")}

    if not build():
        print("BASELINE-BUILD-FAILED", file=sys.stderr)
        return 1
    inventory = outcomes()
    if not inventory or not all(inventory.values()) or set(inventory) != declared():
        print("BASELINE-NOT-PASSING", file=sys.stderr)
        return 1

    records, failures = [], 0
    try:
        for guard, case, before, after, companions in mutations:
            assert original.count(before) == 1, (guard, "anchor")
            changed = original.replace(before, after, 1)
            SOURCE.write_text(changed)
            reached = SOURCE.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory) == declared()
                broke = sorted(name for name, held in result.items() if not held)
            SOURCE.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                      "restored_baseline": restored,
                      "source_unchanged": SOURCE.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline",
                                               "source_unchanged")):
                failures += 1
    finally:
        SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

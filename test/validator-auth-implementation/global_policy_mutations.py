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

REFERENCE = Path("validator/auth/lifecycle.cpp")
PERSISTENT = Path("validator/auth/native-registry.cpp")
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
# The persistent registry's three writes. Each is a place the two
# implementations of one transition can quietly stop being one.
ACTIVATION_KEY = """    auto key = height(change.activation.effective_from_);
"""
POLICY_WRITE = """  put(next.policies_, policy_id, change.policy, vm::Dictionary::SetMode::Add, next.budget_);
"""
GLOBAL_WRITE = """  put(next.identities_, Hash{}, change.global,
      next.identity(Hash{}).ok() ? vm::Dictionary::SetMode::Replace : vm::Dictionary::SetMode::Set, next.budget_);
"""
SCHEDULE_WRITE = """    need(schedule.set_builder(bits(key), 32, b, vm::Dictionary::SetMode::Add), "policy-index");
"""


def scoped(text: str, signature: str) -> str:
    """The body of one function.

    The schedule insertion is written identically in bootstrap and in the
    global install, and the shorter indentation is a substring of the longer
    one. Widening the anchor to tell them apart would leave whichever copy it
    did not match untested, so the scope is narrowed instead."""
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", default="48")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    originals = {REFERENCE: REFERENCE.read_text(), PERSISTENT: PERSISTENT.read_text()}
    mutations = [
        # The one this suite exists for.
        (REFERENCE, "checkpoint-is-any-legal-anchor", "global-policy-checkpoint-is-governing-anchor", STAMP, FOREIGN, []),
        (REFERENCE, "predecessor-unchecked", "global-policy-old-policy-cas-refused", PREDECESSOR, "", []),
        (REFERENCE, "height-unchecked", "global-policy-wrong-effective-height-refused", HEIGHT, "", []),
        (REFERENCE, "policy-revision-unchecked", "global-policy-activation-chain-revision-refused", REVISION, "", []),
        (REFERENCE, "configuration-admitted", "global-policy-configuration-operation-refused", CONFIGURATION, "", []),
        # The nonce standing still, which would let one authorization be spent
        # twice for two different policies.
        (REFERENCE, "nonce-does-not-advance", "global-policy-zero-nonce-advances", NONCE,
         "  change.global.next_nonce_ = global.next_nonce_;\n", []),
        # The persistent side writing the same transition somewhere else. None
        # of these make either implementation incoherent on its own; they make
        # the two stop being one, which only the root comparison can see.
        (PERSISTENT, "activation-keyed-on-another-height", "global-policy-persistent-root-equals-reference",
         ACTIVATION_KEY, "    auto key = height(change.activation.effective_from_ + 1);\n", []),
        (PERSISTENT, "policy-not-written", "global-policy-persistent-root-equals-reference", POLICY_WRITE, "", []),
        (PERSISTENT, "global-record-not-written", "global-policy-persistent-root-equals-reference",
         GLOBAL_WRITE, "", []),
        # The height index is derived state and is not encoded, so an operation
        # that wrote the policy and never indexed it produces exactly the same
        # root and a different current policy at the boundary. The root
        # comparison cannot see it; the replay to the effective height can.
        (PERSISTENT, "schedule-not-indexed", "global-policy-selects-the-new-policy-at-its-height",
         SCHEDULE_WRITE, "", [], "void NativeRegistry::install_global("),
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
        for source, guard, case, before, after, companions, *scope in mutations:
            original = originals[source]
            region = scoped(original, scope[0]) if scope else original
            if scope:
                assert original.count(scope[0]) == 1, (guard, "scope")
            assert region.count(before) == 1, (guard, "anchor")
            changed = original.replace(region, region.replace(before, after, 1), 1)
            source.write_text(changed)
            reached = source.read_text() == changed
            compiled = build()
            broke, complete = [], False
            if compiled:
                result = outcomes()
                complete = set(result) == set(inventory) == declared()
                broke = sorted(name for name, held in result.items() if not held)
            source.write_text(original)
            restored = build() and all(outcomes().values())
            record = {"guard": guard, "case": case, "edit_reached_source": reached, "compiled": compiled,
                      "every_case_reported": complete, "cases_broken": broke,
                      "declared_companions": companions,
                      "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                      "restored_baseline": restored,
                      "source": str(source),
                      "source_unchanged": source.read_text() == original}
            records.append(record)
            print(json.dumps(record), flush=True)
            if not all(record[key] for key in ("edit_reached_source", "compiled", "every_case_reported",
                                               "only_declared_cases_broke", "restored_baseline",
                                               "source_unchanged")):
                failures += 1
    finally:
        for source, text in originals.items():
            source.write_text(text)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

"""Remove one part of the configuration account's persistence at a time.

The account carries the registry checkpoint its state is restored from, beside
the configuration parameter that holds the registry itself. Three separate
things keep that true: the load that reads it back, the store that writes it
forward, and the registry update that replaces it with the one for the state it
just staged. Each is removable on its own, so each is removed on its own.

The store is the one that hides. Every registry case starts from an account that
already has a checkpoint, so a store that dropped it would still leave a
registry update looking correct -- the damage appears one ordinary vote later,
in a block none of those cases reach.

Cases are run one at a time rather than as a suite, because this suite stops at
its first failure and a case that never ran cannot be told from one that held.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path("crypto/smartcont/config-code.fc")


def scoped(text: str, signature: str) -> str:
    """The body of one function, so an anchor written the same way in two of
    them says which one it removed.

    Restaging the checkpoint is written identically in the registry branch and
    in the tick-tock, because it is the same act. Widening the anchor to tell
    them apart would leave whichever copy the wider anchor did not match
    untested, which is the opposite of what a unique anchor is for."""
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)]

BINARY = Path("build-p0/test/validator-auth-implementation/test-p0-config-contract")

LOAD = """  registry_checkpoint = null();
  if (cs.slice_refs()) {
    registry_checkpoint = cs~load_ref();
  }
"""

# The requirement the loader no longer makes. It is asked by every path that
# could still produce state the chain treats as authenticated, so removing it
# is removing all of them at once -- which is why this mutation names the first
# case to notice and declares the rest as companions.
REQUIREMENT = """  throw_if(47, validator_auth_active() & cell_null?(registry_checkpoint));
"""

# The two decisions such a chain may still take about itself. Widening this
# widens the recovery surface; narrowing it to nothing leaves the account
# readable and permanently unrepairable, which is the state this whole
# arrangement exists to avoid.
RECOVERY = """  if (param_id == -1000) {
    return true;
  }
  if (param_id == 8) {
    return ~ config8_activates?(param_val);
  }
  return false;
"""

# Whether the governing quorum is also required. Requiring it unconditionally
# is the deadlock: the quorum is exactly what a chain with no registry context
# cannot consult.
GOVERNANCE = """  ifnot (cell_null?(registry_checkpoint)) {
    return true;
  }
  var (param_id, param_val, _) = parse_config_proposal(proposal);
  return ~ recovery_change?(param_id, param_val);
"""

STORE = "    .store_checkpoint()\n"
# Two lines, not one. The finalization branch restages the checkpoint the same
# way with deeper indentation, and the shorter form is a substring of it; a
# single anchor would leave whichever copy it did not match untested, so each
# copy has its own anchor and its own mutation.
STAGED = ('    registry_checkpoint = vauth_registry_state();\n'
          '    accept_message();\n')
STAGED_FINALIZE = ('      registry_checkpoint = vauth_registry_state();\n'
                   '      accept_message();\n')
# The tick-tock persistence, as one block. Removing it returns the account to
# the shape that let a block with no registry message keep the parent's
# parameter 46 -- whose schedule still names transitions as due at a coordinate
# that has passed, so the next block's registry refuses to open at all.
TERMINAL_REQUIRED = """      throw_unless(52, awaiting_governance?(rest));
"""
FOUND_REQUIRED = """      throw_unless(50, found?);
"""
REGISTRY_KEPT = """      cfg_dict~idict_set_ref(32, 46, finalized);
"""
PROPOSAL_CONSUMED = """      vote_dict~udict_delete?(256, phash);
"""
# Accepting before the conditions are decided. The request is unsigned and
# replayable, and these conditions can refuse a finalization whose governance is
# perfectly valid, so accepting first makes the configuration account pay again
# for every replay of a request that could never have succeeded.
ACCEPT_AFTER_RULES = """      (cfg_dict, var param_id, var param_val) = accept_proposal(cfg_dict, proposal, critical?);
      throw_unless(53, param_id);
      registry_checkpoint = vauth_registry_state();
      accept_message();
"""
ACCEPT_BEFORE_RULES = """      registry_checkpoint = vauth_registry_state();
      accept_message();
      (cfg_dict, var param_id, var param_val) = accept_proposal(cfg_dict, proposal, critical?);
      throw_unless(53, param_id);
"""
RV_EARLY = """  if (validator_auth_active()) {
    if (awaiting_governance?(rest)) {
      return (vote_dict, null(), 3);
    }
  }
"""
RV_THRESHOLD = """  if (validator_auth_active() & needs_governance?(proposal)) {
    if (wins >= min_wins) {
      ;; Normal voting is complete and nothing is installed. The exact proposal
      ;; stays where it is, marked terminal, until a governance operation
      ;; finalizes it; a configuration parameter needs that quorum as well.
      vote_dict~udict_set_builder(256, phash,
        begin_pack_proposal_status(expires, proposal, critical?, voters, weight_remaining, vset_id)
        .store_uint(rounds_remaining, 8)
        .store_uint(255, 8)
        .store_uint(losses, 8));
      return (vote_dict, null(), 3);
    }
  }
"""
SCAN_GATE = """  if (validator_auth_active()) {
    if (awaiting_governance?(rest)) {
      return (pstatus, false);
    }
  }
"""
SENTINEL = """        .store_uint(255, 8)
"""
TICKTOCK = """  if (validator_auth_active()) {
    require_registry_checkpoint();
    registry_checkpoint = vauth_registry_state();
    var rcs = registry_checkpoint.begin_parse();
    rcs~skip_bits(80);
    cfg_dict~idict_set_ref(kl, 46, rcs~load_ref());
  }
"""

AUTHENTICATED_DESCRIPTOR = """  if (cs.preload_uint(8) == 0xb3) {
    cs~skip_bits(8);
    throw_unless(41, cs~load_uint(32) == 0x8e81278a);
    return (cs~load_uint(256), cs~load_uint(64));
  }
"""

PROPOSAL_GUARD = """  if (validator_auth_active() & validator_set_param(param_id)) {
"""

MUTATIONS = [
    # One per index, because the predicate being complete is a different claim
    # from the guard being present, and the mutations that remove the whole
    # guard cannot tell them apart. Closing 34 and 36 while leaving 35 and 37
    # open is exactly the state this branch was in, and no case noticed.
    ("validator-set-index-32-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 32) |", "(0) |", []),
    ("validator-set-index-33-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 33) |", "(0) |", []),
    ("validator-set-index-34-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 34) |", "(0) |",
     ["a-finalization-cannot-install-a-validator-set", "an-owner-action-cannot-install-a-validator-set"]),
    ("validator-set-index-35-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 35) |", "(0) |", []),
    ("validator-set-index-36-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 36) |", "(0) |", []),
    ("validator-set-index-37-unprotected", "no-generic-writer-installs-any-validator-set-index",
     "(param_id == 37);", "(0);", []),
    # The two generic writers of a configuration parameter, each closed against
    # the three indices that hold a validator set. Neither guard is reachable on
    # an inactive chain, and the inactive cases are companions of neither: they
    # have to keep passing while the guard is gone, which is what says the
    # mutation removed a rule about activation rather than a rule about an index.
    ("validator-set-not-installable-by-proposal", "a-finalization-cannot-install-a-validator-set",
     PROPOSAL_GUARD, "  if (0) {\n",
     ["no-generic-writer-installs-any-validator-set-index"]),
    # The account that is the configuration contract, closed on its own. The
    # whole-guard mutation above cannot distinguish this from the validator-set
    # rule beside it, and the two are protected for different reasons.
    ("configuration-contract-address-unprotected-by-owner",
     "the-configuration-key-cannot-redirect-the-configuration-contract",
     " | configuration_contract_param(param_index)", "", []),
    # Parameter 8 as a recovery by its number rather than by its value. This is
    # the defect the value check replaced: a Config8 that leaves the chain
    # authenticated passing as a recovery, and taking the checkpoint
    # requirement and the governing quorum with it.
    ("recovery-ignores-the-value", "a-checkpointless-active-chain-refuses-a-config8-that-stays-authenticated",
     "    return ~ config8_activates?(param_val);\n", "    return true;\n",
     ["a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated"]),
    ("validator-set-not-installable-by-owner", "an-owner-action-cannot-install-a-validator-set",
     """    throw_if(48, validator_auth_active() &
                 (validator_set_param(param_index) | configuration_contract_param(param_index)));\n""", "",
     ["no-generic-writer-installs-any-validator-set-index",
      "the-configuration-key-cannot-redirect-the-configuration-contract"]),
    # The refusal that an active chain must not run without a checkpoint. It
    # had no mutation at all: the branch was added and the fixture that would
    # have reached it seeds one, so nothing exercised it. This removes the
    # throw and requires the case built for it to notice.
    # Every path that could still produce authenticated state asks one
    # question, so removing it removes all of them. The tick-tock is the first
    # case to say so; the rest are companions rather than a relaxed rule.
    ("active-chain-needs-a-checkpoint", "an-active-chain-without-a-checkpoint-is-refused",
     REQUIREMENT, "", [
      "a-checkpointless-active-chain-applies-no-registry-update",
      "a-checkpointless-active-chain-changes-no-ordinary-parameter",
      "a-checkpointless-active-chain-installs-no-elected-set",
      "a-checkpointless-active-chain-refuses-a-config8-that-stays-authenticated"
     ]),
    # The recovery surface has to be exactly two parameters. Closing it leaves
    # a readable account nothing can repair.
    ("recovery-surface-closed", "a-checkpointless-active-chain-may-stop-being-authenticated",
     RECOVERY, "  return false;\n", [
      "a-checkpointless-active-chain-may-replace-its-code",
      "a-checkpointless-active-chain-votes-in-a-config8-that-deactivates"
     ]),
    # And opening it to every parameter would make the requirement above mean
    # nothing at all, so the case that refuses an ordinary parameter is what
    # notices.
    ("recovery-surface-opened", "a-checkpointless-active-chain-changes-no-ordinary-parameter",
     RECOVERY, "  return true;\n", [
      "a-checkpointless-active-chain-refuses-a-config8-that-stays-authenticated",
      "a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated",
      "an-active-chain-without-a-checkpoint-is-refused"
     ]),
    # Requiring the governing quorum unconditionally is the deadlock this
    # carve-out exists to avoid: the code upgrade can then never be voted
    # through on a chain whose registry context cannot open.
    ("governance-required-even-for-recovery", "a-checkpointless-active-chain-may-replace-its-code",
     GOVERNANCE, "  return true;\n", [
      "a-checkpointless-active-chain-votes-in-a-config8-that-deactivates"
     ]),
    # An active chain installs its elected set through VAUTH_BIND, which writes
    # validator_auth#b3. Without this branch the voting path refuses that
    # descriptor for its shape, so the normal vote a configuration parameter
    # now needs cannot be cast at all and the governance door behind it is
    # never reached. The fixture used to build the legacy shape whether the
    # chain was active or not, which is what let that look correct.
    ("authenticated-descriptor-votes", "a-completed-vote-installs-nothing-under-governance",
     AUTHENTICATED_DESCRIPTOR, "",
     [
      "a-checkpointless-active-chain-may-replace-its-code",
      "a-checkpointless-active-chain-still-registers-votes",
      "a-checkpointless-active-chain-votes-in-a-config8-that-deactivates",
      "a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated",
      "a-terminal-proposal-takes-no-further-votes"
     ]),
    # The store lives in store_data rather than in the registry branch exactly
    # so a path with nothing to do with the registry carries it too. The vote
    # case is what proves that, and it is named here rather than the registry
    # one because it is the case the placement exists for.
    ("checkpoint-stored", "a-vote-keeps-the-checkpoint", STORE, "",
     ["a-registry-update-stores-the-staged-checkpoint", "a-due-only-tick-tock-persists-the-prefix",
      "a-governance-operation-finalizes-a-completed-proposal"]),
    # Reading it back is what makes it survive an operation that does not touch
    # the registry; without it the account opens with nothing to carry forward,
    # and every case that restores one fails.
    ("checkpoint-loaded", "a-vote-keeps-the-checkpoint", LOAD,
     "  registry_checkpoint = null();\n  cs~load_ref();\n",
     [
      "a-checkpointless-active-chain-applies-no-registry-update",
      "a-checkpointless-active-chain-changes-no-ordinary-parameter",
      "a-checkpointless-active-chain-installs-no-elected-set",
      "a-checkpointless-active-chain-may-replace-its-code",
      "a-checkpointless-active-chain-may-stop-being-authenticated",
      "a-checkpointless-active-chain-refuses-a-config8-that-stays-authenticated",
      "a-checkpointless-active-chain-still-registers-votes",
      "a-checkpointless-active-chain-votes-in-a-config8-that-deactivates",
      "a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated",
      "a-due-only-tick-tock-persists-the-prefix",
      "a-finalization-cannot-install-a-validator-set",
      "a-governance-operation-finalizes-a-completed-proposal",
      "a-proposal-still-in-voting-is-not-finalizable",
      "a-refused-finalization-leaves-the-proposal",
      "a-refused-finalization-never-accepts",
      "a-terminal-proposal-survives-a-tick-tock-scan",
      "a-valid-finalization-reaches-accept-with-real-gas-credit",
      "a-vote-keeps-the-checkpoint",
      "active-set-with-bindings-is-installed-bound",
      "active-unbound-set-is-refused",
      "an-active-chain-without-a-checkpoint-is-refused",
      "an-inactive-chain-installs-on-the-threshold",
      "an-inactive-chain-keeps-every-validator-set-index-writable",
      "an-inactive-chain-keeps-the-configuration-contract-address-writable",
      "an-inactive-chain-lets-the-owner-install-a-validator-set",
      "an-inactive-chain-tick-tock-asks-for-nothing",
      "an-inactive-chain-without-a-checkpoint-is-accepted",
      "an-owner-action-installs-an-ordinary-parameter",
      "an-unknown-proposal-is-not-finalizable",
      "governance-cannot-redirect-the-configuration-contract-while-active",
      "no-generic-writer-installs-any-validator-set-index",
      "no-generic-writer-installs-the-configuration-contract-address",
      "registry-c4-installs-parameter-46",
      "registry-c4-replaces-old-parameter-46",
      "registry-first-checkpoint-installs-new-parameter",
      "registry-first-checkpoint-replaces-old-parameter",
      "the-configuration-key-cannot-redirect-the-configuration-contract"
     ]),
    ("checkpoint-restaged", "a-registry-update-stores-the-staged-checkpoint", STAGED,
     "    accept_message();\n", [], "() recv_external(slice in_msg) impure {"),
    ("checkpoint-restaged-on-finalization", "a-governance-operation-finalizes-a-completed-proposal",
     STAGED_FINALIZE, "      accept_message();\n", [], "() recv_external(slice in_msg) impure {"),
    # A block with nothing to process still has state to persist. Without this
    # the tick-tock runs, stores its data and commits -- which is why the case
    # asserts what parameter 46 holds afterwards rather than that the tick-tock
    # ran. Everything about the transaction looks the same either way.
    ("ticktock-persists-the-prefix", "a-due-only-tick-tock-persists-the-prefix", TICKTOCK, "",
     ["an-active-chain-without-a-checkpoint-is-refused"],
     "() run_ticktock(int is_tock) impure {"),
    # Normal voting reaching its threshold must stop installing. Three separate
    # paths can undo that, and none of them is reachable from the others: the
    # vote that crosses the threshold, a later vote arriving at a proposal that
    # already did, and the tick-tock scan, which reaches the rotation reset with
    # no vote at all.
    ("threshold-still-installs", "a-completed-vote-installs-nothing-under-governance", RV_THRESHOLD, "",
     [
      "a-checkpointless-active-chain-still-registers-votes",
      "a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated"
     ],
     "(cell, cell, int) register_vote(vote_dict, phash, idx, weight) inline_ref {"),
    ("terminal-takes-more-votes", "a-terminal-proposal-takes-no-further-votes", RV_EARLY, "", [],
     "(cell, cell, int) register_vote(vote_dict, phash, idx, weight) inline_ref {"),
    ("terminal-reset-by-scan", "a-terminal-proposal-survives-a-tick-tock-scan", SCAN_GATE, "", [],
     "(slice, int) scan_proposal(int phash, slice pstatus) inline_ref {"),
    # The marker itself. Writing the threshold back instead of the sentinel
    # leaves a proposal that looks ordinary again, so the next vote resumes
    # counting and eventually installs.
    # The second gate itself. Without the terminal requirement a governing
    # quorum could install a proposal the validators never finished voting on,
    # which is the whole thing the two-stage rule prevents.
    ("finalizes-without-normal-voting", "a-proposal-still-in-voting-is-not-finalizable",
     TERMINAL_REQUIRED, "", [], "() recv_external(slice in_msg) impure {"),
    # The unpack below throws on a missing status anyway, so what this proves is
    # that the refusal names the missing proposal rather than arriving as
    # whatever the decoder happened to raise. The case asserts the exact code.
    ("finalizes-an-unknown-proposal", "an-unknown-proposal-is-not-finalizable",
     FOUND_REQUIRED, "", [], "() recv_external(slice in_msg) impure {"),
    # And the two halves of the one commit. The registry set in this dictionary
    # rather than through set_conf_param is what survives the store below.
    ("accept-before-final-configuration-rules", "a-refused-finalization-never-accepts",
     ACCEPT_AFTER_RULES, ACCEPT_BEFORE_RULES, [], "() recv_external(slice in_msg) impure {"),
    ("registry-lost-to-the-store", "a-governance-operation-finalizes-a-completed-proposal",
     REGISTRY_KEPT, "", ["a-valid-finalization-reaches-accept-with-real-gas-credit"],
     "() recv_external(slice in_msg) impure {"),
    ("finalized-proposal-not-consumed", "a-governance-operation-finalizes-a-completed-proposal",
     PROPOSAL_CONSUMED, "", [], "() recv_external(slice in_msg) impure {"),
    ("sentinel-is-the-threshold", "a-completed-vote-installs-nothing-under-governance", SENTINEL,
     "        .store_uint(wins, 8)\n", [
      "a-checkpointless-active-chain-votes-in-no-config8-that-stays-authenticated"
     ],
     "(cell, cell, int) register_vote(vote_dict, phash, idx, weight) inline_ref {"),
]


def contract(tree: str, workdir: str) -> str | None:
    fif, boc = f"{workdir}/config.fif", f"{workdir}/config.boc"
    if subprocess.run([f"{tree}/crypto/func", "-PS", "-o", fif, "crypto/smartcont/stdlib.fc", str(SOURCE)],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    script = f"{workdir}/assemble.fif"
    Path(script).write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    if subprocess.run([f"{tree}/crypto/fift", "-I", "crypto/fift/lib", "-s", script],
                      capture_output=True, text=True, check=False).returncode != 0:
        return None
    return boc


def inventory(boc: str) -> list[str]:
    listed = subprocess.run([str(BINARY), boc, "--list"], capture_output=True, text=True, check=False)
    return [line.strip() for line in listed.stdout.splitlines() if line.strip()]


def outcomes(boc: str, cases: list[str]) -> dict[str, bool]:
    return {case: subprocess.run([str(BINARY), boc, case], capture_output=True, text=True,
                                 check=False).returncode == 0
            for case in cases}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", default="build-p0")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    original = SOURCE.read_text()
    with tempfile.TemporaryDirectory() as work:
        boc = contract(args.build, work)
        if boc is None:
            print("BASELINE-CONTRACT-FAILED", file=sys.stderr)
            return 1
        cases = inventory(boc)
        if not cases or not all(outcomes(boc, cases).values()):
            print("BASELINE-NOT-PASSING", file=sys.stderr)
            return 1

        records, failures = [], 0
        try:
            for guard, case, before, after, companions, *scope in MUTATIONS:
                # An anchor is unique within its scope, and the scope itself
                # must be unique in the file, or "the anchor matched once" is a
                # statement about the wrong function.
                region = scoped(original, scope[0]) if scope else original
                if scope and original.count(scope[0]) != 1:
                    print(f"SCOPE-NOT-UNIQUE {guard} ({original.count(scope[0])})", file=sys.stderr)
                    failures += 1
                    continue
                if region.count(before) != 1:
                    print(f"ANCHOR-NOT-UNIQUE {guard} ({region.count(before)})", file=sys.stderr)
                    failures += 1
                    continue
                changed = original.replace(region, region.replace(before, after, 1), 1)
                SOURCE.write_text(changed)
                reached = SOURCE.read_text() == changed
                mutated = contract(args.build, work)
                broke = []
                if mutated is not None:
                    broke = sorted(name for name, held in outcomes(mutated, cases).items() if not held)
                SOURCE.write_text(original)
                restored = contract(args.build, work) is not None and all(outcomes(boc, cases).values())
                record = {"guard": guard, "case": case, "edit_reached_source": reached,
                          "compiled": mutated is not None, "cases_run": len(cases), "cases_broken": broke,
                          "declared_companions": companions,
                          "only_declared_cases_broke": case in broke and set(broke) <= {case, *companions},
                          "restored_baseline": restored, "source_unchanged": SOURCE.read_text() == original}
                records.append(record)
                print(json.dumps(record), flush=True)
                if not all(record[key] for key in ("edit_reached_source", "compiled", "only_declared_cases_broke",
                                                   "restored_baseline", "source_unchanged")):
                    failures += 1
        finally:
            SOURCE.write_text(original)

    (args.out / "mutations.json").write_text(json.dumps(records, indent=1) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

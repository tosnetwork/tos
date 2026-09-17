"""Hold both levels of the external-message evidence expansion boundary.

The registry admission source may open an arriving evidence container once, under
the admission allowance. The ingress checker has a second, wider invariant: a
failed VM run is repeated with logging, but that diagnostic retry must reuse the
material already admitted by the first attempt rather than run admission again.
The retry still needs a fresh host because host state and work allowance are
mutable.

Neither property changes a functional answer when it regresses. The same message
is merely parsed twice, or the same host is accidentally reused, so ordinary
accept/refuse tests are the wrong instrument. This check holds the source shape
and mutates both invariants in memory to prove the check itself speaks.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADMISSION = ROOT / "validator/auth/native-registry-admission.cpp"
TRANSACTION = ROOT / "validator/auth/native-config-transaction.cpp"
INGRESS = ROOT / "validator/impl/ext-message-checker.cpp"
OPEN = re.compile(r"NativeEvidence::open\s*\(")
OFFER = re.compile(r"offer_validator_auth\s*\(")


def between(source: str, start: str, end: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start)) if begin >= 0 else -1
    if begin < 0 or finish < 0:
        return ""
    return source[begin:finish]


def admission_errors(source: str) -> list[str]:
    errors: list[str] = []
    openings = OPEN.findall(source)
    if len(openings) != 1:
        errors.append(
            f"the registry admission source opens an arriving container {len(openings)} times; expected one"
        )
    if "admission_evidence_budget()" not in source:
        errors.append("the registry admission opening is not made under the admission allowance")
    return errors


def ingress_errors(source: str, transaction: str | None = None) -> list[str]:
    errors: list[str] = []
    check = between(
        source,
        "td::actor::Task<ExtMessageChecker::CheckedExtMsg> ExtMessageChecker::check(",
        "td::Result<ExtMessageChecker::ConfigSnapshot> ExtMessageChecker::resolve_config(",
    )
    run = between(
        source,
        "td::Status ExtMessageChecker::run_message(",
        "td::actor::Task<ExtMessageChecker::ResolvedState> ExtMessageChecker::resolve_state(",
    )
    offer = between(
        source,
        "bool ExtMessageChecker::offer_validator_auth(",
        "td::Status ExtMessageChecker::run_message(",
    )
    if not check or not run or not offer:
        return ["cannot isolate the ingress checker functions"]

    run_call = check.find("CO_TRY(run_message(")
    offers = list(OFFER.finditer(check))
    if len(offers) != 1:
        errors.append(f"the ingress check performs {len(offers)} authority admissions; expected one")
    elif run_call < 0 or offers[0].start() > run_call:
        errors.append("authority admission occurs inside/after run_message instead of once before both VM attempts")

    if "clone_for_execution()" not in check[run_call if run_call >= 0 else 0 :]:
        errors.append("the diagnostic retry has no fresh-host clone from admitted material")
    if run.count("authority()") != 2:
        errors.append(
            f"run_message constructs an execution authority {run.count('authority()')} times in source; expected nolog and log"
        )
    if OFFER.search(run):
        errors.append("run_message itself can re-enter authority admission")
    if offer.count("assemble_registry_authority(") != 1:
        errors.append("offer_validator_auth no longer has exactly one production authority assembly")

    if transaction is None:
        transaction = TRANSACTION.read_text() if TRANSACTION.exists() else ""
    clone = between(
        transaction,
        "std::unique_ptr<NativeConfigTransaction> NativeConfigTransaction::clone_for_execution() const",
        "const FinalizedAnchorSource& NativeConfigTransaction::history() const",
    )
    if not clone:
        errors.append("cannot isolate clone_for_execution")
    else:
        if OPEN.search(clone):
            errors.append("clone_for_execution re-opens evidence")
        if "new NativeConfigTransaction(material_)" not in clone:
            errors.append("clone_for_execution no longer derives solely from immutable admitted material")
    return errors


def require_mutation_rejected(name: str, mutated: str, transaction: str | None = None) -> list[str]:
    errors = ingress_errors(mutated, transaction)
    if errors:
        print(f"MUTATION_KILLED {name}: {errors[0]}")
        return []
    return [f"guard mutation survived: {name}"]


def main() -> int:
    admission = ADMISSION.read_text()
    ingress = INGRESS.read_text()
    errors = admission_errors(admission) + ingress_errors(ingress)

    # Regression one: move the one admission into the factory run_message calls
    # for both nolog and log attempts. This is the exact expensive-work doubling
    # the outer guard exists to catch.
    admission_line = (
        "  offer_validator_auth(message->root_cell(), config_snapshot, mc_state, state.utime, admitted_authority);\n"
    )
    factory_open = (
        "      [authority = std::move(admitted_authority), first = true]() mutable -> "
        "std::shared_ptr<vm::ValidatorAuthHost> {\n"
    )
    if ingress.count(admission_line) != 1 or ingress.count(factory_open) != 1:
        errors.append("mutation anchors for repeated ingress admission are not unique")
    else:
        repeated = ingress.replace(admission_line, "", 1).replace(
            factory_open,
            factory_open
            + "        offer_validator_auth(message->root_cell(), config_snapshot, mc_state, state.utime, authority);\n",
            1,
        )
        errors += require_mutation_rejected("admission-moved-into-retry-factory", repeated)

    # Regression two: return the same stateful host on the logging attempt. It
    # avoids the second parse but inherits settled work and staged state, which
    # makes the diagnostic run asymmetric with its rebuilt account.
    clone_line = (
        "          execution = std::shared_ptr<tos::auth::NativeConfigTransaction>(authority->clone_for_execution());\n"
    )
    if ingress.count(clone_line) != 1:
        errors.append("mutation anchor for stateful-host reuse is not unique")
    else:
        reused = ingress.replace(clone_line, "          execution = authority;\n", 1)
        errors += require_mutation_rejected("logging-run-reuses-stateful-host", reused)

    # Regression three: parse the arriving container again for every execution.
    # This is the one the runtime case cannot reach. Admission's charger is not
    # reachable from a clone, so a clone that re-expanded attacker-chosen bytes
    # would move no counter and the config-transaction suite would still pass.
    # The clause below is therefore the only thing holding it, and a clause no
    # mutation exercises is a clause nobody has heard speak.
    transaction = TRANSACTION.read_text()
    clone_return = "  return std::unique_ptr<NativeConfigTransaction>(new NativeConfigTransaction(material_));\n"
    if transaction.count(clone_return) != 1:
        errors.append("mutation anchor for a second evidence opening is not unique")
    else:
        reopened = transaction.replace(
            clone_return,
            "  auto again = NativeEvidence::open(material_->evidence.root(), EvidenceCharge{});\n"
            "  (void)again;\n" + clone_return,
            1,
        )
        errors += require_mutation_rejected("clone-reopens-the-evidence-container", ingress, reopened)

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: one evidence opening, one ingress admission, fresh host for the logging retry")
    return 0


if __name__ == "__main__":
    sys.exit(main())

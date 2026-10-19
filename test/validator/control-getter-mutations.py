#!/usr/bin/env python3
"""Run bounded-getter controls in isolated worktrees with strict native flags."""

import argparse
import json
import shlex
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

CORE = "validator-engine/control-getter.cpp"
POOL = "validator-engine/control-getter-executor.cpp"
HEADER = "validator-engine/control-getter.h"
REFS = "crypto/common/refcnt.cpp"
CONTROLS = {
    "active": (
        HEADER,
        "kControlGetterActiveJobs = 2",
        "kControlGetterActiveJobs = 3",
        "executor",
        "executor-reservations-2-8",
    ),
    "queue": (
        HEADER,
        "kControlGetterQueuedJobs = 8",
        "kControlGetterQueuedJobs = 9",
        "executor",
        "executor-eleventh-busy",
    ),
    "dispatch": (
        POOL,
        "if (job_->phase != Job::Phase::Preparing)",
        "if (false)",
        "executor",
        "executor-second-dispatch-refused",
    ),
    "cancel": (
        POOL,
        "job_->cancelled = true;",
        "job_->cancelled = true; for (auto& slot : state_->active) { if (slot == job_ && job_->phase == Job::Phase::Running) { slot.reset(); } }",
        "executor",
        "executor-cancel-keeps-reservation",
    ),
    "stopped": (
        POOL,
        "if (state_->stopped) {",
        "if (false) {",
        "executor",
        "executor-shutdown-refuses",
    ),
    "exception": (
        POOL,
        'result = td::Status::Error("control getter worker exception");',
        "result = td::Status::OK();",
        "executor",
        "executor-exception-reported",
    ),
    "workers": (
        POOL,
        "state->serve(lane);",
        "static_cast<void>(state); static_cast<void>(lane);",
        "actor",
        "actor-getter-started",
    ),
    "shutdown": (
        POOL,
        "for (const auto& job : state_->queued) {\n      job->cancelled = true;\n    }",
        "for (const auto& job : state_->queued) { static_cast<void>(job); }",
        "shutdown",
        "shutdown-queued-cancelled",
    ),
    "aggregate": (
        CORE,
        "TRY_STATUS(budget.charge(used));",
        "TRY_STATUS(budget.charge(0));",
        "vm",
        "vm-aggregate-only-refused",
    ),
    "vm-exit": (
        CORE,
        "if (exit_code != 0 && exit_code != 1)",
        "if (false)",
        "context",
        "vm-exit-refused",
    ),
    "snapshot": (CORE, "header.seq_no != block_id.seqno()", "false", "vm", "snapshot-other-height"),
    "provenance": (
        CORE,
        "if (!account.belongs_to(snapshot.state_root()))",
        "if (false)",
        "vm",
        "vm-mixed-snapshot-refused",
    ),
    "signature": (
        CORE,
        "vm.set_chksig_always_succeed(false)",
        "vm.set_chksig_always_succeed(true)",
        "context",
        "signature-check-enabled",
    ),
    "clock": (
        CORE,
        "prepare_get_method_c7(snapshot.now(), snapshot.lt()",
        "prepare_get_method_c7(0, snapshot.lt()",
        "context",
        "context-now",
    ),
    "libraries": (
        CORE,
        "block::get_method_libraries(snapshot.config(), account.libraries)",
        "std::vector<td::Ref<vm::Cell>>{}",
        "context",
        "library-present",
    ),
    "immutable": (
        CORE,
        "return decode(vm.get_stack_const());",
        "const_cast<Account&>(account).data = vm.get_c4(); return decode(vm.get_stack_const());",
        "vm",
        "vm-private-c4-reset",
    ),
    "count": (
        CORE,
        "if (count == limit)",
        "if (count == limit && limit == 0)",
        "limits",
        "list-one-over-before-visit",
    ),
    "arity": (
        CORE,
        "cursor.as_tuple()->size() != 2",
        "cursor.as_tuple()->size() < 2",
        "limits",
        "list-extra-field",
    ),
    "visitor": (
        CORE,
        "TRY_STATUS(visit(pair->at(0)));",
        "visit(pair->at(0)).ignore();",
        "limits",
        "list-visitor-refused",
    ),
    "bytes": (CORE, "if (bytes > limit_ - used_)", "if (false)", "limits", "reply-one-over"),
    "delete": (REFS, "if (is_active_) {", "if (false) {", "delete", "deep-drop-small-stack"),
    "headroom": (
        HEADER,
        "kPastElectionsGasLimit = 50000",
        "kPastElectionsGasLimit = 25000",
        "budget",
        "BUDGET_GATE_FAIL past-shape=1",
    ),
    "per-gas": (
        HEADER,
        "kReturnedStakeGasLimit = 40000",
        "kReturnedStakeGasLimit = 20000",
        "budget",
        "BUDGET_MEASUREMENT_FAILURE returned-deepest",
    ),
}


def run(command, cwd=None, check=True, timeout=300):
    result = subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise RuntimeError(
            f"exit {result.returncode}: {shlex.join(command)}\n{result.stdout}\n{result.stderr}"
        )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=10)
    parser.add_argument("--only", choices=CONTROLS)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    commands = run(
        [
            "ninja",
            "-C",
            str(build),
            "-t",
            "commands",
            "test-control-getter",
            "test-control-getter-budget",
        ]
    ).stdout.splitlines()
    compile_commands = {}
    for relative in [
        CORE,
        POOL,
        REFS,
        "test/validator/control-getter-test.cpp",
        "test/validator/control-getter-budget-test.cpp",
    ]:
        matched = set(line for line in commands if f" -c {source / relative}" in line)
        if len(matched) != 1:
            raise RuntimeError(f"expected one compilation of {relative}, got {len(matched)}")
        compile_commands[relative] = shlex.split(next(iter(matched)))
    patch = run(["git", "diff", "--binary", "HEAD"], source).stdout
    cases = [args.only] if args.only else list(CONTROLS)
    with tempfile.TemporaryDirectory(prefix="control-getter-mutations-") as directory:
        root = Path(directory)
        patch_file = root / "candidate.patch"
        patch_file.write_text(patch)

        def check_case(name):
            checkout = root / name
            run(["git", "worktree", "add", "--detach", str(checkout), "HEAD"], source)
            try:
                if patch:
                    run(["git", "apply", str(patch_file)], checkout)
                relative, before, after, suite, expected = CONTROLS[name]
                target = checkout / "mutation-build"
                target.mkdir()
                executable = (
                    "test-control-getter-budget" if suite == "budget" else "test-control-getter"
                )
                test_source = "test/validator/" + executable.replace("test-", "", 1) + "-test.cpp"
                units = [test_source, CORE, POOL]
                if relative == REFS:
                    units.append(REFS)
                rules = []
                objects = []
                for index, unit in enumerate(units):
                    command = compile_commands[unit].copy()
                    for at, word in enumerate(command):
                        if word.startswith("-I" + str(source)) and not word.startswith(
                            ("-I" + str(build), "-I" + str(source / "tl/generate"))
                        ):
                            command[at] = word.replace(str(source), str(checkout), 1)
                    command.extend(word for word in compile_commands[unit] if word.startswith("-I"))
                    output = target / (Path(unit).name + ".o")
                    for option in ["-o", "-MF", "-MT", "-c"]:
                        at = command.index(option) + 1
                        command[at] = (
                            str(checkout / unit)
                            if option == "-c"
                            else str(output) + (".d" if option == "-MF" else "")
                        )
                    rules.append(
                        f"rule compile{index}\n  command = {shlex.join(command)}\nbuild {output}: compile{index} {checkout / unit}\n"
                    )
                    objects.append(output)
                links = set(line for line in commands if f" -o {executable} " in line)
                if len(links) != 1:
                    raise RuntimeError("expected one link command")
                link = shlex.split(next(iter(links)).split("&&")[1])
                link.remove(f"CMakeFiles/{executable}.dir/{test_source}.o")
                at = link.index("-o")
                link[at + 1] = str(target / "control")
                link[at:at] = [str(obj) for obj in objects]
                link = [
                    str(build / word)
                    if not word.startswith("/") and word.endswith((".a", ".o"))
                    else word
                    for word in link
                ]
                rules.append(
                    f"rule link\n  command = {shlex.join(link)}\nbuild {target / 'control'}: link {' '.join(str(obj) for obj in objects)}\n"
                )
                (target / "build.ninja").write_text("\n".join(rules))
                command = [
                    str(target / "control"),
                    str(build / "getter-context-data/zerostate.boc"),
                    str(source / "test/validator/fixtures/control-getter"),
                ]
                if suite != "budget":
                    command.append(suite)
                run(["ninja", "-C", str(target), "-j6"])
                green = run(command)
                marker = "gate_failures=0" if suite == "budget" else "failures=0"
                if marker not in green.stdout:
                    raise RuntimeError("baseline ran no passing assertions")
                path = checkout / relative
                original = path.read_text()
                if original.count(before) != 1:
                    raise RuntimeError(f"{name}: expected one anchor, got {original.count(before)}")
                line = original[: original.index(before)].count("\n") + 1
                path.write_text(original.replace(before, after))
                # Headers are dependencies too: force exactly these small objects.
                for obj in objects:
                    obj.unlink(missing_ok=True)
                run(["ninja", "-C", str(target), "-j6"])
                red = run(command, check=False)
                prefix = "" if suite == "budget" else "CONTROL_GETTER_FAIL "
                if red.returncode != 1 or prefix + expected not in red.stderr:
                    raise RuntimeError(
                        f"{name}: not an intended assertion: {red.returncode}\n{red.stdout}\n{red.stderr}"
                    )
                path.write_text(original)
                for obj in objects:
                    obj.unlink(missing_ok=True)
                run(["ninja", "-C", str(target), "-j6"])
                restored = run(command)
                if marker not in restored.stdout:
                    raise RuntimeError("restored run had no passing assertions")
                return {
                    "control": name,
                    "file": relative,
                    "line": line,
                    "anchors": 1,
                    "suite": suite,
                    "assertion": expected,
                    "green_exit": 0,
                    "red_exit": 1,
                    "restored_exit": 0,
                }
            finally:
                run(["git", "worktree", "remove", "--force", str(checkout)], source)

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(check_case, cases):
                print(json.dumps(result), flush=True)
    print(f"CONTROL_GETTER_MUTATIONS controls={len(cases)} not_red=0")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Rebuild context controls in separate detached worktrees and Ninja targets.

Unchanged dependency objects come from the supplied, fully built candidate.
Each target recompiles the test and the guarded production translation units
using that candidate's actual compiler flags. No candidate source is mutated.
"""

import argparse
import json
import shlex
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HELPER = "crypto/block/get-method-context.cpp"
SERVER = "validator/impl/liteserver.cpp"
CONTROLS = {
    "clock": (HELPER, "td::make_refint(now)", "td::make_refint(0)", "context", "context-v3"),
    "logical-time": (HELPER, "td::make_refint(lt)", "td::make_refint(0)", "context", "context-v3"),
    "seed": (HELPER, "std::move(rand_seed_int),", "td::zero_refint(),", "vm", "vm-context"),
    "balance": (
        HELPER,
        "balance.as_vm_tuple()",
        "CurrencyCollection::zero().as_vm_tuple()",
        "context",
        "context-v3",
    ),
    "config": (
        HELPER,
        "config ? config->get_root_cell() : vm::StackEntry()",
        "vm::StackEntry()",
        "context",
        "context-v3",
    ),
    "code": (HELPER, "vm::StackEntry::maybe(my_code)", "vm::StackEntry()", "context", "context-v4"),
    "previous": (
        HELPER,
        "info.is_ok() ? info.move_as_ok() : vm::StackEntry()",
        "vm::StackEntry()",
        "context",
        "context-v4",
    ),
    "unpacked": (
        HELPER,
        "vm::StackEntry::maybe(config->get_unpacked_config_tuple(now))",
        "vm::StackEntry()",
        "context",
        "context-v6",
    ),
    "debt": (
        HELPER,
        "tuple.push_back(due_payment)",
        "tuple.push_back(td::zero_refint())",
        "context",
        "context-v6",
    ),
    "precompiled": (
        HELPER,
        "precompiled ? td::make_refint(precompiled.value().gas_usage) : vm::StackEntry()",
        "vm::StackEntry()",
        "context",
        "context-v6",
    ),
    "version": (
        HELPER,
        "get_global_version() >= 11",
        "get_global_version() >= 12",
        "context",
        "context-v11",
    ),
    "account-library": (
        HELPER,
        "get_global_version() < 15",
        "get_global_version() < 16",
        "libraries",
        "libraries-v15",
    ),
    "global-library": (
        HELPER,
        "if (config.get_libraries_root().not_null())",
        "if (false)",
        "libraries",
        "libraries-v14-global",
    ),
    "basic-export": (
        SERVER,
        "nullptr, {}, td::zero_refint(), rand_seed",
        "config.get(), {}, td::zero_refint(), rand_seed",
        "liteserver",
        "wire-c7-participants-12",
    ),
    "call-site": (
        SERVER,
        "prepare_get_method_c7(gen_utime, gen_lt",
        "prepare_get_method_c7(0, gen_lt",
        "liteserver",
        "liteserver-context-fields",
    ),
}


def run(command, cwd=None, timeout=180, check=True):
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {shlex.join(command)}\n{result.stdout}\n{result.stderr}"
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
        ["ninja", "-C", str(build), "-t", "commands", "test-get-method-context"]
    ).stdout.splitlines()
    test_source = "test/validator/getter-context-test.cpp"
    compile_commands = {}
    for relative in (test_source, HELPER, SERVER):
        matched = [shlex.split(line) for line in commands if f" -c {source / relative}" in line]
        if len(matched) != 1:
            raise RuntimeError(
                f"expected exactly one compiler command for {relative}, got {len(matched)}"
            )
        compile_commands[relative] = matched[0]
    links = [line for line in commands if " -o test-get-method-context " in line]
    if len(links) != 1:
        raise RuntimeError("expected one candidate link command")
    link = shlex.split(links[0].split("&&")[1])
    patch = run(["git", "diff", "--binary", "HEAD"], source).stdout
    cases = [args.only] if args.only else list(CONTROLS)
    results = []
    with tempfile.TemporaryDirectory(prefix="getter-context-controls-") as temporary:
        root = Path(temporary)
        patch_file = root / "candidate.patch"
        patch_file.write_text(patch)

        def check_case(name):
            checkout = root / name
            run(["git", "worktree", "add", "--detach", str(checkout), "HEAD"], source)
            try:
                if patch:
                    run(["git", "apply", str(patch_file)], checkout)
                target = checkout / "mutation-build"
                target.mkdir()

                def compile_object(relative):
                    command = compile_commands[relative].copy()
                    for index, word in enumerate(command):
                        generated = ("-I" + str(build), "-I" + str(source / "tl/generate"))
                        if word.startswith("-I" + str(source)) and not word.startswith(generated):
                            command[index] = word.replace(str(source), str(checkout), 1)
                    # Generated headers are immutable candidate dependencies;
                    # checkout include directories take precedence over them.
                    command.extend(
                        word for word in compile_commands[relative] if word.startswith("-I")
                    )
                    output = target / (Path(relative).name + ".o")
                    for option in ("-o", "-MF", "-MT", "-c"):
                        index = command.index(option) + 1
                        command[index] = (
                            str(checkout / relative)
                            if option == "-c"
                            else str(output) + (".d" if option == "-MF" else "")
                        )
                    return command, output

                units = [test_source, HELPER]
                if CONTROLS[name][0] == SERVER:
                    units.append(SERVER)
                rules = []
                outputs = []
                for index, relative in enumerate(units):
                    command, output = compile_object(relative)
                    rules.append(
                        f"rule compile{index}\n  command = {shlex.join(command)}\nbuild {output}: compile{index} {checkout / relative}\n"
                    )
                    outputs.append(output)
                command = link.copy()
                old_object = "CMakeFiles/test-get-method-context.dir/test/validator/getter-context-test.cpp.o"
                command.remove(old_object)
                index = command.index("-o")
                command[index + 1] = str(target / "control")
                command[index:index] = [str(path) for path in outputs]
                command = [
                    str(build / word)
                    if not word.startswith("/") and word.endswith((".a", ".o"))
                    else word
                    for word in command
                ]
                rules.append(
                    f"rule link\n  command = {shlex.join(command)}\nbuild {target / 'control'}: link {' '.join(str(path) for path in outputs)}\n"
                )
                (target / "build.ninja").write_text("\n".join(rules))
                test = [
                    str(target / "control"),
                    str(build / "getter-context-data/zerostate.boc"),
                    str(source / "doc/evidence/getter-serialization-budget/elector-snapshot"),
                    str(
                        source
                        / "tosctl/src/node-control/contracts/tests/fixtures/list_proposals/config-code.boc"
                    ),
                    "--case",
                    CONTROLS[name][3],
                    "--baseline",
                    str(source / "test/validator/data/getter-context-before.tsv"),
                ]
                run(["ninja", "-C", str(target), "-j6"], timeout=600)
                green = run(test)
                if "checks=" not in green.stdout or "failures=0" not in green.stdout:
                    raise RuntimeError("baseline ran no passing assertions")
                relative, before, after, _, expected = CONTROLS[name]
                path = checkout / relative
                text = path.read_text()
                count = text.count(before)
                if count != (2 if name in {"call-site", "logical-time"} else 1):
                    raise RuntimeError(f"mutation {name} has {count} anchors")
                line = text[: text.index(before)].count("\n") + 1
                path.write_text(text.replace(before, after))
                run(["ninja", "-C", str(target), "-j6"], timeout=600)
                red = run(test, check=False)
                if red.returncode != 1 or f"GETTER_CONTEXT_FAIL {expected}" not in red.stderr:
                    raise RuntimeError(
                        f"{name} did not fail its assertion: exit={red.returncode}\n{red.stdout}\n{red.stderr}"
                    )
                path.write_text(text)
                run(["ninja", "-C", str(target), "-j6"], timeout=600)
                restored = run(test)
                if "failures=0" not in restored.stdout:
                    raise RuntimeError("restoration ran no passing assertions")
                return {
                    "control": name,
                    "file": relative,
                    "line": line,
                    "anchors": count,
                    "green_exit": green.returncode,
                    "red_exit": red.returncode,
                    "assertion": expected,
                    "restored_exit": restored.returncode,
                }
            finally:
                run(["git", "worktree", "remove", "--force", str(checkout)], source)

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(check_case, cases):
                results.append(result)
                print(json.dumps(result), flush=True)
    print(f"GETTER_CONTEXT_MUTATIONS controls={len(results)} not_red=0", flush=True)


if __name__ == "__main__":
    main()

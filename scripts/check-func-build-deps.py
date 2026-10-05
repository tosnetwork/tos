#!/usr/bin/env python3
"""Require every FunC build rule to depend on every file its sources include.

func reads #include files itself, so a build rule that lists only the files it
passes to the compiler leaves its output stale when an included library
changes: the next build reports nothing to do and every test reads the
previous code. This reads each rule that compiles FunC in CMakeLists.txt and
crypto/CMakeLists.txt, follows the #includes of its compiled sources, and
fails if a rule does not name one of them. A recognized call it cannot
classify also fails. Rules are found by the helper and command names this
script knows; a rule built through a new helper it does not recognize is not
discovered, so extend the patterns when adding one.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = re.compile(r'^\s*#include\s+"([^"]+)"', re.M)
FC = re.compile(r"[\w${}./-]+\.fc\b")


def includes(source: Path, seen: set[Path]) -> set[Path]:
    """Every file `source` includes, directly or not, resolved as func does."""
    for name in INCLUDE.findall(source.read_text()):
        path = (source.parent / name).resolve()
        if path not in seen:
            seen.add(path)
            if not path.exists():
                raise SystemExit(f"{source}: includes missing file {name}")
            includes(path, seen)
    return seen


def calls(text: str, name: str):
    """The argument text of every call to `name(...)`, outside comments."""
    for match in re.finditer(rf"^\s*{re.escape(name)}\(", text, re.M):
        depth, start = 1, match.end()
        for i in range(start, len(text)):
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            if depth == 0:
                yield text[start:i]
                break


def paths(args: str, base: Path, root_dir: Path) -> list[Path]:
    """The .fc paths named in `args`, resolved like the rule resolves them."""
    found = []
    for token in FC.findall(args):
        token = token.replace("${CMAKE_CURRENT_SOURCE_DIR}", str(root_dir))
        if "${" in token:
            raise SystemExit(f"unresolved variable in {token!r}")
        path = Path(token)
        found.append((path if path.is_absolute() else base / path).resolve())
    return found


def check() -> list[str]:
    problems, rules = [], 0
    top = (ROOT / "CMakeLists.txt").read_text()
    crypto = (ROOT / "crypto/CMakeLists.txt").read_text()
    smartcont = ROOT / "crypto/smartcont"

    def compare(label: str, compiled: list[Path], declared: list[Path]) -> None:
        nonlocal rules
        rules += 1
        if not compiled:
            problems.append(f"{label}: no FunC source found in the rule")
            return
        needed: set[Path] = set()
        for source in compiled:
            includes(source, needed)
        for path in sorted(needed - set(declared) - set(compiled)):
            problems.append(f"{label}: does not depend on {path.relative_to(ROOT)}")

    for args in calls(crypto, "GenFif"):
        source = re.search(r"SOURCE\s+(\S+)", args)
        if source is None:
            problems.append(f"GenFif without SOURCE: {args.split()[:2]}")
            continue
        compiled = [(ROOT / "crypto" / source.group(1)).resolve()]
        declared = paths(args, ROOT / "crypto", ROOT / "crypto")
        declared.append((smartcont / "stdlib.fc").resolve())
        compare(f"GenFif {source.group(1)}", compiled, declared)

    for args in calls(crypto, "add_custom_command"):
        if "$<TARGET_FILE:func>" not in args and "FUNC_BIN=" not in args:
            continue
        main = re.search(r"MAIN_DEPENDENCY\s+(\S+\.fc)", args)
        if main is None:
            if "${ARG_SOURCE}" in args:
                continue  # GenFif's own body, checked through its call sites
            command, found, depends = args.partition("DEPENDS")
            if not found:
                problems.append(f"crypto/CMakeLists.txt: FunC rule without DEPENDS: {args[:80]!r}")
                continue
            compiled = paths(command, ROOT / "crypto", ROOT / "crypto")
            compare(
                f"rule compiling {[p.name for p in compiled]}",
                compiled,
                paths(depends, ROOT / "crypto", ROOT / "crypto"),
            )
            continue
        compiled = [(ROOT / "crypto" / main.group(1)).resolve()]
        compare(f"embed {main.group(1)}", compiled, paths(args, ROOT / "crypto", ROOT / "crypto"))

    for args in calls(top, "smartcont_func_to_boc"):
        words = args.split()
        if len(words) < 2:
            continue
        compiled = [smartcont / words[1], smartcont / "stdlib.fc"]
        declared = [(smartcont / w).resolve() for w in words[2:]]
        compare(f"smartcont_func_to_boc {words[1]}", compiled, declared)

    for args in calls(top, "slice1_func_to_boc"):
        if "OUT_BOC WORKING_DIR" in args:
            continue  # the definition
        sources, _, extra = args.partition("INCLUDES")
        compare(
            f"slice1_func_to_boc {args.split()[0]}",
            paths(sources, ROOT, ROOT),
            paths(extra, ROOT, ROOT),
        )

    if rules < 30:
        problems.append(f"only {rules} FunC rules found; the parser no longer matches the build")
    print(f"{rules} FunC build rules checked")
    return problems


def main() -> int:
    problems = check()
    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

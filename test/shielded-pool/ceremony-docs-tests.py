#!/usr/bin/env python3
"""The ceremony documents point at things that exist, and quote commands that run.

A participant follows these files on a machine they have never used before,
one copied line at a time. Every failure mode here is silent in the way this
repository keeps warning about: a link that 404s, a filename that was renamed,
a flag that no longer exists. Nothing fails when the documents rot -- someone
just gets stuck, and they are usually the person least equipped to tell
whether the instructions or their machine is wrong.

Four checks, none of which needs the ceremony to be running:

1. every relative link resolves to a file that exists;
2. every repository path quoted in a command exists;
3. no entry on the "not created yet" waiver list has quietly come into
   existence, which is how such a list turns into a permanent exemption;
4. every option the guide tells a participant to pass is one the program
   actually accepts.

Checks 1 and 2 both caught real breakage the first time they ran: three dead
links, and a `less ~/tos/...` line in the guide naming a path that did not
exist. Check 4 exists because the runbook documented `--sign-with` for months
while nothing verified a signature -- a flag that exists is not a flag that
works, but a flag that does not exist is certainly broken, and that much is
cheap to know.
"""

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DOCS = [
    "artifacts/phase2/README.md",
    "artifacts/phase2/PARTICIPANT-GUIDE.md",
    "artifacts/phase2/ANNOUNCEMENT.md",
    "doc/shielded-pool-phase2-runbook.md",
]

LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

# Paths the documents name that do not exist yet because the ceremony has not
# opened. Listed rather than pattern-matched away, so the set stays small and
# visible: each entry is a promise that something will be created, and an
# entry that is still here once the ceremony is running is a bug. They are
# printed on every run for that reason.
CREATED_WHEN_THE_CEREMONY_OPENS = {
    "artifacts/phase2/beacon.bin",
}


def links_resolve() -> list[str]:
    problems = []
    for name in DOCS:
        path = ROOT / name
        for text, target in LINK.findall(path.read_text()):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = target.split("#")[0]
            if not target:
                continue
            if not (path.parent / target).resolve().exists():
                problems.append(f"{name}: [{text}]({target}) does not exist")
    return problems


def quoted_paths_exist() -> list[str]:
    """Repository paths named in the docs, held to existing.

    Only paths rooted at a directory this repository actually has, so prose
    like `~/ceremony` and a participant's own `~/.ssh/...` are not mistaken
    for claims about this tree.
    """
    roots = ("tools/", "test/", "scripts/", "doc/", "artifacts/", "crypto/")
    # Backtick-quoted paths in prose, and bare paths in the command blocks a
    # participant copies. The second kind matters more: prose is read, but a
    # wrong path inside a `less ~/tos/...` line is pasted straight into a
    # terminal by someone with no way to tell whether the file should exist.
    pattern = re.compile(r"[`\s(]((?:~/tos/)?(?:tools|test|scripts|doc|artifacts|crypto)/[A-Za-z0-9_./-]+)")
    problems = []
    for name in DOCS:
        path = ROOT / name
        for quoted in pattern.findall(path.read_text()):
            quoted = quoted.removeprefix("~/tos/").rstrip("`.,;:")
            if not quoted.startswith(roots):
                continue
            if quoted.endswith("/"):
                continue
            # A path with a wildcard or a placeholder is prose, not a claim.
            if "*" in quoted or "<" in quoted:
                continue
            if quoted in CREATED_WHEN_THE_CEREMONY_OPENS:
                continue
            if not (ROOT / quoted).exists():
                problems.append(f"{name}: `{quoted}` does not exist")
    return problems


def pending_paths_are_still_pending() -> list[str]:
    """The waiver list above is not carrying an entry that already exists.

    Without this the list is a place for a stale exemption to sit forever: a
    path is added while it is genuinely missing, the file appears later, and
    the waiver keeps excusing it long after there is nothing to excuse.
    """
    return [
        f"`{path}` now exists; remove it from CREATED_WHEN_THE_CEREMONY_OPENS"
        for path in sorted(CREATED_WHEN_THE_CEREMONY_OPENS)
        if (ROOT / path).exists()
    ]


def options_of(module_path: str, builder: str) -> set[str]:
    """The option strings a module's parser actually defines.

    Asked of the parser rather than of any output it produces. Two earlier
    versions of this check were blind:

    - grepping `--help` matched the module docstring, because these modules
      build their parser with `description=__doc__` and describe their own
      flags in prose. Renaming `--in-progress` in the code left the check
      green, since the docstring still said `--in-progress`;
    - running the program with the flag and looking for "unrecognized
      arguments" never reached the question, because argparse reports a
      missing *required* argument first.

    `_option_string_actions` is private, and using it is still the honest
    choice here: it is the mapping argparse itself resolves flags through, so
    a flag in it is a flag that works and nothing else can stand in for it.
    """
    spec = importlib.util.spec_from_file_location("_probe", ROOT / module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_probe"] = module
    spec.loader.exec_module(module)
    return set(getattr(module, builder)()._option_string_actions)


def flags_are_accepted() -> list[str]:
    """Options the documents tell people to pass, against the real parsers."""
    problems = []
    skipped: list[str] = []
    for module_path, builder, flags in (
        (
            "test/shielded-pool/verify-attestations.py",
            "build_parser",
            ("--roster", "--attestations", "--unattested-ok", "--in-progress"),
        ),
        (
            "test/shielded-pool/mutations-ceremony.py",
            "build_parser",
            ("--only", "--check-anchors"),
        ),
    ):
        defined = options_of(module_path, builder)
        name = Path(module_path).name
        for flag in flags:
            if flag not in defined:
                problems.append(f"{name} does not accept {flag}")

    # The contribution script parses its own options; read them out of it
    # rather than running it, because running it contributes.
    script = (ROOT / "scripts/shielded-pool-phase2-contribute.sh").read_text()
    for flag in ("--sign-with", "--entropy-file"):
        if f"{flag})" not in script:
            problems.append(f"the contribution script does not handle {flag}")

    # The two binaries print a usage line when given nothing, which is where
    # their real option names are.
    for binary, flags in (
        ("phase2-contribute", ("--entropy-file",)),
        ("phase2-verify", ("--vk-out",)),
    ):
        built = ROOT / "tools/shielded-pool-ceremony/target/release" / binary
        if not built.exists():
            # Said out loud. A check that quietly does nothing when the thing
            # it checks is absent reports success for the same reason it
            # would report success if everything were fine.
            skipped.append(f"{binary} is not built here, so its usage was not read")
            continue
        usage = subprocess.run(
            [str(built)], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60
        )
        for flag in flags:
            if flag not in usage.stdout + usage.stderr:
                problems.append(f"{binary} does not mention {flag} in its usage")

    for note in skipped:
        print(f"        (skipped: {note})")
    return problems


def main() -> int:
    failures = 0
    total = 4
    print("not created until the ceremony opens:")
    for path in sorted(CREATED_WHEN_THE_CEREMONY_OPENS):
        print(f"    {path}")
    print()

    for name, check in (
        ("every relative link resolves", links_resolve),
        ("every quoted repository path exists", quoted_paths_exist),
        ("no waiver outlived the thing it waived", pending_paths_are_still_pending),
        ("every documented flag is accepted", flags_are_accepted),
    ):
        problems = check()
        if problems:
            print(f"  FAIL  {name}")
            for problem in problems:
                print(f"          {problem}")
            failures += 1
        else:
            print(f"  ok    {name}")
    print()
    print(f"{total} checks, {total - failures} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

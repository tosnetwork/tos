#!/usr/bin/env python3
"""The tool that provisions a validator's one post-quantum key.

Everything here is about what the tool refuses and what it never prints. The rules the
key file itself is held to are tested in consensus-key-file-test.cpp; this is the layer
above them, where an operator's typing arrives.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SEED_HEX = "2a" * 32


class Failure(Exception):
    pass


def run(tool: Path, args: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([str(tool), *args], input=stdin, capture_output=True, timeout=120)


def private_dir(parent: Path, name: str) -> Path:
    d = parent / name
    d.mkdir()
    d.chmod(0o700)
    return d


def key_id_of(output: bytes) -> str:
    m = re.search(rb"^key_id\s+([0-9a-f]{64})$", output, re.M)
    if not m:
        raise Failure(f"no key_id in output: {output!r}")
    return m.group(1).decode()


def check(tool: Path, work: Path) -> None:
    home = private_dir(work, "private")

    # Generating one, and reading it back: the same key, from the file, every time.
    made = run(tool, ["generate", str(home / "a.key")])
    if made.returncode != 0:
        raise Failure(f"generate failed: {made.stderr!r}")
    shown = run(tool, ["show", str(home / "a.key")])
    if shown.returncode != 0 or key_id_of(shown.stdout) != key_id_of(made.stdout):
        raise Failure("show does not report the key generate wrote")
    if (home / "a.key").stat().st_mode & 0o077:
        raise Failure("a generated key is readable by somebody else")
    if (home / "a.key").stat().st_size != 32:
        raise Failure("a generated key is not a 32-byte seed")

    # Two generated keys are two keys.
    other = run(tool, ["generate", str(home / "b.key")])
    if key_id_of(other.stdout) == key_id_of(made.stdout):
        raise Failure("two generated keys have the same identity")

    # Putting a saved seed back gives the identity it had, wherever it is put.
    first = run(tool, ["import", str(home / "c.key")], SEED_HEX.encode())
    if first.returncode != 0:
        raise Failure(f"import failed: {first.stderr!r}")
    again = run(tool, ["import", str(home / "d.key")], (SEED_HEX + "\n").encode())
    if key_id_of(first.stdout) != key_id_of(again.stdout):
        raise Failure("the same seed imported twice gives two identities")
    if key_id_of(run(tool, ["show", str(home / "c.key")]).stdout) != key_id_of(first.stdout):
        raise Failure("show does not report the key import wrote")

    # Neither command replaces a key that is there.
    for command, stdin in (("generate", b""), ("import", SEED_HEX.encode())):
        refused = run(tool, [command, str(home / "a.key")], stdin)
        if refused.returncode == 0:
            raise Failure(f"{command} replaced a key that was already there")
    if key_id_of(run(tool, ["show", str(home / "a.key")]).stdout) != key_id_of(made.stdout):
        raise Failure("a refused command changed the key anyway")

    # A seed is 64 hexadecimal digits, with space allowed only around them. Anything else
    # is a different seed, or the same seed written a second way.
    bad = {
        "empty": b"",
        "short": ("2a" * 31).encode(),
        "long": ("2a" * 33).encode(),
        "one digit too many": (SEED_HEX + "a").encode(),
        "not hexadecimal": ("zz" + "2a" * 31).encode(),
        "0x prefixed": ("0x" + SEED_HEX).encode(),
        "a space between the digits": (SEED_HEX[:32] + " " + SEED_HEX[32:]).encode(),
        "a newline between the digits": (SEED_HEX[:32] + "\n" + SEED_HEX[32:]).encode(),
        "digits after the space": (SEED_HEX + " 2a").encode(),
        "a NUL byte": (SEED_HEX[:-1]).encode() + b"\x00",
    }
    for why, text in bad.items():
        target = home / ("refused-" + why.replace(" ", "-") + ".key")
        refused = run(tool, ["import", str(target)], text)
        if refused.returncode == 0:
            raise Failure(f"import accepted {why}")
        if target.exists():
            raise Failure(f"import left a file behind after refusing {why}")

    # A seed arrives on a pipe, and a pipe has no length. The tool stops at the first
    # digit past the seed rather than reading whatever is sent, so a stream that never
    # ends is refused instead of consumed.
    endless = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "block = b'2a' * 4096\n"
            "try:\n"
            "    while True:\n"
            "        sys.stdout.buffer.write(block)\n"
            "except (BrokenPipeError, OSError):\n"
            "    pass\n",
        ],
        stdout=subprocess.PIPE,
    )
    try:
        refused = subprocess.run(
            [str(tool), "import", str(home / "endless.key")],
            stdin=endless.stdout,
            capture_output=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        raise Failure("import read a stream that never ends")
    finally:
        if endless.stdout is not None:
            endless.stdout.close()
        endless.kill()
        endless.wait()
    if refused.returncode == 0:
        raise Failure("import accepted a stream that never ends")
    if (home / "endless.key").exists():
        raise Failure("import wrote a key from a stream that never ends")

    # Space around the digits is fine, and is the same seed.
    padded = run(tool, ["import", str(home / "padded.key")], (" \t\n" + SEED_HEX + " \n").encode())
    if padded.returncode != 0 or key_id_of(padded.stdout) != key_id_of(first.stdout):
        raise Failure("surrounding space changed the seed, or was refused")

    # A directory anyone can write takes no key, by either route.
    shared = work / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    for command, stdin in (("generate", b""), ("import", SEED_HEX.encode())):
        refused = run(tool, [command, str(shared / "k.key")], stdin)
        if refused.returncode == 0:
            raise Failure(f"{command} wrote a key into a directory anyone can write")

    # Nothing any command prints is the key -- and the way that is held is the whole
    # output, not a search for the secrets this test happens to know. An expanded secret
    # key is bytes this test has never seen, so looking for known bytes would miss it;
    # requiring the output to be exactly three named lines does not.
    shape = re.compile(
        rb"\Aalgorithm mldsa44\nkey_id    [0-9a-f]{64}\npublic    [0-9a-f]{2624}\n\Z"
    )
    successes = [
        run(tool, ["generate", str(home / "shape.key")]),
        run(tool, ["import", str(home / "shape-import.key")], SEED_HEX.encode()),
        run(tool, ["show", str(home / "shape.key")]),
    ]
    for done in successes:
        if done.returncode != 0:
            raise Failure(f"a command that should succeed did not: {done.stderr!r}")
        if not shape.match(done.stdout):
            raise Failure(f"a successful command printed more than the identity: {done.stdout!r}")
        if done.stderr != b"":
            raise Failure(f"a successful command wrote to stderr: {done.stderr!r}")

    # The failures, and the commands that do not exist, print no key either. Here the
    # seed is known, so it can be looked for directly.
    seed = bytes.fromhex(SEED_HEX)
    failures = [
        run(tool, ["show", str(home / "missing.key")]),
        run(tool, ["generate", str(home / "a.key")]),
        run(tool, ["import", str(home / "a.key")], SEED_HEX.encode()),
        run(tool, ["import", str(home / "never.key")], b"not hexadecimal"),
        run(tool, ["export", str(home / "c.key")]),
        run(tool, ["show"]),
        run(tool, []),
    ]
    for done in failures:
        if done.returncode == 0:
            raise Failure("a command that should fail succeeded")
        for stream in (done.stdout, done.stderr):
            if seed in stream:
                raise Failure("a command printed the seed")
            if SEED_HEX.encode() in stream or SEED_HEX.upper().encode() in stream:
                raise Failure("a command printed the seed in hexadecimal")
            if shape.match(stream):
                raise Failure("a refused command printed an identity")

    # And there is no command that would.
    for invented in ("export", "dump", "secret", "private", "seed"):
        made_up = run(tool, [invented, str(home / "c.key")])
        if made_up.returncode == 0:
            raise Failure(f"the tool has a '{invented}' command")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True, help="path to tos-pq-consensus-key")
    args = parser.parse_args()
    tool = Path(args.tool).resolve()
    if not tool.is_file():
        print(f"no tool at {tool}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        try:
            check(tool, Path(tmp))
        except Failure as failure:
            print(f"CONSENSUS_KEY_TOOL_FAILED {failure}", file=sys.stderr)
            return 1
    print(
        "CONSENSUS_KEY_TOOL_OK generate/import/show round-trip; a seed that is not exactly "
        "64 digits is refused and writes nothing; no command prints a key"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

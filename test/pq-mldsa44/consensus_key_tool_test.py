#!/usr/bin/env python3
"""The tool that provisions a validator's one post-quantum key.

Everything here is about what the tool refuses and what it prints. The rules the key file
itself is held to are tested in consensus-key-file-test.cpp; this is the layer above them,
where an operator's typing arrives. Only `export` prints the seed, and only into a pipe;
`bind-node` writes a node's configuration and nothing else.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import json
import os
import pty
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


def check(tool: Path, work: Path, shim: Path | None) -> None:
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
    with open(home / "export-target.txt", "wb") as regular_file:
        to_a_file = subprocess.run(
            [str(tool), "export", str(home / "c.key")],
            stdout=regular_file,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    to_a_file.stdout = (home / "export-target.txt").read_bytes()
    failures = [
        run(tool, ["show", str(home / "missing.key")]),
        run(tool, ["generate", str(home / "a.key")]),
        run(tool, ["import", str(home / "a.key")], SEED_HEX.encode()),
        run(tool, ["import", str(home / "never.key")], b"not hexadecimal"),
        run(tool, ["export", str(home / "missing.key")]),
        to_a_file,
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

    # And there is no other command that would.
    for invented in ("dump", "secret", "private", "seed"):
        made_up = run(tool, [invented, str(home / "c.key")])
        if made_up.returncode == 0:
            raise Failure(f"the tool has a '{invented}' command")

    check_export(tool, work, home)
    check_bind_node(tool, work, home, shim)


def export_through_pty(tool: Path, key: Path) -> tuple[int, bytes]:
    """Run export with a terminal as its standard output, and collect what reached it."""
    controller, terminal = pty.openpty()
    try:
        done = subprocess.run(
            [str(tool), "export", str(key)],
            stdout=terminal,
            stderr=terminal,
            stdin=subprocess.DEVNULL,
            timeout=120,
        )
    finally:
        os.close(terminal)
    seen = b""
    while True:
        try:
            chunk = os.read(controller, 4096)
        except OSError:  # EIO once the terminal side is closed and drained
            break
        if not chunk:
            break
        seen += chunk
    os.close(controller)
    return done.returncode, seen


def check_export(tool: Path, work: Path, home: Path) -> None:
    seed = bytes.fromhex(SEED_HEX)

    # Into a pipe, it is exactly the 64 digits import reads, and the warning and identity
    # go to stderr without the seed.
    exported = run(tool, ["export", str(home / "c.key")])
    if exported.returncode != 0:
        raise Failure(f"export into a pipe failed: {exported.stderr!r}")
    if exported.stdout != (SEED_HEX + "\n").encode():
        raise Failure(f"export did not print exactly the seed: {exported.stdout!r}")
    if b"WARNING" not in exported.stderr:
        raise Failure("export printed the seed without a warning")
    if SEED_HEX.encode() in exported.stderr or seed in exported.stderr:
        raise Failure("export repeated the seed on stderr")
    shown = run(tool, ["show", str(home / "c.key")])
    if key_id_of(exported.stderr) != key_id_of(shown.stdout):
        raise Failure("export reported a different identity from the key it exported")

    # The point of it: a key moved by export | import is the same key.
    source = subprocess.Popen(
        [str(tool), "export", str(home / "a.key")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sink = subprocess.run(
        [str(tool), "import", str(home / "moved.key")],
        stdin=source.stdout,
        capture_output=True,
        timeout=120,
    )
    if source.stdout is not None:
        source.stdout.close()
    source_err = source.stderr.read() if source.stderr is not None else b""
    if source.wait(timeout=120) != 0 or sink.returncode != 0:
        raise Failure(f"export | import failed: {source_err!r} {sink.stderr!r}")
    original = key_id_of(run(tool, ["show", str(home / "a.key")]).stdout)
    if key_id_of(sink.stdout) != original or key_id_of(source_err) != original:
        raise Failure("export | import produced a different key")
    if (home / "moved.key").read_bytes() != (home / "a.key").read_bytes():
        raise Failure("export | import did not move the seed byte for byte")

    # Never onto a terminal: refused before the key is read, and nothing of it reaches
    # the screen.
    code, screen = export_through_pty(tool, home / "c.key")
    if code == 0:
        raise Failure("export wrote the seed to a terminal")
    if SEED_HEX.encode() in screen or seed in screen:
        raise Failure("a refused export still put the seed on the terminal")
    if b"not a pipe" not in screen:
        raise Failure(f"a refused export did not say why: {screen!r}")

    # Nor into a file left by a redirect, nor a device.
    target = home / "redirected.txt"
    with open(target, "wb") as handle:
        refused = subprocess.run(
            [str(tool), "export", str(home / "c.key")], stdout=handle, stderr=subprocess.PIPE
        )
    if refused.returncode == 0 or target.read_bytes() != b"":
        raise Failure("export wrote the seed into a regular file")
    with open(os.devnull, "wb") as handle:
        refused = subprocess.run(
            [str(tool), "export", str(home / "c.key")], stdout=handle, stderr=subprocess.PIPE
        )
    if refused.returncode == 0:
        raise Failure("export wrote the seed into a device")

    # The key is read under the node's rules: a key others can read is not exported, and
    # a symbolic link is not followed.
    loose = private_dir(work, "loose")
    if run(tool, ["import", str(loose / "k.key")], SEED_HEX.encode()).returncode != 0:
        raise Failure("could not place the key the next check loosens")
    (loose / "k.key").chmod(0o640)
    refused = run(tool, ["export", str(loose / "k.key")])
    if refused.returncode == 0 or refused.stdout != b"":
        raise Failure("export read a key that is readable by others")
    os.symlink(home / "c.key", home / "link.key")
    refused = run(tool, ["export", str(home / "link.key")])
    if refused.returncode == 0 or refused.stdout != b"":
        raise Failure("export followed a symbolic link")


VALIDATOR_HEX = "5a" * 32
OTHER_VALIDATOR_HEX = "6b" * 32


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def node_config(extraconfig: dict | None = None) -> dict:
    """A configuration in the encoding the engine writes, with every kind of field."""
    head = {
        "@type": "engine.validator.config",
        "out_port": 3278,
        "addrs": [
            {
                "@type": "engine.addr",
                "ip": 2130706433,
                "port": 30001,
                "categories": [0, 1, 2, 3],
                "priority_categories": [],
            }
        ],
        "adnl": [{"@type": "engine.adnl", "id": b64(bytes([1]) * 32), "category": 0}],
        "dht": [{"@type": "engine.dht", "id": b64(bytes([2]) * 32)}],
        "validators": [],
        "collators": [],
        "fullnode": b64(bytes([3]) * 32),
        "fullnodeslaves": [],
        "fullnodemasters": [],
    }
    tail = {
        "liteservers": [{"@type": "engine.liteServer", "id": b64(bytes([4]) * 32), "port": 30003}],
        "control": [
            {
                "@type": "engine.controlInterface",
                "id": b64(bytes([5]) * 32),
                "port": 30002,
                "allowed": [
                    {
                        "@type": "engine.controlProcess",
                        "id": b64(bytes([6]) * 32),
                        "permissions": 15,
                    }
                ],
            }
        ],
        "shards_to_monitor": [
            {"@type": "tosNode.shardId", "workchain": -1, "shard": "-9223372036854775808"}
        ],
        "gc": {"@type": "engine.gc", "ids": [b64(bytes([7]) * 32)]},
    }
    middle = {} if extraconfig is None else {"extraconfig": extraconfig}
    return {**head, **middle, **tail}


def pq_consensus(validator_hex: str, key_file: Path) -> dict:
    # The test harness's encoding: int256 as standard base64, the path as given.
    return {
        "@type": "engine.validator.pqConsensus",
        "validator_id": b64(bytes.fromhex(validator_hex)),
        "consensus_key_file": str(key_file),
    }


def write_config(db: Path, config: dict, mode: int = 0o600) -> Path:
    path = db / "config.json"
    path.write_text(json.dumps(config, indent=2))
    path.chmod(mode)
    return path


def unchanged(path: Path, before: bytes, why: str) -> None:
    if path.read_bytes() != before:
        raise Failure(f"{why}, and the configuration changed anyway")


def leftovers(db: Path) -> list[str]:
    return [p.name for p in db.iterdir() if ".pq-bind." in p.name]


def bound_key_id(output: bytes) -> str:
    m = re.search(rb"^key_id\s+([0-9a-f]{64})$", output, re.M)
    if not m:
        raise Failure(f"no key_id in bind-node output: {output!r}")
    return m.group(1).decode()


def refuses(tool: Path, args: list[str], reason: bytes, why: str, timeout: int = 120) -> None:
    try:
        refused = subprocess.run(
            [str(tool), "bind-node", *args], capture_output=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise Failure(f"bind-node hung on {why}")
    if refused.returncode != 1:
        raise Failure(f"bind-node did not refuse {why}: {refused!r}")
    if reason not in refused.stderr:
        raise Failure(f"bind-node refused {why} without saying why: {refused.stderr!r}")
    if refused.stdout != b"":
        raise Failure(f"bind-node printed a binding while refusing {why}")


def held_lock(path: Path):
    """An exclusive fcntl lock on `path`, as the engine and the binder take it."""
    handle = open(path, "ab")
    fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return handle


def check_bind_node(tool: Path, work: Path, home: Path, shim: Path | None) -> None:
    key = home / "c.key"
    other_key = home / "a.key"
    key_id = key_id_of(run(tool, ["show", str(key)]).stdout)
    seed = bytes.fromhex(SEED_HEX)

    # A configuration as the generate step leaves it: no extra configuration at all. The
    # database root is what is named; the configuration is where the engine reads it.
    db = private_dir(work, "db")
    original = node_config()
    path = write_config(db, original, 0o640)
    bound = run(tool, ["bind-node", str(db), str(key), VALIDATOR_HEX])
    if bound.returncode != 0:
        raise Failure(f"bind-node failed: {bound.stderr!r}")
    for stream in (bound.stdout, bound.stderr):
        if seed in stream or SEED_HEX.encode() in stream:
            raise Failure("bind-node printed the seed")
    if bound_key_id(bound.stdout) != key_id:
        raise Failure(f"bind-node did not report the key file's identity: {bound.stdout!r}")
    if not bound.stdout.endswith(f"{path} updated\n".encode()):
        raise Failure(f"bind-node did not say it changed the configuration: {bound.stdout!r}")
    written = json.loads(path.read_text())
    # Absent, the extra configuration means a running state serializer; present, it has to
    # say so, and carries the binding in the harness's own encoding.
    expected = node_config(
        {
            "@type": "engine.validator.extraConfig",
            "state_serializer_enabled": True,
            "fast_sync_member_certificates": [],
            "fast_sync_overlay_clients": [],
            "pq_consensus": pq_consensus(VALIDATOR_HEX, key),
        }
    )
    if written != expected:
        raise Failure(
            "bind-node wrote something other than the binding into a fresh configuration:\n"
            f"{json.dumps(written, indent=1)}"
        )
    if (path.stat().st_mode & 0o7777) != 0o640:
        raise Failure(f"bind-node changed the configuration's mode to {path.stat().st_mode:o}")
    if leftovers(db):
        raise Failure(f"bind-node left temporary files: {leftovers(db)}")

    # The same binding again changes nothing, not even the file's timestamps; the
    # controller's address form names the same validator.
    before = path.read_bytes()
    stamp = path.stat().st_mtime_ns
    again = run(tool, ["bind-node", str(db), str(key), "-1:" + VALIDATOR_HEX.upper()])
    if again.returncode != 0 or not again.stdout.endswith(b" unchanged\n"):
        raise Failure(f"binding the same key twice was not a no-op: {again!r}")
    unchanged(path, before, "an identical binding was applied")
    if path.stat().st_mtime_ns != stamp:
        raise Failure("an identical binding rewrote the configuration")

    # A different binding is not replaced by accident...
    refuses(tool, [str(db), str(other_key), VALIDATOR_HEX], b"--replace", "another key")
    refuses(tool, [str(db), str(key), OTHER_VALIDATOR_HEX], b"--replace", "another validator")
    unchanged(path, before, "replacing a binding without --replace was refused")

    # ...only deliberately, and then completely.
    replaced = run(tool, ["bind-node", "--replace", str(db), str(other_key), OTHER_VALIDATOR_HEX])
    if replaced.returncode != 0:
        raise Failure(f"bind-node --replace failed: {replaced.stderr!r}")
    now = json.loads(path.read_text())
    if now["extraconfig"]["pq_consensus"] != pq_consensus(OTHER_VALIDATOR_HEX, other_key):
        raise Failure("bind-node --replace did not install the new binding")
    if {k: v for k, v in now.items() if k != "extraconfig"} != original:
        raise Failure("bind-node --replace changed fields other than the binding")

    # Whatever else the extra configuration says is kept, including a disabled serializer.
    db2 = private_dir(work, "db2")
    extra = {
        "@type": "engine.validator.extraConfig",
        "state_serializer_enabled": False,
        "fast_sync_member_certificates": [],
        "collator_node_whitelist": {
            "@type": "engine.validator.collatorNodeWhitelist",
            "enabled": True,
            "adnl_ids": [b64(bytes([8]) * 32)],
        },
        "fast_sync_overlay_clients": [
            {
                "@type": "engine.validator.fastSyncOverlayClient",
                "adnl_id": b64(bytes([9]) * 32),
                "slot": 2,
            }
        ],
    }
    path2 = write_config(db2, node_config(extra))
    if run(tool, ["bind-node", str(db2), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a configuration with an extra configuration")
    kept = json.loads(path2.read_text())
    if kept != node_config({**extra, "pq_consensus": pq_consensus(VALIDATOR_HEX, key)}):
        raise Failure(f"bind-node lost configuration: {json.dumps(kept, indent=1)}")

    # Refusals, each naming its reason (a crash also exits non-zero and says something)
    # and each leaving the configuration as it was.
    db3 = private_dir(work, "db3")
    path3 = write_config(db3, node_config())
    before3 = path3.read_bytes()
    loose = work / "loose" / "k.key"  # readable by others; made by check_export
    bad = {
        "a zero validator id": ([str(db3), str(key), "00" * 32], b"zero"),
        "a zero controller address": ([str(db3), str(key), "-1:" + "00" * 32], b"zero"),
        "a basechain address": ([str(db3), str(key), "0:" + VALIDATOR_HEX], b"masterchain"),
        "a short validator id": ([str(db3), str(key), VALIDATOR_HEX[:-2]], b"64 hexadecimal"),
        "a non-hex validator id": (
            [str(db3), str(key), "zz" + VALIDATOR_HEX[2:]],
            b"64 hexadecimal",
        ),
        "a relative key path": ([str(db3), "c.key", VALIDATOR_HEX], b"absolute"),
        "a missing key": (
            [str(db3), str(home / "missing.key"), VALIDATOR_HEX],
            b"cannot be opened",
        ),
        "a key readable by others": (
            [str(db3), str(loose), VALIDATOR_HEX],
            b"readable or writable by group or others",
        ),
        "a key behind a symbolic link": (
            [str(db3), str(home / "link.key"), VALIDATOR_HEX],
            b"symbolic link",
        ),
        "a database root that is not a directory": (
            [str(path3), str(key), VALIDATOR_HEX],
            b"not a database directory",
        ),
        "a database without a configuration": (
            [str(private_dir(work, "db-empty")), str(key), VALIDATOR_HEX],
            b"cannot open the configuration",
        ),
    }
    for why, (args, reason) in bad.items():
        refuses(tool, args, reason, why)
        unchanged(path3, before3, f"{why} was refused")
    stray = run(tool, ["bind-node", "--force", str(db3), str(key), VALIDATOR_HEX])
    if stray.returncode == 0 or b"usage:" not in stray.stderr:
        raise Failure("bind-node accepted a stray argument")
    unchanged(path3, before3, "a stray argument was refused")
    if leftovers(db3):
        raise Failure(f"a refused bind-node left temporary files: {leftovers(db3)}")

    # A relative key path is refused even where it names a good key: the node does not
    # start in the directory this runs in.
    refused = subprocess.run(
        [str(tool), "bind-node", str(db3), "c.key", VALIDATOR_HEX],
        cwd=home,
        capture_output=True,
        timeout=120,
    )
    if refused.returncode == 0 or b"absolute" not in refused.stderr:
        raise Failure("bind-node accepted a relative key path")
    unchanged(path3, before3, "a relative key path was refused")

    # The configuration has to be one: JSON, of the engine's schema, and a plain file.
    for index, (why, text, reason) in enumerate(
        (
            ("not JSON", "{", b"not JSON"),
            ("not an object", "[]", b"not a JSON object"),
            (
                "not the engine's schema",
                json.dumps({"@type": "engine.validator.config", "addrs": 7}),
                b"schema",
            ),
            ("empty", "", b"empty"),
        )
    ):
        db_bad = private_dir(work, f"bad-{index}")
        bad_path = db_bad / "config.json"
        bad_path.write_text(text)
        refuses(
            tool, [str(db_bad), str(key), VALIDATOR_HEX], reason, f"a configuration that is {why}"
        )
        if bad_path.read_text() != text:
            raise Failure(f"bind-node rewrote a configuration that is {why}")

    # Content the engine's schema would drop is refused by name, not silently lost: at the
    # top level, inside the extra configuration, and as a value of the wrong kind.
    for index, (why, config, name) in enumerate(
        (
            (
                "an unknown top-level field",
                {**node_config(), "operator_notes": "keep me"},
                b"$.operator_notes",
            ),
            (
                "an unknown nested field",
                node_config({**extra, "comment": "keep me"}),
                b"$.extraconfig.comment",
            ),
            (
                "an unknown field in a list entry",
                {
                    **node_config(),
                    "dht": [{"@type": "engine.dht", "id": b64(bytes([2]) * 32), "x": 1}],
                },
                b"$.dht[0].x",
            ),
        )
    ):
        db_extra = private_dir(work, f"extra-{index}")
        extra_path = write_config(db_extra, config)
        extra_before = extra_path.read_bytes()
        refuses(tool, [str(db_extra), str(key), VALIDATOR_HEX], name, why)
        unchanged(extra_path, extra_before, f"{why} was refused")

    # A configuration behind a symbolic link is not followed, and the link stays.
    db_link = private_dir(work, "db-link")
    os.symlink(path3, db_link / "config.json")
    refuses(
        tool,
        [str(db_link), str(key), VALIDATOR_HEX],
        b"symbolic link is refused",
        "a symlinked configuration",
    )
    if not (db_link / "config.json").is_symlink():
        raise Failure("bind-node replaced a symbolic link to a configuration")
    unchanged(path3, before3, "a configuration behind a symbolic link was refused")

    # A FIFO at the configuration's name is refused at once, not waited on.
    db_fifo = private_dir(work, "db-fifo")
    os.mkfifo(db_fifo / "config.json", 0o600)
    refuses(
        tool, [str(db_fifo), str(key), VALIDATOR_HEX], b"not a regular file", "a FIFO", timeout=20
    )

    # The lock file persists and the engine opens it for writing at every start, so a
    # refusal about whose configuration this is must not leave one behind: created by
    # the wrong user, it would keep the node from starting although nobody holds it. A
    # database that has no regular configuration of this user's gets no lock file.
    for db_refused in (private_dir(work, "db-empty-lock"), db_link, db_fifo):
        refuses(
            tool,
            [str(db_refused), str(key), VALIDATOR_HEX],
            b"configuration",
            "a database that is not this user's",
            timeout=20,
        )
        if (db_refused / "config.json.lock").exists():
            raise Failure(f"a refused bind-node left a lock file in {db_refused.name}")

    # A key file that is a FIFO is refused at once too, by bind-node and by every reader
    # of the seed, rather than waited on until something writes to it.
    fifo_key = home / "fifo.key"
    os.mkfifo(fifo_key, 0o600)
    refuses(
        tool,
        [str(db3), str(fifo_key), VALIDATOR_HEX],
        b"not a regular file",
        "a FIFO key file",
        timeout=20,
    )
    for command in ("show", "export"):
        try:
            done = subprocess.run(
                [str(tool), command, str(fifo_key)], capture_output=True, timeout=20
            )
        except subprocess.TimeoutExpired:
            raise Failure(f"{command} hung on a FIFO key file")
        if done.returncode == 0 or b"not a regular file" not in done.stderr:
            raise Failure(f"{command} did not refuse a FIFO key file: {done!r}")

    # A config.json.tmp left by an interrupted engine write may be the newer of the two;
    # which one is right is the operator's call, so nothing is edited until it is gone.
    db_tmp = private_dir(work, "db-tmp")
    path_tmp = write_config(db_tmp, node_config())
    before_tmp = path_tmp.read_bytes()
    (db_tmp / "config.json.tmp").write_text("{}")
    refuses(
        tool,
        [str(db_tmp), str(key), VALIDATOR_HEX],
        b"interrupted engine write",
        "a leftover config.json.tmp",
    )
    unchanged(path_tmp, before_tmp, "a leftover config.json.tmp was refused")
    if (db_tmp / "config.json.tmp").read_text() != "{}":
        raise Failure("bind-node touched the engine's leftover temporary file")
    (db_tmp / "config.json.tmp").unlink()
    if run(tool, ["bind-node", str(db_tmp), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused once the leftover temporary file was resolved")

    # The configuration lock. A running node holds it for as long as it runs, and another
    # binder for its whole edit: while it is held nothing is read or written, whether or
    # not the cell database's lock file exists. Released, the same command succeeds.
    with held_lock(db3 / "config.json.lock"):
        refuses(
            tool,
            [str(db3), str(key), VALIDATOR_HEX],
            b"held by a running node",
            "a held configuration lock",
        )
    unchanged(path3, before3, "the configuration of a running node was refused")
    if (db3 / "celldb").exists():
        raise Failure("the configuration lock test needs a database without a cell database")

    # The cell database's own lock is a second signal and refuses on its own.
    (db3 / "celldb").mkdir()
    with held_lock(db3 / "celldb" / "LOCK"):
        refuses(tool, [str(db3), str(key), VALIDATOR_HEX], b"running node", "a held cell database")
    unchanged(path3, before3, "a held cell database was refused")
    if run(tool, ["bind-node", str(db3), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a stopped node whose locks were released")

    # The configuration keeps its group, not the group of whoever ran this.
    others = [g for g in os.getgroups() if g != os.getegid()]
    if others:
        db_group = private_dir(work, "db-group")
        path_group = write_config(db_group, node_config(), 0o640)
        os.chown(path_group, -1, others[0])
        if run(tool, ["bind-node", str(db_group), str(key), VALIDATOR_HEX]).returncode != 0:
            raise Failure("bind-node refused a configuration with another of this user's groups")
        if path_group.stat().st_gid != others[0]:
            raise Failure(
                f"bind-node changed the configuration's group from {others[0]} to {path_group.stat().st_gid}"
            )
    else:
        print(
            "note: no supplementary group; the group-preservation case did not run", file=sys.stderr
        )

    # A configuration far larger than any encoder buffer is written whole.
    db_big = private_dir(work, "db-big")
    big = node_config()
    big["dht"] = [
        {"@type": "engine.dht", "id": b64(i.to_bytes(32, "big"))} for i in range(1, 20001)
    ]
    path_big = write_config(db_big, big)
    if path_big.stat().st_size < 1 << 20:
        raise Failure("the large configuration is not large")
    if run(tool, ["bind-node", str(db_big), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a large configuration")
    written_big = json.loads(path_big.read_text())
    if {k: v for k, v in written_big.items() if k != "extraconfig"} != big:
        raise Failure("bind-node lost part of a large configuration")

    # A directory flush that fails after the rename is not a refusal: the binding is in
    # place, and the tool says it is not confirmed durable with its own exit status.
    if shim is not None:
        db_flush = private_dir(work, "db-flush")
        path_flush = write_config(db_flush, node_config())
        failed = subprocess.run(
            [str(tool), "bind-node", str(db_flush), str(key), VALIDATOR_HEX],
            capture_output=True,
            timeout=120,
            env={**os.environ, "LD_PRELOAD": str(shim), "TOS_TEST_FAIL_DIR_FSYNC": "1"},
        )
        if failed.returncode != 3:
            raise Failure(f"a failed directory flush did not exit 3: {failed!r}")
        if b"not confirmed durable" not in failed.stderr or not failed.stdout.endswith(
            b" updated\n"
        ):
            raise Failure(f"a failed directory flush was not reported as such: {failed!r}")
        if json.loads(path_flush.read_text()).get("extraconfig", {}).get(
            "pq_consensus"
        ) != pq_consensus(VALIDATOR_HEX, key):
            raise Failure("a failed directory flush was reported, but the binding is not in place")
    else:
        print("note: no fsync shim given; the directory-flush case did not run", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True, help="path to tos-pq-consensus-key")
    parser.add_argument("--fsync-shim", help="LD_PRELOAD library that fails directory fsync")
    args = parser.parse_args()
    tool = Path(args.tool).resolve()
    if not tool.is_file():
        print(f"no tool at {tool}", file=sys.stderr)
        return 2
    shim = Path(args.fsync_shim).resolve() if args.fsync_shim else None
    if shim is not None and not shim.is_file():
        print(f"no shim at {shim}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        try:
            check(tool, Path(tmp), shim)
        except Failure as failure:
            print(f"CONSENSUS_KEY_TOOL_FAILED {failure}", file=sys.stderr)
            return 1
    print(
        "CONSENSUS_KEY_TOOL_OK generate/import/show round-trip; a seed that is not exactly "
        "64 digits is refused and writes nothing; only export prints a seed, only into a "
        "pipe, and export | import moves it; bind-node binds a stopped node's configuration "
        "under the configuration lock and refuses everything else"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

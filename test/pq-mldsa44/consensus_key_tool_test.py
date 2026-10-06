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
    check_bind_node(tool, work, home)


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
        "liteservers": [
            {"@type": "engine.liteServer", "id": b64(bytes([4]) * 32), "port": 30003}
        ],
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


def check_bind_node(tool: Path, work: Path, home: Path) -> None:
    key = home / "c.key"
    other_key = home / "a.key"
    key_id = key_id_of(run(tool, ["show", str(key)]).stdout)
    seed = bytes.fromhex(SEED_HEX)

    # A configuration as the generate step leaves it: no extra configuration at all.
    db = private_dir(work, "db")
    original = node_config()
    path = write_config(db, original, 0o640)
    bound = run(tool, ["bind-node", str(path), str(key), VALIDATOR_HEX])
    if bound.returncode != 0:
        raise Failure(f"bind-node failed: {bound.stderr!r}")
    for stream in (bound.stdout, bound.stderr):
        if seed in stream or SEED_HEX.encode() in stream:
            raise Failure("bind-node printed the seed")
    if bound_key_id(bound.stdout) != key_id:
        raise Failure(f"bind-node did not report the key file's identity: {bound.stdout!r}")
    if not bound.stdout.endswith(b" updated\n"):
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
    again = run(tool, ["bind-node", str(path), str(key), "-1:" + VALIDATOR_HEX.upper()])
    if again.returncode != 0 or not again.stdout.endswith(b" unchanged\n"):
        raise Failure(f"binding the same key twice was not a no-op: {again!r}")
    unchanged(path, before, "an identical binding was applied")
    if path.stat().st_mtime_ns != stamp:
        raise Failure("an identical binding rewrote the configuration")

    # A different binding is not replaced by accident...
    for args, why in (
        ([str(path), str(other_key), VALIDATOR_HEX], "another key"),
        ([str(path), str(key), OTHER_VALIDATOR_HEX], "another validator"),
    ):
        refused = run(tool, ["bind-node", *args])
        if refused.returncode == 0:
            raise Failure(f"bind-node replaced a binding to {why} without --replace")
        if b"--replace" not in refused.stderr:
            raise Failure(f"refusing {why} did not say how to replace it: {refused.stderr!r}")
        unchanged(path, before, f"replacing a binding to {why} was refused")

    # ...only deliberately, and then completely.
    replaced = run(
        tool, ["bind-node", "--replace", str(path), str(other_key), OTHER_VALIDATOR_HEX]
    )
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
    if run(tool, ["bind-node", str(path2), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a configuration with an extra configuration")
    kept = json.loads(path2.read_text())
    if kept != node_config({**extra, "pq_consensus": pq_consensus(VALIDATOR_HEX, key)}):
        raise Failure(f"bind-node lost configuration: {json.dumps(kept, indent=1)}")

    # Refusals, each leaving the configuration as it was.
    db3 = private_dir(work, "db3")
    path3 = write_config(db3, node_config())
    before3 = path3.read_bytes()
    loose = work / "loose" / "k.key"  # readable by others; made by check_export
    # Each refusal names its reason: a crash also exits non-zero and says something.
    bad = {
        "a zero validator id": ([str(path3), str(key), "00" * 32], b"zero"),
        "a zero controller address": ([str(path3), str(key), "-1:" + "00" * 32], b"zero"),
        "a basechain address": ([str(path3), str(key), "0:" + VALIDATOR_HEX], b"masterchain"),
        "a short validator id": ([str(path3), str(key), VALIDATOR_HEX[:-2]], b"64 hexadecimal"),
        "a non-hex validator id": (
            [str(path3), str(key), "zz" + VALIDATOR_HEX[2:]],
            b"64 hexadecimal",
        ),
        "a relative key path": ([str(path3), "c.key", VALIDATOR_HEX], b"absolute"),
        "a missing key": (
            [str(path3), str(home / "missing.key"), VALIDATOR_HEX],
            b"cannot be opened",
        ),
        "a key readable by others": (
            [str(path3), str(loose), VALIDATOR_HEX],
            b"readable or writable by group or others",
        ),
        "a key behind a symbolic link": (
            [str(path3), str(home / "link.key"), VALIDATOR_HEX],
            b"symbolic link",
        ),
        "a missing configuration": (
            [str(db3 / "absent.json"), str(key), VALIDATOR_HEX],
            b"cannot open the configuration",
        ),
        "a stray argument": (["--force", str(path3), str(key), VALIDATOR_HEX], b"usage:"),
    }
    for why, (args, reason) in bad.items():
        refused = run(tool, ["bind-node", *args])
        if refused.returncode == 0:
            raise Failure(f"bind-node accepted {why}")
        if reason not in refused.stderr:
            raise Failure(f"bind-node refused {why} without saying why: {refused.stderr!r}")
        unchanged(path3, before3, f"{why} was refused")
    if leftovers(db3):
        raise Failure(f"a refused bind-node left temporary files: {leftovers(db3)}")

    # A relative key path is refused even where it names a good key: the node does not
    # start in the directory this runs in.
    refused = subprocess.run(
        [str(tool), "bind-node", str(path3), "c.key", VALIDATOR_HEX],
        cwd=home,
        capture_output=True,
        timeout=120,
    )
    if refused.returncode == 0 or b"absolute" not in refused.stderr:
        raise Failure("bind-node accepted a relative key path")
    unchanged(path3, before3, "a relative key path was refused")

    # A configuration far larger than any encoder buffer is written whole.
    db_big = private_dir(work, "db-big")
    big = node_config()
    big["dht"] = [
        {"@type": "engine.dht", "id": b64(i.to_bytes(32, "big"))} for i in range(1, 20001)
    ]
    path_big = write_config(db_big, big)
    if path_big.stat().st_size < 1 << 20:
        raise Failure("the large configuration is not large")
    if run(tool, ["bind-node", str(path_big), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a large configuration")
    written_big = json.loads(path_big.read_text())
    if {k: v for k, v in written_big.items() if k != "extraconfig"} != big:
        raise Failure("bind-node lost part of a large configuration")

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
        refused = run(tool, ["bind-node", str(bad_path), str(key), VALIDATOR_HEX])
        if refused.returncode == 0 or bad_path.read_text() != text:
            raise Failure(f"bind-node rewrote a configuration that is {why}")
        if reason not in refused.stderr:
            raise Failure(f"bind-node refused a configuration that is {why} for another reason")
    db_link = private_dir(work, "db-link")
    os.symlink(path3, db_link / "config.json")
    refused = run(tool, ["bind-node", str(db_link / "config.json"), str(key), VALIDATOR_HEX])
    if refused.returncode == 0 or b"symbolic link is refused" not in refused.stderr:
        raise Failure(f"bind-node followed a symbolic link to a configuration: {refused!r}")
    if not (db_link / "config.json").is_symlink():
        raise Failure("bind-node replaced a symbolic link to a configuration")
    unchanged(path3, before3, "a configuration behind a symbolic link was refused")

    # A running node holds its cell database locked, and would write its own configuration
    # over this edit. While the lock is held nothing is written; once it is released, the
    # same command succeeds.
    (db3 / "celldb").mkdir()
    with open(db3 / "celldb" / "LOCK", "wb") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        refused = run(tool, ["bind-node", str(path3), str(key), VALIDATOR_HEX])
        fcntl.lockf(lock, fcntl.LOCK_UN)
    if refused.returncode == 0 or b"running node" not in refused.stderr:
        raise Failure(f"bind-node edited the configuration of a running node: {refused!r}")
    unchanged(path3, before3, "the configuration of a running node was refused")
    if run(tool, ["bind-node", str(path3), str(key), VALIDATOR_HEX]).returncode != 0:
        raise Failure("bind-node refused a stopped node whose database lock was released")


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
        "64 digits is refused and writes nothing; only export prints a seed, only into a "
        "pipe, and export | import moves it; bind-node binds a stopped node's configuration "
        "and refuses everything else"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

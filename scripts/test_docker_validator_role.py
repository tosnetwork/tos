#!/usr/bin/env python3
"""Offline tests for the container's opt-in validator role (docker/validator-role.sh).

The role writes extraconfig.pq_consensus into the node's config.json. Each
refusal test checks the specific reason and that config.json was left alone.
The entrypoint itself (docker/init.sh) is run against a temporary directory
with stand-ins for the node binaries. When a built validator-engine is
available, one test also has the real engine read the binding back.

The binding itself is written by `tos-pq-consensus-key bind-node`. Tests that
need a real binding written run only when such a binary is found
(TOS_PQ_BIND_NODE_TOOL, or the build tree's tos-pq-consensus-key when its usage
lists bind-node) and are skipped otherwise; the calls the script makes are
checked against a recording stand-in in every run.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ROLE = REPO / "docker" / "validator-role.sh"
INIT = REPO / "docker" / "init.sh"
DOCKERFILE = REPO / "Dockerfile"
ENGINE_SOURCE = REPO / "validator-engine" / "validator-engine.cpp"
ENGINE_GLOBAL_CONFIG = REPO / "tosctl" / "src" / "adnl" / "tests" / "config" / "testnet.json"

VALIDATOR_ID = "0123456789abcdef" * 4
VALIDATOR_ID_B64 = base64.b64encode(bytes.fromhex(VALIDATOR_ID)).decode()
SEED = bytes(range(101, 133))

# What `validator-engine -C <global> --db <dir> --ip <addr>` writes on a first
# start, in the engine's own formatting (observed from the built engine). The
# entrypoint's control and liteserver steps edit this text with sed.
ENGINE_CONFIG = """{
   "@type" : "engine.validator.config",
   "out_port" : 3278,
   "addrs" : [
      {
         "@type" : "engine.addr",
         "ip" : 2130706433,
         "port" : 30001,
         "categories" : [
            0,
            1,
            2,
            3
         ],
         "priority_categories" : [
         ]
      }
   ],
   "adnl" : [
      {
         "@type" : "engine.adnl",
         "id" : "6Bc6q1jAfKKJhlO/Er7uFrpOEGyFmvZQcgZA0d2yZZY=",
         "category" : 1
      }
   ],
   "dht" : [
   ],
   "validators" : [
   ],
   "collators" : [
   ],
   "fullnode" : "6Bc6q1jAfKKJhlO/Er7uFrpOEGyFmvZQcgZA0d2yZZY=",
   "fullnodeslaves" : [
   ],
   "fullnodemasters" : [
   ],
   "liteservers" : [
   ],
   "control" : [
   ],
   "shards_to_monitor" : [
   ],
   "gc" : {
      "@type" : "engine.gc",
      "ids" : [
      ]
   }
}
"""

ENGINE_STUB = """#!/usr/bin/env bash
# Stand-in for validator-engine: initializes a database, or records a start.
echo "$*" >>"$STUB_LOG/engine-calls"
db=""
init=false
while [ $# -gt 0 ]; do
  case "$1" in
    --db) db="$2"; shift ;;
    --ip) init=true ;;
  esac
  shift
done
if [ "$init" = true ]; then
  mkdir -p "$db/keyring"
  cp "$STUB_ENGINE_CONFIG" "$db/config.json"
  exit 0
fi
echo started >>"$STUB_LOG/engine-started"
exit 0
"""

GENERATE_ID_STUB = """#!/usr/bin/env bash
# Stand-in for generate-random-id -m keys -n NAME: writes NAME and NAME.pub.
name=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) name="$2"; shift ;;
  esac
  shift
done
printf 'private' >"$name"
printf 'public' >"$name.pub"
echo "$(printf '%s' "$name" | sha256sum | cut -c1-64 | tr a-f A-F) c2VydmVyLXB1YmxpYy1rZXktZm9yLSRuYW1lLXRlc3Q="
"""

WGET_STUB = """#!/usr/bin/env bash
# Stand-in for wget -q URL -O PATH.
while [ $# -gt 0 ]; do
  case "$1" in
    -O) out="$2"; shift ;;
  esac
  shift
done
printf '{"@type":"config.global"}' >"$out"
"""


def find_bind_node_tool() -> Path | None:
    configured = os.environ.get("TOS_PQ_BIND_NODE_TOOL")
    candidates = [Path(configured)] if configured else []
    candidates.append(REPO / "build" / "crypto" / "pq" / "tos-pq-consensus-key")
    for candidate in candidates:
        if not (candidate.is_file() and os.access(candidate, os.X_OK)):
            continue
        probe = subprocess.run(
            [str(candidate)], capture_output=True, text=True, timeout=60, check=False
        )
        if "bind-node" in probe.stderr:
            return candidate
    return None


BIND_NODE_TOOL = find_bind_node_tool()
requires_bind_node = unittest.skipIf(
    BIND_NODE_TOOL is None,
    "needs a tos-pq-consensus-key with bind-node; set TOS_PQ_BIND_NODE_TOOL to run it",
)
TOOL_ENV = {"TOS_PQ_CONSENSUS_KEY_TOOL": str(BIND_NODE_TOOL or "/nonexistent/tos-pq-consensus-key")}

# Records each call and answers with STUB_STATUS, printing STUB_OUTPUT.
BIND_NODE_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" >"$STUB_CALL"
printf '%s' "${STUB_OUTPUT:-}" >&2
exit "${STUB_STATUS:-0}"
"""


def write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


class RoleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="validator-role-"))
        self.tmp.chmod(0o700)
        self.keys = self.tmp / "keys"
        self.keys.mkdir(mode=0o700)
        self.seed = self.keys / "pq-consensus.seed"
        self.seed.write_bytes(SEED)
        self.seed.chmod(0o600)
        self.config = self.tmp / "config.json"
        self.config.write_text(ENGINE_CONFIG)
        self.config.chmod(0o644)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def env(self, **overrides: str | None) -> dict[str, str]:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **TOOL_ENV}
        values: dict[str, str | None] = {
            "VALIDATOR_ID": VALIDATOR_ID,
            "PQ_CONSENSUS_KEY_FILE": str(self.seed),
        }
        values.update(overrides)
        env.update({key: value for key, value in values.items() if value is not None})
        return env

    def role(self, *args: str, **overrides: str | None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(ROLE), *args],
            env=self.env(**overrides),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def apply(self, **overrides: str | None) -> subprocess.CompletedProcess[str]:
        return self.role("apply", str(self.config), **overrides)

    def assert_refused(self, reason: str, **overrides: str | None) -> None:
        before = self.config.read_bytes()
        result = self.apply(**overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("VALIDATOR_ROLE_REFUSED", result.stderr)
        self.assertIn(reason, result.stderr)
        self.assertEqual(self.config.read_bytes(), before, "a refusal must not touch config.json")
        self.assert_seed_not_printed(result)

    def assert_seed_not_printed(self, result: subprocess.CompletedProcess[str]) -> None:
        output = result.stdout + result.stderr
        for spelling in (SEED.hex(), SEED.hex().upper(), base64.b64encode(SEED).decode()):
            self.assertNotIn(spelling, output)
        self.assertNotIn(SEED.decode("latin-1"), output)

    def binding(self) -> dict[str, object]:
        return json.loads(self.config.read_text())["extraconfig"]

    # ---- role off

    def test_without_the_role_nothing_changes(self) -> None:
        result = self.apply(VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Validator role disabled", result.stdout)
        self.assertEqual(self.config.read_text(), ENGINE_CONFIG)

    def test_without_the_role_a_lite_server_is_allowed(self) -> None:
        result = self.role(
            "check",
            str(self.config),
            VALIDATOR_ID=None,
            PQ_CONSENSUS_KEY_FILE=None,
            LITESERVER="true",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    # ---- happy path

    @requires_bind_node
    def test_binding_is_written_in_the_engine_format(self) -> None:
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_seed_not_printed(result)
        extra = self.binding()
        self.assertEqual(extra["@type"], "engine.validator.extraConfig")
        self.assertIs(extra["state_serializer_enabled"], True)
        self.assertEqual(
            extra["pq_consensus"],
            {
                "@type": "engine.validator.pqConsensus",
                "validator_id": VALIDATOR_ID_B64,
                "consensus_key_file": str(self.seed),
            },
        )
        written = json.loads(self.config.read_text())
        original = json.loads(ENGINE_CONFIG)
        written.pop("extraconfig")
        self.assertEqual(written, original, "every other field is kept")
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o644)

    @requires_bind_node
    def test_masterchain_address_form_is_the_same_validator(self) -> None:
        result = self.apply(VALIDATOR_ID="-1:" + VALIDATOR_ID)
        self.assertEqual(result.returncode, 0, result.stderr)
        pq = self.binding()["pq_consensus"]
        assert isinstance(pq, dict)
        self.assertEqual(pq["validator_id"], VALIDATOR_ID_B64)

    @requires_bind_node
    def test_content_the_engine_would_drop_is_refused(self) -> None:
        config = json.loads(ENGINE_CONFIG)
        config["operator_note"] = "kept nowhere by the engine"
        self.config.write_text(json.dumps(config))
        self.assert_refused("schema does not keep")

    @requires_bind_node
    def test_interrupted_engine_write_is_refused(self) -> None:
        (self.tmp / "config.json.tmp").write_text(ENGINE_CONFIG)
        self.assert_refused("an interrupted engine write")

    @requires_bind_node
    def test_upper_case_id_is_the_same_validator(self) -> None:
        result = self.apply(VALIDATOR_ID=VALIDATOR_ID.upper())
        self.assertEqual(result.returncode, 0, result.stderr)
        pq = self.binding()["pq_consensus"]
        assert isinstance(pq, dict)
        self.assertEqual(pq["validator_id"], VALIDATOR_ID_B64)

    @requires_bind_node
    def test_existing_extraconfig_keeps_its_fields(self) -> None:
        config = json.loads(ENGINE_CONFIG)
        config["extraconfig"] = {
            "@type": "engine.validator.extraConfig",
            "state_serializer_enabled": False,
            "fast_sync_member_certificates": [],
            "fast_sync_overlay_clients": [],
        }
        self.config.write_text(json.dumps(config))
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        extra = self.binding()
        self.assertIs(extra["state_serializer_enabled"], False)
        self.assertEqual(extra["fast_sync_overlay_clients"], [])
        self.assertIn("pq_consensus", extra)

    @requires_bind_node
    def test_second_apply_with_the_same_binding_changes_nothing(self) -> None:
        self.assertEqual(self.apply().returncode, 0)
        before = self.config.read_bytes()
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unchanged", result.stdout)
        self.assertEqual(self.config.read_bytes(), before)

    def test_loopback_json_rpc_is_allowed(self) -> None:
        for custom in (
            "--json-rpc-address 127.0.0.1:8081",
            "--json-rpc-address=[::1]:8081",
            "--json-rpc-address 127.255.0.9:1",
            "--verbosity 3\n--json-rpc-address\t127.0.0.1:65535",
        ):
            with self.subTest(custom=custom):
                result = self.role("check", str(self.config), CUSTOM_ARG=custom)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_persisted_binding_alone_keeps_the_role(self) -> None:
        self.write_bound_config()
        result = self.role("check", str(self.config), VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already binds a validator", result.stdout)

    # ---- refusals

    @requires_bind_node
    def test_a_different_existing_binding_is_not_rewritten(self) -> None:
        self.write_bound_config()
        self.assert_refused("pass --replace to change it deliberately", VALIDATOR_ID="ab" * 32)

    def test_id_without_key_file_is_refused(self) -> None:
        self.assert_refused("PQ_CONSENSUS_KEY_FILE is not set", PQ_CONSENSUS_KEY_FILE=None)

    def test_key_file_without_id_is_refused(self) -> None:
        self.assert_refused("PQ_CONSENSUS_KEY_FILE is set without VALIDATOR_ID", VALIDATOR_ID=None)

    def test_malformed_ids_are_refused(self) -> None:
        for value in (
            VALIDATOR_ID[:-1],
            VALIDATOR_ID + "0",
            "g" + VALIDATOR_ID[1:],
            "0:" + VALIDATOR_ID,
            "-1:" + VALIDATOR_ID[:-1],
            "-1:-1:" + VALIDATOR_ID,
        ):
            with self.subTest(value=value):
                self.assert_refused("exactly 64 hexadecimal digits", VALIDATOR_ID=value)

    def test_zero_id_is_refused(self) -> None:
        self.assert_refused("VALIDATOR_ID is zero", VALIDATOR_ID="0" * 64)

    def test_relative_key_path_is_refused(self) -> None:
        self.assert_refused("must be an absolute path", PQ_CONSENSUS_KEY_FILE="keys/pq.seed")

    def test_missing_key_file_is_refused(self) -> None:
        self.assert_refused("does not exist", PQ_CONSENSUS_KEY_FILE=str(self.keys / "absent"))

    def test_symlinked_key_file_is_refused(self) -> None:
        link = self.keys / "link.seed"
        link.symlink_to(self.seed)
        self.assert_refused("is a symbolic link", PQ_CONSENSUS_KEY_FILE=str(link))

    def test_directory_as_key_file_is_refused(self) -> None:
        directory = self.keys / "dir.seed"
        directory.mkdir(mode=0o700)
        self.assert_refused("is not a regular file", PQ_CONSENSUS_KEY_FILE=str(directory))

    def test_wrong_sizes_are_refused(self) -> None:
        for size in (0, 31, 33, 64):
            with self.subTest(size=size):
                self.seed.write_bytes(bytes(size))
                self.assert_refused(f"holds {size} bytes")

    def test_group_or_world_permissions_are_refused(self) -> None:
        for mode in (0o640, 0o604, 0o620, 0o602, 0o610):
            with self.subTest(mode=oct(mode)):
                self.seed.chmod(mode)
                self.assert_refused("no group or other permissions")

    def test_writable_key_directory_is_refused(self) -> None:
        for mode in (0o770, 0o702, 0o1777):
            with self.subTest(mode=oct(mode)):
                self.keys.chmod(mode)
                self.assert_refused("group- or world-writable")
        self.keys.chmod(0o700)

    def test_lite_server_with_the_role_is_refused(self) -> None:
        for value in ("true", "false", "1"):
            with self.subTest(value=value):
                self.assert_refused("a validator runs no lite server", LITESERVER=value)

    def test_public_json_rpc_with_the_role_is_refused(self) -> None:
        for custom in (
            "--json-rpc-address 0.0.0.0:8081",
            "--verbosity 3 --json-rpc-address=203.0.113.5:8081",
            # Every line of CUSTOM_ARG reaches the engine, not only the first.
            "--verbosity 3\n--json-rpc-readonly --json-rpc-address 0.0.0.0:8081",
            "--verbosity\t3\t--json-rpc-address=0.0.0.0:8081",
            # The engine resolves host names; only a literal loopback IP is provably local.
            "--json-rpc-address 127.validator.example:8081",
            "--json-rpc-address localhost:8081",
            "--json-rpc-address 127.0.0.256:8081",
            "--json-rpc-address 127.1:8081",
            "--json-rpc-address [::2]:8081",
            "--json-rpc-address 127.0.0.1",
            "--json-rpc-address 127.0.0.1:0",
            "--json-rpc-address 127.0.0.1:65536",
            "--json-rpc-address 127.0.0.1:8081 --json-rpc-address 0.0.0.0:8082",
        ):
            with self.subTest(custom=custom):
                self.assert_refused("loopback only", CUSTOM_ARG=custom)

    def test_configured_lite_servers_with_the_role_are_refused(self) -> None:
        config = json.loads(ENGINE_CONFIG)
        config["liteservers"] = [{"@type": "engine.liteServer", "id": "AAAA", "port": 30003}]
        self.config.write_text(json.dumps(config))
        self.assert_refused("configures 1 lite server(s)")

    def write_bound_config(self, **fields: object) -> None:
        config = json.loads(ENGINE_CONFIG)
        config["extraconfig"] = {
            "@type": "engine.validator.extraConfig",
            "state_serializer_enabled": True,
            "pq_consensus": {
                "@type": "engine.validator.pqConsensus",
                "validator_id": VALIDATOR_ID_B64,
                "consensus_key_file": str(self.seed),
            },
        }
        config.update(fields)
        self.config.write_text(json.dumps(config))

    def test_bound_node_without_the_variables_still_refuses_public_services(self) -> None:
        cases = (
            ({}, {"LITESERVER": "true"}, "a validator runs no lite server"),
            ({}, {"CUSTOM_ARG": "--json-rpc-address 0.0.0.0:8081"}, "loopback only"),
            (
                {"liteservers": [{"@type": "engine.liteServer", "id": "AAAA", "port": 30003}]},
                {},
                "configures 1 lite server(s)",
            ),
        )
        for fields, env, reason in cases:
            with self.subTest(reason=reason):
                self.write_bound_config(**fields)
                before = self.config.read_bytes()
                result = self.role(
                    "check", str(self.config), VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None, **env
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(reason, result.stderr)
                self.assertEqual(self.config.read_bytes(), before)

    MOVING_ARGS = (
        "--db /other-db --json-rpc-readonly --json-rpc-address 0.0.0.0:8081",
        "--db=/other-db",
        "-D /other-db",
        "-D/other-db",
        # Bundles in which D or c is reached as an option letter.
        "-dD/other-db",
        "-dD /other-db",
        "-dc/other-db/config.json",
        "-MdD/other-db",
        "-hc /other-db/config.json",
        "--local-config /other-db/config.json",
        "--local-config=/other-db/config.json",
        "-c /other-db/config.json",
        "--verbosity 3\n-D /other-db",
    )

    def test_custom_arg_cannot_move_the_database_for_any_role(self) -> None:
        for role_env in ({}, {"VALIDATOR_ID": None, "PQ_CONSENSUS_KEY_FILE": None}):
            for custom in self.MOVING_ARGS:
                with self.subTest(custom=custom, role=bool(role_env) is False):
                    result = self.role("check", str(self.config), CUSTOM_ARG=custom, **role_env)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("fixed by the entrypoint", result.stderr)

    def test_redirected_bound_database_is_refused(self) -> None:
        # The bound, lite-serving config sits in another database that
        # CUSTOM_ARG would point the engine at; no role variables are set.
        other = self.tmp / "other-db"
        other.mkdir()
        config = json.loads(ENGINE_CONFIG)
        config["liteservers"] = [{"@type": "engine.liteServer", "id": "AAAA", "port": 30003}]
        config["extraconfig"] = {
            "@type": "engine.validator.extraConfig",
            "state_serializer_enabled": True,
            "pq_consensus": {
                "@type": "engine.validator.pqConsensus",
                "validator_id": VALIDATOR_ID_B64,
                "consensus_key_file": str(self.seed),
            },
        }
        (other / "config.json").write_text(json.dumps(config))
        result = self.role(
            "check",
            str(self.config),
            VALIDATOR_ID=None,
            PQ_CONSENSUS_KEY_FILE=None,
            CUSTOM_ARG=f"--db {other} --json-rpc-readonly --json-rpc-address 0.0.0.0:8081",
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("fixed by the entrypoint", result.stderr)

    def test_options_that_keep_the_database_are_allowed(self) -> None:
        for custom in (
            "--verbosity 3",
            "-v 3",
            "--db-event-fifo /tmp/fifo",
            "--threads 4",
            # Attached values of options that take an argument, however they
            # are spelled, never move the database.
            "-C/config/global.json",
            "-l/var/log/consensus.log",
            "-f/opt/config/fift",
            "-vD/x",
            "-dl/var/log/Dc.log",
            "-l -D",
            "-t 4 -d",
        ):
            with self.subTest(custom=custom):
                result = self.role(
                    "check",
                    str(self.config),
                    VALIDATOR_ID=None,
                    PQ_CONSENSUS_KEY_FILE=None,
                    CUSTOM_ARG=custom,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_short_option_is_refused(self) -> None:
        result = self.role(
            "check",
            str(self.config),
            VALIDATOR_ID=None,
            PQ_CONSENSUS_KEY_FILE=None,
            CUSTOM_ARG="-dq",
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("uses -q, which is not a validator-engine option", result.stderr)

    def test_option_table_matches_the_engine(self) -> None:
        # Every option the engine registers -- its long name, its short
        # letter, and whether its callback takes an argument -- must be what
        # the script parses CUSTOM_ARG with. All registrations must be read.
        options = engine_option_table()
        script = ROLE.read_text()

        def listed(variable: str) -> list[str]:
            match = re.search(rf'^{variable}="\n(.*?)\n"$', script, re.M | re.S)
            assert match is not None, variable
            return [line.strip() for line in match.group(1).splitlines()]

        self.assertEqual(
            sorted(listed("LONG_OPTIONS_WITH_ARGUMENT")),
            sorted(name for name, (_, takes) in options.items() if takes),
        )
        self.assertEqual(
            sorted(listed("LONG_OPTIONS_WITHOUT_ARGUMENT")),
            sorted(name for name, (_, takes) in options.items() if not takes),
        )
        short = re.search(r'^SHORT_OPTIONS="([^"]*)"$', script, re.M)
        assert short is not None
        self.assertEqual(
            sorted(short.group(1).split()),
            sorted(f"{letter}={name}" for name, (letter, _) in options.items() if letter),
        )

    def test_engine_option_parsing_is_followed_word_by_word(self) -> None:
        refused = (
            # A long option that takes an argument takes the next word, even
            # one starting with '-', so the option after it is real.
            "--logname -v --db /other",
            "--logname -v --local-config /other.json",
            "--global-config -C -D/other",
            "--session-logs --threads --db=/other",
            "plain --db /other",
            "--logname=x -dD /other",
            # What the engine refuses to start on.
            "--no-such-option",
            "--daemonize=1",
            "--threads",
            "-l",
            "-dq",
        )
        accepted = (
            "--logname -D",
            "--logname --db",
            "--logname=--db=/other",
            "--json-rpc-cors-origin -c",
            "-l -D",
            "-vD/x",
            "-- --db /other",
            "--verbosity 3 -- -D/other",
            "-",
        )
        for custom in refused:
            with self.subTest(custom=custom):
                result = self.role(
                    "check",
                    str(self.config),
                    VALIDATOR_ID=None,
                    PQ_CONSENSUS_KEY_FILE=None,
                    CUSTOM_ARG=custom,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("VALIDATOR_ROLE_REFUSED", result.stderr)
        for custom in accepted:
            with self.subTest(custom=custom):
                result = self.role(
                    "check",
                    str(self.config),
                    VALIDATOR_ID=None,
                    PQ_CONSENSUS_KEY_FILE=None,
                    CUSTOM_ARG=custom,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_json_rpc_address_is_read_as_the_engine_reads_it(self) -> None:
        # Consumed as logname's value: no listener is configured at all.
        result = self.role(
            "check", str(self.config), CUSTOM_ARG="--logname --json-rpc-address 0.0.0.0:1"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        # Its own value may start with '-' and is still checked.
        self.assert_refused("loopback only", CUSTOM_ARG="--json-rpc-address -0.0.0.0:1")
        self.assert_refused("needs a value", CUSTOM_ARG="--json-rpc-address")

    def test_recovery_config_is_inspected_when_config_is_missing(self) -> None:
        # The engine renames config.json.tmp into place when config.json is
        # missing, so the temporary file decides the role in that state.
        self.write_bound_config(
            liteservers=[{"@type": "engine.liteServer", "id": "AAAA", "port": 30003}]
        )
        temporary = self.tmp / "config.json.tmp"
        self.config.rename(temporary)
        cases = (
            (
                {"VALIDATOR_ID": None, "PQ_CONSENSUS_KEY_FILE": None, "LITESERVER": "true"},
                "a validator runs no lite server",
            ),
            ({"VALIDATOR_ID": None, "PQ_CONSENSUS_KEY_FILE": None}, "configures 1 lite server(s)"),
            ({}, "configures 1 lite server(s)"),
        )
        for env, reason in cases:
            with self.subTest(reason=reason, env=env):
                result = self.role("check", str(self.config), **env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(reason, result.stderr)

    def test_unbound_recovery_config_leaves_the_role_off(self) -> None:
        self.config.rename(self.tmp / "config.json.tmp")
        result = self.role(
            "check", str(self.config), VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None, LITESERVER="1"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Validator role disabled", result.stdout)

    def test_unreadable_config_is_refused(self) -> None:
        self.config.write_text("{not json")
        result = self.role("check", str(self.config), VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot parse", result.stderr)

    def test_missing_config_is_refused(self) -> None:
        self.config.unlink()
        result = self.apply()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("initialize the node first", result.stderr)


class BindNodeCallTest(unittest.TestCase):
    """What the script hands bind-node, and how it reads each answer."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="validator-bind-call-"))
        self.tmp.chmod(0o700)
        self.keys = self.tmp / "keys"
        self.keys.mkdir(mode=0o700)
        self.seed = self.keys / "pq-consensus.seed"
        self.seed.write_bytes(SEED)
        self.seed.chmod(0o600)
        self.db = self.tmp / "db"
        self.db.mkdir()
        self.config = self.db / "config.json"
        self.config.write_text(ENGINE_CONFIG)
        self.stub = self.tmp / "bind-node-stub"
        write_executable(self.stub, BIND_NODE_STUB)
        self.call = self.tmp / "call"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def apply(self, config: Path | None = None, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TOS_PQ_CONSENSUS_KEY_TOOL": str(self.stub),
            "STUB_CALL": str(self.call),
            "VALIDATOR_ID": VALIDATOR_ID,
            "PQ_CONSENSUS_KEY_FILE": str(self.seed),
            **extra,
        }
        return subprocess.run(
            ["bash", str(ROLE), "apply", str(config or self.config)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_binding_is_left_to_bind_node_without_replace(self) -> None:
        for given in (VALIDATOR_ID.upper(), "-1:" + VALIDATOR_ID):
            with self.subTest(given=given):
                result = self.apply(VALIDATOR_ID=given)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    self.call.read_text().splitlines(),
                    ["bind-node", str(self.db), str(self.seed), VALIDATOR_ID],
                )
                self.assertEqual(self.config.read_text(), ENGINE_CONFIG, "the script never writes")

    def test_refusal_is_reported_and_stops_the_container(self) -> None:
        result = self.apply(STUB_STATUS="1", STUB_OUTPUT="config.json: already bound elsewhere")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("bind-node refused, nothing was written", result.stderr)
        self.assertIn("already bound elsewhere", result.stderr)

    def test_a_key_tool_without_bind_node_is_refused(self) -> None:
        result = self.apply(
            STUB_STATUS="2", STUB_OUTPUT="usage: tos-pq-consensus-key generate KEYFILE"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no usable bind-node command", result.stderr)

    def with_sync_stub(self, status: int) -> dict[str, str]:
        # A sync that records its arguments and answers with `status`.
        directory = self.tmp / "sync-bin"
        directory.mkdir(exist_ok=True)
        write_executable(
            directory / "sync",
            f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" >"{self.tmp}/sync-call"\nexit {status}\n',
        )
        return {"PATH": f"{directory}:{os.environ.get('PATH', '/usr/bin:/bin')}"}

    def test_unconfirmed_durability_is_flushed_again_and_continues(self) -> None:
        result = self.apply(
            STUB_STATUS="3",
            STUB_OUTPUT="db: the directory could not be flushed",
            **self.with_sync_stub(0),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flushed again and confirmed", result.stdout)
        # The configuration and its directory, each fsynced and checked.
        self.assertEqual(
            (self.tmp / "sync-call").read_text().splitlines(),
            ["--", str(self.config), str(self.db)],
        )

    def test_failed_flush_stops_the_container(self) -> None:
        result = self.apply(
            STUB_STATUS="3",
            STUB_OUTPUT="db: the directory could not be flushed",
            **self.with_sync_stub(1),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not be flushed to disk; the node was not started", result.stderr)

    def test_real_flush_of_the_configuration_succeeds(self) -> None:
        # The image's coreutils sync with file arguments, on a real directory.
        result = self.apply(STUB_STATUS="3", STUB_OUTPUT="db: the directory could not be flushed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("flushed again and confirmed", result.stdout)

    def test_missing_tool_is_refused(self) -> None:
        result = self.apply(TOS_PQ_CONSENSUS_KEY_TOOL=str(self.tmp / "absent"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not installed", result.stderr)
        self.assertFalse(self.call.exists())

    def test_config_must_be_the_database_config(self) -> None:
        other = self.db / "node.json"
        other.write_text(ENGINE_CONFIG)
        result = self.apply(other)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("takes the node's DB_ROOT/config.json", result.stderr)
        self.assertFalse(self.call.exists())

    def test_script_never_writes_config_itself(self) -> None:
        text = ROLE.read_text()
        for writer in ("mktemp", "mv --", '> "$config', '>"$config', "--replace"):
            self.assertNotIn(writer, text)


class EntrypointTest(unittest.TestCase):
    """docker/init.sh with its paths moved into a temporary directory."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="validator-init-"))
        self.tmp.chmod(0o700)
        self.root = self.tmp / "tos-work"
        self.db = self.root / "db"
        self.scripts = self.root / "scripts"
        self.bin = self.tmp / "bin"
        self.log = self.tmp / "log"
        for directory in (self.db, self.scripts, self.bin, self.log):
            directory.mkdir(parents=True)
        self.keys = self.tmp / "keys"
        self.keys.mkdir(mode=0o700)
        self.seed = self.keys / "pq-consensus.seed"
        self.seed.write_bytes(SEED)
        self.seed.chmod(0o600)
        text = INIT.read_text()
        self.assertIn("/var/tos-work/", text)
        self.init = self.scripts / "init.sh"
        write_executable(self.init, text.replace("/var/tos-work", str(self.root)))
        shutil.copy(ROLE, self.scripts / "validator-role.sh")
        shutil.copy(REPO / "docker" / "control.template", self.scripts / "control.template")
        write_executable(self.scripts / "import-snapshot.sh", "#!/bin/sh\nexit 0\n")
        write_executable(self.bin / "validator-engine", ENGINE_STUB)
        write_executable(self.bin / "generate-random-id", GENERATE_ID_STUB)
        write_executable(self.bin / "wget", WGET_STUB)
        engine_config = self.tmp / "engine-config.json"
        engine_config.write_text(ENGINE_CONFIG)
        self.engine_config = engine_config

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_init(self, **extra: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "PUBLIC_IP": "203.0.113.10",
            "STUB_LOG": str(self.log),
            "STUB_ENGINE_CONFIG": str(self.engine_config),
            **TOOL_ENV,
            **extra,
        }
        return subprocess.run(
            ["bash", str(self.init)],
            cwd=self.db,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def validator_env(self, **extra: str) -> dict[str, str]:
        return {"VALIDATOR_ID": VALIDATOR_ID, "PQ_CONSENSUS_KEY_FILE": str(self.seed), **extra}

    def engine_calls(self) -> list[str]:
        calls = self.log / "engine-calls"
        return calls.read_text().splitlines() if calls.exists() else []

    @requires_bind_node
    def test_validator_role_is_configured_before_the_engine_starts(self) -> None:
        result = self.run_init(**self.validator_env())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((self.db / "config.json").read_text())
        self.assertEqual(config["extraconfig"]["pq_consensus"]["validator_id"], VALIDATOR_ID_B64)
        self.assertEqual(
            config["extraconfig"]["pq_consensus"]["consensus_key_file"], str(self.seed)
        )
        self.assertIs(config["extraconfig"]["state_serializer_enabled"], True)
        # The console control interface the entrypoint adds survives the edit.
        self.assertEqual(len(config["control"]), 1)
        self.assertEqual(config["liteservers"], [])
        self.assertEqual(len(self.engine_calls()), 2, "initialize, then start")
        self.assertTrue((self.log / "engine-started").exists())

    @requires_bind_node
    def test_restart_keeps_the_binding(self) -> None:
        self.assertEqual(self.run_init(**self.validator_env()).returncode, 0)
        before = (self.db / "config.json").read_bytes()
        result = self.run_init(**self.validator_env())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.db / "config.json").read_bytes(), before)

    def test_full_node_gets_no_binding(self) -> None:
        result = self.run_init(LITESERVER="true")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads((self.db / "config.json").read_text())
        self.assertNotIn("extraconfig", config)
        self.assertEqual(len(config["liteservers"]), 1)

    def test_lite_server_validator_stops_before_anything_is_created(self) -> None:
        result = self.run_init(**self.validator_env(LITESERVER="true"))
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("a validator runs no lite server", result.stderr)
        self.assertEqual(self.engine_calls(), [])
        self.assertEqual(list(self.db.iterdir()), [])

    def test_lite_server_node_restarted_as_validator_is_refused(self) -> None:
        self.assertEqual(self.run_init(LITESERVER="true").returncode, 0)
        result = self.run_init(**self.validator_env())
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("configures 1 lite server(s)", result.stderr)
        self.assertEqual(len(self.engine_calls()), 2, "only the first, full-node run started it")

    def bind_fixture(self) -> None:
        # A full-node first start, then the block bind-node would have added.
        self.assertEqual(self.run_init().returncode, 0)
        path = self.db / "config.json"
        config = json.loads(path.read_text())
        config["extraconfig"] = {
            "@type": "engine.validator.extraConfig",
            "state_serializer_enabled": True,
            "pq_consensus": {
                "@type": "engine.validator.pqConsensus",
                "validator_id": VALIDATOR_ID_B64,
                "consensus_key_file": str(self.seed),
            },
        }
        path.write_text(json.dumps(config))

    def test_bound_node_restarted_with_a_lite_server_is_refused(self) -> None:
        self.bind_fixture()
        result = self.run_init(LITESERVER="true")
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("a validator runs no lite server", result.stderr)
        self.assertEqual(len(self.engine_calls()), 2, "only the first, validator run started it")

    def test_custom_arg_moving_the_database_stops_before_the_engine(self) -> None:
        result = self.run_init(
            CUSTOM_ARG="--db /other-db --json-rpc-readonly --json-rpc-address 0.0.0.0:8081"
        )
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("fixed by the entrypoint", result.stderr)
        self.assertEqual(self.engine_calls(), [])

    def test_bound_recovery_config_stops_a_lite_server_start(self) -> None:
        self.bind_fixture()
        (self.db / "config.json").rename(self.db / "config.json.tmp")
        calls = len(self.engine_calls())
        result = self.run_init(LITESERVER="true")
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("a validator runs no lite server", result.stderr)
        self.assertEqual(len(self.engine_calls()), calls, "the engine was not run again")

    def test_numeric_settings_cannot_add_engine_words(self) -> None:
        # Only CUSTOM_ARG is split into several engine words; the numbers
        # init.sh passes must stay one word each.
        for name in ("VERBOSITY", "THREADS", "STATE_TTL", "ARCHIVE_TTL"):
            with self.subTest(name=name):
                result = self.run_init(**{name: "3 --db /other-db"})
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
                self.assertIn(f"{name} must be a decimal number", result.stdout)
                self.assertEqual(self.engine_calls(), [])

    def test_bad_key_stops_before_anything_is_created(self) -> None:
        self.seed.chmod(0o644)
        result = self.run_init(**self.validator_env())
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("no group or other permissions", result.stderr)
        self.assertEqual(self.engine_calls(), [])

    def test_image_installs_the_role_script(self) -> None:
        dockerfile = DOCKERFILE.read_text()
        self.assertRegex(
            dockerfile, r"COPY [^\n]*\./docker/validator-role\.sh[^\n]* /var/tos-work/scripts/"
        )
        self.assertRegex(dockerfile, r"chmod \+x [^\n]*/var/tos-work/scripts/validator-role\.sh")


def engine_option_table() -> dict[str, tuple[str, bool]]:
    """long name -> (short letter or "", takes an argument), from the source."""
    source = ENGINE_SOURCE.read_text()
    calls = re.findall(r"\bp\.add_(?:checked_)?option\(", source)
    registrations = re.findall(
        r"\bp\.add_(?:checked_)?option\(\s*('(?:\\0|.)'|0),\s*\"([^\"]+)\",(.*?)\[[^\]]*\]\s*\(([^)]*)\)",
        source,
        re.S,
    )
    assert len(calls) > 50 and len(registrations) == len(calls), (len(calls), len(registrations))
    table: dict[str, tuple[str, bool]] = {}
    for short, name, _, params in registrations:
        letter = "" if short in ("'\\0'", "0") else short[1]
        assert name not in table, name
        table[name] = (letter, bool(params.strip()))
    return table


FIXED_PORT, OTHER_PORT = 41001, 41002


def local_config(port: int) -> str:
    """A minimal local config the engine builds a database config.json from."""
    return json.dumps(
        {
            "@type": "config.local",
            "local_ids": [],
            "dht": [],
            "validators": [],
            "liteservers": [{"@type": "liteserver.config.random.local", "port": port}],
            "control": [],
        }
    )


def free_local_port() -> int:
    # A port well away from every range a local validator network uses.
    for port in range(47000, 48000):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free local port in 47000-47999")


def find_built(relative: str, variable: str) -> Path | None:
    configured = os.environ.get(variable)
    candidates = [Path(configured)] if configured else []
    candidates.append(REPO / "build" / relative)
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


class RealEngineTest(unittest.TestCase):
    """The built engine reads back the binding the role wrote."""

    def test_option_table_matches_the_built_engine_help(self) -> None:
        engine = find_built("validator-engine/validator-engine", "TOS_VALIDATOR_ENGINE")
        if engine is None:
            self.skipTest("no built validator-engine; set TOS_VALIDATOR_ENGINE to run this test")
        shown = subprocess.run([str(engine), "-h"], capture_output=True, text=True, timeout=60)
        rows = re.findall(r"^  (?:-(.), )?--([a-z0-9-]+)(<arg>)?", shown.stdout, re.M)
        self.assertGreater(len(rows), 20, shown.stdout[-2000:])
        table = engine_option_table()
        for letter, name, takes in rows:
            with self.subTest(option=name):
                self.assertEqual(table.get(name), (letter, bool(takes)))

    def test_helper_agrees_with_the_engine_on_a_corpus(self) -> None:
        # For each command-line tail, the real engine shows which database it
        # opens (it creates the directory before anything else) and which
        # local config it builds that database's config.json from (the two
        # local configs differ only in a lite server port). The helper must
        # refuse exactly the tails that change either. A tail the engine
        # refuses before choosing a database never runs; either verdict is
        # safe there.
        engine = find_built("validator-engine/validator-engine", "TOS_VALIDATOR_ENGINE")
        if engine is None:
            self.skipTest("no built validator-engine; set TOS_VALIDATOR_ENGINE to run this test")
        with tempfile.TemporaryDirectory(prefix="validator-engine-corpus-") as scratch:
            root = Path(scratch)
            global_config = json.loads(ENGINE_GLOBAL_CONFIG.read_text())
            global_config["dht"]["static_nodes"]["nodes"] = []
            global_config.pop("liteservers", None)
            global_path = root / "global.json"
            global_path.write_text(json.dumps(global_config))
            other_db, other_local = root / "other", root / "other.json"
            fixed_db, fixed_local = root / "fixed", root / "fixed.json"
            tokens = [
                "--logname",
                "-v",
                "--db",
                str(other_db),
                "--local-config",
                str(other_local),
                "-D" + str(other_db),
                "-dD" + str(other_db),
                "-dc" + str(other_local),
                "-c",
                "-D",
                "-l",
                "--",
                "plain",
                "--threads",
                "4",
                "--verbosity=3",
                "--db=" + str(other_db),
                "--daemonize",
                "--daemonize=1",
                "-M",
                "-Mv",
                "3",
                "--session-logs",
                "--json-rpc-readonly",
                "-vD",
                "-x",
                "--no-such",
                "--local-config=" + str(other_local),
                "-dl",
                "-",
            ]
            generator = random.Random(20261006)
            corpus = [
                ["--logname", "-v", "--db", str(other_db)],
                ["--logname", "-v", "--local-config", str(other_local)],
                ["--global-config", "-C", "-D" + str(other_db)],
                [],
            ]
            corpus += [
                [generator.choice(tokens) for _ in range(generator.randint(1, 5))]
                for _ in range(120)
            ]
            work = root / "work"
            undecided = 0
            verdicts: set[bool] = set()
            for words in corpus:
                with self.subTest(words=" ".join(words)):
                    for path in (fixed_db, other_db, work):
                        shutil.rmtree(path, ignore_errors=True)
                    work.mkdir()
                    for path, port in ((fixed_local, FIXED_PORT), (other_local, OTHER_PORT)):
                        path.write_text(local_config(port))
                    subprocess.run(
                        [
                            str(engine),
                            "-c",
                            str(fixed_local),
                            "-C",
                            str(global_path),
                            "--db",
                            str(fixed_db),
                            *words,
                        ],
                        cwd=work,
                        capture_output=True,
                        timeout=60,
                        check=False,
                    )
                    if not fixed_db.is_dir() and not other_db.is_dir():
                        undecided += 1
                        continue
                    chosen = other_db if other_db.is_dir() else fixed_db
                    created = chosen / "config.json"
                    # A local config other than the fixed one: the other port,
                    # or none built at all (a file the engine could not use).
                    engine_moved = (
                        chosen == other_db
                        or not created.is_file()
                        or json.loads(created.read_text())["liteservers"][0]["port"] != FIXED_PORT
                    )
                    verdicts.add(engine_moved)
                    helper = subprocess.run(
                        ["bash", str(ROLE), "check", str(root / "config.json")],
                        env={
                            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                            # One word per argument, exactly as the engine got them.
                            "CUSTOM_ARG": " ".join(words),
                        },
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    self.assertEqual(helper.returncode != 0, engine_moved, helper.stderr)
                    for path in root.iterdir():
                        if path not in (global_path, work):
                            shutil.rmtree(path) if path.is_dir() else path.unlink()
            # The corpus must exercise both answers, mostly on decided runs.
            self.assertEqual(verdicts, {True, False})
            self.assertLess(undecided, len(corpus) // 2)

    @requires_bind_node
    def test_engine_loads_the_bound_validator_and_key(self) -> None:
        engine = find_built("validator-engine/validator-engine", "TOS_VALIDATOR_ENGINE")
        key_tool = find_built("crypto/pq/tos-pq-consensus-key", "TOS_PQ_CONSENSUS_KEY")
        if engine is None or key_tool is None:
            self.skipTest(
                "no built validator-engine and tos-pq-consensus-key; set TOS_VALIDATOR_ENGINE "
                "and TOS_PQ_CONSENSUS_KEY to run this test"
            )
        with tempfile.TemporaryDirectory(prefix="validator-engine-role-") as scratch:
            root = Path(scratch)
            root.chmod(0o700)
            db, keys = root / "db", root / "keys"
            keys.mkdir(mode=0o700)
            # The test network's zero state with no DHT nodes and no lite
            # servers, so the engine contacts nobody.
            global_config = json.loads(ENGINE_GLOBAL_CONFIG.read_text())
            global_config["dht"]["static_nodes"]["nodes"] = []
            global_config.pop("liteservers", None)
            global_path = root / "global.json"
            global_path.write_text(json.dumps(global_config))
            address = f"127.0.0.1:{free_local_port()}"
            init = subprocess.run(
                [str(engine), "-C", str(global_path), "--db", str(db), "--ip", address],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(init.returncode, 0, init.stderr[-2000:])
            seed = keys / "pq-consensus.seed"
            generated = subprocess.run(
                [str(key_tool), "generate", str(seed)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            key_id_hex = next(
                line.split()[1]
                for line in generated.stdout.splitlines()
                if line.startswith("key_id")
            )
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                **TOOL_ENV,
                "VALIDATOR_ID": VALIDATOR_ID,
                "PQ_CONSENSUS_KEY_FILE": str(seed),
            }
            applied = subprocess.run(
                ["bash", str(ROLE), "apply", str(db / "config.json")],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            log = root / "engine.log"
            with log.open("wb") as sink:
                process = subprocess.Popen(
                    [str(engine), "-C", str(global_path), "--db", str(db), "--ip", address],
                    stdout=sink,
                    stderr=subprocess.STDOUT,
                )
                try:
                    deadline = time.monotonic() + 60
                    line = ""
                    while time.monotonic() < deadline and process.poll() is None:
                        text = log.read_bytes().decode(errors="replace")
                        found = [
                            entry
                            for entry in text.splitlines()
                            if "post-quantum consensus custody: validator" in entry
                        ]
                        if found:
                            line = found[0]
                            break
                        time.sleep(0.2)
                finally:
                    process.kill()
                    process.wait(timeout=30)
            self.assertTrue(line, log.read_bytes().decode(errors="replace")[-3000:])
            # The engine names both in lower-case hex, the way the key tool prints
            # the key id, so the two can be compared as text.
            self.assertIn(f"validator_id {VALIDATOR_ID} ", line)
            self.assertRegex(key_id_hex, r"^[0-9a-f]{64}$")
            self.assertRegex(line, rf"\bkey_id {key_id_hex}(?![0-9a-f])")


if __name__ == "__main__":
    unittest.main()

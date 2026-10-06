#!/usr/bin/env python3
"""Offline tests for the container's opt-in validator role (docker/validator-role.sh).

The role writes extraconfig.pq_consensus into the node's config.json. Each
refusal test checks the specific reason and that config.json was left alone.
The entrypoint itself (docker/init.sh) is run against a temporary directory
with stand-ins for the node binaries. When a built validator-engine is
available, one test also has the real engine read the binding back.
"""

from __future__ import annotations

import base64
import json
import os
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
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
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

    def test_binding_is_written_in_the_engine_format(self) -> None:
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_seed_not_printed(result)
        self.assertEqual(
            self.binding(),
            {
                "@type": "engine.validator.extraConfig",
                "state_serializer_enabled": True,
                "pq_consensus": {
                    "@type": "engine.validator.pqConsensus",
                    "validator_id": VALIDATOR_ID_B64,
                    "consensus_key_file": str(self.seed),
                },
            },
        )
        written = json.loads(self.config.read_text())
        original = json.loads(ENGINE_CONFIG)
        written.pop("extraconfig")
        self.assertEqual(written, original, "every other field is kept")
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o644)

    def test_upper_case_id_is_the_same_validator(self) -> None:
        result = self.apply(VALIDATOR_ID=VALIDATOR_ID.upper())
        self.assertEqual(result.returncode, 0, result.stderr)
        pq = self.binding()["pq_consensus"]
        assert isinstance(pq, dict)
        self.assertEqual(pq["validator_id"], VALIDATOR_ID_B64)

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

    def test_second_apply_with_the_same_binding_changes_nothing(self) -> None:
        self.assertEqual(self.apply().returncode, 0)
        before = self.config.read_bytes()
        result = self.apply()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already present", result.stdout)
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
        self.assertEqual(self.apply().returncode, 0)
        result = self.role("check", str(self.config), VALIDATOR_ID=None, PQ_CONSENSUS_KEY_FILE=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("already binds a validator", result.stdout)

    # ---- refusals

    def test_a_different_existing_binding_is_not_rewritten(self) -> None:
        self.assertEqual(self.apply().returncode, 0)
        self.assert_refused("is not rewritten from the environment", VALIDATOR_ID="ab" * 32)

    def test_id_without_key_file_is_refused(self) -> None:
        self.assert_refused("PQ_CONSENSUS_KEY_FILE is not set", PQ_CONSENSUS_KEY_FILE=None)

    def test_key_file_without_id_is_refused(self) -> None:
        self.assert_refused("PQ_CONSENSUS_KEY_FILE is set without VALIDATOR_ID", VALIDATOR_ID=None)

    def test_malformed_ids_are_refused(self) -> None:
        for value in (
            VALIDATOR_ID[:-1],
            VALIDATOR_ID + "0",
            "g" + VALIDATOR_ID[1:],
            "-1:" + VALIDATOR_ID,
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
            "--json-rpc-address",
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

    def test_short_option_table_matches_the_engine(self) -> None:
        # Every short option the engine registers, split by whether its
        # callback takes an argument, must be what the script walks with.
        source = ENGINE_SOURCE.read_text()
        registrations = re.findall(
            r"add_(?:checked_)?option\(\s*'(\\0|.)',\s*\"([^\"]+)\"(.*?)\[&\]\(([^)]*)\)",
            source,
            re.S,
        )
        letters = [(letter, bool(params.strip())) for letter, _, _, params in registrations]
        short = [(letter, takes) for letter, takes in letters if letter != "\\0"]
        self.assertGreater(len(short), 15, "the engine's option registrations were not found")
        self.assertEqual(len({letter for letter, _ in short}), len(short))
        script = ROLE.read_text()
        with_argument = re.search(r'^SHORT_OPTIONS_WITH_ARGUMENT="([^"]*)"$', script, re.M)
        without_argument = re.search(r'^SHORT_OPTIONS_WITHOUT_ARGUMENT="([^"]*)"$', script, re.M)
        assert with_argument is not None and without_argument is not None
        self.assertEqual(
            sorted(with_argument.group(1)), sorted(letter for letter, takes in short if takes)
        )
        self.assertEqual(
            sorted(without_argument.group(1)),
            sorted(letter for letter, takes in short if not takes),
        )

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

    def test_bound_node_restarted_with_a_lite_server_is_refused(self) -> None:
        self.assertEqual(self.run_init(**self.validator_env()).returncode, 0)
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
        self.assertEqual(self.run_init(**self.validator_env()).returncode, 0)
        (self.db / "config.json").rename(self.db / "config.json.tmp")
        calls = len(self.engine_calls())
        result = self.run_init(LITESERVER="true")
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("a validator runs no lite server", result.stderr)
        self.assertEqual(len(self.engine_calls()), calls, "the engine was not run again")

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

    def test_helper_refuses_exactly_the_bundles_that_move_the_database(self) -> None:
        # The engine creates its database directory before it reads the
        # global config, so a missing global config shows which database a
        # command line selects without starting anything.
        engine = find_built("validator-engine/validator-engine", "TOS_VALIDATOR_ENGINE")
        if engine is None:
            self.skipTest("no built validator-engine; set TOS_VALIDATOR_ENGINE to run this test")
        with tempfile.TemporaryDirectory(prefix="validator-engine-bundle-") as scratch:
            root = Path(scratch)
            for word in (
                "-dD{}/moved",
                "-MdD{}/moved",
                "-vD{}/moved",
                "-C{}/Dc.json",
                "-l{}/c.log",
                "-f{}/fiftD",
                "-d",
            ):
                spelled = word.format(root)
                with self.subTest(word=word):
                    for entry in root.iterdir():
                        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
                    subprocess.run(
                        [
                            str(engine),
                            "--db",
                            str(root / "fixed"),
                            "-C",
                            str(root / "missing-global.json"),
                            spelled,
                        ],
                        capture_output=True,
                        timeout=60,
                        check=False,
                    )
                    moved = (root / "moved").is_dir()
                    self.assertTrue(
                        moved or (root / "fixed").is_dir(), "the engine chose no database"
                    )
                    helper = subprocess.run(
                        ["bash", str(ROLE), "check", str(root / "config.json")],
                        env={
                            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                            "CUSTOM_ARG": spelled,
                        },
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    self.assertEqual(helper.returncode != 0, moved, helper.stderr)

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
            self.assertIn(f"validator {VALIDATOR_ID.upper()} ", line)
            key_id_b64 = base64.b64encode(bytes.fromhex(key_id_hex)).decode()
            self.assertIn(f"key {key_id_b64}", line)


if __name__ == "__main__":
    unittest.main()

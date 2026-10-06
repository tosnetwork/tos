"""The operator tools build exactly what the election fixture builds.

A production operator deploys a controller with `tos-pq-controller init-data` and
`state-init`, and points the node at its key with `tos-pq-consensus-key bind-node`. The
fixture the PQ election rehearsals run does the same three things in Python. Each test
here builds both from the same keys and requires the same bytes, so neither side can
drift without the other noticing.
"""

import base64
import fcntl
import json
import os
import subprocess
from pathlib import Path

from pytosiq_core import Cell
from tosapi import tos_api
from tostester.install import Install
from tostester.pq_election_fixture import compile_controller_code, make_controller_fixture

ROOT = Path(__file__).resolve().parents[4]
INSTALL = Install(ROOT / "build", ROOT)
CONTROLLER_TOOL = INSTALL.build_dir / "crypto/tos-pq-controller"


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)
    assert result.returncode == 0, f"{args[:2]} failed: {result.stderr}"
    return result


def _stderr_field(result: subprocess.CompletedProcess, name: str) -> str:
    for line in result.stderr.splitlines():
        key, _, value = line.partition(" ")
        if key == name:
            return value
    raise AssertionError(f"{name} missing from {result.stderr!r}")


def test_controller_init_data_and_state_init_are_the_fixtures(tmp_path):
    code = compile_controller_code(INSTALL, tmp_path / "code")
    fixture = make_controller_fixture(INSTALL, tmp_path / "keys", code, 3)
    fixture_data = fixture.state_init.data
    consensus_id = fixture.consensus.key_id.hex()

    # The fixture's root seed file, as the operator holds it offline.
    from_seed = _run(
        [str(CONTROLLER_TOOL), "init-data", str(tmp_path / "keys/root-3.seed"), consensus_id]
    )
    data = Cell.one_from_boc(base64.b64decode(from_seed.stdout.strip()))
    assert data.hash == fixture_data.hash
    assert base64.b64decode(from_seed.stdout.strip()) == fixture_data.to_boc()
    assert _stderr_field(from_seed, "consensus_key_id") == consensus_id

    # The public key alone, as `tos-pq-key public` prints it, builds the same data.
    public = _run(
        [str(INSTALL.pq_consensus_key_exe), "show", str(tmp_path / "keys/root-3.seed")]
    ).stdout
    root_public_hex = next(
        line.split()[1] for line in public.splitlines() if line.startswith("public")
    )
    from_public = _run([str(CONTROLLER_TOOL), "init-data", root_public_hex, consensus_id])
    assert from_public.stdout == from_seed.stdout

    # The state init a wallet sends lands at the fixture's controller address, and the
    # birth witness for it is the fixture's witness.
    code_b64 = base64.b64encode(code.to_boc()).decode()
    data_b64 = from_seed.stdout.strip()
    state = _run([str(CONTROLLER_TOOL), "state-init", code_b64, data_b64])
    state_cell = Cell.one_from_boc(base64.b64decode(state.stdout.strip()))
    assert state_cell.hash == fixture.state_init.serialize().hash
    assert _stderr_field(state, "address") == "-1:" + fixture.address.hash_part.hex()
    assert _stderr_field(state, "code_hash") == code.hash.hex()
    witness = _run([str(CONTROLLER_TOOL), "witness", code_b64, data_b64])
    assert Cell.one_from_boc(base64.b64decode(witness.stdout.strip())).hash == (
        fixture.birth_witness.hash
    )


def test_documented_code_recipe_is_the_compiled_controller(tmp_path):
    """The recipe in `tos-pq-controller` usage builds the code the fixture compiles."""
    source = INSTALL.source_dir / "crypto/smartcont"
    boc = tmp_path / "controller.boc"
    fif = tmp_path / "controller.fif"
    _run(
        [
            str(INSTALL.build_dir / "crypto/func"),
            "-W",
            str(boc),
            "-AP",
            "-o",
            str(fif),
            str(source / "stdlib.fc"),
            str(source / "validator-controller-v1.fc"),
        ],
        cwd=INSTALL.source_dir,
    )
    _run(
        [str(INSTALL.build_dir / "crypto/fift"), str(fif)],
        cwd=INSTALL.source_dir,
        env={**os.environ, "FIFTPATH": str(INSTALL.source_dir / "crypto/fift/lib")},
    )
    compiled = compile_controller_code(INSTALL, tmp_path / "fixture")
    assert Cell.one_from_boc(boc.read_bytes()).hash == compiled.hash


def test_bind_node_writes_what_the_test_harness_writes(tmp_path):
    db = tmp_path / "db"
    db.mkdir(mode=0o700)
    db.chmod(0o700)
    key_file = (db / "pq-consensus.seed").resolve()
    _run(
        [str(INSTALL.pq_consensus_key_exe), "import", str(key_file)],
        input=("3c" * 32) + "\n",
    )
    validator_id = bytes(range(1, 33))

    # The configuration as the harness holds it before binding, and as it holds it after
    # `_provision_pq_validator` has set the extra configuration.
    before = tos_api.Engine_validator_config()
    config = db / "config.json"
    config.write_text(before.to_json())
    config.chmod(0o600)
    after = tos_api.Engine_validator_config.from_json(before.to_json())
    after.extraconfig = tos_api.Engine_validator_extraConfig(
        state_serializer_enabled=True,
        pq_consensus=tos_api.Engine_validator_pqConsensus(
            validator_id=validator_id,
            consensus_key_file=str(key_file),
        ),
    )

    _run(
        [
            str(INSTALL.pq_consensus_key_exe),
            "bind-node",
            str(db),
            str(key_file),
            validator_id.hex(),
        ]
    )
    assert json.loads(config.read_text()) == json.loads(after.to_json())
    held = tos_api.Engine_validator_config.from_json(config.read_text())
    assert held.extraconfig is not None and held.extraconfig.pq_consensus is not None
    assert held.extraconfig.pq_consensus.validator_id == validator_id
    assert held.extraconfig.pq_consensus.consensus_key_file == str(key_file)


def _start_engine(db: Path) -> subprocess.CompletedProcess:
    # No global configuration exists, so an engine that gets past the lock stops at once
    # on that, before it opens a database or a socket.
    return subprocess.run(
        [
            str(INSTALL.validator_engine_exe),
            "-D",
            str(db),
            "-C",
            str(db.parent / "absent-global-config.json"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_engine_will_not_start_while_the_configuration_lock_is_held(tmp_path):
    """The engine and bind-node exclude each other through the same lock."""
    db = tmp_path / "db"
    db.mkdir(mode=0o700)

    # Unheld, the engine passes the lock and stops on the missing global configuration;
    # that is what shows the held case below is refused by the lock and nothing else.
    free = _start_engine(db)
    assert free.returncode == 2
    assert "failed to load global config" in free.stdout + free.stderr
    assert "configuration lock" not in free.stdout + free.stderr

    with open(db / "config.json.lock", "ab") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held = _start_engine(db)
    assert held.returncode == 2
    assert "configuration lock" in held.stdout + held.stderr
    assert "failed to load global config" not in held.stdout + held.stderr

    # And a binder meeting an engine's lock refuses, naming it.
    key_file = (db / "pq-consensus.seed").resolve()
    _run([str(INSTALL.pq_consensus_key_exe), "import", str(key_file)], input=("3d" * 32) + "\n")
    (db / "config.json").write_text(tos_api.Engine_validator_config().to_json())
    with open(db / "config.json.lock", "ab") as lock:
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        refused = subprocess.run(
            [
                str(INSTALL.pq_consensus_key_exe),
                "bind-node",
                str(db),
                str(key_file),
                "5a" * 32,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert refused.returncode == 1
    assert "held by a running node or another bind-node" in refused.stderr

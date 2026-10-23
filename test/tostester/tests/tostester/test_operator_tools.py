"""The operator tools write exactly what the election harnesses write.

A production operator points the node at its consensus key and at the account that
stakes for it with `tos-pq-consensus-key bind-node`. The PQ election rehearsals do
the same in Python. Each test here does both from the same inputs and requires the
same bytes, so neither side can drift without the other noticing.
"""

import fcntl
import json
import subprocess
from pathlib import Path

from tosapi import tos_api
from tostester.install import Install

ROOT = Path(__file__).resolve().parents[4]
INSTALL = Install(ROOT / "build", ROOT)


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, check=False, **kwargs)
    assert result.returncode == 0, f"{args[:2]} failed: {result.stderr}"
    return result


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


def _start_engine(db: Path) -> subprocess.CompletedProcess[str]:
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

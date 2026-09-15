from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


# Moving the install after commit leaves live c4 updated on a full run but its
# committed_data stale. The two full-run c4 cases deliberately inspect both, so
# they are measured companions of the checkpoint-ordering mutation as well.
mutations = ROOT / "test/validator-auth-implementation/config_contract_persistence_mutations.py"
replace_once(
    mutations,
    '        ["registry-checkpoint-replaces-before-interruption"],\n',
    '        [\n'
    '            "registry-c4-installs-parameter-46",\n'
    '            "registry-c4-replaces-old-parameter-46",\n'
    '            "registry-checkpoint-replaces-before-interruption",\n'
    '        ],\n',
    "checkpoint-order companion inventory",
)

# The permanent focused workflow must run when any part of the evidence seam
# changes, not just when the FunC source or C++ fixture changes.
workflow = ROOT / ".github/workflows/validator-auth-config-persistence.yml"
replace_once(
    workflow,
    "      - 'test/validator-auth-implementation/config_contract_persistence.py'\n"
    "      - 'crypto/smartcont/config-code.fc'\n",
    "      - 'test/validator-auth-implementation/config_contract_persistence.py'\n"
    "      - 'test/validator-auth-implementation/config_contract_persistence_mutations.py'\n"
    "      - 'test/validator-auth-implementation/config_action_phase_mutations.py'\n"
    "      - 'tosctl/src/executor/src/blockchain_config.rs'\n"
    "      - 'tosctl/src/executor/src/transaction_executor.rs'\n"
    "      - 'tosctl/src/sandbox/src/blockchain.rs'\n"
    "      - 'tosctl/src/node-control/contracts/tests/native_registry_sandbox.rs'\n"
    "      - 'doc/validator-auth-p0-native-insertions.json'\n"
    "      - 'crypto/smartcont/config-code.fc'\n",
    "permanent workflow evidence paths",
)

print("CONFIG_PERSISTENCE_EVIDENCE_FIXUP_OK")

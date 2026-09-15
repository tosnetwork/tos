from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


# The checkpoint-ordering mutation keeps the installation and only moves it
# after the checkpoint, so the parameter still reaches the live register on a
# full run. Only the cases that read the committed data break. Running every
# other case under the mutation reports one companion; the two full-run c4 cases
# pass. A companion list is a measurement, and predicting one here declared two
# cases that were never observed to break.

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

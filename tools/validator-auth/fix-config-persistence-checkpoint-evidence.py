from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, before: str, after: str, label: str) -> None:
    text = path.read_text()
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(before, after, 1))


cpp = ROOT / "test/validator-auth-implementation/config-contract-test.cpp"
old_helper = '''// Find an actual gas interruption after a checkpoint, not a simulated action\n// phase. The checkpoint's c4, not the live register, is what compute can offer\n// to transaction processing on this exit. The checkpoint must already contain\n// both the new registry and its consumed external-message sequence number.\nOutcome interrupted_registry_run(const td::Ref<vm::Cell>& contract, const RegistryCells& cells, bool previous) {\n  auto full_host = registry_host(cells);\n  auto full = registry_run(contract, cells, full_host, previous);\n  expect(full.exit == 0 && full.committed && full_host.applies == 1, "interrupt-control-runs-contract");\n  expect(full.gas > 1 && full.gas < 1000000, "interrupt-search-bound");\n  long long low = 1, high = full.gas;\n  while (low < high) {\n    const auto middle = low + (high - low) / 2;\n    auto host = registry_host(cells);\n    const auto attempt = registry_run(contract, cells, host, previous, middle);\n    if (attempt.committed)\n      high = middle;\n    else\n      low = middle + 1;\n  }\n  auto host = registry_host(cells);\n  auto interrupted = registry_run(contract, cells, host, previous, low);\n  std::cout << "MEASURE gas_limit=" << low << " full_gas=" << full.gas << " exit=" << interrupted.exit\n            << " committed=" << interrupted.committed << " applies=" << host.applies\n            << " checkpoint_has_new_registry="\n            << same_cell(installed_parameter(interrupted.committed_data, 46), cells.after) << '\\n' << std::flush;\n  expect(interrupted.exit == -14 && interrupted.committed && host.applies == 1,\n         "interrupt-reaches-postcommit-out-of-gas");\n  return interrupted;\n}\n'''
new_helper = '''// Find the smallest real gas limit that produces a committed checkpoint. After\n// the safe ordering there need not be a gas-consuming instruction after commit,\n// so a successful full run may be the first committed execution. The invariant\n// is about checkpoint contents, not about manufacturing a later exception: once\n// VAUTH_APPLY has succeeded, every committed c4 must already contain both the\n// returned registry and the consumed external-message sequence number.\nOutcome first_committed_registry_run(const td::Ref<vm::Cell>& contract, const RegistryCells& cells, bool previous) {\n  auto full_host = registry_host(cells);\n  auto full = registry_run(contract, cells, full_host, previous);\n  expect(full.exit == 0 && full.committed && full_host.applies == 1, "checkpoint-control-runs-contract");\n  expect(full.gas > 1 && full.gas < 1000000, "checkpoint-search-bound");\n  long long low = 1, high = full.gas;\n  while (low < high) {\n    const auto middle = low + (high - low) / 2;\n    auto host = registry_host(cells);\n    const auto attempt = registry_run(contract, cells, host, previous, middle);\n    if (attempt.committed)\n      high = middle;\n    else\n      low = middle + 1;\n  }\n  auto host = registry_host(cells);\n  auto first = registry_run(contract, cells, host, previous, low);\n  std::cout << "MEASURE first_committed_gas=" << low << " full_gas=" << full.gas << " exit=" << first.exit\n            << " committed=" << first.committed << " applies=" << host.applies\n            << " checkpoint_has_new_registry="\n            << same_cell(installed_parameter(first.committed_data, 46), cells.after) << '\\n' << std::flush;\n  expect(first.committed && host.applies == 1 && (first.exit == 0 || first.exit == -14),\n         "first-committed-checkpoint-reached");\n  return first;\n}\n'''
replace_once(cpp, old_helper, new_helper, "first committed checkpoint helper")
replace_once(
    cpp,
    '''      {"registry-checkpoint-installs-before-interruption", [=] {\n         auto cells = registry_cells();\n         const auto run = interrupted_registry_run(contract, cells, false);\n         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&\n                    stored_sequence(run.committed_data) == 1, "registry-checkpoint-installs-before-interruption");\n       }},\n      {"registry-checkpoint-replaces-before-interruption", [=] {\n         auto cells = registry_cells();\n         const auto run = interrupted_registry_run(contract, cells, true);\n         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&\n                    stored_sequence(run.committed_data) == 1, "registry-checkpoint-replaces-before-interruption");\n       }},\n''',
    '''      {"registry-first-checkpoint-installs-new-parameter", [=] {\n         auto cells = registry_cells();\n         const auto run = first_committed_registry_run(contract, cells, false);\n         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&\n                    stored_sequence(run.committed_data) == 1, "registry-first-checkpoint-installs-new-parameter");\n       }},\n      {"registry-first-checkpoint-replaces-old-parameter", [=] {\n         auto cells = registry_cells();\n         const auto run = first_committed_registry_run(contract, cells, true);\n         expect(same_cell(installed_parameter(run.committed_data, 46), cells.after) &&\n                    stored_sequence(run.committed_data) == 1, "registry-first-checkpoint-replaces-old-parameter");\n       }},\n''',
    "first committed checkpoint cases",
)

mutations = ROOT / "test/validator-auth-implementation/config_contract_persistence_mutations.py"
text = mutations.read_text()
for old, new in (
    ("registry-checkpoint-installs-before-interruption", "registry-first-checkpoint-installs-new-parameter"),
    ("registry-checkpoint-replaces-before-interruption", "registry-first-checkpoint-replaces-old-parameter"),
):
    if old not in text:
        raise RuntimeError(f"mutation case name missing: {old}")
    text = text.replace(old, new)
mutations.write_text(text)

print("CONFIG_PERSISTENCE_CHECKPOINT_EVIDENCE_FIXUP_OK")

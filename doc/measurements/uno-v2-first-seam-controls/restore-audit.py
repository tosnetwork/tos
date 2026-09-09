import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[3]
directory = Path(__file__).parent
sha = lambda data: hashlib.sha256(data).hexdigest()
rows = []
expected_names = {
    "combined-entry", "settlement-observer", "input-binding", "usage-tracking-bypass",
    "usage-node-handoff", "state-snapshot-handoff", "effects-budget", "output-budget",
    "early-adapter-release", "terminal-adapter-release", "binding-observation", "missing-state-classification",
}
assert {p.parent.name for p in directory.glob("*/record.json")} == expected_names
mutant_binaries = set()
for path in sorted(directory.glob("*/record.json")):
    record = json.loads(path.read_text())
    test_path = record.get("test_source_path", "crypto/test/test-workchain-settlement-continuation.cpp")
    test = (root / test_path).read_bytes()
    source = (root / record["path"]).read_bytes()
    before, after = record["from"].encode(), record["to"].encode()
    assert source.count(before) == 1, path
    assert source.count(after) == 0, path
    mutant = source.replace(before, after, 1)
    assert sha(source) == record["baseline_sha256"] == record["restored_sha256"], path
    assert sha(mutant) == record["recorded_mutant_sha256"], path
    assert sha(test) == record["test_source_sha256"], path
    assert record["compile_exit"] == record["restore_compile_exit"] == record["restore_run_exit"] == 0, path
    assert record["run_exit"] != 0 and record["expected_failure"], path
    target = record.get("target", "test-workchain-settlement-continuation")
    assert sha((root / "build" / target).read_bytes()) == record["restored_binary_sha256"], path
    mutant_binaries.add(record["mutant_binary_sha256"])
    for log in ("compile.log", "restore-compile.log"):
        assert "Linking CXX executable " + target in (path.parent / log).read_text(), path
    positive = (path.parent / "restore-run.log").read_text()
    if target == "test-tos-collator":
        assert "test-counter-account-binding-readiness" in positive, path
        assert "100% tests passed, 0 tests failed out of 1" in positive, path
    else:
        for scenario in ("once", "tracking"):
            assert scenario + ": actual_engine_calls=1 inspections=1" in positive, path
        for scenario in ("input", "state", "observer"):
            assert scenario + ": exact local refusal; actual_engine_calls=1" in positive, path
        for scenario in ("effects", "output"):
            assert scenario + ": typed budget refusal; actual_engine_calls=1" in positive, path
    output = (path.parent / "run.log").read_text()
    assert record["expected"] in output, path
    if "positive" in record:
        assert record["positive"] in output, path
    if record.get("target") == "test-tos-collator":
        # Classification comes from the terminal typed result, not CTest logs.
        prefix = path.parent / "account_binding_refused.result"
        assert prefix.read_text() == "collate -7201\n", path
        assert Path(str(prefix) + ".kind").read_text() == "error\n", path
        assert Path(str(prefix) + ".message").read_text() == (
            "cannot execute configured workchain: multi-account admission and replay are not connected"), path
        assert (path.parent / "calls.txt").read_text() == "config=2\nexecute=0\n", path
        assert "transactions=0\n" in Path(str(prefix) + ".stats").read_text(), path
    rows.append({"name": record["name"], "source_sha256": sha(source), "test_source_path": test_path,
                 "test_source_sha256": sha(test),
                 "recorded_mutant_sha256": record["recorded_mutant_sha256"],
                 "reconstructed_mutant_sha256": sha(mutant),
                 "restored_sha256": record["restored_sha256"]})
assert len(rows) == 12, len(rows)
assert len(mutant_binaries) == 12
print(json.dumps({"controls": rows}, indent=2))

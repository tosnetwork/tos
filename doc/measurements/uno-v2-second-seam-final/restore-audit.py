#!/usr/bin/env python3
"""Reconstruct both single-point mutants from the final classifier bytes."""
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
repo = here.parents[2]
source = repo / "validator/impl/workchain-collator-compute-mode.h"
test = repo / "crypto/test/test-workchain-collator-compute-mode.cpp"
binary = repo / "build/test-workchain-collator-compute-mode"
sha = lambda data: hashlib.sha256(data).hexdigest()
baseline = {line.split()[1]: line.split()[0] for line in (here / "baseline.sha256").read_text().splitlines()}
original = source.read_bytes()
before = b"        return false;\n"
assert original.count(before) == 1
records = []
for name, after, failure in [
    ("wrong-mode", b"        return true;\n", "batch.not_account_compute"),
    ("old-refusal", b'        return td::Status::Error(static_cast<int>(block::WorkchainExecutionFailure::LocalUnavailable),\n                                 "multi-account admission and replay are not connected");\n',
     "classification.must_not_authorize_or_refuse_execution"),
]:
    recorded = (here / (name + "-source.sha256")).read_text().split()[0]
    mutant_binary = (here / (name + "-binary.sha256")).read_text().split()[0]
    assert sha(original.replace(before, after)) == recorded
    assert (here / (name + ".log")).read_text().strip() == failure
    assert (here / (name + "-restored.log")).read_text() == (here / "baseline.log").read_text()
    assert mutant_binary != baseline["build/test-workchain-collator-compute-mode"]
    records.append(dict(name=name, source=str(source.relative_to(repo)),
                        before=before.decode(), after=after.decode(),
                        recorded_mutant_sha256=recorded,
                        reconstructed_mutant_sha256=sha(original.replace(before, after)),
                        restored_sha256=sha(original), mutant_binary_sha256=mutant_binary,
                        failure_identity=failure))
for path in (source, test, binary):
    assert sha(path.read_bytes()) == baseline[str(path.relative_to(repo))], str(path)
print(json.dumps(dict(base_commit=(here / "base-commit.txt").read_text().strip(),
                     controls=records, test_source_sha256=sha(test.read_bytes()),
                     restored_binary_sha256=sha(binary.read_bytes())), indent=2))

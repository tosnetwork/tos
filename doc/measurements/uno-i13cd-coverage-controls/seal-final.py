import hashlib
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

repo = Path('/home/tomi/tos')
dest = repo / 'doc/measurements/uno-i13cd-coverage-controls/final'
dest.mkdir(parents=True, exist_ok=True)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
report = Path('/tmp/uno-read-final-regression.xml')
tests = list(ET.parse(report).iter('testcase'))
old = json.loads((repo / 'doc/measurements/uno-i13a-scan-controls/final/comparison.json').read_text())
expected = {r['name']: r['failure_reason'] for r in old['rows']}
failed = [t for t in tests if t.find('failure') is not None]
assert len(tests) == 130 and {t.get('name') for t in failed} == set(expected)
assert not any(t.find('skipped') is not None or t.find('error') is not None for t in tests)
rows = []
for t in failed:
    name = t.get('name')
    output = t.findtext('system-out', '')
    paths = set(re.findall(r'/home/tomi/tos/build/counter-integration-[0-9a-f]{12}', output))
    assert len(paths) == 1, (name, output)
    fixture = Path(paths.pop())
    raw = (fixture / 'bootstrap.log').read_text()
    reason = expected[name]
    actual = re.findall(r'invalid instance installation : \[Error : (\d+) : ([^\]\n]+)\]', raw)
    assert actual and {msg for _, msg in actual} == {reason}, (name, actual)
    case = dest / 'cases' / name
    case.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for filename in ['bootstrap.log','bootstrap.result','bootstrap.result.kind','bootstrap.result.message','zerostate.boc']:
        src = fixture / filename
        assert src.is_file(), src
        shutil.copy2(src, case / filename)
        hashes[filename] = sha(src)
    rows.append(dict(name=name, fixture=str(fixture), reason=reason, raw_diagnostics=actual,
        artifact_sha256=hashes,
        disposition='Owner-deferred pending genesis installation and matching identity/fixture migration; not a pass or unrelated waiver.',
        observation_boundary='bootstrap.result is collator result only, not validator terminal classification; log locates cause only.'))
for suffix in ['default-build.log','regression.log','regression.xml','private.log','private.xml','registered.json','ci-observer.log','removed-guard.log']:
    shutil.copy2('/tmp/uno-read-final-' + suffix, dest / suffix)
for suffix in ['before','delete','after']:
    shutil.copy2('/tmp/uno-read-final-cleanup-' + suffix + '.log', dest / ('cleanup-' + suffix + '.log'))
for suffix in ['standalone.cpp','standalone-command.json','standalone.log']:
    shutil.copy2('/tmp/uno-read-phase-' + suffix, dest / suffix)
sources = ['crypto/block/workchain-coverage.h','crypto/block/workchain-read-phase.h',
           'crypto/test/test-workchain-coverage.cpp','crypto/test/workchain-coverage.py',
           'crypto/test/workchain-coverage.cmake','crypto/test/workchain-private-i13.cmake',
           '.github/scripts/check-i13-results.py','.github/scripts/test-i13-results.py',
           '.github/workflows/private-i13-acceptance.yml']
summary = dict(base_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
    actual_entries=len(tests),passed=len(tests)-len(failed),deferred=len(failed),unresolved=0,skipped=0,
    rows=rows, source_sha256={p:sha(repo / p) for p in sources},
    binaries={p:sha(Path(p)) for p in ['/tmp/uno-coverage-build/test-workchain-coverage','/home/tomi/tos/build/test-tos-collator','/home/tomi/tos/build/test-workchain-block']},
    junit_sha256=sha(report),
    cleanup=dict(before=9,after=0,diagnostic_files=194,archive='/home/tomi/tos/build/counter-fixture-diagnostics-1788999835551605425.tar.gz'),
    deferral_scope='Re-derived from this unmerged integration tree and fresh fixtures. Not transferable to a later merge; the other branch has already repaired seven cases.',
    separate_guard=dict(exit_code=1, scope='Five existing Counter fixture tag comments hit the removed-domain path rule. Not part of the 130 ordinary CTests; no exemption added in this unit.'),
    default_build_command=['cmake','--build','/home/tomi/tos/build','-j32'],
    regression_command=['ctest','--test-dir','/home/tomi/tos/build','-j32','--output-on-failure','--output-junit',str(report)],
    private_registered=6,private_executed=['test-workchain-coverage-gates'],
    remaining_seams={'collator':1,'validator':3,'separate_registry_readiness':1})
(dest / 'final-checks.json').write_text(json.dumps(summary,indent=2)+'\n')
print('130 = 121 passed + 9 individually matched deferrals + 0 unresolved + 0 skipped')
for row in rows:
    print(row['name'], ':', row['reason'])

"""Archive retained validator runs, including passing raw sidecars."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile

root = Path(sys.argv[1])
out = Path(__file__).resolve().parent
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

for dirname in ('scripts', 'fixture-identity'):
    (root / dirname).mkdir(exist_ok=True)
for script in ('classifier.py', 'check-separation.py', 'archive.py', 'observe.gdb'):
    shutil.copyfile(out / script, root / 'scripts' / script)
for item in ('global.json', 'counter-state.rhash', 'counter-state.fhash'):
    shutil.copyfile(Path('/tmp/uno-a2-registry-jqOjoDbi/fixture') / item, root / 'fixture-identity' / item)
paths = []
for name in ('earlier-native', 'gate', 'restored-gate', 'missing-delivery-native', 'reject', 'separation',
             'final-earlier', 'final-gate', 'final-accept', 'final-separation', 'scripts', 'fixture-identity',
             'final-delivery-mutant', 'final-restored', 'final-reject', 'reviewed-separation',
             'restored-complete', 'complete-separation', 'final-checks'):
    paths.extend(p for p in (root / name).rglob('*') if p.is_file())
paths.extend(p for p in root.iterdir() if p.is_file() and p.suffix in ('.py', '.json', '.log', '.sha256', '.gdb', '.txt', '.patch', '.calls'))
paths.append(root / 'source/validator/manager-disk.cpp')
paths.append(root / 'fresh-build/CMakeCache.txt')
paths.append(root / 'fresh-build/compile_commands.json')
paths = sorted(set(paths))
hashes = {str(p.relative_to(root)): digest(p) for p in paths}
archive = out / 'raw-run.tar.gz'
with tarfile.open(archive, 'w:gz') as tar:
    for path in paths:
        tar.add(path, arcname=str(path.relative_to(root)), recursive=False)
tools = [root / 'fresh-build/test-tos-collator', root / 'fresh-build/crypto/create-state']
report = {
    'status': 'reviewed validator controlled-import evidence; coordinator acceptance pending',
    'base_tree': '63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8',
    'merge_inputs': ['33af64ee8775e89035c5c364615ff6e3ada853a8', '203354611ba872d84687a1787bfdebf2cab5c730'],
    'observed_tree': 'c2c78fe49f27a378330f2c7512221720240bac84',
    'source_overlay': {'path': 'validator/manager-disk.cpp', 'sha256': digest(root / 'source/validator/manager-disk.cpp')},
    'binary_hashes': {str(p.relative_to(root)): digest(p) for p in tools},
    'raw_archive_sha256': digest(archive), 'files': hashes,
    'boundary': 'controlled --import-candidate disk injection, is_fake=true; not network delivery',
    'build': 'fresh configure and explicit test-tos-collator/create-state builds, -j32; create-state retry with FUNC_BIN/FIFT_BIN',
    'restoration': 'source and both binary SHA256 values match baseline; explicit tool rebuild and restored gate rerun passed',
    'controls': '29 final observation-input controls; compiled delivery control; historical controls remain labelled checkpoints. Native accept/export and engine counter selftest are positive calibrations.',
    'retention': 'fresh independent run directories outside lifecycle cleanup; successful and failed sidecars retained',
}
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('Retained files:', len(paths), 'archive:', report['raw_archive_sha256'])

"""Seal a complete stable round, then independently read back every member."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1]).resolve()
out = Path(__file__).resolve().parent
def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

state = json.loads((root / 'round.json').read_text())
freeze = json.loads((root / 'freeze.json').read_text())
if state['failed'] or state['phase'] != 'complete':
    raise RuntimeError('incomplete or failed round cannot be sealed')
if any(row['returncode'] != row['expected'] for row in state['commands']):
    raise RuntimeError('unexpected command outcome')
for path, expected in freeze['immutable'].items():
    if digest(path) != expected:
        raise RuntimeError('frozen input changed before sealing: ' + path)
for path, expected in freeze['source_links'].items():
    if os.readlink(path) != expected:
        raise RuntimeError('frozen source link changed before sealing: ' + path)
base = root.parent
if digest(base / 'source/validator/manager-disk.cpp') != freeze['native_source'] or digest(base / 'fresh-build/test-tos-collator') != freeze['binary']:
    raise RuntimeError('native restoration changed before sealing')
files = {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*')) if p.is_file()}
archive = out / 'raw-run.tar.gz'
if archive.exists():
    raise RuntimeError('archive already exists; never overwrite a previous round')
with tarfile.open(archive, 'w:gz') as tar:
    for name in files:
        tar.add(root / name, arcname=name, recursive=False)
with tarfile.open(archive, 'r:gz') as tar:
    if set(tar.getnames()) != set(files):
        raise RuntimeError('archive member set differs')
    for member in tar:
        stream = tar.extractfile(member)
        if stream is None:
            raise RuntimeError('archive member is not a regular file')
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
        if h.hexdigest() != files[member.name]:
            raise RuntimeError('archive readback differs: ' + member.name)
report = {'status': 'fixed matrix completed without instrument or criterion changes',
          'frozen_commit': freeze['commit'], 'observed_tree': freeze['tree'],
          'boundary': 'controlled --import-candidate disk run, is_fake=true; not network delivery',
          'steps': freeze['steps'], 'commands': state['commands'],
          'raw_archive_sha256': digest(archive), 'readback_verified': len(files), 'files': files}
(out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print('verified archive members:', len(files), report['raw_archive_sha256'])

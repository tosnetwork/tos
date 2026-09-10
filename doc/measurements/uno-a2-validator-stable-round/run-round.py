"""Run the predeclared matrix without retries or changes to its instruments."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time

REPO = Path('/home/tomi/tos')
BASE = Path('/tmp/uno-validator-observe-fjd2efrp')
DOC = REPO / 'doc/measurements/uno-a2-validator-closed'
TREE = 'c2c78fe49f27a378330f2c7512221720240bac84'
PIN = '06d644d5dc04fb8e70fd30a654ac2f4f0e0a3b75'
NATIVE = BASE / 'source/validator/manager-disk.cpp'
BINARY = BASE / 'fresh-build/test-tos-collator'
TOOL = BASE / 'fresh-build/crypto/create-state'
DELIVERY = b'        td::write_file(prefix + ".delivery", "recorded\\n").ensure();\n'
phase, directory = sys.argv[1:]
root = Path(directory).resolve()
if root.parent != BASE:
    raise ValueError('round directory must be a fresh direct child of the isolated workspace')

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def save(name, value):
    (root / name).write_text(json.dumps(value, indent=2) + '\n')

state = {'phase': 'preparation', 'failed': False, 'commands': []}
if phase != 'start':
    state = json.loads((root / 'round.json').read_text())
    if state['failed']:
        raise RuntimeError('failed round cannot resume as a passing round')

def command(name, argv, expected=0):
    save(name + '.argv.json', argv)
    with (root / (name + '.log')).open('xb') as stream:
        result = subprocess.run(argv, cwd=REPO, stdout=stream, stderr=subprocess.STDOUT,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=600)
    state['commands'].append({'name': name, 'returncode': result.returncode, 'expected': expected})
    save('round.json', state)
    if result.returncode != expected:
        raise RuntimeError(f'{name}: exit {result.returncode}, expected {expected}')

def probe(kind, name):
    command(name, [sys.executable, str(BASE / 'probe.py'), kind, root.name + '/' + name])
    trace = json.loads((root / name / 'trace.json').read_text())
    if type(trace.get('exit_code')) is not int or trace['errors']:
        raise RuntimeError(name + ': incomplete or failed observation')

def classify(name, expected):
    command(name + '-classification', [sys.executable, str(root / 'instruments/classifier.py'),
                                       str(root / name), expected])

def frozen(mutant=False):
    manifest = json.loads((root / 'freeze.json').read_text())
    for path, expected in manifest['immutable'].items():
        if digest(path) != expected:
            raise RuntimeError('frozen input changed: ' + path)
    for path, expected in manifest['source_links'].items():
        if os.readlink(path) != expected:
            raise RuntimeError('frozen source link changed: ' + path)
    expected = manifest['mutant_source'] if mutant else manifest['native_source']
    if digest(NATIVE) != expected:
        raise RuntimeError('native source is not the declared variant')
    if not mutant and digest(BINARY) != manifest['binary']:
        raise RuntimeError('native binary differs from frozen baseline')

try:
    if phase == 'start':
        if any(root.iterdir()):
            raise RuntimeError('round directory is not empty')
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
        if head != PIN:
            raise RuntimeError('integration tip changed before freeze')
        (root / 'instruments').mkdir()
        for name in ('classifier.py', 'check-separation.py', 'observe.gdb'):
            shutil.copyfile(DOC / name, root / 'instruments' / name)
        source = NATIVE.read_bytes()
        if source.count(DELIVERY) != 1:
            raise RuntimeError('delivery mutation is not single-site')
        shutil.copyfile(NATIVE, root / 'native-baseline.cpp')
        classifier = (root / 'instruments/classifier.py').read_bytes()
        old = b"if fields['message'] == EARLIER and shape == (1, 0, 0):"
        if classifier.count(old) != 1:
            raise RuntimeError('overlap mutation is not single-site')
        (root / 'instruments/classifier-overlap.py').write_bytes(classifier.replace(old, b'if True:'))
        # Compare exported bytes, including the tree's declared line endings.
        # A Git blob is not necessarily byte-identical to its archive checkout.
        verified = {}
        source_links = {}
        with subprocess.Popen(['git', 'archive', '--format=tar', TREE], cwd=REPO, stdout=subprocess.PIPE) as process:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for item in archive:
                    path = BASE / 'source' / item.name
                    if item.isdir():
                        continue
                    if item.issym():
                        if os.readlink(path) != item.linkname:
                            raise RuntimeError('source symlink mismatch: ' + str(path))
                        source_links[str(path)] = item.linkname
                        continue
                    elif item.isfile():
                        expected = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
                        if digest(path) != expected:
                            raise RuntimeError('source archive mismatch: ' + str(path))
                    else:
                        raise RuntimeError('unhandled source archive entry')
                    verified[str(path)] = digest(path)
            if process.wait() != 0:
                raise RuntimeError('source archive command failed')
        save('source-tree-verification.json', {'tree': TREE, 'files': verified, 'links': source_links})
        immutable = dict(verified)
        del immutable[str(NATIVE)]
        paths = [Path(__file__).resolve(), Path(__file__).with_name('seal.py').resolve(), BASE / 'probe.py', TOOL,
                 Path(sys.executable), Path('/usr/bin/clang++'), Path('/usr/bin/cmake'), Path('/usr/bin/gdb'), Path('/usr/bin/git'),
                 BASE / 'fresh-build/CMakeCache.txt', BASE / 'fresh-build/compile_commands.json',
                 BASE / 'fresh-build/CMakeFiles/test-tos-collator.dir/link.txt',
                 REPO / 'doc/measurements/uno-validator-input-reachability/candidate.bin']
        paths += list((root / 'instruments').iterdir()) + [DOC / n for n in ('classifier.py', 'check-separation.py', 'observe.gdb')]
        paths += [BASE / 'source/crypto/block' / name for name in ('block-auto.h', 'block-auto.cpp')]
        paths += [p for p in (BASE / 'source/tl/generate/auto').rglob('*') if p.is_file()]
        for fixture in ('fixture', 'singleton-input'):
            origin = Path('/tmp/uno-a2-registry-jqOjoDbi') / fixture
            target = root / 'inputs' / fixture
            target.mkdir(parents=True)
            for name in ('global.json', 'counter-state.rhash', 'counter-state.fhash'):
                shutil.copyfile(origin / name, target / name)
            paths += [origin / n for n in ('global.json', 'counter-state.rhash', 'counter-state.fhash')]
            paths += [p for p in (origin / 'peer/db').rglob('*') if p.is_file()]
        paths.append(Path('/tmp/uno-a2-registry-jqOjoDbi/singleton-input/idle1.candidate'))
        immutable.update({str(p): digest(p) for p in paths})
        for script in (Path(__file__), Path(__file__).with_name('seal.py'), BASE / 'probe.py'):
            shutil.copyfile(script, root / 'instruments' / script.name)
        prior = json.loads((DOC / 'report.json').read_text())
        if digest(BINARY) != prior['binary_hashes']['fresh-build/test-tos-collator'] or digest(TOOL) != prior['binary_hashes']['fresh-build/crypto/create-state']:
            raise RuntimeError('tool differs from accepted-content archive')
        save('freeze.json', {'commit': PIN, 'tree': TREE, 'immutable': immutable, 'source_links': source_links,
                            'native_source': digest(NATIVE), 'binary': digest(BINARY),
                            'mutant_source': hashlib.sha256(source.replace(DELIVERY, b'')).hexdigest(),
                            'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                            'steps': ['hashes', 'positive controls', 'earlier then five layers',
                                      '29 controls and two declared source mutations', 'restore and archive readback']})
        frozen()
        command('execute-positive', [str(BINARY), '--account-binding-probe-selftest', str(root / 'execute-positive.calls')])
        if (root / 'execute-positive.calls').read_text() != 'config=0\nexecute=1\n':
            raise RuntimeError('execution positive control failed')
        probe('accept', 'final-accept')
        if (root / 'final-accept/result.validation.kind').read_text() != 'accept\n' or not (root / 'final-accept/unexpected-export').is_file():
            raise RuntimeError('accept/export positive control failed')
        probe('reject', 'final-reject')
        probe('earlier', 'final-earlier')
        classify('final-earlier', 'earlier_configuration_failure')
        # The gate measurement starts only after independent earlier calibration.
        probe('gate', 'final-gate')
        classify('final-gate', 'account_readiness')
        command('observation-controls', [sys.executable, str(root / 'instruments/check-separation.py'), str(root), str(root / 'controls')])
        cases = json.loads((root / 'controls/report.json').read_text())
        if len(cases) != 29 or len({item['control'] for item in cases}) != 29:
            raise RuntimeError('observation matrix count differs')
        frozen()
        state['phase'] = 'baseline_complete'
    elif phase == 'delivery':
        if state['phase'] != 'baseline_complete':
            raise RuntimeError('wrong phase for delivery mutation')
        frozen(mutant=True)
        command('delivery-build', ['cmake', '--build', str(BASE / 'fresh-build'), '--target', 'test-tos-collator', '-j32'])
        save('delivery-mutant.json', {'source': digest(NATIVE), 'binary': digest(BINARY)})
        probe('gate', 'delivery-mutant')
        command('delivery-control', [sys.executable, str(root / 'instruments/classifier.py'), str(root / 'delivery-mutant'), 'account_readiness'], 1)
        if 'ValueError: unconfirmed typed delivery' not in (root / 'delivery-control.log').read_text():
            raise RuntimeError('delivery control failed for a different reason')
        if (root / 'delivery-mutant/result.validation.delivery').read_text() != 'pending\n':
            raise RuntimeError('missing final acknowledgement did not leave pending')
        frozen(mutant=True)
        state['phase'] = 'delivery_complete'
    elif phase == 'restored':
        if state['phase'] != 'delivery_complete':
            raise RuntimeError('wrong phase for restoration')
        if digest(NATIVE) != json.loads((root / 'freeze.json').read_text())['native_source']:
            raise RuntimeError('source restoration is not byte exact')
        command('restored-build', ['cmake', '--build', str(BASE / 'fresh-build'), '--target', 'test-tos-collator', '-j32'])
        frozen()
        probe('gate', 'restored-gate')
        classify('restored-gate', 'account_readiness')
        command('overlap-control', [sys.executable, str(root / 'instruments/classifier-overlap.py'), str(root / 'final-gate'), 'account_readiness'], 1)
        if "['earlier_configuration_failure', 'account_readiness']" not in (root / 'overlap-control.log').read_text():
            raise RuntimeError('overlap control failed for a different reason')
        command('overlap-restored-classification', [sys.executable, str(root / 'instruments/classifier.py'),
                                                   str(root / 'final-gate'), 'account_readiness'])
        frozen()
        state['phase'] = 'complete'
    else:
        raise ValueError('unknown phase')
    save('round.json', state)
    print(state['phase'], flush=True)
except BaseException as error:
    state['failed'] = True
    state['failure'] = repr(error)
    save('round.json', state)
    raise

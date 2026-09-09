#!/usr/bin/env python3
"""Manual closed-activation disk smoke; never constructs admitted/replay objects."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
TVM = {'format': 0, 'selector': -1}
PROBE = {'format': 0, 'selector': 0x434e5431}


def command(args, cwd, log, env=None):
    with log.open('xb') as stream:
        return subprocess.run(args, cwd=cwd, env=env, stdout=stream,
                              stderr=subprocess.STDOUT, timeout=120).returncode


def prepare(root):
    seed = root / 'seed'
    if seed.exists():
        if not (seed / 'ready.json').is_file():
            raise RuntimeError('incomplete seed; retain it and choose a fresh root')
        manifest = json.loads((seed / 'ready.json').read_text())
        for name, digest in manifest.items():
            assert hashlib.sha256((seed / name).read_bytes()).hexdigest() == digest, name
        return seed
    seed.mkdir()
    (seed / 'db/static').mkdir(parents=True)
    source = (REPO / 'test/counter-masterchain-genesis.fif').read_text()
    marker = '<b x{57495431} s, native-ingress-dict @ dict, b> 84 config!'
    assert source.count('1024 or config.version!') == source.count(marker) == 1
    source = source.replace('1024 or config.version!', '0 or config.version!').replace(marker, '')
    (seed / 'inactive-genesis.fif').write_text(source)
    epoch = str(int(time.time()))
    for path in (REPO / 'test/counter-shard-genesis.fif', seed / 'inactive-genesis.fif'):
        status = command([str(root / 'create-state'), '-I',
                          f'{REPO}/crypto/fift/lib:{REPO}/build/crypto/smartcont:{REPO}/crypto/smartcont',
                          str(path)], seed, seed / (path.stem + '.log'),
                         dict(os.environ, SOURCE_DATE_EPOCH=epoch))
        assert status == 0, (path, status)
    for name in ('zerostate', 'basestate0', 'counter-state'):
        state = seed / (name + '.boc')
        digest = hashlib.sha256(state.read_bytes()).hexdigest().upper()
        shutil.copyfile(state, seed / 'db/static' / digest)
    zero = {'workchain': -1, 'shard': -9223372036854775808, 'seqno': 0,
            'root_hash': base64.b64encode((seed / 'zerostate.rhash').read_bytes()).decode(),
            'file_hash': base64.b64encode((seed / 'zerostate.fhash').read_bytes()).decode()}
    (seed / 'global.json').write_text(json.dumps({
        '@type': 'config.global', 'dht': {'@type': 'dht.config.global', 'k': 6, 'a': 3,
                                        'static_nodes': {'@type': 'dht.nodes', 'nodes': []}},
        'validator': {'@type': 'validator.config.global', 'zero_state': zero, 'hardforks': []}}))
    (seed / 'epoch.txt').write_text(epoch)
    (seed / 'ready.json').write_text(json.dumps({
        str(p.relative_to(seed)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(seed.rglob('*')) if p.is_file()}, indent=2))
    return seed


def observe(root, mode):
    assert mode in ('off', 'on')
    seed = prepare(root)
    fixture = root / (mode + '-fixture')
    shutil.copytree(seed, fixture)  # Existing results must not be reused.
    binary = root / mode / 'test-tos-collator'
    prior = (f"(2,8000000000000000,0):{(seed / 'counter-state.rhash').read_bytes().hex()}:"
             f"{(seed / 'counter-state.fhash').read_bytes().hex()}")
    queries = [('bootstrap', ['-w', '-1', '--export-candidate', str(fixture / 'bootstrap.candidate')], 0),
               ('account', ['-w', '2', '-T', prior, '--counter-increment', '1',
                            '--account-binding-probe', str(fixture / 'calls.txt'),
                            '--export-candidate', str(fixture / 'unexpected.candidate')], 2)]
    for label, extra, expected in queries:
        args = [str(binary), '-C', str(fixture / 'global.json'), '-D', str(fixture / 'db'),
                '--query-result', str(fixture / (label + '.result')), *extra]
        (fixture / (label + '.argv.json')).write_text(json.dumps(args))
        status = command(['gdb', '-q', '--batch', '--return-child-result', '-x',
                          str(Path(__file__).with_suffix('.gdb')), '--args', *args], fixture,
                         fixture / (label + '.gdb.log'), dict(os.environ,
                         CONNECTIVITY_TRACE=str(fixture / (label + '.trace.json')),
                         CONNECTIVITY_TYPES=str(root / 'types.o')))
        trace = json.loads((fixture / (label + '.trace.json')).read_text())
        assert status == trace['exit_code'] == expected and not trace['errors'], trace
    # Nonzero calibration of the same engine-invocation instrument, not connectivity.
    status = command([str(binary), '--account-binding-probe-selftest', str(fixture / 'instrument.txt')],
                     fixture, fixture / 'instrument.log')
    assert status == 0 and (fixture / 'instrument.txt').read_text() == 'config=0\nexecute=1\n'


def check(root):
    spec = importlib.util.spec_from_file_location('activation_observation',
                                                 Path(__file__).with_name('workchain-activation-rejection.py'))
    activation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(activation)
    activation.check_activation_source(REPO)
    def cache(mode):
        return {line.split('=', 1)[0]: line.split('=', 1)[1]
                for line in (root / mode / 'CMakeCache.txt').read_text().splitlines()
                if '=' in line and not line.startswith(('#', '//'))}
    off, on = cache('off'), cache('on')
    differences = {key: (off.get(key), on.get(key)) for key in off.keys() | on.keys()
                   if off.get(key) != on.get(key)}
    assert differences == {'TOS_UNO_CRYPTO_NODE_LINK:BOOL': ('OFF', 'ON')}, differences
    binary_hashes = {mode: {name: hashlib.sha256((root / mode / name).read_bytes()).hexdigest()
                            for name in ('validator-engine', 'test-tos-collator')}
                     for mode in ('off', 'on')}
    for name in ('validator-engine', 'test-tos-collator'):
        assert binary_hashes['off'][name] != binary_hashes['on'][name], ('identical binaries', name)
    snapshots = []
    for mode in ('off', 'on'):
        folder = root / (mode + '-fixture')
        snapshot = {}
        for label in ('bootstrap', 'account'):
            trace = json.loads((folder / (label + '.trace.json')).read_text())
            assert not trace['errors'], trace
            assert trace['exit_code'] == (0 if label == 'bootstrap' else 2), trace
            sequence = [e['site'] for e in trace['events'] if e['site'] not in ('registry_default', 'register_account', 'config')]
            expected = ['preinit', 'validator_set', 'old_state'] if label == 'bootstrap' else ['preinit', 'dispatch']
            assert sequence == expected, ('frontier', mode, label, sequence, expected)
            configs = [e for e in trace['events'] if e['site'] == 'config']
            assert configs and all(e == {'site': 'config', 'version': 15, 'capabilities': 494} for e in configs), configs
            registries = [e for e in trace['events'] if 'registry' in e]
            assert registries, ('missing registry observation', label)
            assert registries[0]['registry'] == {'engines_': [TVM], 'block_engines_': [], 'account_engines_': []}
            for e in registries:
                assert e['registry']['engines_'] == [TVM] and not e['registry']['block_engines_'], e
            registrations = [e for e in registries if e['site'] == 'register_account']
            assert len(registrations) == (1 if label == 'account' else 0)
            if registrations:
                assert registrations[0]['registry']['account_engines_'] == [PROBE], registrations
                assert registries[-1]['registry']['account_engines_'] == [PROBE], registries
            else:
                assert all(not e['registry']['account_engines_'] for e in registries), registries
            snapshot[label] = trace
        expected_files = {
            'account.result': 'collate -7201\n', 'calls.txt': 'config=0\nexecute=0\n',
            'account.result.stats': 'delivery=recorded\nvisited=0\nadapter=0\nowners_before=0\nowners_during=0\nowners_after=0\ntransactions=0\n',
            'bootstrap.result': 'collate 0\n',
            'bootstrap.result.kind': 'success\n', 'bootstrap.result.message': '',
            'account.result.kind': 'error\n',
            'account.result.message': 'cannot create block for configured workchain: descriptor has no registered block engine',
            'bootstrap.result.stats': 'delivery=recorded\nvisited=0\nadapter=0\nowners_before=0\nowners_during=0\nowners_after=0\ntransactions=1\n',
            'instrument.txt': 'config=0\nexecute=1\n',
        }
        for name, value in expected_files.items():
            assert (folder / name).read_text() == value, (mode, name)
        assert activation.is_activation_rejection(-7201, (folder / 'account.result.message').read_text(),
                                                 boundary='collator') is False
        assert not (folder / 'unexpected.candidate').exists(), mode
        assert (folder / 'bootstrap.candidate').stat().st_size > 0, ('export positive control', mode)
        snapshots.append(snapshot)
    assert snapshots[0] == snapshots[1], ('link-dependent-observation', snapshots)
    print(json.dumps({'off_on_observations_equal': True, 'binary_hashes': binary_hashes, 'observed': snapshots[0],
                      'scope': 'production Collator path under the disk manager; closed activation, no admission or replay reached'}, indent=2))


if __name__ == '__main__':
    action, directory = sys.argv[1:3]
    directory = Path(directory).resolve(strict=True)
    if action == 'check':
        check(directory)
    elif action in ('off', 'on'):
        observe(directory, action)
    else:
        raise ValueError('expected off, on, or check')

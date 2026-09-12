#!/usr/bin/env python3
"""Test-owned node fixture. No deployment configuration or permission flag."""
import argparse
import base64
import hashlib
import json
import importlib.util
import shlex
import sys
import shutil
from pathlib import Path
import subprocess
import tempfile
from uno_wallet_freshness import pin

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', required=True, type=Path)
p.add_argument('--m4', action='store_true', help='use explicit M4 test parameters and real Native Deposit')
p.add_argument('--m4-rejections', action='store_true', help='run separate rejection cases after two real Deposits')
p.add_argument('--m5-debit', action='store_true', help='stop after authenticated Withdrawal debit checkpoint')
p.add_argument('--m5-return-route', action='store_true', help='deliver a funded payout to wc0 and observe the actual return')
p.add_argument('--m5-failed', action='store_true', help='publish the funded phase-0 return atomically at custody')
p.add_argument('--m5-bucket-small', action='store_true', help='real bounce below local issuance fees')
p.add_argument('--m5-completion-late', action='store_true',
               help='establish Q through real owner operations before importing the return')
p.add_argument('--m5-return-principal', type=int, help='explicit real-payout fixture principal')
p.add_argument('--completion-expect-offset', type=int, choices=(-1, 0, 1),
               help='assert observed y is h plus this exact boundary offset')
p.add_argument('--completion-contract', choices=('bucket-small',),
               help='run the existing frozen real-host completion contract')
p.add_argument('--failed-routing-probe', action='store_true',
               help='run the real fee-routing producer mutation before normal Failed publication')
p.add_argument('--failed-routing-binary', type=Path,
               help='isolated test binary for oracle-removal control only')
a = p.parse_args()
if a.m5_bucket_small or a.m5_completion_late:
    a.m5_failed = True
if a.failed_routing_probe:
    a.m5_failed = True
if a.m5_failed:
    a.m5_return_route = True
if a.m5_return_route:
    a.m5_debit = True
repo = Path(__file__).resolve().parents[1]
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
if f'CMAKE_HOME_DIRECTORY:INTERNAL={repo}' not in cache:
    p.error('build belongs to another tree')
if 'TOS_UNO_CRYPTO_NODE_LINK:BOOL=ON' not in cache:
    p.error('real node verification requires TOS_UNO_CRYPTO_NODE_LINK=ON')
if a.m5_return_principal is not None and not (a.m5_return_route and 0 < a.m5_return_principal < 2**64):
    p.error('explicit principal requires a real return and must fit uint64')
if a.completion_expect_offset is not None and not a.m5_bucket_small:
    p.error('boundary observation requires the bucket fixture')

if a.completion_contract:
    # Complete the existing carrier here; do not introduce a parallel runner.
    work = Path(tempfile.mkdtemp(prefix='uno-completion-bucket-'))
    print(f'COMPLETION_RUN:{work}', flush=True)
    spec = importlib.util.spec_from_file_location('completion_oracle',
        repo / 'crypto/test/workchain_withdrawal_completion_oracle.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)

    def run_boundary(label, principal=None, offset=None):
        args = [sys.executable, str(Path(__file__).resolve()), '--build', str(build),
                '--m5-bucket-small', '--m5-completion-late']
        if principal is not None:
            args += ['--m5-return-principal', str(oracle.checked(principal)),
                     '--completion-expect-offset', str(offset)]
        with (work / (label + '.log')).open('w') as log:
            result = subprocess.run(args, stdout=log, stderr=log)
        lines = (work / (label + '.log')).read_text().splitlines()
        fixtures = [Path(line.removeprefix('Test-owned fixture: ')) for line in lines
                    if line.startswith('Test-owned fixture: ')]
        if len(fixtures) != 1:
            raise RuntimeError(f'{label}: missing unique live fixture; see {work}')
        if result.returncode:
            raise RuntimeError(f'{label}: real boundary run failed ({result.returncode}); see {work}')
        data = json.loads((fixtures[0] / 'completion-observation.json').read_text())
        return fixtures[0], data

    _, calibration = run_boundary('calibration')
    ci = calibration['input']
    h = oracle.checked(oracle.checked(ci['slot']) + oracle.checked(ci['base'] * ci['units']))
    loss = oracle.checked(ci['x'] - ci['y'])
    samples = {}
    for offset, label in ((-1, 'below'), (0, 'equal'), (1, 'above')):
        # Native loss is measured, not a tariff default. Each new run checks its
        # actual y against the requested boundary, so size-dependent repricing
        # cannot silently turn these into tests of different input values.
        samples[label] = run_boundary(label, oracle.checked(oracle.checked(h + loss) + offset), offset)
    for fixture_path, data in samples.values():
        i = data['input']
        if i['phase'] != 1 or i['height'] <= oracle.checked(i['Q'] + i['window']):
            raise RuntimeError('COMPLETION_NOT_READY: authenticated late-phase fixture missing')

    def shadow_binary(label, old, replacement):
        root = work / label
        header = root / 'block/workchain-failed-funded.h'
        header.parent.mkdir(parents=True)
        text = (repo / 'crypto/block/workchain-failed-funded.h').read_text()
        if text.count(old) != 1:
            raise RuntimeError('semantic mutation target changed: ' + label)
        header.write_text(text.replace(old, replacement))
        source = repo / 'test/test-m3-live.cpp'
        entries = [e for e in json.loads((build / 'compile_commands.json').read_text())
                   if Path(e['file']).resolve() == source]
        if len(entries) != 1:
            raise RuntimeError('missing unique live compile command')
        command = shlex.split(entries[0]['command'])
        command[1:1] = ['-I' + str(root), '-I' + str(repo / 'crypto/block')]
        obj = root / 'live.o'
        command[command.index('-o') + 1] = str(obj)
        with (root / 'build.log').open('w') as log:
            subprocess.run(command, cwd=build, stdout=log, stderr=log, check=True)
            link = shlex.split(subprocess.check_output(['ninja', '-t', 'commands', 'test-m3-live'],
                                                       cwd=build, text=True).splitlines()[-1])
            if link[:2] != [':', '&&'] or link[-2:] != ['&&', ':']:
                raise RuntimeError('unrecognized live link command')
            link = link[2:-2]
            original = 'CMakeFiles/test-m3-live.dir/test/test-m3-live.cpp.o'
            if link.count(original) != 1:
                raise RuntimeError('missing live object in link')
            link[link.index(original)] = str(obj)
            binary = root / 'test-m3-live'
            link[link.index('-o') + 1] = str(binary)
            subprocess.run(link, cwd=build, stdout=log, stderr=log, check=True)
        return binary

    def replay(label, binary):
        source = samples['below'][0]
        target = work / label
        target.mkdir()
        for file in source.iterdir():
            if file.is_file() and not file.name.startswith(('enabled.', 'closed.', 'completion-observation')):
                shutil.copy2(file, target / file.name)
        shutil.copytree(source / 'db', target / 'db')
        shutil.copytree(source / 'm4-blocks', target / 'm4-blocks')
        result = subprocess.run([str(binary), str(target)], text=True, capture_output=True)
        (target / 'completion-execution.log').write_text(result.stdout + result.stderr)
        output = target / 'completion-observation.json'
        # The unmodified adapter checks actual callee execution even when the
        # mutant refuses before publication; an earlier failure is not a red.
        subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                        'bucket-small', str(target), str(output)], check=True)
        return result.returncode, json.loads(output.read_text())

    for label, target, replacement, assertion in (
        ('refusal', '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
         '      return error("isolated bucket disposition refusal");\n'
         '      WorkchainFailedFundedResult result{owner_data, coordinator_data, {}, {},',
         'DISPOSITION_MUST_PUBLISH'),
        ('attribution', '        credited.bucket.entries.back().account_id = owner.account.address.account;',
         '        // Isolated mutation: omit the beneficiary from the installed bucket entry.',
         'BUCKET_FIXED_ATTRIBUTION')):
        binary = shadow_binary(label, target, replacement)
        _, data = replay(label + '-run', binary)
        oracle.expect_red('bucket-small', data, assertion)
        print('COMPLETION_REAL_RED:' + assertion, flush=True)
        try:
            oracle.expect_red('bucket-small', data, assertion, observer=lambda case, observation: None)
        except oracle.Violation as error:
            if str(error) != 'ORACLE_MISSING:' + assertion:
                raise
            print(str(error), flush=True)
        else:
            raise RuntimeError('disabled oracle driver did not fail')
    code, restored = replay('restored', build / 'test-m3-live')
    if code != 0:
        raise RuntimeError('restored real execution failed')
    oracle.check('bucket-small', restored)
    print('WITHDRAWAL-COMPLETION_D78_OBSERVED:test-workchain-withdrawal-completion-bucket-small')
    raise SystemExit(0)

fixture = Path(tempfile.mkdtemp(prefix='uno-m3-live-'))
wallet = pin(repo, build / 'm3-vector-wallet-target/release/examples/m3-scenario', fixture)
# Establish that the same numeric predicate used after each accepted block
# rejects unpaired principal and nonzero cross-block D, then restores to green.
# A crash, unknown mode or missing binary is not an expected rejection.
for mode, expected in [('unpaired', 1), ('cross-block-d', 1), ('restored', 0)]:
    control = subprocess.run([str(build / 'test-m3-live'), '--m4-backing-control', mode],
                             text=True, capture_output=True)
    if control.returncode != expected or f'M4 backing control {mode}:' not in control.stdout:
        raise RuntimeError(f'backing control {mode}: rc={control.returncode}, '
                           f'stdout={control.stdout}, stderr={control.stderr}')
    if expected and 'M4 per-block backing mismatch or nonzero cross-block D' not in control.stdout:
        raise RuntimeError('backing control failed for an unrelated reason')
    print(f'Backing control exit={control.returncode}: {control.stdout.strip()}', flush=True)
# Reader-only controls: distinguish unavailable evidence from actual zero/one.
# Real counter emission is separately exercised by Failed fault injection below.
probe = fixture / 'unknown-reader-probe'
for value, expected, code, diagnostic in [
        (None, '0', 2, 'UNKNOWN_ORIGIN_OBSERVATION_UNAVAILABLE:'),
        ('0\n', '0', 0, ''), ('1\n', '1', 0, ''),
        ('1\n', '0', 2, 'UNKNOWN_ORIGIN_OBSERVATION_MISMATCH:')]:
    if value is not None:
        probe.write_text(value)
    result = subprocess.run([str(build / 'test-m3-live'), '--check-unknown-observation', str(probe), expected],
                            text=True, capture_output=True)
    if result.returncode != code or diagnostic not in result.stderr:
        raise RuntimeError(f'unknown observation reader control failed: {result.returncode}; {result.stderr}')
print('UNKNOWN_READER_CONTROLS: unavailable / zero / one / mismatch distinguished', flush=True)
# Reuse the existing test-owned genesis construction without its collation
# scenarios or cleanup. Never import a deployment DB/configuration. This prefix
# contains all schema-dependent fixture code; do not maintain a second copy.
source = (repo / 'test/test-counter-disk-integration.cmake').read_text()
marker = 'set(node_db "${fixture}/db")\nfunction(run_node'
if source.count(marker) != 1:
    raise RuntimeError('genesis preparation boundary changed')
(fixture / '.counter-managed-v1').write_text('M3 test-owned fixture, not a deployment source.\n')
prepare = fixture / 'prepare.cmake'
subprocess.run([str(build / 'test-m3-live'), '--m4-coordinator-data',
                str(fixture / 'coordinator-data.boc')], check=True)
# Keep all instance issuance in the existing create-state route. Change the
# wc=2 state BEFORE its descriptor/instance are issued, never after hashing it.
# These operating coins are assumed test state, not M4 Deposit or principal.
shard = (repo / 'test/counter-shard-genesis.fif').read_text()
old_account = ('empty_cell\n<b x{57424531} s, 0 1 u, <b 40 64 u, b> ref, b>\n'
               'empty_cell 1000 0 0 0 6 register_smc drop')
if shard.count(old_account) != 1:
    raise RuntimeError('test coordinator construction changed')
shard = shard.replace(old_account, '<{ 63 THROW }>c\n"coordinator-data.boc" file>B B>boc\n'
                      'empty_cell 1000000000 0 0 0 6 register_smc drop')
if True:
    # Zero principal custody exists before descriptor issuance. This is not
    # confidential test funding: every later principal coin must be imported.
    # Nonempty inert data is a fixture representation choice: register_smc
    # omits empty data, whereas engine update rows require a present data cell.
    shard = shard.replace('create_state\n', '<{ 63 THROW }>c\n<b 0 1 u, b>\n'
                          'empty_cell 0 0 0 256 1<<1- 6 register_smc drop\ncreate_state\n')
(fixture / 'm3-shard-genesis.fif').write_text(shard)
prefix = source.split(marker)[0]
route = '  set(script_path "${SOURCE_DIR}/test/${script}.fif")'
if prefix.count(route) != 1:
    raise RuntimeError('test genesis script route changed')
prefix = prefix.replace(route, route + '''
  if(script STREQUAL "counter-shard-genesis")
    set(script_path "${fixture}/m3-shard-genesis.fif")
  elseif(script STREQUAL "counter-native-sender")
    set(script_path "${SOURCE_DIR}/test/m3-native-sender.fif")
  endif()''')
prepare.write_text(prefix)
subprocess.run(['cmake', '-DCOUNTER_FIXTURE_CHILD=ON', f'-DCOUNTER_FIXTURE_PATH={fixture}',
                '-DACCOUNT_BINDING_ONLY=ON', '-DNATIVE_SENDER=ON',
                f'-DSOURCE_DIR={repo}', f'-DBUILD_DIR={build}',
                f'-DCREATE_STATE={build / "crypto/create-state"}',
                f'-DCOLLATOR={build / "test-m3-live"}', '-P', str(prepare)], check=True)
print(f'Test-owned fixture: {fixture}', flush=True)
shutil.copyfile(fixture / 'counter-state.boc', fixture / 'current-state.boc')
subprocess.run([str(build / 'test-m3-live'), '--prepare-m5-completion-config' if a.m5_completion_late else
                '--prepare-m5-return-config' if a.m5_return_route else
                '--prepare-m5-debit-config' if a.m5_debit else '--prepare-m4-config', str(fixture)], check=True)
# Bind disk lookup and global.json to the actual edited TEST genesis bytes.
# No prior DB is reused and no deployment configuration is read or written.
zero_bytes = (fixture / 'zerostate.boc').read_bytes()
zero_file_hash = hashlib.sha256(zero_bytes).digest()
(fixture / 'zerostate.fhash').write_bytes(zero_file_hash)
(fixture / 'db/static' / zero_file_hash.hex().upper()).write_bytes(zero_bytes)
global_config = json.loads((fixture / 'global.json').read_text())
zero = global_config['validator']['zero_state']
zero['root_hash'] = base64.b64encode((fixture / 'zerostate.rhash').read_bytes()).decode()
zero['file_hash'] = base64.b64encode(zero_file_hash).decode()
(fixture / 'global.json').write_text(json.dumps(global_config))
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1',
                '--query-result', str(fixture / 'bootstrap.result')], check=True)
(fixture / 'wallet-key.request.txt').write_text('secret=101\n')
subprocess.run([str(wallet), 'key', str(fixture / 'wallet-key.request.txt'),
                str(fixture / 'wallet-key.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-request', str(fixture)], check=True)
subprocess.run([str(wallet), 'register', str(fixture / 'registration-0.request.txt'),
                str(fixture / 'registration-0.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-finish', str(fixture)], check=True)
# Real Native source transaction, then authenticated masterchain top descriptor:
# neither the collator nor the validator is given an invented inbox envelope.
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'registration-0.message.boc'),
                '-s', str(fixture / 'payer-top-'), '--query-result', str(fixture / 'payer.result'),
                '--export-candidate', str(fixture / 'payer.candidate')], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payer-top-1.boc'),
                '--query-result', str(fixture / 'payer-master.result')], check=True)
def registration_pair():
    shutil.copyfile(fixture / 'registration-0.candidate.boc', fixture / 'operation.candidate.boc')
    shutil.copyfile(fixture / 'registration-0.declarations.boc', fixture / 'operation.declarations.boc')
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

registration_pair()

# Continue on the accepted database, not a PureBackend account side table.
# Keep each pair's observations distinct so no earlier sidecar can satisfy a
# later step. These are temporary run files, not a separate evidence archive.
def advance_pair(number):
    (fixture / 'db').rename(fixture / f'before-{number}-db')
    (fixture / 'enabled-db').rename(fixture / 'db')
    (fixture / 'closed-db').rename(fixture / f'closed-{number}-db')
    for path in list(fixture.iterdir()):
        if path.is_file() and path.name.startswith(('closed.', 'enabled.', 'enabled-top')):
            path.rename(fixture / f'{number}-{path.name}')
    shutil.copyfile(fixture / 'accepted-state.boc', fixture / 'current-state.boc')

advance_pair(0)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '0-enabled-top1.boc'),
                '--query-result', str(fixture / 'register-a-master.result')], check=True)
(fixture / 'wallet-key.request.txt').write_text('secret=223\n')
subprocess.run([str(wallet), 'key', str(fixture / 'wallet-key.request.txt'),
                str(fixture / 'wallet-key.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-request-b', str(fixture)], check=True)
subprocess.run([str(wallet), 'register', str(fixture / 'registration-0.request.txt'),
                str(fixture / 'registration-0.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--registration-finish', str(fixture)], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'registration-0.message.boc'),
                '-s', str(fixture / 'payer-b-top'), '--query-result', str(fixture / 'payer-b.result')], check=True)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payer-b-top1.boc'),
                '--query-result', str(fixture / 'payer-b-master.result')], check=True)
registration_pair()
print('Both registrations accepted on real collator/validator with paired OFF runs.', flush=True)
advance_pair(1)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '1-enabled-top1.boc'),
                '--query-result', str(fixture / 'register-b-master.result')], check=True)
if True:
    subprocess.run([str(build / 'test-m3-live'), '--wallet-policy', str(fixture)], check=True)
    policy = dict(line.split('=', 1) for line in (fixture / 'wallet-policy.txt').read_text().splitlines())
    # M3 now starts from real backing. Pay the added initial COLLECT explicitly;
    # do not weaken the frozen minimum or install available directly.
    principal = 1000000000 if a.m4 else 1000000000 + int(policy['collect_fee'])
    if principal > 2**64 - 1:
        raise RuntimeError('initial Deposit principal overflow')
    for number in ((2, 3) if a.m4 else (2,)):
        (fixture / 'deposit.request.txt').write_text(f'principal={principal}\n')
        subprocess.run([str(build / 'test-m3-live'), '--deposit-request', str(fixture)], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '0', '-m', str(fixture / 'deposit.message.boc'),
                        '-s', str(fixture / f'deposit-{number}-payer-top'),
                        '--query-result', str(fixture / f'deposit-{number}-payer.result')], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1',
                        '-M', str(fixture / f'deposit-{number}-payer-top1.boc'),
                        '--query-result', str(fixture / f'deposit-{number}-master.result')], check=True)
        subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
        shutil.copyfile(fixture / 'accepted-receipt.id', fixture / f'deposit-{number}.id')
        advance_pair(number)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / f'{number}-enabled-top1.boc'),
                        '--query-result', str(fixture / f'deposit-{number}-accepted-master.result')], check=True)
    if a.m4 and a.m4_rejections:
        from uno_m4_rejection_sequence import run
        run(build, fixture, advance_pair)
        raise SystemExit(0)
    if a.m4:
        from uno_m4_live_sequence import run
        run(build, fixture, wallet, advance_pair)
        raise SystemExit(0)

from uno_m4_live_sequence import run
initial, initial_blind, send_fee, collect_fee, limits = run(
    build, fixture, wallet, advance_pair, initial_only=True, initial_principal=principal)
if a.m5_debit:
    request = dict(secret=101, old_value=initial, old_blind=initial_blind, new_blind=71, aux_blind=83,
                   principal=a.m5_return_principal if a.m5_return_principal is not None else
                             1000000 if a.m5_bucket_small else 10000000 if a.m5_return_route else 137, outward_fee=17,
                   fee=257, **limits)
    def debit_write(name, values):
        (fixture / name).write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
    def withdrawal_request(values):
        debit_write('operation.request.txt',values)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-payout-quote',str(fixture)],check=True)
        values['outward_fee'] = int((fixture / 'payout.quote.txt').read_text())
        debit = values['principal'] + values['outward_fee'] + values['fee']
        if not 0 <= debit < 2**64 or values['old_value'] < debit:
            raise RuntimeError('fixture Withdrawal debit overflow or insufficient available')
        debit_write('operation.request.txt',values)
        subprocess.run([str(wallet),'withdrawal-points',str(fixture / 'operation.request.txt'),str(fixture / 'operation.points.txt')],check=True)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-request',str(fixture)],check=True)
        statement = dict(line.split('=',1) for line in (fixture / 'operation.statement.txt').read_text().splitlines())
        debit_write('operation.request.txt',dict(values,**statement))
        subprocess.run([str(wallet),'withdrawal-prove',str(fixture / 'operation.request.txt'),str(fixture / 'operation.proof.txt')],check=True)
        subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-finish',str(fixture)],check=True)
        remaining = values['old_value'] - debit
        debit_write('operation.expected.txt',dict(before=values['old_value'],after=remaining))
        return remaining
    available = withdrawal_request(request)
    print(f'DEBIT_FIXTURE={fixture}',flush=True)
    subprocess.run([str(build / 'test-m3-live'),str(fixture)],check=True)
    if a.m5_return_route:
        advance_pair(4)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '4-enabled-top1.boc'),
                        '--query-result', str(fixture / 'payout-master.result')], check=True)
        subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                        '-D', str(fixture / 'db'), '-w', '0', '-s', str(fixture / 'payout-recipient-top'),
                        '--query-result', str(fixture / 'payout-recipient.result'),
                        '--export-candidate', str(fixture / 'payout-recipient.candidate')], check=True)
        subprocess.run([str(build / 'test-m3-live'), '--observe-m5-payout-recipient', str(fixture)], check=True)
        if not (fixture / 'failed-bounce.boc').is_file():
            raise RuntimeError('funded return route did not produce a real bounce')
        if a.m5_failed:
            subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                            '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / 'payout-recipient-top1.boc'),
                            '--query-result', str(fixture / 'return-master.result')], check=True)
            if a.m5_completion_late:
                shutil.copyfile(fixture / 'prepare-payout.boc',fixture / 'completion-original-payout.boc')
                old_blind = request['new_blind']
                for number, new_blind in ((5,79),(6,83)):
                    followup = dict(secret=101, old_value=available, old_blind=old_blind,
                                    new_blind=new_blind, aux_blind=89, principal=137,
                                    outward_fee=17, fee=257, **limits)
                    available = withdrawal_request(followup)
                    completed = subprocess.run([str(build / 'test-m3-live'),str(fixture)],
                                               text=True,capture_output=True)
                    (fixture / f'completion-owner-{number}.log').write_text(completed.stdout+completed.stderr)
                    print(completed.stdout,end=''); print(completed.stderr,end='',file=sys.stderr)
                    completed.check_returncode()
                    advance_pair(number)
                    subprocess.run([str(build / 'test-tos-collator'), '-C',str(fixture / 'global.json'),
                                    '-D',str(fixture / 'db'), '-w','-1', '-M',
                                    str(fixture / f'{number}-enabled-top1.boc'), '--query-result',
                                    str(fixture / f'completion-owner-{number}-master.result')],check=True)
                    old_blind = new_blind
                shutil.copyfile(fixture / 'current-state.boc',fixture / 'completion-record-state.boc')
                shutil.copyfile(fixture / 'completion-original-payout.boc',fixture / 'prepare-payout.boc')
            subprocess.run([str(build / 'test-m3-live'), '--failed-request', str(fixture)], check=True)
            if a.failed_routing_probe:
                probe = fixture / 'routing-probe'
                # The backing observer intentionally refuses to overwrite its
                # observations. Mutant and restored runs need separate outputs.
                shutil.copytree(fixture, probe, ignore=shutil.ignore_patterns('routing-probe'))
                result = subprocess.run([str(a.failed_routing_binary or build / 'test-m3-live'), '--failed-fee-routing-control', str(probe)],
                                        text=True, capture_output=True)
                (fixture / 'routing-probe.log').write_text(result.stdout + result.stderr)
                print(f'FAILED_ROUTING_PROBE fixture={fixture} exit={result.returncode}', flush=True)
                for suffix, expected in [('.validation.kind', 'accept\n'),
                                         ('.validation.result', 'validate accept\n')]:
                    if (probe / ('routing-enabled.result' + suffix)).read_text() != expected:
                        raise RuntimeError('routing mutation did not reach accepted Native publication')
                if not (probe / 'routing-enabled.candidate').is_file():
                    raise RuntimeError('routing mutation has no exported candidate')
                if result.returncode == 0 or 'FAILED_COST_ROUTING:' not in result.stderr:
                    raise RuntimeError('FAILED_ORACLE_MISSING:FAILED_COST_ROUTING; '
                                       'expected designated routing red, not an earlier failure')
            subprocess.run([str(build / 'test-m3-live'), '--failed-incarnation-control', str(fixture)], check=True)
            subprocess.run([str(build / 'test-m3-live'), '--failed-unknown-control', str(fixture)], check=True)
            shutil.copyfile(fixture / 'current-state.boc', fixture / 'completion-before-state.boc')
            completed = subprocess.run([str(build / 'test-m3-live'), str(fixture)], text=True, capture_output=True)
            (fixture / 'completion-execution.log').write_text(completed.stdout + completed.stderr)
            print(completed.stdout, end=''); print(completed.stderr, end='', file=__import__('sys').stderr)
            if a.m5_bucket_small:
                observation = fixture / 'completion-observation.json'
                case = 'row6' if a.completion_expect_offset == 1 else 'bucket-small'
                subprocess.run([str(build / 'test-m3-live'), '--completion-observation',
                                case, str(fixture), str(observation)], check=True)
                if a.completion_expect_offset is not None:
                    values = json.loads(observation.read_text())['input']
                    h = values['slot'] + values['base'] * values['units']
                    if not 0 <= h < 2**64 or values['y'] != h + a.completion_expect_offset:
                        raise RuntimeError('COMPLETION_BOUNDARY_INPUT_MISMATCH: actual y is not h+offset')
                subprocess.run(['python3', str(repo / 'crypto/test/workchain_withdrawal_completion_oracle.py'),
                                '--case', case, '--observation', str(observation)], check=True)
            completed.check_returncode()
    raise SystemExit(0)
# Keep the final B->A receipt at 432: compensate only the changed SEND/COLLECT
# tariffs in the first receipt. The remaining two receipts retain 251 and 89.
first_value = 137 + (send_fee - 11) + 2 * (collect_fee - 17)
if not 1 <= first_value <= int(limits['max_value']):
    raise RuntimeError('real-Deposit M3 sequence cannot fund the closing sender')

# Wallet witnesses remain proposer-side only. Each validator obtains the full
# public statement and authorization from the emitted permanent block.
def send_pair(owner, old_value, old_blind, value, new_blind, transfer_blind):
    secret, receiver = (101, 223) if owner == 0 else (223, 101)
    witness = dict(secret=secret, receiver_secret=receiver, old_value=old_value,
                   old_blind=old_blind, value=value, new_blind=new_blind,
                   transfer_blind=transfer_blind, aux_blind=43)
    def write_fields(path, fields):
        path.write_text(''.join(f'{k}={v}\n' for k, v in fields.items()))
    write_fields(fixture / 'operation.wallet.txt', dict(owner=owner))
    write_fields(fixture / 'operation.request.txt',
                 dict(witness, kind=1, fee=send_fee, **limits))
    subprocess.run([str(wallet), 'points', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.points.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--send-request', str(fixture)], check=True)
    statement = dict(line.split('=', 1) for line in
                     (fixture / 'operation.statement.txt').read_text().splitlines())
    if set(statement) & set(witness):
        raise RuntimeError('wallet witness overwrites authenticated statement fields')
    write_fields(fixture / 'operation.request.txt', dict(witness, **statement))
    subprocess.run([str(wallet), 'prove', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.proof.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--send-finish', str(fixture)], check=True)
    if value + send_fee > old_value:
        raise RuntimeError('test SEND expectation underflow')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=old_value-value-send_fee))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

send_pair(0, initial, initial_blind, first_value, 31, 37)
first_receipt = (fixture / 'accepted-receipt.id').read_text()

def advance_operation(number):
    advance_pair(number)
    subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                    '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / f'{number}-enabled-top1.boc'),
                    '--query-result', str(fixture / f'operation-{number}-master.result')], check=True)

advance_operation(4)
a_first = initial - first_value - send_fee  # coverage checked by send_pair
send_pair(0, a_first, 31, 251, 47, 43)
second_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(5)

def collect_pair(old_value, old_blind, new_blind, receipts):
    # Wallet selection is sorted here. Host does not duplicate the kernel's
    # strict sorted/unique ID check. Witnesses travel in exactly the same order.
    selected = sorted(receipts)
    fields = dict(secret=223, old_value=old_value, old_blind=old_blind,
                  new_blind=new_blind, aux_blind=83,
                  values=','.join(str(value) for _, value, _ in selected),
                  blinds=','.join(str(blind) for _, _, blind in selected),
                  auxiliaries=','.join(str(89+i) for i in range(len(selected))))
    def write_fields(path, values):
        path.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
    write_fields(fixture / 'operation.wallet.txt',
                 dict(owner=1, selected=''.join(receipt for receipt, _, _ in selected)))
    write_fields(fixture / 'operation.request.txt',
                 dict(fields, kind=2, fee=collect_fee, **limits))
    subprocess.run([str(wallet), 'points', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.points.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--collect-request', str(fixture)], check=True)
    statement = dict(line.split('=', 1) for line in
                     (fixture / 'operation.statement.txt').read_text().splitlines())
    if set(statement) & set(fields):
        raise RuntimeError('COLLECT witness overwrites authenticated statement')
    write_fields(fixture / 'operation.request.txt', dict(fields, **statement))
    subprocess.run([str(wallet), 'prove', str(fixture / 'operation.request.txt'),
                    str(fixture / 'operation.proof.txt')], check=True)
    subprocess.run([str(build / 'test-m3-live'), '--collect-finish', str(fixture)], check=True)
    total = old_value + sum(value for _, value, _ in selected)
    if total < collect_fee or total > 2**64-1:
        raise RuntimeError('COLLECT expected balance out of range')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=total-collect_fee))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

collect_pair(0, 0, 67, [(first_receipt, first_value, 37)])
advance_operation(6)
a_second = a_first - 251 - send_fee  # coverage checked by send_pair
send_pair(0, a_second, 47, 89, 59, 61)
third_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(7)
collect_pair(first_value - collect_fee, 67, 71, [(second_receipt, 251, 43), (third_receipt, 89, 61)])
advance_operation(8)
send_pair(1, first_value + 340 - 2 * collect_fee, 71, 432, 73, 79)
advance_operation(9)
a_final = a_second - 89 - send_fee  # coverage checked by send_pair
(fixture / 'closure.expected.txt').write_text(f'other={a_final}\n')
(fixture / 'closure.owner.txt').write_text('owner=1\n')
subprocess.run([str(build / 'test-m3-live'), '--closure-request', str(fixture)], check=True)
subprocess.run([str(wallet), 'close', str(fixture / 'closure.request.txt'),
                str(fixture / 'closure.proof.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--closure-finish', str(fixture)], check=True)
subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
print('M3 sequence completed under test-constructed configuration, with paired OFF runs. '
      f'Real Native Deposit principal={principal}; A={a_final}, B=0; '
      'refund is a one-way message, delivery not guaranteed.')

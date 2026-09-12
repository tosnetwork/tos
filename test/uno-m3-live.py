#!/usr/bin/env python3
"""Test-owned node fixture. No deployment configuration or permission flag."""
import argparse
import base64
import hashlib
import json
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
p.add_argument('--failed-routing-probe', action='store_true',
               help='run the real fee-routing producer mutation before normal Failed publication')
p.add_argument('--failed-routing-binary', type=Path,
               help='isolated test binary for oracle-removal control only')
a = p.parse_args()
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
subprocess.run([str(build / 'test-m3-live'), '--prepare-m5-return-config' if a.m5_return_route else
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
                   principal=10000000 if a.m5_return_route else 137, outward_fee=17,
                   fee=257, **limits)
    def debit_write(name, values):
        (fixture / name).write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
    debit_write('operation.request.txt',request)
    subprocess.run([str(build / 'test-m3-live'),'--withdrawal-payout-quote',str(fixture)],check=True)
    request['outward_fee'] = int((fixture / 'payout.quote.txt').read_text())
    debit_write('operation.request.txt',request)
    subprocess.run([str(wallet),'withdrawal-points',str(fixture / 'operation.request.txt'),str(fixture / 'operation.points.txt')],check=True)
    subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-request',str(fixture)],check=True)
    statement = dict(line.split('=',1) for line in (fixture / 'operation.statement.txt').read_text().splitlines())
    debit_write('operation.request.txt',dict(request,**statement))
    subprocess.run([str(wallet),'withdrawal-prove',str(fixture / 'operation.request.txt'),str(fixture / 'operation.proof.txt')],check=True)
    subprocess.run([str(build / 'test-m3-live'),'--withdrawal-debit-finish',str(fixture)],check=True)
    debit_write('operation.expected.txt',dict(before=initial,after=initial-request['principal']-request['outward_fee']-request['fee']))
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
            subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
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

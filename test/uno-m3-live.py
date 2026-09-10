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

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build', required=True, type=Path)
a = p.parse_args()
repo = Path(__file__).resolve().parents[1]
build = a.build.resolve()
cache = (build / 'CMakeCache.txt').read_text()
if f'CMAKE_HOME_DIRECTORY:INTERNAL={repo}' not in cache:
    p.error('build belongs to another tree')
if 'TOS_UNO_CRYPTO_NODE_LINK:BOOL=ON' not in cache:
    p.error('real node verification requires TOS_UNO_CRYPTO_NODE_LINK=ON')
fixture = Path(tempfile.mkdtemp(prefix='uno-m3-live-'))
# Reuse the existing test-owned genesis construction without its collation
# scenarios or cleanup. Never import a deployment DB/configuration. This prefix
# contains all schema-dependent fixture code; do not maintain a second copy.
source = (repo / 'test/test-counter-disk-integration.cmake').read_text()
marker = 'set(node_db "${fixture}/db")\nfunction(run_node'
if source.count(marker) != 1:
    raise RuntimeError('genesis preparation boundary changed')
(fixture / '.counter-managed-v1').write_text('M3 test-owned fixture, not a deployment source.\n')
prepare = fixture / 'prepare.cmake'
subprocess.run([str(build / 'test-m3-live'), '--coordinator-data',
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
subprocess.run([str(build / 'test-m3-live'), '--prepare-config', str(fixture)], check=True)
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
wallet = build / 'm3-vector-wallet-target/release/examples/m3-scenario'
if not wallet.is_file():
    raise RuntimeError('build the existing real M3 prover example before the live test')
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
print('Both registrations accepted on real collator/validator with paired OFF runs; transfer sequence pending.')
advance_pair(1)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '1-enabled-top1.boc'),
                '--query-result', str(fixture / 'register-b-master.result')], check=True)
(fixture / 'seed.request.txt').write_text(
    'secret=101\nold_value=50000\nold_blind=23\nnew_blind=1\naux_blind=1\nfee=0\n')
subprocess.run([str(wallet), 'seed', str(fixture / 'seed.request.txt'), str(fixture / 'seed.result.txt')], check=True)
subprocess.run([str(build / 'test-m3-live'), '--test-funding-request', str(fixture)], check=True)
subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)
advance_pair(2)
subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / '2-enabled-top1.boc'),
                '--query-result', str(fixture / 'test-funding-master.result')], check=True)

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
                 dict(witness, kind=1, fee=11, max_balance=1000000, max_value=10000))
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
    if value + 11 > old_value:
        raise RuntimeError('test SEND expectation underflow')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=old_value-value-11))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

send_pair(0, 50000, 23, 137, 31, 37)
first_receipt = (fixture / 'accepted-receipt.id').read_text()

def advance_operation(number):
    advance_pair(number)
    subprocess.run([str(build / 'test-tos-collator'), '-C', str(fixture / 'global.json'),
                    '-D', str(fixture / 'db'), '-w', '-1', '-M', str(fixture / f'{number}-enabled-top1.boc'),
                    '--query-result', str(fixture / f'operation-{number}-master.result')], check=True)

advance_operation(3)
send_pair(0, 49852, 31, 251, 47, 43)
second_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(4)

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
                 dict(fields, kind=2, fee=17, max_balance=1000000, max_value=10000))
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
    if total < 17 or total > 2**64-1:
        raise RuntimeError('COLLECT expected balance out of range')
    write_fields(fixture / 'operation.expected.txt', dict(before=old_value, after=total-17))
    subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

collect_pair(0, 0, 67, [(first_receipt, 137, 37)])
advance_operation(5)
send_pair(0, 49590, 47, 89, 59, 61)
third_receipt = (fixture / 'accepted-receipt.id').read_text()
advance_operation(6)
collect_pair(120, 67, 71, [(second_receipt, 251, 43), (third_receipt, 89, 61)])
advance_operation(7)
send_pair(1, 443, 71, 432, 73, 79)

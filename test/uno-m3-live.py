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
subprocess.run([str(build / 'test-m3-live'), str(fixture)], check=True)

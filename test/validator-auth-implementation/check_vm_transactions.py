"""Run the public P0 binding through native and Rust whole-transaction execution."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'test/auth-extensions'), str(ROOT / 'test/mldsa-auth'),
                str(ROOT / 'test/pq-readiness')]
from cells import Cell, from_boc, read_dict, make_dict
from native import NOW, Emulator, account_data, active_account, config, internal, outgoing, state_init
from protocol import emulator_library
import tx_parity


def main(build, vectors, driver, out, emulator_path=None):
    build, vectors, driver, out = (p.resolve() for p in (build, vectors, driver, out))
    out.mkdir()
    os.environ['EMULATOR_PATH'] = str(emulator_path.resolve() if emulator_path else emulator_library(build))
    asm = out / 'probe.fif'
    sources = [ROOT / 'crypto/smartcont/stdlib.fc', ROOT / 'crypto/smartcont/validator-auth.fc',
               ROOT / 'test/validator-auth-implementation/vm-probe.fc']
    subprocess.run([str(build / 'crypto/func'), '-SPA', '-o', str(asm), *map(str, sources)], check=True)
    run = out / 'compile.fif'
    run.write_text(f'"Asm.fif" include\n"{asm}" include\n2 boc+>B "{out / "probe.boc"}" B>file\n')
    subprocess.run([str(build / 'crypto/fift'), '-I', str(ROOT / 'crypto/fift/lib'), '-s', str(run)], check=True)
    code = from_boc((out / 'probe.boc').read_bytes())
    data = Cell().uint(0, 32)
    account = (0, int.from_bytes(state_init(code, data).hash, 'big'))
    target = (0, 99)
    message = from_boc((vectors / '0/message.boc').read_bytes())
    signature = from_boc((vectors / '0/signature.boc').read_bytes())
    public = int.from_bytes((vectors / '0/key').read_bytes(), 'big')
    broken = Cell().uint(int(signature.bits, 2) ^ 1, 512)
    cpp_rows, rust_rows, details = [], [], []
    tx_parity.outgoing = outgoing
    for capabilities in (1024, 0):
        entries = read_dict(config(16), 32)
        entries[8] = Cell().ref(Cell().uint(0xc4, 8).uint(16, 32).uint(capabilities, 64))
        configuration = make_dict(entries, 32)
        fixture = from_boc((ROOT / 'tosctl/src/executor/real_boc/default_config.boc').read_bytes())
        config_file = out / f'config-{capabilities}.boc'
        config_file.write_bytes(Cell().uint(int(fixture.bits, 2), 256).ref(configuration).boc())
        emulator = Emulator(16)
        emulator.lib.transaction_emulator_set_config.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        emulator.lib.transaction_emulator_set_config.restype = ctypes.c_bool
        assert emulator.lib.transaction_emulator_set_config(emulator.ptr, configuration.b64()), 'fixture-config'
        scenarios = []
        try:
            for name, sig, amount, balance in [
                ('accept-relay', signature, 1_000_000_000, 100_000_000_000),
                ('reject-signature', broken, 1_000_000_000, 100_000_000_000),
                ('action-rollback', signature, 200_000_000_000, 100_000_000_000),
                ('accept-second-target', signature, 100_000_000, 100_000_000_000),
            ]:
                label = f'{capabilities}-{name}'
                body = Cell().ref(message).ref(sig).uint(public, 256).coins(amount).addr(target)
                shard = active_account(account, code, data, balance)
                incoming = internal((0, 17), account, body, 1_000_000_000)
                result = emulator.send(shard, incoming)
                assert result['success'], (label, 'emulator setup', result)
                tx = from_boc(result['transaction'])
                after = from_boc(result['shard_account'])
                observed = result['details']
                expected_exit = 6 if capabilities == 0 else 401 if name == 'reject-signature' else 0
                assert observed['exit'] == expected_exit, (label, observed)
                expected_action = 37 if capabilities and name == 'action-rollback' else 0
                assert (observed.get('action') or {}).get('code', 0) == expected_action, (label, observed)
                accepted = expected_exit == 0 and expected_action == 0
                final_data, _ = account_data(after)
                assert final_data.hash == Cell().uint(int(accepted), 32).hash, (label, 'data rollback')
                assert len(outgoing(tx)) == int(accepted), (label, 'outgoing messages')
                cpp_rows.append(tx_parity.transcript(label, observed, tx, after.refs[0]))
                scenarios.append('\t'.join([label, str(NOW), str(emulator.lt), shard.refs[0].boc().hex(), incoming.boc().hex(), '-']))
                details.append({'case': label, **observed})
        finally:
            emulator.close()
        scenario_file = out / f'scenarios-{capabilities}.tsv'
        scenario_file.write_text('\n'.join(scenarios) + '\n')
        result = subprocess.run([str(driver), str(config_file), str(scenario_file)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Rust transaction driver: ' + result.stderr)
        rust_rows.extend(result.stdout.splitlines())
    result = tx_parity.report(cpp_rows, rust_rows)
    result['details'] = details
    result['contract_code_hash'] = code.hash.hex()
    result['source_sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (out / 'cpp.tsv').write_text('\n'.join(cpp_rows) + '\n')
    (out / 'rust.tsv').write_text('\n'.join(rust_rows) + '\n')
    (out / 'transactions.json').write_text(json.dumps(result, indent=2) + '\n')
    assert result['success'], result['differences']
    print('PASS: 8 native/Rust transactions; capability, real signature, relay and action rollback')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('build', 'vectors', 'driver', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--emulator', type=Path)
    args = parser.parse_args()
    main(args.build, args.vectors, args.driver, args.out, args.emulator)

"""Native transaction-emulator adapter; signature checks are never disabled."""
import base64
import ctypes
import json
import os
import subprocess
from pathlib import Path
from cells import Cell, from_boc, read_dict, make_dict

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_780_000_000
GLOBAL_ID = 42


def compile_contract(name, output):
    source = ROOT / 'crypto/smartcont' / name
    output = Path(output)
    asm = output.with_suffix('.fif')
    if name.endswith('.fc'):
        subprocess.run([os.environ['FUNC_PATH'], '-SPA', '-o', str(asm),
                        str(ROOT / 'crypto/smartcont/stdlib.fc'), str(source)], check=True, capture_output=True)
    else:
        env = dict(os.environ, TOL_STDLIB=str(ROOT / 'crypto/smartcont/tol-stdlib'))
        subprocess.run([os.environ['TOL_PATH'], '-o', str(asm), str(source)], check=True, env=env, capture_output=True)
    run = output.with_suffix('.run.fif')
    run.write_text(f'"Asm.fif" include\n"{asm}" include\n2 boc+>B "{output}" B>file\n')
    subprocess.run([os.environ['FIFT_PATH'], '-I', f'{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont',
                    '-s', str(run)], check=True, capture_output=True)
    return from_boc(output.read_bytes())


def config(global_version=6):
    fixture = from_boc((ROOT / 'tosctl/src/executor/real_boc/default_config.boc').read_bytes())
    entries = read_dict(fixture.refs[0], 32)
    entries[0] = Cell().ref(Cell().uint(int(fixture.bits, 2), 256))
    old = entries[8].refs[0].slice()
    assert old.uint(8) == 0xc4
    old.uint(32)
    caps = old.uint(64)
    entries[8] = Cell().ref(Cell().uint(0xc4, 8).uint(global_version, 32).uint(caps, 64))
    entries[19] = Cell().ref(Cell().sint(GLOBAL_ID, 32))
    return make_dict(entries, 32)


def state_init(code, data):
    return Cell().uint(0, 2).maybe(code).maybe(data).uint(0, 1)


def active_account(address, code, data, balance=100_000_000_000):
    init = state_init(code, data)
    account = (Cell().uint(1, 1).addr(address).varuint(0, 7).varuint(0, 7)
               .uint(0, 3).uint(NOW, 32).uint(0, 1).uint(0, 64).coins(balance)
               .uint(0, 1).uint(1, 1))
    account.bits += init.bits
    account.refs.extend(init.refs)
    return Cell().uint(0, 256).uint(0, 64).ref(account)


def account_data(shard):
    s = shard.refs[0].slice()
    assert s.uint(1)
    s.addr(); s.varuint(7); s.varuint(7)
    extra = s.uint(3)
    if extra == 1: s.uint(256)
    else: assert extra == 0
    s.uint(32)
    if s.uint(1): s.coins()
    s.uint(64)
    balance = s.coins()
    s.maybe()
    assert s.uint(1) == 1, 'account must remain active'
    assert s.uint(2) == 0
    code = s.maybe()
    data = s.maybe()
    s.maybe()
    s.end()
    return data, balance


def internal(sender, destination, body, value=1_000_000_000, bounced=False):
    return (Cell().uint(5 if bounced else 4, 4).addr(sender).addr(destination).coins(value)
            .uint(0, 1).coins(0).coins(0).uint(0, 64).uint(NOW, 32)
            .uint(0, 1).uint(1, 1).ref(body))


def external(destination, body):
    return Cell().uint(8, 4).addr(destination).coins(0).uint(0, 1).uint(1, 1).ref(body)


def transaction_details(transaction):
    # The description is the third reference, after messages and HASH_UPDATE.
    c = transaction.refs[2].slice()
    assert c.uint(4) == 0
    c.uint(1)  # credit_first
    if c.uint(1):
        c.coins()
        if c.uint(1): c.coins()
        if c.uint(1): c.uint(1)
    if c.uint(1):
        if c.uint(1): c.coins()
        c.coins(); c.maybe()
    if not c.uint(1):
        return {'exit': None, 'skipped': True, 'reason': c.bits[:3]}
    compute_success = bool(c.uint(1))
    c.uint(2); c.coins()
    vm = c.ref().slice()
    gas = vm.varuint(7); gas_limit = vm.varuint(7)
    if vm.uint(1): vm.varuint(3)
    vm.sint(8)
    exit_code = vm.sint(32)
    action = c.maybe()
    aborted = bool(c.uint(1))
    result = {'exit': exit_code, 'gas': gas, 'gas_limit': gas_limit,
              'compute_success': compute_success, 'aborted': aborted, 'action': None}
    if action:
        a = action.slice()
        ok = bool(a.uint(1)); a.uint(2)
        if a.uint(1): a.uint(1)
        if a.uint(1): a.coins()
        if a.uint(1): a.coins()
        result['action'] = {'success': ok, 'code': a.sint(32)}
    return result


def outgoing(transaction):
    s = transaction.refs[0].slice()
    s.maybe()  # inbound message
    return [v.refs[0] for _, v in sorted(read_dict(s.maybe(), 15).items())]


class Emulator:
    def __init__(self, global_version=6):
        self.lib = ctypes.CDLL(os.environ['EMULATOR_PATH'])
        self.lib.transaction_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.lib.transaction_emulator_create.restype = ctypes.c_void_p
        self.lib.transaction_emulator_emulate_transaction.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        self.lib.transaction_emulator_emulate_transaction.restype = ctypes.c_void_p
        self.lib.string_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_set_unixtime.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib.transaction_emulator_set_lt.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.lib.transaction_emulator_set_ignore_chksig.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        self.lib.emulator_set_verbosity_level(0)
        self.ptr = self.lib.transaction_emulator_create(config(global_version).b64(), 1)
        assert self.ptr, 'native emulator must load the test configuration'
        self.lib.transaction_emulator_set_unixtime(self.ptr, NOW)
        self.lib.transaction_emulator_set_ignore_chksig(self.ptr, False)
        self.lt = 1_000_000

    def close(self):
        if self.ptr:
            self.lib.transaction_emulator_destroy(self.ptr)
            self.ptr = None

    def send(self, shard, message):
        self.lt += 1_000_000
        self.lib.transaction_emulator_set_lt(self.ptr, self.lt)
        ptr = self.lib.transaction_emulator_emulate_transaction(self.ptr, shard.b64(), message.b64())
        assert ptr
        try:
            result = json.loads(ctypes.string_at(ptr))
        finally:
            self.lib.string_destroy(ptr)
        if result['success']:
            result['details'] = transaction_details(from_boc(result['transaction']))
        return result

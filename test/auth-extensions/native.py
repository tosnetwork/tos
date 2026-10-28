"""Native transaction-emulator adapter; signature checks are never disabled."""

import ctypes
import json
import os
import re
import subprocess
from pathlib import Path

from cells import Cell, from_boc, make_dict, read_dict

ROOT = Path(__file__).resolve().parents[2]
NOW = 1_780_000_000
GLOBAL_ID = 42
CURRENT_GLOBAL_VERSION = 16


def compile_contract(name, output):
    source = ROOT / "crypto/smartcont" / name
    output = Path(output)
    asm = output.with_suffix(".fif")
    if name.endswith(".fc"):
        subprocess.run(
            [
                os.environ["FUNC_PATH"],
                "-SPA",
                "-o",
                str(asm),
                str(ROOT / "crypto/smartcont/stdlib.fc"),
                str(source),
            ],
            check=True,
            capture_output=True,
        )
    else:
        env = dict(os.environ, TOL_STDLIB=str(ROOT / "crypto/smartcont/tol-stdlib"))
        subprocess.run(
            [os.environ["TOL_PATH"], "-o", str(asm), str(source)],
            check=True,
            env=env,
            capture_output=True,
        )
    run = output.with_suffix(".run.fif")
    run.write_text(f'"Asm.fif" include\n"{asm}" include\n2 boc+>B "{output}" B>file\n')
    subprocess.run(
        [
            os.environ["FIFT_PATH"],
            "-I",
            f"{ROOT}/crypto/fift/lib:{ROOT}/crypto/smartcont",
            "-s",
            str(run),
        ],
        check=True,
        capture_output=True,
    )
    return from_boc(output.read_bytes())


def size_limits(max_msg_cells, max_msg_bits=1 << 21):
    """ConfigParam 43, size_limits_config#01, as the account reads it.

    Only max_msg_bits and max_msg_cells are consulted by the contract, but the
    whole constructor is written so the emulator can unpack it into the
    configuration tuple the contract indexes.
    """
    return (
        Cell()
        .uint(0x01, 8)
        .uint(max_msg_bits, 32)
        .uint(max_msg_cells, 32)
        .uint(1000, 32)
        .uint(512, 16)
        .uint(65535, 32)
        .uint(512, 16)
    )


# size_limits_config_v3#03 in crypto/block/block.tlb, field by field. The
# Maybe uint32 is spelled as its presence bit and its value.
GENESIS_SIZE_LIMIT_FIELDS = (
    ("max_msg_bits", 32),
    ("max_msg_cells", 32),
    ("max_library_cells", 32),
    ("max_vm_data_depth", 16),
    ("max_ext_msg_size", 32),
    ("max_ext_msg_depth", 16),
    ("max_acc_state_cells", 32),
    ("max_mc_acc_state_cells", 32),
    ("max_acc_public_libraries", 32),
    ("defer_out_queue_size_limit", 32),
    ("max_msg_extra_currencies", 32),
    ("max_acc_fixed_prefix_length", 8),
    ("acc_state_cells_for_storage_dict", 32),
    ("has_max_transaction_library_loads", 1),
    ("max_transaction_library_loads", 32),
    ("max_total_msg_bits", 32),
    ("max_total_msg_cells", 32),
    ("out_msg_queue_size_hard_limit", 32),
    ("out_msg_queue_size_soft_limit", 32),
)


def genesis_size_limits():
    """ConfigParam 43 exactly as crypto/smartcont/gen-zerostate.fif writes it.

    The committed emulator fixture carries an older constructor with other
    account-state limits, so tests about those limits load genesis instead.
    Returns the cell and its fields by name.
    """
    genesis = (ROOT / "crypto/smartcont/gen-zerostate.fif").read_text()
    blocks = re.findall(r"<b x\{03\} s,(.*?)b> 43 config!", genesis, re.DOTALL)
    assert len(blocks) == 1, "genesis must write ConfigParam 43 exactly once"
    values = [(int(v), int(w)) for v, w in re.findall(r"(\d+) (\d+) u,", blocks[0])]
    assert [w for _, w in values] == [w for _, w in GENESIS_SIZE_LIMIT_FIELDS], values
    cell = Cell().uint(0x03, 8)
    for value, width in values:
        cell.uint(value, width)
    fields = {name: value for (name, _), (value, _) in zip(GENESIS_SIZE_LIMIT_FIELDS, values)}
    return cell, fields


def config(global_version=CURRENT_GLOBAL_VERSION, max_msg_cells=None, limits=None):
    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    entries = read_dict(fixture.refs[0], 32)
    entries[0] = Cell().ref(Cell().uint(int(fixture.bits, 2), 256))
    old = entries[8].refs[0].slice()
    assert old.uint(8) == 0xC4
    old.uint(32)
    caps = old.uint(64)
    entries[8] = Cell().ref(Cell().uint(0xC4, 8).uint(global_version, 32).uint(caps, 64))
    entries[19] = Cell().ref(Cell().sint(GLOBAL_ID, 32))
    if max_msg_cells is not None:
        entries[43] = Cell().ref(size_limits(max_msg_cells))
    if limits is not None:
        assert max_msg_cells is None
        entries[43] = Cell().ref(limits)
    return make_dict(entries, 32)


def state_init(code, data, library=None):
    return Cell().uint(0, 2).maybe(code).maybe(data).maybe(library)


def distinct_cells(*roots):
    """Distinct cells under the roots together, the executor's state count."""
    seen, stack = set(), [r for r in roots if r is not None]
    while stack:
        c = stack.pop()
        if c.hash not in seen:
            seen.add(c.hash)
            stack.extend(c.refs)
    return len(seen)


def uninitialized_account(address, balance=100_000_000_000):
    """A funded account with no code yet (account_uninit$00)."""
    account = (
        Cell()
        .uint(1, 1)
        .addr(address)
        .varuint(0, 7)
        .varuint(0, 7)
        .uint(0, 3)
        .uint(NOW, 32)
        .uint(0, 1)
        .uint(0, 64)
        .coins(balance)
        .uint(0, 1)
        .uint(0, 2)
    )
    return Cell().uint(0, 256).uint(0, 64).ref(account)


def active_account(address, code, data, balance=100_000_000_000):
    init = state_init(code, data)
    account = (
        Cell()
        .uint(1, 1)
        .addr(address)
        .varuint(0, 7)
        .varuint(0, 7)
        .uint(0, 3)
        .uint(NOW, 32)
        .uint(0, 1)
        .uint(0, 64)
        .coins(balance)
        .uint(0, 1)
        .uint(1, 1)
    )
    account.bits += init.bits
    account.refs.extend(init.refs)
    return Cell().uint(0, 256).uint(0, 64).ref(account)


def account_data(shard):
    s = shard.refs[0].slice()
    assert s.uint(1)
    s.addr()
    s.varuint(7)
    s.varuint(7)
    extra = s.uint(3)
    if extra == 1:
        s.uint(256)
    else:
        assert extra == 0
    s.uint(32)
    if s.uint(1):
        s.coins()
    s.uint(64)
    balance = s.coins()
    s.maybe()
    assert s.uint(1) == 1, "account must remain active"
    assert s.uint(2) == 0
    _code = s.maybe()
    data = s.maybe()
    s.maybe()
    s.end()
    return data, balance


def internal(sender, destination, body, value=1_000_000_000, bounced=False):
    return (
        Cell()
        .uint(5 if bounced else 4, 4)
        .addr(sender)
        .addr(destination)
        .coins(value)
        .uint(0, 1)
        .coins(0)
        .coins(0)
        .uint(0, 64)
        .uint(NOW, 32)
        .uint(0, 1)
        .uint(1, 1)
        .ref(body)
    )


def external(destination, body, init=None):
    """ext_in_msg_info; a StateInit, when given, and the body each in a reference."""
    message = Cell().uint(8, 4).addr(destination).coins(0)
    if init is None:
        message.uint(0, 1)
    else:
        message.uint(1, 1).uint(1, 1).ref(init)
    return message.uint(1, 1).ref(body)


def transaction_details(transaction):
    # The description is the third reference, after messages and HASH_UPDATE.
    c = transaction.refs[2].slice()
    assert c.uint(4) == 0
    c.uint(1)  # credit_first
    if c.uint(1):
        c.coins()
        if c.uint(1):
            c.coins()
        if c.uint(1):
            c.uint(1)
    if c.uint(1):
        if c.uint(1):
            c.coins()
        c.coins()
        c.maybe()
    if not c.uint(1):
        return {"exit": None, "skipped": True, "reason": c.bits[:3]}
    compute_success = bool(c.uint(1))
    c.uint(2)
    c.coins()
    vm = c.ref().slice()
    gas = vm.varuint(7)
    gas_limit = vm.varuint(7)
    if vm.uint(1):
        vm.varuint(3)
    vm.sint(8)
    exit_code = vm.sint(32)
    action = c.maybe()
    aborted = bool(c.uint(1))
    result = {
        "exit": exit_code,
        "gas": gas,
        "gas_limit": gas_limit,
        "compute_success": compute_success,
        "aborted": aborted,
        "action": None,
    }
    if action:
        a = action.slice()
        ok = bool(a.uint(1))
        a.uint(2)
        if a.uint(1):
            a.uint(1)
        if a.uint(1):
            a.coins()
        if a.uint(1):
            a.coins()
        code = a.sint(32)
        if a.uint(1):
            a.sint(32)
        result["action"] = {"success": ok, "code": code, "actions": a.uint(16)}
    return result


def outgoing(transaction):
    s = transaction.refs[0].slice()
    s.maybe()  # inbound message
    return [v.refs[0] for _, v in sorted(read_dict(s.maybe(), 15).items())]


class Emulator:
    def __init__(
        self,
        global_version=CURRENT_GLOBAL_VERSION,
        max_msg_cells=None,
        vm_log_verbosity=1,
        limits=None,
    ):
        self._initialize(config(global_version, max_msg_cells, limits), vm_log_verbosity)

    @classmethod
    def from_config(cls, configuration, vm_log_verbosity=1):
        """Load the supplied config dictionary without synthesizing or changing fields."""
        emulator = cls.__new__(cls)
        emulator._initialize(configuration, vm_log_verbosity)
        return emulator

    def _initialize(self, configuration, vm_log_verbosity):
        self.lib = ctypes.CDLL(os.environ["EMULATOR_PATH"])
        self.lib.transaction_emulator_create.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self.lib.transaction_emulator_create.restype = ctypes.c_void_p
        self.lib.transaction_emulator_emulate_transaction.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self.lib.transaction_emulator_emulate_transaction.restype = ctypes.c_void_p
        self.lib.string_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_destroy.argtypes = [ctypes.c_void_p]
        self.lib.transaction_emulator_set_unixtime.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.lib.transaction_emulator_set_lt.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        self.lib.transaction_emulator_set_ignore_chksig.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        self.lib.emulator_set_verbosity_level(0)
        self.ptr = self.lib.transaction_emulator_create(configuration.b64(), vm_log_verbosity)
        assert self.ptr, "native emulator must load the test configuration"
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
        ptr = self.lib.transaction_emulator_emulate_transaction(
            self.ptr, shard.b64(), message.b64()
        )
        assert ptr
        try:
            result = json.loads(ctypes.string_at(ptr))
        finally:
            self.lib.string_destroy(ptr)
        if result["success"]:
            result["details"] = transaction_details(from_boc(result["transaction"]))
        return result

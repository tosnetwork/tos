"""Native/Rust transaction error boundaries, bounded in separate processes.

Uses public deterministic fixtures. Original inconsistent storage fixtures remain
covered by precompiled_external; these root controls derive valid input storage
statistics directly from the original AccountStorage graph.
"""

import argparse
import ctypes
import importlib.util
import json
import os
import resource
import signal
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "precompiled", root / "test/executor-parity/precompiled_external.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
parser = argparse.ArgumentParser(
    description="Compare transaction rejection classes and accepted complete roots through both C APIs."
)
parser.add_argument("--native", type=Path)
parser.add_argument("--rust", type=Path)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(exist_ok=False)
if args.worker:
    resource.setrlimit(resource.RLIMIT_AS, (4 * 1024**3, 4 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024**2, 16 * 1024**2))

base = native.config(16)
over = (m.gas_limit(base) - 1).bit_length()


def consistent(shard):
    a = shard.refs[0]
    s = a.slice()
    present = s.uint(1)
    address = s.addr()
    s.varuint(7)
    s.varuint(7)
    remaining = s.bits
    s.uint(3)
    s.uint(32)
    assert s.uint(1) == 0
    storage = Cell(bits=s.bits, refs=s.refs)
    seen = {}

    def visit(c):
        if c.hash in seen:
            return
        seen[c.hash] = len(c.bits)
        for r in c.refs:
            visit(r)

    visit(storage)
    updated = (
        Cell().uint(present, 1).addr(address).varuint(len(seen), 7).varuint(sum(seen.values()), 7)
    )
    updated.bits += remaining
    updated.refs = list(a.refs)
    return Cell(bits=shard.bits, refs=[updated])


cases = []
for precompiled in (False, True):
    for external in (False, True):
        for kind in (
            "burn-before-accept",
            "burn-after-accept",
            "commit-then-burn",
            "throw13",
            "accept",
        ):
            if kind == "throw13":
                contract = Cell().raw(bytes([0xF2, 0x0D]))
            elif kind == "accept":
                contract = m.ACCEPT
            else:
                burn = m.burn_then_accept(over)
                prefix = (
                    m.ACCEPT
                    if kind == "burn-after-accept"
                    else Cell().raw(bytes([0xF8, 0x00, 0xF8, 0x0F]))
                )
                contract = (
                    burn
                    if kind == "burn-before-accept"
                    else Cell(bits=prefix.bits + burn.bits, refs=burn.refs)
                )
            cfg = m.with_precompiled(base, contract, 0) if precompiled else base
            label = f"{'precompiled' if precompiled else 'ordinary'}-{'external' if external else 'internal'}-{kind}"
            cases.append(
                (
                    label,
                    cfg,
                    consistent(native.active_account(m.PROBE, contract, Cell())),
                    native.external(m.PROBE, Cell())
                    if external
                    else native.internal(m.SENDER, m.PROBE, Cell()),
                )
            )
cases.append(
    (
        "external-precompiled-nogas",
        m.with_precompiled(base, m.ACCEPT, (1 << 64) - 1),
        consistent(native.active_account(m.PROBE, m.ACCEPT, Cell())),
        native.external(m.PROBE, Cell()),
    )
)
storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1).uint(0, 2)
uninit = (
    Cell()
    .uint(1, 1)
    .addr(m.PROBE)
    .varuint(1, 7)
    .varuint(len(storage.bits), 7)
    .uint(0, 3)
    .uint(native.NOW, 32)
    .uint(0, 1)
)
uninit.bits += storage.bits
cases.append(
    ("external-no-state", base, Cell().uint(0, 320).ref(uninit), native.external(m.PROBE, Cell()))
)

# A StateInit whose address hash does not match the original uninitialized
# account reaches the BadState skip, distinct internally from NoState/NoGas.
bad_init = native.state_init(m.ACCEPT, Cell())
bad_message = (
    Cell().uint(8, 4).addr(m.PROBE).coins(0).uint(3, 2).ref(bad_init).uint(1, 1).ref(Cell())
)
cases.append(("external-bad-state", base, Cell().uint(0, 320).ref(uninit), bad_message))

# A program cannot spoof real OOG by THROWANY(-14): native range-checks
# the exception number and reports integer-out-of-range (5).
negative_throw = Cell().raw(bytes([0x80, 0xF2, 0xF2, 0xF0]))
cases.append(
    (
        "precompiled-external-negative-throwany",
        m.with_precompiled(base, negative_throw, 0),
        consistent(native.active_account(m.PROBE, negative_throw, Cell())),
        native.external(m.PROBE, Cell()),
    )
)

# Native's ConfigParam45 optimization applies only to ordinary transactions.
# These are real masterchain fundamental tick/tock accounts (CP31), with a
# small special gas limit so genuine OOG is deterministic and bounded.
tentries = read_dict(native.config(16), 32)
tentries.pop(45, None)
prices = tentries[20].refs[0]
offset = 136 if int(prices.bits[:8], 2) == 0xD1 else 0
assert int(prices.bits[offset : offset + 8], 2) == 0xDE
offset += 8 + 2 * 64
tentries[20] = Cell().ref(
    Cell(
        bits=prices.bits[:offset] + format(2000, "064b") + prices.bits[offset + 64 :],
        refs=prices.refs,
    )
)
tentries[31] = Cell().ref(Cell().maybe(make_dict({0x4545: Cell()}, 256)))
tick_config = make_dict(tentries, 32)
for is_tock in (False, True):
    for burns in (False, True):
        contract = m.burn_then_accept(12) if burns else m.ACCEPT
        init = Cell().uint(0, 1).uint(1, 1).uint(3, 2).maybe(contract).maybe(Cell()).uint(0, 1)
        storage = Cell().uint(0, 64).coins(100_000_000_000).uint(0, 1).uint(1, 1)
        storage.bits += init.bits
        storage.refs.extend(init.refs)
        account = (
            Cell()
            .uint(1, 1)
            .addr((-1, 0x4545))
            .varuint(0, 7)
            .varuint(0, 7)
            .uint(0, 3)
            .uint(native.NOW, 32)
            .uint(0, 1)
        )
        account.bits += storage.bits
        account.refs = list(storage.refs)
        shard = consistent(Cell().uint(0, 320).ref(account))
        for usage in (None, 0, (1 << 64) - 1):
            configuration = (
                tick_config if usage is None else m.with_precompiled(tick_config, contract, usage)
            )
            label = f"{'tock' if is_tock else 'tick'}-{'oog' if burns else 'accept'}-{usage}"
            # No inbound message is supplied to this C API; the empty cell is
            # only a retained fixture marker for the common artifact layout.
            cases.append((label, configuration, shard, Cell()))


def tick_details(transaction, is_tock):
    c = transaction.refs[2].slice()
    assert c.uint(3) == 1 and bool(c.uint(1)) == is_tock
    c.coins()
    if c.uint(1):
        c.coins()
    if c.uint(1):
        c.uint(1)
    assert c.uint(1) == 1, "tick/tock must execute a VM compute phase"
    success = bool(c.uint(1))
    c.uint(2)
    c.coins()
    vm = c.ref().slice()
    gas = vm.varuint(7)
    limit = vm.varuint(7)
    if vm.uint(1):
        vm.varuint(3)
    vm.sint(8)
    exit_code = vm.sint(32)
    c.maybe()
    aborted = bool(c.uint(1))
    return dict(exit=exit_code, gas=gas, gas_limit=limit, compute_success=success, aborted=aborted)


def send_tick(emulator, shard, is_tock):
    fn = emulator.lib.transaction_emulator_emulate_tick_tock_transaction
    fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
    fn.restype = ctypes.c_void_p
    emulator.lib.transaction_emulator_set_lt(emulator.ptr, 2_000_000)
    raw = fn(emulator.ptr, shard.b64(), is_tock)
    assert raw
    try:
        result = json.loads(ctypes.string_at(raw))
    finally:
        emulator.lib.string_destroy(raw)
    if result["success"]:
        result["details"] = tick_details(from_boc(result["transaction"]), is_tock)
    return result


def outcome(r):
    if r["success"]:
        tx = from_boc(r["transaction"])
        after = from_boc(r["shard_account"])
        return ["accepted", tx.hash.hex(), after.refs[0].hash.hex(), after.hash.hex()]
    assert "transaction" not in r and "shard_account" not in r
    if r.get("external_not_accepted") is True:
        assert isinstance(r.get("vm_exit_code"), int)
        return ["unaccepted", r["vm_exit_code"]]
    assert "vm_exit_code" not in r
    error = r.get("error", "")
    if (
        "cannot create compute phase of a new transaction" in error
        or error == "Precompiled fallback exhausted gas during compute phase"
    ):
        return ["precompiled-compute-failed"]
    raise AssertionError("unknown failure: " + str(r))


def run_worker(library):
    os.environ["EMULATOR_PATH"] = str(library.resolve())
    report = []
    for label, cfg, shard, message in cases:
        for kind, value in [("config", cfg), ("shard", shard), ("message", message)]:
            (out / (label + "-" + kind + ".boc")).write_bytes(value.boc())
        em = native.Emulator.from_config(cfg)
        try:
            result = (
                send_tick(em, shard, label.startswith("tock-"))
                if label.startswith(("tick-", "tock-"))
                else em.send(shard, message)
            )
        finally:
            em.close()
        (out / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        observed = outcome(result)
        # Independent classifications ensure two identically wrong adapters cannot
        # pass by collapsing every failure or accepting every input.
        if label.endswith("nogas") or label in ("external-no-state", "external-bad-state"):
            expected = ["unaccepted", 0]
        elif label.startswith("precompiled-") and "burn" in label:
            expected = ["precompiled-compute-failed"]
        elif label.endswith("negative-throwany"):
            expected = ["unaccepted", 5]
        elif "-external-throw13" in label:
            expected = ["unaccepted", 13]
        elif label == "ordinary-external-burn-before-accept":
            expected = ["unaccepted", -14]
        else:
            expected = ["accepted"]
        assert observed[: len(expected)] == expected, (label, observed, expected)
        if result["success"]:
            details = result["details"]
            if label.startswith(("tick-", "tock-")):
                burns = "-oog-" in label
                assert details["exit"] == (-14 if burns else 0), (label, details)
                assert details["gas"] == (2000 if burns else 31), (label, details)
                assert details["compute_success"] == (not burns), (label, details)
                assert details["aborted"] == burns, (label, details)
                report.append(dict(name=label, outcome=observed))
                continue
            expected_exit = (
                13
                if label.endswith("throw13")
                else 0
                if label.endswith("accept") and "burn" not in label
                else -14
            )
            assert details["exit"] == expected_exit, (label, details)
            if label.startswith("precompiled-"):
                assert details["gas"] == 0, (label, details)
        report.append(dict(name=label, outcome=observed))
    for transaction_kind in ("tick", "tock"):
        for execution in ("accept", "oog"):
            prefix = f"{transaction_kind}-{execution}-"
            outcomes = [row["outcome"] for row in report if row["name"].startswith(prefix)]
            assert len(outcomes) == 3 and all(value == outcomes[0] for value in outcomes), prefix
    (out / "outcomes.json").write_text(json.dumps(report, indent=2) + "\n")


def interrupted(signum, frame):
    raise KeyboardInterrupt(f"interrupted by signal {signum}")


def supervised(library, folder):
    child = None
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    mask = None
    try:
        # Mask delivery until the parent owns the child handle; restore in the child
        # before entering native code. No descendant survives parent interruption.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(previous))
        try:
            with (out / (folder.name + ".log")).open("wb") as log:

                def child_signals():
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)

                child = subprocess.Popen(
                    [
                        sys.executable,
                        str(Path(__file__).resolve()),
                        "--worker",
                        str(library.resolve()),
                        "--output",
                        str(folder),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    preexec_fn=child_signals,
                )
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                mask = None
                assert child.wait(timeout=90) == 0, f"{folder.name} worker failed; see retained log"
        finally:
            cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set(previous))
            try:
                if child is not None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


if args.worker:
    run_worker(args.worker)
else:
    parser.error("--native and --rust are required") if not args.native or not args.rust else None
    for backend, library in [("native", args.native), ("rust", args.rust)]:
        supervised(library, out / backend)
    left = json.loads((out / "native/outcomes.json").read_text())
    right = json.loads((out / "rust/outcomes.json").read_text())
    assert len(left) == len(right) == 36
    assert left == right, "native/Rust transaction outcomes differ"
    # Every oracle uses exactly the same complete original inputs and config.
    for label, _, _, _ in cases:
        for kind in ["config", "shard", "message"]:
            name = label + "-" + kind + ".boc"
            assert (out / "native" / name).read_bytes() == (out / "rust" / name).read_bytes(), name
    (out / "summary.json").write_text(json.dumps(dict(cases=36, matched=True), indent=2) + "\n")
    print("PASS: 36 transaction outcomes; accepted transaction/Account/ShardAccount roots match")

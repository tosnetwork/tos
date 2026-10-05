"""Real LMS external fee -> SLH module -> complete PQ-only receiver; candidate limits."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
sys.path.insert(0, str(ROOT / "test/rescue-fee-gate"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from test_auth_policy import policy as global_policy  # noqa: E402
from test_fee_identity import vault_data  # noqa: E402
from test_identity import chain  # noqa: E402
from test_receiver_auth import request  # noqa: E402
from test_rescue_e2e import Signers, digest  # noqa: E402
from test_state import fee, state  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--credit-probe",
        action="store_true",
        help="Measure required credit without changing protocol defaults",
    )
    p.add_argument("--gas-trace", action="store_true", help="Retain instruction gas accounting")
    options = p.parse_args()
    out = options.output
    out.mkdir(parents=True, exist_ok=True)
    # Public deterministic test key only. Never use this tree or seed for funds.
    tree = out / "PUBLIC-TEST-ONLY-lms-tree"
    args = ["44" * 32, "55" * 16, "20", str(tree)]
    pub = bytes.fromhex(
        subprocess.run(
            [os.environ["LMS_TOOL"], "keygen", *args], check=True, capture_output=True, text=True
        ).stdout.strip()
    )
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for src in (ROOT / "crypto/smartcont").glob("wallet-v5r2-*.fc"):
            shutil.copyfile(src, work / src.name)
        for name in ["auth-policy.fc", "pq.fc", "pq-bytes.fc", "wallet-v5-action-list.fc"]:
            shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
        vault = native.compile_contract(str(work / "wallet-v5r2-fee-vault.fc"), out / "vault.boc")
        const = f'cell compiled_vault() asm "B{{{vault.boc().hex()}}} B>boc PUSHREF";\n'
        (work / "module.fc").write_text(
            '#include "wallet-v5r2-module.fc";\n'
            + const
            + "cell r2module_vault_code() inline { return compiled_vault(); }\n"
        )
        module = native.compile_contract(str(work / "module.fc"), out / "module.boc")
        (work / "wallet.fc").write_text(
            '#include "wallet-v5r2-code.fc";\n'
            + const
            + f"int r2wallet_network() inline {{ return 123; }}\nint r2wallet_module_hash() inline {{ return 0x{module.hash.hex()}; }}\ncell r2wallet_vault_code() inline {{ return compiled_vault(); }}\n"
        )
        wallet = native.compile_contract(str(work / "wallet.fc"), out / "wallet.boc")
        signer = Signers(work)
        md = (
            Cell()
            .uint(1, 8)
            .sint(42, 32)
            .uint(123, 256)
            .uint(1, 8)
            .ref(chain(signer.ml_pk.read_bytes()))
            .raw(signer.slh_pk)
            .uint(1, 8)
        )
        mi = native.state_init(module, md)
        root = int.from_bytes(mi.hash, "big")
        metadata = fee(key=chain(pub), epoch0=native.NOW - 2 * 3600 - 10)
        wd = state(mi, metadata=metadata, mode=2, seqno=0, epoch=1, primary=0, rescue=0, retired=0)
        wa = (0, int.from_bytes(native.state_init(wallet, wd).hash, "big"))
        vd = vault_data(metadata=metadata, wallet=wa[1], module=root)
        vi = native.state_init(vault, vd)
        va = (0, int.from_bytes(vi.hash, "big"))
        (work / "recipient.fc").write_text(
            "() recv_internal(slice body) impure { set_data(begin_cell().store_uint(get_data().begin_parse().preload_uint(32) + 1, 32).end_cell()); }\n"
        )
        recipient_code = native.compile_contract(str(work / "recipient.fc"), out / "recipient.boc")
        recipient_data = Cell().uint(0, 32)
        recipient = (
            0,
            int.from_bytes(native.state_init(recipient_code, recipient_data).hash, "big"),
        )
        payment = native.internal(wa, recipient, Cell(), value=1_000_000_000)
        actions = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(payment)
        req = request(root=root, role=2, account=wa, body=Cell().uint(0x45584543, 32).ref(actions))
        submit = Cell().uint(0x53554233, 32).ref(req).ref(chain(signer.slh(digest(req))))
        intent = (
            Cell()
            .uint(0x46454534, 32)
            .raw(b"TOS-RESCUE-FEE-v1")
            .uint(1, 8)
            .addr(va)
            .uint(vd.slice().uint(8 + 32 + 256) & ((1 << 256) - 1), 256)
            .uint(8, 32)
            .uint(native.NOW + 600, 32)
            .coins(5_000_000_000)
            .ref(submit)
        )
        msg = work / "message"
        sig = work / "signature"
        msg.write_bytes(intent.hash)
        subprocess.run(
            [os.environ["LMS_TOOL"], "sign", *args, "8", str(msg), "66" * 32, str(sig)],
            check=True,
            capture_output=True,
        )
        ext = native.external(va, Cell().ref(intent).ref(chain(sig.read_bytes())))
        entries = read_dict(native.config(17), 32)
        entries[48] = Cell().ref(global_policy())
        initial = native.active_account(va, vault, vd, balance=10**15)
        credit_probe = None
        if options.credit_probe:
            original = entries[21].refs[0]
            assert int(original.bits[:8], 2) == 0xD1 and int(original.bits[136:144], 2) == 0xDE
            offset = 336
            assert int(original.bits[offset : offset + 64], 2) == 10000
            with patch.object(native, "config", return_value=make_dict(entries, 32)):
                baseline = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
            try:
                default_result = baseline.send(initial, ext)
            finally:
                baseline.close()
            (out / "default-credit-result.json").write_text(
                json.dumps(default_result, indent=2) + "\n"
            )
            low, high = 0, 30000
            while low + 1 < high:
                credit = (low + high) // 2
                changed = Cell(
                    bits=original.bits[:offset]
                    + format(credit, "064b")
                    + original.bits[offset + 64 :],
                    refs=original.refs,
                )
                entries[21] = Cell().ref(changed)
                with patch.object(native, "config", return_value=make_dict(entries, 32)):
                    probe = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
                try:
                    result = probe.send(initial, ext)
                finally:
                    probe.close()
                if result["success"]:
                    assert result["details"]["exit"] == 0, result["details"]
                    high = credit
                else:
                    assert result.get("vm_exit_code") == -14, {
                        k: v for k, v in result.items() if k != "vm_log"
                    }
                    low = credit
            credit_probe = {
                "default_credit": 10000,
                "minimum_accept_credit": high,
                "production_admission_passed": high <= 10000,
                "downstream_diagnostic_credit": max(high, 20000),
            }
            entries[21] = Cell().ref(
                Cell(
                    bits=original.bits[:offset]
                    + format(max(high, 20000), "064b")
                    + original.bits[offset + 64 :],
                    refs=original.refs,
                )
            )
            (out / "credit-probe.json").write_text(json.dumps(credit_probe, indent=2) + "\n")
            print(json.dumps(credit_probe), flush=True)
        with patch.object(native, "config", return_value=make_dict(entries, 32)):
            e = native.Emulator(17, vm_log_verbosity=3 if options.gas_trace else 1)
        try:
            paid = e.send(native.active_account(va, vault, vd, balance=10**15), ext)
            (out / "vault-result.json").write_text(json.dumps(paid, indent=2) + "\n")
            if options.gas_trace and paid["success"]:
                initial_credit = (
                    credit_probe["downstream_diagnostic_credit"] if credit_probe else 10000
                )
                remaining = initial_credit
                costs = {}
                instruction = None
                for line in paid["vm_log"].splitlines():
                    if line.startswith("execute "):
                        instruction = line.removeprefix("execute ").split()[0]
                        if instruction == "ACCEPT":
                            break
                    if line.startswith("gas remaining:"):
                        current = int(line.split(":", 1)[1])
                        assert instruction is not None and current <= remaining
                        costs[instruction] = costs.get(instruction, 0) + remaining - current
                        remaining = current
                assert instruction == "ACCEPT", "trace omitted admission or was truncated"
                profile = {
                    "before_accept": initial_credit - remaining,
                    "lms_opcode": costs["LMSCHECKFEEHASH"],
                    "other_admission": initial_credit - remaining - costs["LMSCHECKFEEHASH"],
                    "instruction_totals": dict(sorted(costs.items(), key=lambda item: -item[1])),
                }
                (out / "gas-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
            assert paid["success"], paid
            assert paid["details"]["exit"] == 0 and not paid["details"]["aborted"], paid
            failures = {}
            corrupt = sig.read_bytes()
            corrupt = corrupt[:-1] + bytes([corrupt[-1] ^ 1])
            invalid = native.external(va, Cell().ref(intent).ref(chain(corrupt)))
            bad = e.send(initial, invalid)
            assert not bad["success"] and bad.get("vm_exit_code") == 2007, bad
            failures["invalid_fee_signature"] = bad["vm_exit_code"]
            poor = e.send(native.active_account(va, vault, vd, balance=5_000_000_000), ext)
            assert not poor["success"] and poor.get("vm_exit_code") == 2008, poor
            failures["insufficient_reserve"] = poor["vm_exit_code"]
            (out / "failure-results.json").write_text(
                json.dumps({"invalid_signature": bad, "insufficient_reserve": poor}, indent=2)
                + "\n"
            )

            messages = native.outgoing(from_boc(paid["transaction"]))
            assert len(messages) == 1
            relayed = e.send(
                native.active_account((0, root), module, md, balance=10**12), messages[0]
            )
            (out / "module-result.json").write_text(json.dumps(relayed, indent=2) + "\n")
            assert relayed["success"] and relayed["details"]["exit"] == 0, relayed
            messages = native.outgoing(from_boc(relayed["transaction"]))
            assert len(messages) == 1
            executed = e.send(native.active_account(wa, wallet, wd, balance=10**15), messages[0])
            (out / "wallet-result.json").write_text(json.dumps(executed, indent=2) + "\n")
            assert executed["success"] and executed["details"]["exit"] == 0, executed
            assert len(native.outgoing(from_boc(executed["transaction"]))) == 1
            outgoing = native.outgoing(from_boc(executed["transaction"]))[0]
            delivered = e.send(
                native.active_account(
                    recipient, recipient_code, recipient_data, balance=1_000_000_000
                ),
                outgoing,
            )
            assert (
                delivered["success"]
                and delivered["details"]["exit"] == 0
                and not delivered["details"]["aborted"]
            ), delivered
            recipient_after, recipient_balance = native.account_data(
                from_boc(delivered["shard_account"])
            )
            assert (
                recipient_after.hash == Cell().uint(1, 32).hash
                and recipient_balance > 1_000_000_000
            )
            (out / "recipient-result.json").write_text(json.dumps(delivered, indent=2) + "\n")
            vault_after = native.account_data(from_boc(paid["shard_account"]))[0]
            vs = vault_after.slice()
            assert vs.uint(8) == 3 and vs.uint(32) == 9
            replay = e.send(from_boc(paid["shard_account"]), ext)
            assert not replay["success"] and replay.get("vm_exit_code") == 2004, replay
            (out / "replay-result.json").write_text(json.dumps(replay, indent=2) + "\n")

            report = {
                "scope": __doc__,
                "credit_probe": credit_probe,
                "vault": paid["details"],
                "module": relayed["details"],
                "wallet": executed["details"],
                "recipient": delivered["details"],
                "replay_exit": replay["vm_exit_code"],
                "failure_exits": failures,
                "addresses": {
                    "wallet": hex(wa[1]),
                    "module": hex(root),
                    "vault": hex(va[1]),
                    "recipient": hex(recipient[1]),
                },
            }
            (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            e.close()


if __name__ == "__main__":
    main()

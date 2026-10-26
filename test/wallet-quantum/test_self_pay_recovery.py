#!/usr/bin/env python3
"""Funded possession proof, same-address rotation and new-root payment.

Uses actual outgoing messages, both native signers and whole transactions.
This covers contract recovery, not mobile backup/UI acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from test_self_pay import Harness, Cell, ROOT, NETWORK, TAGS, chain, config, from_boc, native, run, unpack, uninitialized
from fee_tx_parity import transcript


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rust-driver", type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    old = Harness(out / "old")
    new = Harness(out / "new", primary_seed="33", rescue_seed="44")
    successor = new.make_authority(policy_value=2)
    probe = native.compile_contract("wallet-quantum-possession-probe.fc", out / "probe.boc")
    challenge = int.from_bytes(hashlib.sha256(b"PUBLIC TEST SUCCESSOR CHALLENGE").digest(), "big")

    def identity(target=old.address, expires=native.NOW + 600, random=challenge, authority=successor):
        return (Cell().uint(0x51505031, 32).sint(native.GLOBAL_ID, 32).uint(NETWORK, 256)
                .addr(target).uint(random, 256).uint(expires, 32).ref(authority))

    immutable = identity()
    data = Cell().uint(1, 8).uint(0, 1).ref(immutable)
    init = native.state_init(probe, data)
    address = (0, int.from_bytes(init.hash, "big"))
    digest = Cell().uint(0x51505031, 32).raw(probe.hash).ref(immutable).hash
    digest_file = out / "digest.bin"
    digest_file.write_bytes(digest)
    primary_sig, rescue_sig = out / "primary.sig", out / "rescue.sig"
    run(os.environ["MLDSA_TOOL"], "sign", new.skfile, b"TOS-QSP-POP-MLDSA44-v1".hex(), digest_file, primary_sig)
    run(os.environ["SLH_TOOL"], "sign", new.slh_sk, b"TOS-QSP-POP-SLH128S-v1".hex(), digest_file, rescue_sig)
    body = Cell().ref(chain(primary_sig.read_bytes())).ref(chain(rescue_sig.read_bytes()))
    rows, scenarios, expected_rows = [], [], []

    def send(label, account, message, expected=0, accepted=True):
        emu = native.Emulator.from_config(config(), vm_log_verbosity=0)
        try:
            result = emu.send(account, message)
            lt = emu.lt
        finally:
            emu.close()
        (out / (label + ".json")).write_text(json.dumps(result, indent=2) + "\n")
        assert result["success"] == accepted, (label, result.get("error"), result.get("vm_exit_code"))
        if accepted:
            assert result["details"]["exit"] == expected, (label, result["details"])
            after = from_boc(result["shard_account"])
            saved, balance = native.account_data(after)
            row = dict(name=label, **result["details"], data_hash=saved.hash.hex(), balance=balance)
        else:
            assert result.get("external_not_accepted") and result["vm_exit_code"] == expected
            row = dict(name=label, exit=expected, accepted=False)
        scenarios.append("\t".join([label, str(native.NOW), str(lt), account.refs[0].boc().hex(), message.boc().hex(), "-"]))
        expected_rows.append(transcript(label, result))
        rows.append(row)
        print(json.dumps(row), flush=True)
        return result

    # The existing root locks PRIMARY, then funds the immutable successor probe.
    locked = send("lock", old.account, old.message(role=2, kind=3))
    old_account = from_boc(locked["shard_account"])
    assert unpack(native.account_data(old_account)[0])["retired"] == 2
    funded = (Cell().uint(4, 4).addr(old.address).addr(address).coins(1_000_000_000)
              .uint(0, 1).coins(0).coins(0).uint(0, 64).uint(native.NOW, 32)
              .uint(1, 1).uint(1, 1).ref(init).uint(1, 1).ref(body))
    action = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(funded)
    result = send("fund-probe", old_account, old.message(role=2, epoch=1,
                  payload=Cell().uint(TAGS[0], 32).ref(action)))
    old_account = from_boc(result["shard_account"])
    messages = native.outgoing(from_boc(result["transaction"]))
    assert len(messages) == 1
    result = send("deploy-and-verify-probe", uninitialized(address, 0), messages[0])
    verified_account = from_boc(result["shard_account"])
    saved = native.account_data(verified_account)[0]
    assert saved.bits == f"{1:08b}1" and saved.refs[0].hash == immutable.hash
    assert not native.outgoing(from_boc(result["transaction"]))

    # Duplicate delivery cannot revoke or replace the receipt, even with junk.
    result = send("idempotent-probe", verified_account, native.internal(old.address, address, Cell().uint(7, 3)))
    assert native.account_data(from_boc(result["shard_account"]))[0].hash == saved.hash
    send("external-probe-refused", verified_account, native.external(address, body), expected=1807, accepted=False)

    # Proofs bind the whole immutable identity and cannot be transplanted.
    for label, changed, error in [
        ("different-wallet", identity(target=(0, 99)), 1808),
        ("different-challenge", identity(random=challenge ^ 1), 1808),
        ("expired-proof", identity(expires=native.NOW), 1805),
        ("different-authority", identity(authority=new.make_authority(policy_value=1)), 1808),
    ]:
        changed_data = Cell().uint(1, 8).uint(0, 1).ref(changed)
        account = native.active_account(address, probe, changed_data)
        result = send(label, account, native.internal(old.address, address, body), expected=error)
        assert native.account_data(from_boc(result["shard_account"]))[0].hash == changed_data.hash
        assert not native.outgoing(from_boc(result["transaction"]))
    for role, signature in [(1, primary_sig.read_bytes()), (2, rescue_sig.read_bytes())]:
        bad = bytes([signature[0] ^ 1]) + signature[1:]
        forged = (Cell().ref(chain(bad if role == 1 else primary_sig.read_bytes()))
                  .ref(chain(bad if role == 2 else rescue_sig.read_bytes())))
        account = native.active_account(address, probe, data)
        result = send(f"forged-proof-{role}", account, native.internal(old.address, address, forged), expected=1808)
        assert native.account_data(from_boc(result["shard_account"]))[0].hash == data.hash

    # Same wallet address, newly installed keys. A backup must retain the old
    # StateInit/address because the new keys alone derive a different address.
    result = send("migrate", old_account, old.message(role=2, kind=4, epoch=1, nonce=1,
                  payload=Cell().uint(TAGS[4], 32).ref(successor)))
    rotated = from_boc(result["shard_account"])
    saved = unpack(native.account_data(rotated)[0])
    assert saved["authority"] == successor.hash.hex() and saved["retired"] == 2
    assert saved["seqno"] == 0 and saved["epoch"] == 2
    send("old-authority-refused", rotated, old.message(role=2, epoch=2), expected=1809, accepted=False)
    send("old-rescue-key-refused", rotated, old.message(role=2, epoch=2, authority=successor), expected=1808, accepted=False)
    assert new.address != old.address
    new.address, new.authority = old.address, successor
    target = (0, 2468)
    payment = native.internal(old.address, target, Cell().uint(0, 32), value=100_000_000)
    action = Cell().uint(0x0EC3C86D, 32).uint(3, 8).ref(Cell()).ref(payment)
    result = send("new-rescue-payment", rotated, new.message(role=2, epoch=2,
                  payload=Cell().uint(TAGS[0], 32).ref(action)))
    messages = native.outgoing(from_boc(result["transaction"]))
    assert len(messages) == 1
    from protocol import parse_message
    parsed = parse_message(messages[0])
    assert parsed["destination"] == target and parsed["value"] == 100_000_000
    send("retirement-preserved", rotated, new.message(epoch=2), expected=1817, accepted=False)

    fixture = from_boc((ROOT / "tosctl/src/executor/real_boc/default_config.boc").read_bytes())
    (out / "config.boc").write_bytes(Cell(fixture.bits, [config()]).boc())
    (out / "scenarios.tsv").write_text("\n".join(scenarios) + "\n")
    (out / "native.tsv").write_text("\n".join(expected_rows) + "\n")
    if args.rust_driver:
        r = subprocess.run([str(args.rust_driver.resolve()), str(out / "config.boc"),
                            str(out / "scenarios.tsv"), "16", "--details"], capture_output=True, text=True, check=True)
        (out / "rust.tsv").write_text(r.stdout)
        (out / "rust.log").write_text(r.stderr)
        assert r.stdout.splitlines() == expected_rows, "native/Rust recovery mismatch"
    report = dict(cases=rows, wallet_code_hash=old.code.hash.hex(), probe_code_hash=probe.hash.hex(),
                  rust_parity="passed" if args.rust_driver else "not run",
                  scope="Contract recovery; no mobile cold-backup, UI or live-chain acceptance")
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(cases=len(rows), rust_parity=report["rust_parity"])))


if __name__ == "__main__":
    main()

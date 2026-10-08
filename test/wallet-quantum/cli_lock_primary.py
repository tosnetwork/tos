"""SLH CLI lock execution, replay refusal, and independence from PRIMARY retirement policy."""

import json
import sys
import time
from unittest.mock import patch

import cli_sign_primary as shared

native, Cell, from_boc = shared.native, shared.Cell, shared.from_boc


def execute_lock(submission, report, codes, data, addresses, policy, output, label):
    assert report["status"] == "rescue_lock_submission_signed"
    assert report["suite"] == "SLH-DSA-SHA2-128s" and report["action"] == "lock_primary"
    request = submission.refs[0].slice()
    request.uint(32 + 32 + 256)
    request.addr()
    request.uint(256)
    assert request.uint(8) == 2, "lock was not authorized by RESCUE"
    assert request.uint(64) == report["epoch"]
    assert request.uint(64) == report["nonce"]
    assert request.uint(32) == report["valid_until"]
    assert request.uint(8) == 3, "CLI did not sign a lock action"
    action = request.ref().slice()
    assert action.uint(32) == 0x4C4F434B and action.uint(8) == 1
    action.end()
    request.end()
    original = native.config
    native.NOW = int(time.time())

    def config(*pos, **kw):
        entries = shared.read_dict(original(*pos, **kw), 32)
        if policy is not None:
            entries[48] = Cell().ref(policy)
        else:
            entries.pop(48, None)
        return shared.make_dict(entries, 32)

    with patch.object(native, "config", config):
        emu = native.Emulator(global_version=17)
    try:
        module_before = native.active_account(addresses["module"], codes["module"], data["module"])
        incoming = native.internal((0, 987), addresses["module"], submission, value=10_000_000_000)
        relayed = emu.send(module_before, incoming)
        outgoing = shared.check_execution(relayed, module_before, incoming, "module")
        assert len(outgoing) == 1
        wallet_before = native.active_account(addresses["wallet"], codes["wallet"], data["wallet"])
        locked = emu.send(wallet_before, outgoing[0])
        assert not shared.check_execution(locked, wallet_before, outgoing[0]), (
            "lock emitted a payment"
        )
        after = from_boc(locked["shard_account"])
        state, _ = native.account_data(after)
        outer = state.slice()
        assert outer.uint(1) == 0 and outer.uint(32) == 0
        outer.uint(32 + 256)
        assert outer.maybe() is None
        auth = outer.ref().slice()
        assert auth.uint(8) == 4 and auth.uint(2) == 2
        assert auth.uint(16) & 2, "SLH lock did not retire PRIMARY"
        assert auth.uint(64) == report["epoch"] + 1, "SLH lock did not advance epoch"
        assert auth.uint(64) == 0 and auth.uint(64) == 0
        replay = emu.send(after, outgoing[0])
        assert replay["success"] and not replay["details"]["compute_success"], (
            "lock replay accepted"
        )
        assert native.account_data(from_boc(replay["shard_account"]))[0].hash == state.hash
        signature = submission.refs[1]
        corrupt = Cell(signature.bits[:-1] + str(1 - int(signature.bits[-1])), signature.refs)
        broken = Cell(submission.bits, [submission.refs[0], corrupt])
        rejected = emu.send(
            module_before,
            native.internal((0, 987), addresses["module"], broken, value=10_000_000_000),
        )
        assert rejected["success"] and rejected["details"]["exit"] == 1808, (
            "corrupt SLH signature accepted"
        )
        for name, tx in [
            ("module", relayed),
            ("wallet", locked),
            ("replay", replay),
            ("corrupt", rejected),
        ]:
            (output / f"{label}-{name}.json").write_text(json.dumps(tx, indent=2))
        return dict(
            module=relayed["details"],
            wallet=locked["details"],
            replay_exit=replay["details"]["exit"],
            corrupt_exit=rejected["details"]["exit"],
        )
    finally:
        emu.close()


if __name__ == "__main__":
    sys.argv.append("--rescue-lock")
    shared.main()

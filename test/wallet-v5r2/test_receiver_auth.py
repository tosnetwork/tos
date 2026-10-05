"""Real action-phase tests of the R2 receiving-auth include, not a full-wallet claim."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import Cell, from_boc, make_dict, read_dict  # noqa: E402
from test_auth import SECRET  # noqa: E402
from test_auth_policy import policy as global_policy  # noqa: E402

ACCOUNT, MODULE, RELAYER, VAULT, TARGET = [(0, i) for i in (100, 101, 102, 103, 104)]
NETWORK = 123
MAX = (1 << 64) - 1
TAGS = {0: 0x45584543, 1: 0x434F4E46, 3: 0x4C4F434B, 4: 0x4D494752}


def state(mode=2, policy=1, retired=0, epoch=1, primary=0, rescue=0, seqno=0, key=0, daily=1):
    auth = (
        Cell()
        .uint(mode, 2)
        .uint(MODULE[1], 256)
        .uint(NETWORK, 256)
        .uint(daily, 8)
        .uint(policy, 8)
        .uint(retired, 16)
        .uint(epoch, 64)
        .uint(primary, 64)
        .uint(rescue, 64)
        .ref(Cell().uint(VAULT[1], 256))
    )
    return Cell().uint(0, 1).uint(seqno, 32).uint(7, 32).uint(key, 256).maybe(None).ref(auth)


def unpack(data):
    d = data.slice()
    d.uint(1)
    seqno = d.uint(32)
    d.uint(288)
    d.maybe()
    a = d.ref().slice()
    mode = a.uint(2)
    a.uint(512)
    a.uint(8)
    policy = a.uint(8)
    retired = a.uint(16)
    return dict(
        mode=mode,
        policy=policy,
        retired=retired,
        epoch=a.uint(64),
        primary=a.uint(64),
        rescue=a.uint(64),
        seqno=seqno,
    )


def payload(kind=0, count=1, send_mode=3, new_mode=2):
    p = Cell().uint(TAGS.get(kind, 0), 32)
    if kind == 0:
        actions = Cell()
        message = native.internal(ACCOUNT, TARGET, Cell(), value=1_000_000_000)
        for _ in range(count):
            actions = Cell().uint(0x0EC3C86D, 32).uint(send_mode, 8).ref(actions).ref(message)
        p.ref(actions)
    elif kind == 1:
        p.uint(new_mode, 2)
    elif kind == 3:
        p.uint(1, 8)
    return p


def request(
    role=1,
    kind=0,
    epoch=1,
    nonce=0,
    network=NETWORK,
    global_id=native.GLOBAL_ID,
    account=ACCOUNT,
    root=MODULE[1],
    deadline=native.NOW + 600,
    body=None,
):
    return (
        Cell()
        .uint(0x41553252, 32)
        .sint(global_id, 32)
        .uint(network, 256)
        .addr(account)
        .uint(root, 256)
        .uint(role, 8)
        .uint(epoch, 64)
        .uint(nonce, 64)
        .uint(deadline, 32)
        .uint(kind, 8)
        .ref(payload(kind) if body is None else body)
    )


def cosign(req, secret=SECRET):
    return Cell().raw(secret.sign(Cell().uint(0x544F532D41555448, 64).ref(req).hash))


def relay(req, signature=None, funder=RELAYER):
    body = Cell().uint(0x41553342, 32).ref(req).addr(funder)
    if signature is not None:
        body.ref(signature)  # forbidden extra classical-signature field
    return body


def run(
    code,
    data,
    req=None,
    *,
    expected=0,
    signature=None,
    sender=MODULE,
    funder=RELAYER,
    config="valid",
    envelope=None,
    shard=None,
):
    entries = read_dict(native.config(17), 32)
    if config is not None:
        entries[48] = Cell().ref(global_policy() if config == "valid" else config)
    with patch.object(native, "config", return_value=make_dict(entries, 32)):
        e = native.Emulator(17)
    try:
        shard = shard or native.active_account(ACCOUNT, code, data, balance=1_000_000_000_000_000)
        result = e.send(
            shard,
            native.internal(
                sender,
                ACCOUNT,
                envelope or relay(req or request(), signature, funder),
                value=100_000_000_000,
            ),
        )
        assert result["success"], result
        d = result["details"]
        assert d["exit"] == expected, f"expected exit {expected}, got {d['exit']}: {d}"
        after = native.account_data(from_boc(result["shard_account"]))[0]
        if expected:
            assert after.hash == data.hash, "rejected relay modified counters or authority"
        else:
            assert not d["aborted"] and (d["action"] is None or d["action"]["success"]), d
        messages = native.outgoing(from_boc(result["transaction"]))
        for m in messages:
            s = m.slice()
            flags = s.uint(4)
            s.addr()
            dest = s.addr()
            assert bool(flags & 1) if expected else dest == TARGET
        return unpack(after), len(messages), from_boc(result["shard_account"]), after
    finally:
        e.close()


def compile_driver(work, output, mutation=None):
    for name in [
        "wallet-v5r2-auth.fc",
        "wallet-v5r2-common.fc",
        "auth-policy.fc",
        "wallet-v5-action-list.fc",
    ]:
        shutil.copyfile(ROOT / "crypto/smartcont" / name, work / name)
    if mutation:
        p = work / "wallet-v5r2-auth.fc"
        text = p.read_text()
        assert text.count(mutation[0]) == 1
        p.write_text(text.replace(*mutation))
    shutil.copyfile(ROOT / "test/wallet-v5r2/receiver-auth-driver.fc", work / "driver.fc")
    try:
        return native.compile_contract(str(work / "driver.fc"), output)
    except Exception as e:
        if hasattr(e, "stderr"):
            print(e.stderr.decode(), file=sys.stderr)
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    out = ap.parse_args().output
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        code = compile_driver(work, out / "receiver.boc")
        results = {}

        def case(name, data=None, req=None, **kw):
            answer = run(code, state() if data is None else data, req, **kw)
            results[name] = {"state": answer[0], "messages": answer[1]}
            return answer

        for role in (1, 2):
            for mode in (2,):
                req = request(role=role)
                r = case(
                    f"execute_{role}_{mode}",
                    state(mode=mode),
                    req,
                    signature=None,
                )
                assert (
                    r[0]["primary"] == (role == 1)
                    and r[0]["rescue"] == (role == 2)
                    and r[0]["seqno"] == 1
                )
                assert r[1] == 1
        for kind in (1, 3, 4):
            case(f"primary_control_{kind}", req=request(kind=kind), expected=1812)
        for role in (0, 3, 255):
            case(f"unknown_role_{role}", req=request(role=role), expected=1812)
        for kind in (2, 5, 255):
            case(f"unknown_kind_{kind}", req=request(role=2, kind=kind), expected=1812)
        for mode in (0, 1, 3):
            case(f"non_strict_{mode}", state(mode=mode), expected=1806)
        for policy in (0, 3):
            case(f"unknown_policy_{policy}", state(policy=policy), expected=1806)
        case("unknown_daily", state(daily=2), expected=1806)
        case("wrong_sender", sender=RELAYER, expected=1800)
        case("wrong_sender_wc", sender=(-1, MODULE[1]), expected=1800)
        case("wrong_funder_wc", funder=(-1, RELAYER[1]), expected=1802)
        for field, value, error in [
            ("network", 124, 1801),
            ("global_id", 43, 1801),
            ("account", TARGET, 1802),
            ("root", 102, 1800),
            ("epoch", 0, 1803),
            ("nonce", 1, 1804),
            ("deadline", native.NOW, 1805),
            ("deadline", native.NOW + 3601, 1805),
        ]:
            case(f"binding_{field}_{value}", req=request(**{field: value}), expected=error)
        case("max_ttl", req=request(deadline=native.NOW + 3600))
        case("required_primary", state(policy=2), expected=1817)
        case("required_rescue", state(policy=2), request(role=2))
        case("local_retired_primary", state(retired=2), expected=1813)
        case("local_retired_rescue", state(retired=2), request(role=2))
        for name, cfg, error in [
            ("missing", None, 1820),
            ("retired", global_policy(retired=2), 1813),
            ("deadline", global_policy(deadline=native.NOW), 1813),
            ("network", global_policy(network=124), 1820),
            ("profile", global_policy(spec=1), 1820),
        ]:
            case(f"policy_primary_{name}", config=cfg, expected=error)
            case(f"policy_rescue_{name}", req=request(role=2), config=cfg)
        case("fee_primary", funder=VAULT, expected=1818)
        case("fee_rescue", req=request(role=2), funder=VAULT)
        req = request()
        case("extra_classical_signature", req=req, signature=cosign(req), expected=9)
        old = Cell().uint(0x41553242, 32).ref(req).maybe(None).addr(RELAYER)
        case("legacy_hybrid_envelope", req=req, envelope=old, expected=1811)
        for kind in (3, 4):
            req = request(role=2, kind=kind, nonce=MAX)
            r = case(
                f"saturated_recovery_{kind}",
                state(mode=2, primary=MAX, rescue=MAX, seqno=(1 << 32) - 1),
                req,
                config=None,
            )
            assert r[0]["epoch"] == 2 and r[0]["primary"] == r[0]["rescue"] == 0
            assert r[0]["seqno"] == ((1 << 32) - 1 if kind == 3 else 0)
            assert r[0]["mode"] == 2 and r[1] == 0  # harness migration is counters only
            case(
                f"epoch_exhausted_{kind}",
                state(epoch=MAX),
                request(role=2, kind=kind, epoch=MAX),
                expected=1810,
            )
        for role, field in ((1, "primary"), (2, "rescue")):
            case(
                f"nonce_exhausted_{role}",
                state(**{field: MAX}),
                request(role=role, nonce=MAX),
                expected=1810,
            )
        case("seqno_exhausted", state(seqno=(1 << 32) - 1), expected=1810)
        conf = request(role=2, kind=1)
        case("configure_mode3_refused", state(mode=3), conf, expected=1806)
        r = case("configure_pq_only", state(), conf)
        assert r[0]["epoch"] == 2 and r[0]["mode"] == 2 and r[0]["seqno"] == 1
        # Actual follow-up messages against the committed receiver state.
        locked = case("lock_commit", req=request(role=2, kind=3))
        case("queued_primary_after_lock", locked[3], request(), shard=locked[2], expected=1803)
        case(
            "fresh_primary_after_lock", locked[3], request(epoch=2), shard=locked[2], expected=1813
        )
        case("duplicate_lock", locked[3], request(role=2, kind=3), shard=locked[2], expected=1803)
        paid = case("pay_once")
        case("pay_replay", paid[3], request(), shard=paid[2], expected=1804)
        # Same previously valid relay, current policy changes only.
        case(
            "queued_primary_after_global_retirement",
            req=request(),
            config=global_policy(retired=2),
            expected=1813,
        )
        for count in (0, 1, 254, 255, 256):
            r = case(
                f"action_count_{count}",
                req=request(body=payload(count=count)),
                expected=147 if count > 255 else 0,
            )
            if count <= 255:
                assert r[1] == count
        for mode in range(256):
            expected = 137 if not mode & 2 else 1811 if mode & 44 or mode & 192 == 192 else 0
            case(f"send_mode_{mode}", req=request(body=payload(send_mode=mode)), expected=expected)
        mutations = [
            (
                "global_retirement",
                "    auth_policy_require_primary(network, daily);",
                "",
                lambda c: run(c, state(), config=global_policy(retired=2), expected=1813),
            ),
            (
                "fee_route",
                "    throw_if(r2::primary_fee_route, funder == vault);",
                "",
                lambda c: run(c, state(), funder=VAULT, expected=1818),
            ),
            (
                "primary_nonce",
                "    throw_unless(auth::bad_nonce, nonce == primary_nonce);",
                "",
                lambda c: run(c, state(), request(nonce=1), expected=1804),
            ),
            (
                "pq_only_mode",
                "  throw_unless(auth::bad_mode, mode == 2);",
                "",
                lambda c: run(c, state(mode=3), request(), expected=1806),
            ),
        ]
        killed = {}
        for name, old, new, test in mutations:
            mutant = compile_driver(work, out / (name + ".boc"), (old, new))
            try:
                test(mutant)
            except AssertionError as e:
                assert "got 0:" in str(e), str(e)
                killed[name] = str(e)
            else:
                raise AssertionError("mutation survived: " + name)
            test(code)
        report = {
            "scope": "Receiving AUTH v2 engine with full V5 actions; canonical initialization and signed module integration not covered",
            "cases": len(results),
            "mutations": killed,
            "results": results,
        }
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()

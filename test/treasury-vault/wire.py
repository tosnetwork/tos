"""Developer/test wire builders for Treasury Vault V1; not a signing service.

Uses the repository's small ordinary-cell codec. No secrets are accepted here.
Production integrations must independently validate deployed code and roles.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, make_dict, read_dict  # noqa: E402

SUBMIT, APPROVE, CANCEL_PAYMENT, EXPIRE_PAYMENT, PAUSE = range(0x54560001, 0x54560006)
SCHEDULE, APPLY, VETO, EXPIRE_ADMIN = range(0x54560006, 0x5456000A)
PAYMENT_DOMAIN, ADMIN_DOMAIN = 0x54565031, 0x54564731
DELAY, WINDOW, PAYMENT_TTL, ADMIN_TTL = 172800, 86400, 3600, 777600
COIN, MAX_COINS, MAX_COUNTER = 1_000_000_000, (1 << 120) - 1, (1 << 64) - 1
TOKEN_TRANSFER = 0x0F8A7EA5


def address(value):
    if not isinstance(value, tuple) or len(value) != 2:
        raise ValueError("an address must be a (workchain, uint256) tuple")
    wc, account = value
    if wc != 0 or not isinstance(account, int) or not 0 <= account < 1 << 256:
        raise ValueError("only canonical workchain-0 addresses are supported")
    return value


def coins(value):
    if not isinstance(value, int) or not 0 <= value <= MAX_COINS:
        raise ValueError("amount must fit unsigned Coins")
    return value


def roles(business, guardian, administrator, pauser):
    values = [address(x) for x in (business, guardian, administrator, pauser)]
    if len(set(values)) != 4:
        raise ValueError("all four roles must be distinct")
    return (
        Cell()
        .ref(Cell().addr(business).addr(guardian))
        .ref(Cell().addr(administrator).addr(pauser))
    )


def wallet_field(cell, wallet):
    return cell.uint(0, 2) if wallet is None else cell.addr(address(wallet))


def read_wallet(s):
    if s.bits[:2] == "00":
        s.uint(2)
        return None
    return s.addr()


def asset_record(
    wallet=None,
    per=5 * COIN,
    window=6 * COIN,
    total=10 * COIN,
    enabled=True,
    start=0,
    spent=0,
    cumulative=0,
):
    c = wallet_field(Cell().uint(bool(enabled), 1), wallet)
    return (
        c.coins(coins(per))
        .coins(coins(window))
        .coins(coins(total))
        .uint(start, 32)
        .coins(coins(spent))
        .coins(coins(cumulative))
    )


def decode_asset(record):
    s = record.slice()
    result = dict(
        enabled=bool(s.uint(1)),
        wallet=read_wallet(s),
        per=s.coins(),
        window=s.coins(),
        total=s.coins(),
        start=s.uint(32),
        spent=s.coins(),
        cumulative=s.coins(),
    )
    s.end()
    return result


def state_data(role_cell, records=None, *, epoch=0, payment_nonce=0, admin_nonce=0, paused=False):
    """Optional records/counters are fixture-only; deployments start empty."""
    records = {} if records is None else records
    if len(records) > 16:
        raise ValueError("at most 16 assets")
    entries = {key: Cell().ref(value) for key, value in records.items()}
    return (
        Cell()
        .uint(epoch, 64)
        .uint(payment_nonce, 64)
        .uint(admin_nonce, 64)
        .uint(bool(paused), 1)
        .uint(len(records), 8)
        .ref(role_cell)
        .maybe(make_dict(entries, 256))
        .maybe(None)
        .maybe(None)
    )


def decode_state(data):
    s = data.slice()
    result = dict(
        epoch=s.uint(64),
        payment_nonce=s.uint(64),
        admin_nonce=s.uint(64),
        paused=bool(s.uint(1)),
        count=s.uint(8),
        roles=s.ref(),
    )
    result["assets"] = {key: value.refs[0] for key, value in read_dict(s.maybe(), 256).items()}
    result["payment"], result["admin"] = s.maybe(), s.maybe()
    s.end()
    return result


def payment(asset, amount, recipient, attachment=0):
    if amount <= 0:
        raise ValueError("payment must be positive")
    if not 0 <= attachment <= COIN or (asset == 0) != (attachment == 0):
        raise ValueError("native payment has no attachment; Token payment requires one")
    return (
        Cell()
        .uint(asset, 256)
        .coins(coins(amount))
        .addr(address(recipient))
        .coins(coins(attachment))
    )


def set_asset(asset, wallet=None, per=5 * COIN, window=6 * COIN, total=10 * COIN, enabled=True):
    if (asset == 0) != (wallet is None):
        raise ValueError("native asset has no source wallet; a Token requires one")
    if window < per or total < per or (enabled and per == 0):
        raise ValueError("invalid budget ordering")
    c = wallet_field(Cell().uint(1, 8).uint(asset, 256).uint(bool(enabled), 1), wallet)
    return c.coins(coins(per)).coins(coins(window)).coins(coins(total))


def set_roles(role_cell):
    return Cell().uint(2, 8).ref(role_cell)


def unpause():
    return Cell().uint(3, 8)


def request(vault, epoch, nonce, deadline, payload, *, network, admin=False):
    if not -(1 << 31) <= network < 1 << 31:
        raise ValueError("network global ID must fit int32")
    return (
        Cell()
        .uint(ADMIN_DOMAIN if admin else PAYMENT_DOMAIN, 32)
        .sint(network, 32)
        .addr(address(vault))
        .uint(epoch, 64)
        .uint(nonce, 64)
        .uint(deadline, 32)
        .ref(payload)
    )


def envelope(op, req, query_id=0):
    return Cell().uint(op, 32).uint(query_id, 64).ref(req)


def control(op, epoch, nonce, query_id=0):
    return Cell().uint(op, 32).uint(query_id, 64).uint(epoch, 64).uint(nonce, 64)


def decode_message(message):
    s = message.slice()
    flags = s.uint(4)
    source, target, value = s.addr(), s.addr(), s.coins()
    if s.maybe() is not None:
        raise ValueError("unexpected extra currencies")
    s.coins()
    s.coins()
    s.uint(64)
    s.uint(32)
    if s.uint(1):
        if not s.uint(1):
            raise ValueError("inline StateInit not supported by this test decoder")
        s.ref()
    if s.uint(1):
        body = s.ref()
        s.end()
    else:
        body = Cell(s.bits, s.refs)
    return dict(flags=flags, source=source, target=target, value=value, body=body)

"""Integer-only operating-budget policy for disposable local PQ controllers.

The persistent profile reserves thirty days at the current per-stake grant and
renews at 25% remaining. This is not a lifetime spending cap: elections must
continue to produce key blocks. Production root custody is outside this tool.
"""

NANO = 10**9
COINS_LIMIT = 1 << 120
DAY = 86400


def coins(value, name="amount", *, zero=False):
    if type(value) is not int or not (0 if zero else 1) <= value < COINS_LIMIT:
        raise ValueError(f"{name} must be an integer in the supported nano-TOS range")
    return value


def funding_plan(state, *, now, grant, payer, period=600, days=30,
                 limit=20 * NANO, floor=10 * NANO, target=None):
    """Return a deficit-based kind-4 policy, or None when renewal is unnecessary.

    `funds` is additive on chain; every other payload field replaces its old
    value. `target` is an explicit override for bounded, nonpersistent tests.
    """
    coins(grant, "automatic grant")
    coins(limit, "per-request limit")
    coins(floor, "storage floor")
    if type(now) is not int or not 0 <= now < 1 << 32:
        raise ValueError("invalid chain time")
    if type(days) is not int or not 1 <= days <= 30 or period != 600:
        raise ValueError("unsupported local election profile")
    lifetime = days * DAY
    if now + lifetime >= 1 << 32 or grant > limit:
        raise ValueError("current fees or expiry exceed the approved policy")
    rounds = (lifetime + period - 1) // period
    target = coins(rounds * grant if target is None else target, "funds target")
    if target < 2 * grant:
        raise ValueError("target must cover at least two automatic grants")
    for name in ("funds", "allowance", "limit", "floor"):
        coins(state[name], name, zero=True)
    remaining = max(2 * grant, (target + 3) // 4)
    renew = (min(state["funds"], state["allowance"]) <= remaining
             or state["expires"] <= now + lifetime // 4
             or state["limit"] != limit or state["floor"] != floor
             or state["payer"] != payer)
    if not renew:
        return None
    deposit = max(0, target - state["funds"])
    coins(state["funds"] + deposit, "resulting funds", zero=True)
    return dict(deposit=deposit, funds=state["funds"] + deposit,
                allowance=target, limit=limit, floor=floor,
                expires=now + lifetime, payer=payer)

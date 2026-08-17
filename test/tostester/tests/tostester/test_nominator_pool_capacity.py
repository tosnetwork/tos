"""The two limits that decide who can still deposit into a pool.

pool.fc guards a deposit twice:

    throw_unless(65, nominators_count <= max_nominators_count);
    throw_unless(68, cell_depth(nominators) < max(5, binary_log_ceil(nominators_count) * 2));

The first is a capacity cap and behaves the way it reads. The second does not:
it rejects a deposit based on the *shape* the addresses already admitted happen
to produce. The depositor being turned away did nothing wrong, gets error 68
with no explanation, and cannot fix it except by depositing from a different
address they may not have.

The question worth answering is therefore not whether the guard exists but how
close ordinary use gets to it, and these tests answer that without a chain: the
depth a hashmap reaches is a function of its keys alone.

The answer is closer than it looks. The guard is reachable by ordinary random
addresses, rarely but measurably, so a pool can refuse an honest depositor for
reasons neither party can see. That is why the operator tooling reports depth
headroom -- see ExplorerNominatorPoolRecordDto's deposit_headroom.
"""

import random
from dataclasses import dataclass

import pytest

ADDRESS_BITS = 256
# pool.fc's own default and the value the lifecycle run deploys with.
MAX_NOMINATORS = 40


def ubitsize(value: int) -> int:
    """TVM's UBITSIZE, which pool.fc calls binary_log_ceil."""
    return value.bit_length()


def depth_bound(nominators_count: int) -> int:
    """The exclusive bound guard 68 compares cell_depth against."""
    return max(5, ubitsize(nominators_count) * 2)


def hashmap_depth(keys: list[int], bits: int = ADDRESS_BITS) -> int:
    """Cell depth of a HashmapE holding these keys.

    A hashmap node is a leaf (label plus value) or a fork (label plus two
    references), so cell depth is the number of fork levels on the deepest
    root-to-leaf path. Shared prefixes are absorbed into labels and cost no
    depth, which is why chosen keys and random ones behave so differently.
    """
    if len(keys) <= 1:
        return 0

    def split(subset: list[int], bit: int) -> int:
        if len(subset) <= 1 or bit < 0:
            return 0
        zero = [key for key in subset if not (key >> bit) & 1]
        one = [key for key in subset if (key >> bit) & 1]
        if not zero or not one:
            # Shared bit: absorbed into the label, no fork, no depth.
            return split(subset, bit - 1)
        return 1 + max(split(zero, bit - 1), split(one, bit - 1))

    return split(keys, bits - 1)


def deposit_is_accepted(existing_keys: list[int], max_nominators: int) -> bool:
    """Whether pool.fc would admit one more new depositor.

    Mirrors the contract's own order: the count is incremented for a new
    address first, then the depth of the dictionary *before* the insert is
    compared against the bound derived from the already-incremented count.
    """
    count = len(existing_keys) + 1
    if count > max_nominators:
        return False
    return hashmap_depth(existing_keys) < depth_bound(count)


@dataclass
class Rejection:
    at_nominator: int
    depth: int
    bound: int


def fill_pool(rng: random.Random, max_nominators: int) -> Rejection | None:
    """Add random depositors one at a time until one is refused."""
    keys: list[int] = []
    while len(keys) < max_nominators:
        count = len(keys) + 1
        depth = hashmap_depth(keys)
        if depth >= depth_bound(count):
            return Rejection(count, depth, depth_bound(count))
        keys.append(rng.getrandbits(ADDRESS_BITS))
    return None


# ===== the guard's arithmetic =====


@pytest.mark.parametrize(
    ("count", "bound"),
    [(1, 5), (2, 5), (3, 5), (4, 6), (8, 8), (16, 10), (32, 12), (40, 12)],
)
def test_bound_matches_the_contract_expression(count, bound):
    assert depth_bound(count) == bound


def test_the_floor_of_five_covers_the_first_few_depositors():
    # Below four nominators the log term is smaller than the floor, so the
    # floor is what applies.
    assert [depth_bound(n) for n in range(1, 4)] == [5, 5, 5]


def test_capacity_is_checked_before_depth():
    # A pool at capacity refuses regardless of shape, so the depth guard only
    # ever matters below the cap.
    full = [1 << i for i in range(MAX_NOMINATORS)]
    assert not deposit_is_accepted(full, MAX_NOMINATORS)


# ===== what ordinary use actually meets =====


def test_the_depth_guard_refuses_ordinary_depositors_sometimes():
    """Not a hypothetical: random addresses reach the bound.

    An address is the hash of a wallet's code and initial data, so honest
    depositors do not choose their keys. Filling a pool to capacity with such
    keys still trips guard 68 occasionally, and when it does the depositor is
    told only that the transaction failed.
    """
    rng = random.Random(20260818)
    rejections = [fill_pool(rng, MAX_NOMINATORS) for _ in range(3000)]
    refused = [r for r in rejections if r is not None]

    assert refused, (
        "the guard used to be reachable by random addresses; if this now "
        "passes cleanly the bound or the model changed and the tooling that "
        "reports headroom should be revisited"
    )
    # Rare, but the point is that it is not zero, and the depositor cannot
    # tell it apart from any other failure.
    assert len(refused) < 100, f"unexpectedly frequent: {len(refused)}/3000"


def test_headroom_reaches_zero_well_before_capacity():
    """The margin is one level for much of a pool's life, not comfortable.

    Anything reporting a pool as "accepting deposits" purely because it is
    below max_nominators_count is describing a different limit from the one
    that will actually refuse.
    """
    rng = random.Random(11)
    tightest: dict[int, int] = {}
    for _ in range(2000):
        keys: list[int] = []
        for count in range(1, MAX_NOMINATORS + 1):
            headroom = depth_bound(count) - hashmap_depth(keys) - 1
            tightest[count] = min(tightest.get(count, 99), headroom)
            keys.append(rng.getrandbits(ADDRESS_BITS))
    # Somewhere in the middle of filling a pool the guard is routinely one
    # deposit away from refusing.
    assert min(tightest.values()) <= 0
    assert any(value == 0 for count, value in tightest.items() if 8 <= count <= 32)


# ===== the adversarial edge =====


def crafted_addresses(count: int) -> list[int]:
    """Keys that fork as deep as possible: a chain rather than a balanced tree.

    Each key shares a one-bit-longer prefix with the previous, so every key
    adds a fork level instead of sharing one.
    """
    return [((1 << index) - 1) << (ADDRESS_BITS - index - 1) for index in range(count)]


def test_chosen_addresses_reach_the_bound_far_earlier_than_random_ones():
    crossing = next(
        count
        for count in range(2, MAX_NOMINATORS + 1)
        if hashmap_depth(crafted_addresses(count - 1)) >= depth_bound(count)
    )
    assert crossing <= 12, (
        f"crafted keys crossed only at {crossing}; the model no longer matches "
        "the guard"
    )


def test_reaching_the_guard_costs_a_deposit_per_slot():
    """What the attack buys, stated so it is not overestimated.

    Every key in the dictionary required a deposit of at least
    min_nominator_stake, held by the pool. An attacker deep enough to trip the
    guard has paid for the slots they consumed, and those slots were already
    denied to everyone else by the capacity cap. The guard's marginal
    protection is the difference between refusing at that depth and refusing
    at max_nominators_count -- which is why its cost to honest depositors is
    worth measuring rather than assuming.
    """
    crossing = next(
        count
        for count in range(2, MAX_NOMINATORS + 1)
        if hashmap_depth(crafted_addresses(count - 1)) >= depth_bound(count)
    )
    assert 2 <= crossing <= MAX_NOMINATORS

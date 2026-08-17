"""Cross-checks on how a nominator pool is addressed and spoken to.

Two independent implementations build the same bytes: the operator tool in
Rust, which deploys and resolves pools, and the lifecycle end-to-end script in
Python, which drives one through a round. A disagreement between them is not a
test failure that shows up as a test failure -- it shows up as deposits sent to
an address where no pool exists, or as a stake message the contract rejects
without saying why. So the encodings are pinned on both sides against the same
constants.
"""

import importlib.util
import sys
from pathlib import Path

import pytest
from pytosiq_core import Address, Cell

REPO = Path(__file__).resolve().parents[4]

# Same parameters as pool_address_derivation_is_pinned in
# tosctl/src/node-control/contracts/src/nominator_pool/pool_impl.rs
VALIDATOR_ACCOUNT = bytes([0xAB] * 32)
REWARD_SHARE_BPS = 4000
MAX_NOMINATORS = 40
MIN_VALIDATOR_STAKE = 5_000_000_000_000
MIN_NOMINATOR_STAKE = 100_000_000_000
EXPECTED_ADDRESS = "-1:f551c09c2533d56aad15ef67cd72d4d2b79ef93f447d49e76eda9b09a8bd4382"

POOL_CODE = REPO / "crypto/smartcont/artifacts/nominator-pool-v1.boc"


def _lifecycle_module():
    spec = importlib.util.spec_from_file_location(
        "nominator_pool_lifecycle_e2e", REPO / "scripts/nominator-pool-lifecycle-e2e.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lifecycle = _lifecycle_module()


requires_code = pytest.mark.skipif(
    not POOL_CODE.exists(),
    reason="run scripts/build-nominator-pool-v1.sh to produce the pool artifact",
)


@requires_code
def test_pool_address_matches_the_operator_tool():
    code = Cell.one_from_boc(POOL_CODE.read_bytes())
    state_init = lifecycle.build_pool_state_init(
        code,
        validator_account=VALIDATOR_ACCOUNT,
        reward_share_bps=REWARD_SHARE_BPS,
        max_nominators=MAX_NOMINATORS,
        min_validator_stake=MIN_VALIDATOR_STAKE,
        min_nominator_stake=MIN_NOMINATOR_STAKE,
    )
    address = Address((-1, state_init.serialize().hash))
    assert lifecycle.raw_address(address) == EXPECTED_ADDRESS


def test_a_deposit_is_a_transfer_with_a_one_letter_comment():
    # This encoding is the reason a nominator needs nothing but a wallet.
    body = lifecycle.text_command("d").begin_parse()
    assert body.load_uint(32) == 0
    assert body.load_uint(8) == ord("d")
    assert body.remaining_bits == 0


def test_a_withdrawal_request_uses_the_same_shape():
    body = lifecycle.text_command("w").begin_parse()
    assert body.load_uint(32) == 0
    assert body.load_uint(8) == ord("w")


def test_stake_body_carries_the_amount_before_the_elector_fields():
    # pool.fc reads the value it should forward, then hands the rest to the
    # Elector untouched. Getting that field's position wrong would corrupt the
    # signed payload rather than fail cleanly.
    body = lifecycle.build_pool_stake_body(
        query_id=7,
        stake_value=10_001_000_000_000,
        validator_pubkey=bytes(range(32)),
        election_id=1234,
        max_factor=1 << 16,
        adnl_id=bytes(range(32, 64)),
        signature=bytes(64),
    ).begin_parse()

    assert body.load_uint(32) == 0x4E73744B
    assert body.load_uint(64) == 7
    length = body.load_uint(4)
    assert body.load_uint(length * 8) == 10_001_000_000_000
    assert body.load_bytes(32) == bytes(range(32))
    assert body.load_uint(32) == 1234
    assert body.load_uint(32) == 1 << 16
    assert body.load_bytes(32) == bytes(range(32, 64))
    assert body.refs


@pytest.mark.parametrize(
    ("amount", "length"),
    [(0, 0), (1, 1), (255, 1), (256, 2), (10_001_000_000_000, 6)],
)
def test_coins_use_the_shortest_byte_length(amount, length):
    from pytosiq_core import Builder

    builder = lifecycle.store_coins(Builder(), amount)
    body = builder.end_cell().begin_parse()
    assert body.load_uint(4) == length
    assert (body.load_uint(length * 8) if length else 0) == amount


# Captured from a live pool mid-round: two dictionaries and an empty tuple sit
# among the scalars, and dropping them shifts every field after them.
LIVE_POOL_STACK = (
    " 2 3 10000000000000 5099000000000 "
    "83198038013376700015288955075319620229507546180038893305607971960195988746930 "
    "4000 40 5000000000000 100000000000 "
    "C{11ABED3CAE4FC4559DA9D644F51F6A08449D157FB92C0D93722B670A05B13263} "
    "C{D522420CE5752BFEF6AC47C2C18A8D205F7546B55B8A126DD3FD4A07F6AE3F6A} "
    "1786961271 "
    "9849093653771528673626176294238618023595952502286307336837359536101675960382 "
    "0 1786960671 180 () "
)


def test_stack_slots_survive_cells_and_empty_tuples():
    tokens = lifecycle.PoolLifecycle._stack_tokens(LIVE_POOL_STACK)
    assert len(tokens) == 17
    assert tokens[0] == "2"  # state: staked
    assert tokens[9].startswith("C{")  # nominators
    assert tokens[10].startswith("C{")  # withdraw requests
    assert tokens[11] == "1786961271"  # stake_at, the election it is staked for
    assert tokens[13] == "0"  # validator set changes counted so far
    assert tokens[15] == "180"  # stake_held_for
    assert tokens[16] == "()"


def test_a_naive_parser_would_read_the_counter_as_a_duration():
    """Why the tokenizer exists, stated as a test rather than a comment.

    Keeping only the numeric tokens moves stake_held_for into the slot the
    change counter should occupy. A run using that parser reports that the
    pool has counted 180 changes when it has counted none, and skips the one
    action that makes recovery possible.
    """
    numbers = [t for t in LIVE_POOL_STACK.split() if t.lstrip("-").isdigit()]
    assert numbers[13] == "180"  # the trap: stake_held_for masquerading as a count
    tokens = lifecycle.PoolLifecycle._stack_tokens(LIVE_POOL_STACK)
    assert tokens[13] == "0"

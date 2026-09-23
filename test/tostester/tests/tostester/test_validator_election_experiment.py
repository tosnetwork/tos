"""Unit coverage for the validator-election experiment control surface."""

import asyncio
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[4]
SCRIPT = REPO / "scripts/validator-election-stage-a.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("validator_election_stage_a", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


stage_a = _load_script()


def test_default_cli_selects_complete_pq_launch_gate_profile():
    args = stage_a.parse_args([])

    assert args.mode == "launch-gate"
    assert args.stage == "a"
    assert args.base_port == 26_000
    assert args.output_root is None
    assert stage_a.parse_args(["--mode", "pq-launch-gate"]).mode == "pq-launch-gate"


def test_pq_followup_requires_the_pq_election_fixture(tmp_path):
    with pytest.raises(ValueError, match="requires the PQ election fixture"):
        stage_a.ValidatorElectionRehearsal(
            run_dir=tmp_path / "no-pq-fixture", base_port=26_000,
            build_dir=REPO / "build", sample_interval=10,
            profile=stage_a.PROFILES["a"], pq_full=True,
        )


def test_pq_full_genesis_faucet_is_budgeted_and_checked_before_elections(tmp_path, monkeypatch):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "pq-full-faucet", base_port=26_000,
        build_dir=REPO / "build", sample_interval=10,
        profile=stage_a.PROFILES["a"], pq_election=True, pq_full=True,
    )
    rehearsal.controller_code = stage_a.Cell.empty()
    config = SimpleNamespace()
    rehearsal.configure_network_profile(config)
    expected = (
        4 * stage_a.VALIDATOR_WALLET_FUNDING
        + stage_a.NEGATIVE_WALLET_FUNDING
        + 4 * 10 * stage_a.NANO
        + 2 * 4 * (stage_a.PQ_STAKE_MESSAGE_VALUE + 40 * stage_a.NANO)
        + 2 * 1_000 * stage_a.NANO
    )
    assert config.validator_election_experiment_faucet_balance_nanotos == expected
    faucet = SimpleNamespace(address=stage_a.Address((-1, bytes(32))))
    required = stage_a.PQ_FULL_FOLLOWUP_FAUCET_CAPITAL + stage_a.PQ_FULL_FAUCET_FEE_RESERVE
    current = required - 1

    async def balance(address):
        assert address == faucet.address
        return current

    monkeypatch.setattr(rehearsal, "balance", balance)
    with pytest.raises(AssertionError, match="cannot fund rounds 2 and 3"):
        asyncio.run(rehearsal.require_pq_full_faucet_capacity(faucet))
    current = required
    asyncio.run(rehearsal.require_pq_full_faucet_capacity(faucet))
    assert rehearsal.events[-1]["balance"] == required
    assert rehearsal.events[-1]["genesis_budget"] == expected


def test_pq_stake_reply_queries_are_distinct_across_elections(tmp_path, monkeypatch):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "pq-round-queries", base_port=26_000,
        build_dir=REPO / "build", sample_interval=10,
        profile=stage_a.PROFILES["a"], pq_election=True, pq_full=True,
    )
    address = stage_a.Address((-1, bytes([0x11]) * 32))
    pool_address = stage_a.Address((-1, bytes([0x22]) * 32))
    rehearsal.wallets = [object()]
    rehearsal.pools = [SimpleNamespace(address=pool_address)]
    rehearsal.controllers = [SimpleNamespace(address=address)]
    calls = []

    async def order(index, election_id, query_id, **kwargs):
        calls.append(("order", election_id, query_id, kwargs))
        return stage_a.Cell.empty(), bytes([0x33]) * 32

    async def send(wallet, **kwargs):
        calls.append(("send", kwargs["label"]))

    async def reply(index, query_id, **kwargs):
        calls.append(("reply", query_id))
        return 0xF374484C, 0

    async def method(name, controller_id):
        return stage_a.EFFECTIVE_STAKE

    async def retry(fn, **kwargs):
        return await fn()

    monkeypatch.setattr(rehearsal, "authorized_pq_pool_order", order)
    monkeypatch.setattr(rehearsal, "send_from_wallet", send)
    monkeypatch.setattr(rehearsal, "wait_pq_pool_elector_reply", reply)
    monkeypatch.setattr(rehearsal, "runmethod_int", method)
    monkeypatch.setattr(rehearsal, "retry", retry)
    for round_number in (1, 2, 3):
        asyncio.run(rehearsal.submit_pq_candidate(
            0, 1_700_000_000 + round_number, round_number=round_number,
        ))
    assert [call[2] for call in calls if call[0] == "order"] == [1, 1001, 2001]
    assert [call[1] for call in calls if call[0] == "reply"] == [1, 1001, 2001]
    assert len({call[1] for call in calls if call[0] == "send"}) == 3


def test_shared_pq_pool_order_binds_node_authorization_to_controller_and_pool(
    tmp_path, monkeypatch
):
    """Drive the composition, not merely each of its checked inputs."""
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "pq", base_port=26_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"], pq_election=True,
    )
    controller_id = bytes([0x11]) * 32
    pool_id = bytes([0x22]) * 32
    key_id = bytes([0x33]) * 32
    public_key = bytes([0x44]) * 1312
    signature = bytes([0x55]) * 2420
    adnl_id = bytes([0x66]) * 32
    witness = stage_a.Cell.empty()
    built_order = stage_a.Builder().store_uint(0xCAFE, 16).end_cell()
    authorization = stage_a.tos_api.Engine_validator_pqStakeAuthorization(
        validator_id=controller_id, key_id=key_id, algorithm_id=1,
        public_key=public_key, signature=signature,
    )
    seen = {}

    class FakeConsole:
        async def request(self, request):
            seen["request"] = request
            return authorization.to_dict()

    rehearsal.nodes = [SimpleNamespace(
        validator_key=SimpleNamespace(id=adnl_id), engine_console=FakeConsole()
    )]
    rehearsal.pools = [SimpleNamespace(address=stage_a.Address((-1, pool_id)))]
    rehearsal.controllers = [SimpleNamespace(
        address=stage_a.Address((-1, controller_id)),
        consensus=SimpleNamespace(key_id=key_id, public_key=public_key),
        birth_witness=witness,
    )]

    def fake_builder(path, **fields):
        seen["path"] = path
        seen["fields"] = fields
        return built_order

    monkeypatch.setattr(stage_a, "build_production_pool_stake_order", fake_builder)
    body, actual_key = asyncio.run(rehearsal.authorized_pq_pool_order(0, 1_700_000_000, 19))
    assert body == built_order and actual_key == key_id
    assert seen["request"].election_date == 1_700_000_000
    assert seen["request"].stake_owner == pool_id
    assert seen["request"].adnl_addr == adnl_id
    assert seen["path"].name == "pq_pool_stake_order"
    assert seen["fields"] == {
        "query_id": 19, "stake_amount": stage_a.PQ_STAKE_MESSAGE_VALUE,
        "stake_at": 1_700_000_000, "max_factor": stage_a.MAX_FACTOR,
        "adnl_addr": adnl_id, "algorithm_id": 1,
        "public_key": public_key, "signature": signature, "witness": witness,
    }

    authorization.key_id = bytes(32)
    seen.pop("fields")
    with pytest.raises(AssertionError, match="wrong consensus key"):
        asyncio.run(rehearsal.authorized_pq_pool_order(0, 1_700_000_000, 20))
    assert "fields" not in seen, "a mismatched authorization reached the pool builder"

    authorization.key_id = key_id
    asyncio.run(rehearsal.authorized_pq_pool_order(
        0, 1_700_000_000, 21, corrupt_signature_for_negative=True
    ))
    assert seen["fields"]["signature"] == bytes([signature[0] ^ 1]) + signature[1:]
    assert seen["fields"]["public_key"] == public_key


def test_pq_first_round_negatives_pin_three_elector_reasons_and_unchanged_stake(
    tmp_path, monkeypatch
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "pq-negatives", base_port=26_000,
        build_dir=REPO / "build", sample_interval=10,
        profile=stage_a.PROFILES["a"], pq_election=True,
    )
    controller = stage_a.Address((-1, bytes([0x11]) * 32))
    pool = stage_a.Address((-1, bytes([0x22]) * 32))
    rehearsal.controllers = [SimpleNamespace(address=controller)]
    rehearsal.pools = [SimpleNamespace(address=pool)]
    rehearsal.wallets = [object()]
    seen = []
    reasons = {101: 5, 102: 3, 103: 1}

    async def current_stake(method, controller_id):
        assert method == "participates_in"
        assert controller_id == "0x" + controller.hash_part.hex()
        return 0

    async def make_order(index, election_id, query_id, **options):
        seen.append(("order", index, election_id, query_id, options))
        return stage_a.Cell.empty(), bytes(32)

    async def send(wallet, *, dest, amount, body, label):
        seen.append(("send", dest, amount, label))

    async def reply(index, query_id, *, description):
        seen.append(("reply", index, query_id))
        return 0xEE6F454C, reasons[query_id]

    monkeypatch.setattr(rehearsal, "runmethod_int", current_stake)
    monkeypatch.setattr(rehearsal, "authorized_pq_pool_order", make_order)
    monkeypatch.setattr(rehearsal, "send_from_wallet", send)
    monkeypatch.setattr(rehearsal, "wait_pq_pool_elector_reply", reply)
    asyncio.run(rehearsal.assert_pq_first_round_negative_cases(1_700_000_000))
    assert [call for call in seen if call[0] == "order"] == [
        ("order", 0, 1_700_000_000, 101,
         {"stake_amount": 1_001 * stage_a.NANO, "corrupt_signature_for_negative": False}),
        ("order", 0, 1_700_000_001, 102,
         {"stake_amount": stage_a.PQ_STAKE_MESSAGE_VALUE,
          "corrupt_signature_for_negative": False}),
        ("order", 0, 1_700_000_000, 103,
         {"stake_amount": stage_a.PQ_STAKE_MESSAGE_VALUE,
          "corrupt_signature_for_negative": True}),
    ]
    assert [call[1] for call in seen if call[0] == "send"] == [pool] * 3
    assert [call[2] for call in seen if call[0] == "reply"] == [101, 102, 103]
    assert [event["reason"] for event in rehearsal.events] == [5, 3, 1]

    reasons[103] = 8
    with pytest.raises(AssertionError, match="invalid-signature.*expected elector return reason 1"):
        asyncio.run(rehearsal.assert_pq_first_round_negative_cases(1_700_000_000))


def test_restarted_pq_node_retries_only_pre_send_authorization_transients(tmp_path):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "pq-restart", base_port=26_000,
        build_dir=REPO / "build", sample_interval=10,
        profile=stage_a.PROFILES["a"], pq_election=True,
    )
    calls = []

    class FakeConsole:
        async def request(self, request):
            calls.append("authorization")
            if len(calls) == 1:
                raise stage_a.LocalError(0, "Connection closed")
            if len(calls) == 2:
                raise stage_a.RemoteError(651, "this node cannot authorise a stake: not started")
            return "ready"

    rehearsal.nodes = [SimpleNamespace(engine_console=FakeConsole())]
    result = asyncio.run(rehearsal.request_pq_authorization(
        0, object(), retry_restart_transients=True, timeout=2.0
    ))
    assert result == "ready"
    assert calls == ["authorization"] * 3
    assert rehearsal.events[-1]["transient_connection_closures"] == 1
    assert rehearsal.events[-1]["transient_not_started"] == 1

    class WrongFailure:
        async def request(self, request):
            raise stage_a.RemoteError(651, "invalid consensus key")

    rehearsal.nodes = [SimpleNamespace(engine_console=WrongFailure())]
    with pytest.raises(stage_a.RemoteError, match="invalid consensus key"):
        asyncio.run(rehearsal.request_pq_authorization(
            0, object(), retry_restart_transients=True, timeout=0.01
        ))

    class NeverReturns:
        async def request(self, request):
            await asyncio.Event().wait()

    rehearsal.nodes = [SimpleNamespace(engine_console=NeverReturns())]
    with pytest.raises(TimeoutError, match="validator 1 PQ authorization did not become ready"):
        asyncio.run(rehearsal.request_pq_authorization(
            0, object(), retry_restart_transients=True, timeout=0.01
        ))

    class AlwaysTransient:
        async def request(self, request):
            raise stage_a.RemoteError(651, "not started")

    rehearsal.nodes = [SimpleNamespace(engine_console=AlwaysTransient())]
    with pytest.raises(TimeoutError, match="not started=1"):
        asyncio.run(rehearsal.request_pq_authorization(
            0, object(), retry_restart_transients=True, timeout=0.01
        ))


def test_pq_config34_requires_identity_adnl_pairs_not_just_two_sets():
    first = "11" * 32
    second = "22" * 32
    first_adnl = "AA" * 32
    second_adnl = "BB" * 32
    output = (
        f"value:(validator_pq validator_id:x{first} algorithm_id:1 "
        f"key_id:x{'33' * 32} weight:17 adnl_addr:x{first_adnl})\n"
        f"value:(validator_pq validator_id:x{second} algorithm_id:1 "
        f"key_id:x{'44' * 32} weight:17 adnl_addr:x{second_adnl})"
    )
    expected = {first.upper(): first_adnl, second.upper(): second_adnl}

    def config(raw):
        return stage_a.Config34(
            utime_since=1, utime_until=2, total=2, main=2, total_weight=34,
            validator_ids=[first, second], public_keys=[],
            adnl_ids=stage_a.re.findall(r"adnl_addr:x([0-9A-Fa-f]{64})", raw),
            validator_adnl_pairs=stage_a.parse_pq_validator_adnl_pairs(raw), raw=raw,
        )

    stage_a.require_pq_config34_associations(config(output), expected)
    swapped = output.replace(first_adnl, "CC" * 32).replace(second_adnl, first_adnl).replace(
        "CC" * 32, second_adnl
    )
    assert set(config(swapped).adnl_ids) == {first_adnl, second_adnl}
    with pytest.raises(AssertionError, match="controller-to-ADNL association differs"):
        stage_a.require_pq_config34_associations(config(swapped), expected)
    with pytest.raises(ValueError, match="has 0 ADNL IDs"):
        stage_a.parse_pq_validator_adnl_pairs(output.replace(second_adnl, ""))


def test_experiment_reserves_four_consecutive_loopback_rpc_ports():
    profile = stage_a.ExperimentProfile(
        duration_seconds=10_800,
        settlement_tail_seconds=900,
        rpc_host="127.0.0.1",
        rpc_base_port=8111,
    )

    assert profile.rpc_addresses == [
        "127.0.0.1:8111",
        "127.0.0.1:8112",
        "127.0.0.1:8113",
        "127.0.0.1:8114",
    ]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"duration_seconds": 0}, "duration"),
        ({"settlement_tail_seconds": -1}, "settlement tail"),
        ({"rpc_host": "0.0.0.0"}, "loopback"),
        ({"rpc_base_port": 65_534}, "four valid consecutive ports"),
    ],
)
def test_experiment_rejects_unsafe_or_invalid_runtime_settings(overrides, message):
    values = {
        "duration_seconds": 10_800,
        "settlement_tail_seconds": 900,
        "rpc_host": "127.0.0.1",
        "rpc_base_port": 8111,
        **overrides,
    }

    with pytest.raises(ValueError, match=message):
        stage_a.ExperimentProfile(**values)


def test_json_rpc_is_added_only_in_experiment_mode(tmp_path):
    launch_gate = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "launch",
        base_port=26_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
    )
    experiment = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "experiment",
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(
            duration_seconds=10_800,
            settlement_tail_seconds=900,
            rpc_host="127.0.0.1",
            rpc_base_port=8111,
        ),
    )

    assert "--json-rpc-address" not in launch_gate.validator_start_options().args
    for index, expected in enumerate(experiment.experiment.rpc_addresses):
        options = experiment.validator_start_options(index)
        rpc_flag = options.args.index("--json-rpc-address")
        assert options.args[rpc_flag + 1] == expected


def test_experiment_pool_capital_supports_three_concurrent_unrecovered_stakes(
    tmp_path,
):
    launch_gate = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "launch",
        base_port=26_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
    )
    experiment = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path / "experiment",
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(
            duration_seconds=10_800,
            settlement_tail_seconds=900,
            rpc_host="127.0.0.1",
            rpc_base_port=8111,
        ),
    )

    assert launch_gate.validator_wallet_funding() == 20_020 * stage_a.NANO
    assert launch_gate.validator_wallet_funding() == stage_a.VALIDATOR_WALLET_FUNDING
    assert stage_a.EXPERIMENT_CONCURRENT_STAKE_CAPACITY == 3
    assert experiment.pq_election is True
    assert experiment.validator_wallet_funding() == (
        stage_a.PQ_EXPERIMENT_POOL_CAPITAL + stage_a.EXPERIMENT_OPERATOR_FEE_RESERVE
    )
    assert (
        experiment.validator_wallet_funding()
        == stage_a.EXPERIMENT_VALIDATOR_WALLET_FUNDING
    )
    assert (
        stage_a.PQ_EXPERIMENT_POOL_CAPITAL
        == 3 * (stage_a.PQ_STAKE_MESSAGE_VALUE + 20 * stage_a.NANO)
    )
    assert (
        stage_a.PQ_EXPERIMENT_POOL_CAPITAL - 2 * stage_a.PQ_STAKE_MESSAGE_VALUE
        >= stage_a.PQ_STAKE_MESSAGE_VALUE + 2 * stage_a.NANO
    )
    assert launch_gate.validator_wallet_funding() < stage_a.PQ_EXPERIMENT_POOL_CAPITAL

    launch_config = stage_a.NetworkConfig()
    experiment_config = stage_a.NetworkConfig()
    experiment.controller_code = stage_a.Cell.empty()
    launch_gate.configure_network_profile(launch_config)
    experiment.configure_network_profile(experiment_config)
    assert launch_config.validator_election_experiment_faucet_balance_nanotos is None
    assert (
        experiment_config.validator_election_experiment_faucet_balance_nanotos
        == stage_a.EXPERIMENT_GENESIS_FAUCET_FUNDING
    )
    assert stage_a.EXPERIMENT_GENESIS_FAUCET_FUNDING == (
        4 * stage_a.EXPERIMENT_VALIDATOR_WALLET_FUNDING
        + stage_a.NEGATIVE_WALLET_FUNDING
        + 4 * 10 * stage_a.NANO
        + stage_a.EXPERIMENT_FAUCET_FEE_RESERVE
    )


def test_experiment_candidate_records_node_authorized_pool_owner(tmp_path, monkeypatch):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 600, "127.0.0.1", 8111),
    )
    wallet = stage_a.Address((-1, bytes([0x11]) * 32))
    pool = stage_a.Address((-1, bytes([0x22]) * 32))
    controller = stage_a.Address((-1, bytes([0x33]) * 32))
    adnl = bytes([0x44]) * 32
    rehearsal.wallets = [SimpleNamespace(address=wallet)]
    rehearsal.pools = [SimpleNamespace(address=pool)]
    rehearsal.controllers = [SimpleNamespace(
        address=controller, consensus=SimpleNamespace(key_id=bytes([0x55]) * 32),
    )]
    rehearsal.nodes = [SimpleNamespace(validator_key=SimpleNamespace(id=adnl))]

    async def balance(address):
        return 50 * stage_a.NANO if address == wallet else stage_a.PQ_EXPERIMENT_POOL_CAPITAL

    async def submit(index, election_id, *, round_number):
        assert (index, election_id, round_number) == (0, 100, 1)
        return {
            "query_id": 1, "authorization_key_id_hex": (bytes([0x55]) * 32).hex(),
            "body_boc": {"sha256": "pq-body"},
            "effective_stake_nanotos": 11_001 * stage_a.NANO,
        }

    monkeypatch.setattr(rehearsal, "balance", balance)
    monkeypatch.setattr(rehearsal, "submit_pq_candidate", submit)
    monkeypatch.setattr(rehearsal, "publish_allocation_evidence", lambda status: None)
    asyncio.run(rehearsal.submit_experiment_candidate(index=0, election_id=100, round_number=1))
    candidate = rehearsal.election_allocations[100]["validators"]["1"]
    assert candidate["controller_id_hex"] == controller.hash_part.hex()
    assert candidate["pool_stake_owner_raw"] == stage_a.raw_address(pool)
    assert candidate["recovery_destination_raw"] == stage_a.raw_address(pool)
    assert candidate["operator_wallet_raw"] == stage_a.raw_address(wallet)
    assert candidate["effective_stake_nanotos"] == 11_001 * stage_a.NANO
    assert candidate["pq_authorized_order"]["body_boc"]["sha256"] == "pq-body"


@pytest.mark.parametrize("reply_opcode", [0xF96F7324, 0xEE6F454C])
def test_experiment_recovery_credits_pool_and_requires_mature_reply(
    tmp_path, monkeypatch, reply_opcode,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 600, "127.0.0.1", 8111),
    )
    wallets = [stage_a.Address((-1, bytes([0x10 + index]) * 32)) for index in range(4)]
    pools = [stage_a.Address((-1, bytes([0x20 + index]) * 32)) for index in range(4)]
    controllers = [stage_a.Address((-1, bytes([0x30 + index]) * 32)) for index in range(4)]
    rehearsal.wallets = [SimpleNamespace(address=value) for value in wallets]
    rehearsal.pools = [SimpleNamespace(address=value) for value in pools]
    rehearsal.controllers = [SimpleNamespace(address=value) for value in controllers]
    rehearsal.nodes = [
        SimpleNamespace(validator_key=SimpleNamespace(id=bytes([0x40 + index]) * 32))
        for index in range(4)
    ]
    principal = 11_001 * stage_a.NANO
    credit = principal + 15 * stage_a.NANO
    rehearsal.election_allocations = {
        100: {"initial_unfreeze_estimate": 150, "config34_cell_hash": 1, "validators": {
            "1": {"selection_status": "selected", "recovery_status": "pending", "effective_stake_nanotos": principal},
        }},
    }
    rehearsal.experiment_current_config34_since = 400
    rehearsal.experiment_current_config34_hash = 2
    rehearsal.experiment_past_elections = {100: {"unfreeze_at": 150, "vset_hash": 1, "stake_held": 180}}
    rehearsal.experiment_last_chain_timestamp = 200
    sent = False

    async def runmethod(name, pool_id):
        assert name == "compute_returned_stake"
        assert pool_id.startswith("0x")
        return (0 if sent else credit) if pool_id == "0x" + pools[0].hash_part.hex() else 0

    async def balance(address):
        assert address == pools[0]
        return 100 * stage_a.NANO + (credit - stage_a.NANO if sent else 0)

    async def recovery_body(label):
        return (stage_a.Builder().store_uint(0x47657424, 32)
                .store_uint(77, 64).end_cell())

    async def send(wallet, *, dest, amount, body, label):
        nonlocal sent
        assert wallet.address == wallets[0]
        assert dest == pools[0] and amount == stage_a.NANO
        sent = True

    async def reply(index, query_id, **kwargs):
        assert (index, query_id) == (0, 77)
        return reply_opcode, 0

    async def retry(fn, *, predicate, **kwargs):
        value = await fn()
        assert predicate(value)
        return value

    monkeypatch.setattr(rehearsal, "runmethod_int", runmethod)
    monkeypatch.setattr(rehearsal, "balance", balance)
    monkeypatch.setattr(rehearsal, "recovery_body", recovery_body)
    monkeypatch.setattr(rehearsal, "send_from_wallet", send)
    monkeypatch.setattr(rehearsal, "wait_pq_pool_elector_reply", reply)
    monkeypatch.setattr(rehearsal, "retry", retry)
    monkeypatch.setattr(rehearsal, "publish_allocation_evidence", lambda status: None)
    if reply_opcode != 0xF96F7324:
        with pytest.raises(AssertionError, match="did not receive mature recovery"):
            asyncio.run(rehearsal.recover_experiment_stakes(200))
        assert rehearsal.recovery_records == []
    else:
        assert asyncio.run(rehearsal.recover_experiment_stakes(200)) == 1
        record = rehearsal.recovery_records[0]
        assert record["principal_nanotos"] == principal
        assert record["reward_nanotos"] == 15 * stage_a.NANO
        assert record["pool_stake_owner_raw"] == stage_a.raw_address(pools[0])
        assert record["pool_balance_delta_nanotos"] == credit - stage_a.NANO
        assert record["elector_reply_opcode"] == "0xf96f7324"


@pytest.mark.parametrize("swap_controller_adnl", [False, True])
def test_experiment_activation_joins_pq_controllers_by_adnl_not_zero_public_key(
    tmp_path, monkeypatch, swap_controller_adnl,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 600, "127.0.0.1", 8111),
    )
    controllers = [stage_a.Address((-1, bytes([0x31 + index]) * 32)) for index in range(4)]
    adnl = [bytes([0x41 + index]) * 32 for index in range(4)]
    rehearsal.controllers = [SimpleNamespace(address=value) for value in controllers]
    rehearsal.nodes = [SimpleNamespace(validator_key=SimpleNamespace(id=value)) for value in adnl]
    rehearsal.artifacts_dir.mkdir()
    pairs = [(controller.hash_part.hex().upper(), key.hex().upper())
             for controller, key in zip(controllers, adnl)]
    if swap_controller_adnl:
        pairs[0], pairs[1] = (pairs[0][0], pairs[1][1]), (pairs[1][0], pairs[0][1])
    config = stage_a.Config34(
        utime_since=100, utime_until=400, total=4, main=4, total_weight=100,
        validator_ids=[item[0] for item in pairs], public_keys=[],
        adnl_ids=[item[1] for item in pairs], validator_adnl_pairs=pairs, raw="pq-set",
    )
    rehearsal.election_allocations = {
        100: {"selection_status": "pending", "validators": {
            str(index + 1): {"controller_id_hex": controllers[index].hash_part.hex(),
                             "adnl_id_hex": adnl[index].hex()}
            for index in range(4)
        }, "elector_snapshots": []},
    }

    async def rpc_consensus(election_id):
        assert election_id == 100
        return {"observations": [{"validator_set": {
            "utime_since": 100,
            "validators": [{
                "public_key": stage_a.base64.b64encode(bytes(32)).decode(),
                "adnl_address": stage_a.base64.b64encode(key).decode(),
                "weight": str(index + 1), "cumulative_weight": str(index + 1),
            } for index, key in enumerate(adnl)],
        }}]}

    async def snapshot(label):
        return {"label": label}

    async def get_config():
        return config

    rehearsal.client = SimpleNamespace(
        get_config_param=lambda param: asyncio.sleep(
            0, result=SimpleNamespace(hash=(123).to_bytes(32, "big"))
        )
    )

    async def past_elections(method):
        assert method == "past_elections_list"
        return "result: [ ([100 500 123 180]) ]\nremote result (not to be trusted): [ ]"

    monkeypatch.setattr(rehearsal, "get_config34", get_config)
    monkeypatch.setattr(rehearsal, "runmethod", past_elections)
    monkeypatch.setattr(rehearsal, "rpc_config34_consensus", rpc_consensus)
    monkeypatch.setattr(rehearsal, "capture_elector_snapshot", snapshot)
    monkeypatch.setattr(rehearsal, "publish_allocation_evidence", lambda status: None)
    if swap_controller_adnl:
        with pytest.raises(AssertionError, match="controller.*ADNL|association"):
            asyncio.run(rehearsal.observe_experiment_activation())
    else:
        assert asyncio.run(rehearsal.observe_experiment_activation()) is True
        allocation = rehearsal.election_allocations[100]
        assert allocation["selection_status"] == "selected"
        assert [allocation["validators"][str(index + 1)]["individual_weight"]
                for index in range(4)] == [str(index + 1) for index in range(4)]


@pytest.mark.parametrize("case", ["retained-only", "mixed", "insufficient"])
def test_experiment_pool_credit_includes_matured_rollover_without_greedy_attribution(
    tmp_path, monkeypatch, case,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 600, "127.0.0.1", 8111),
    )
    wallets = [stage_a.Address((-1, bytes([0x50 + index]) * 32)) for index in range(4)]
    pools = [stage_a.Address((-1, bytes([0x60 + index]) * 32)) for index in range(4)]
    controllers = [stage_a.Address((-1, bytes([0x70 + index]) * 32)) for index in range(4)]
    rehearsal.wallets = [SimpleNamespace(address=value) for value in wallets]
    rehearsal.pools = [SimpleNamespace(address=value) for value in pools]
    rehearsal.controllers = [SimpleNamespace(address=value) for value in controllers]
    rehearsal.nodes = [
        SimpleNamespace(validator_key=SimpleNamespace(id=bytes([0x80 + index]) * 32))
        for index in range(4)
    ]
    primary_principal = 11_001 * stage_a.NANO
    rollover_principal = 11_002 * stage_a.NANO
    if case != "retained-only":
        rehearsal.election_allocations[100] = {
            "purpose": "primary-window", "selection_status": "selected",
            "initial_unfreeze_estimate": 150, "config34_cell_hash": 1, "validators": {"1": {
                "selection_status": "selected", "recovery_status": "pending",
                "effective_stake_nanotos": primary_principal,
            }},
        }
    rehearsal.election_allocations[400] = {
        "purpose": "settlement-rollover", "selection_status": "selected",
        "initial_unfreeze_estimate": 900, "config34_cell_hash": 2, "validators": {"1": {
            "selection_status": "selected", "recovery_status": "retained-settlement-rollover",
            "effective_stake_nanotos": rollover_principal,
        }},
    }
    rehearsal.experiment_last_chain_timestamp = 500
    rehearsal.experiment_current_config34_since = 700
    rehearsal.experiment_current_config34_hash = 3
    rehearsal.experiment_past_elections = {
        100: {"unfreeze_at": 150, "vset_hash": 1, "stake_held": 180},
        400: {"unfreeze_at": 450, "vset_hash": 2, "stake_held": 180},
    }
    expected_principal = rollover_principal + (primary_principal if case == "mixed" else 0)
    credit = (
        primary_principal + 15 * stage_a.NANO if case == "insufficient"
        else expected_principal + 15 * stage_a.NANO
    )
    sent = False

    async def runmethod(name, pool_id):
        assert name == "compute_returned_stake"
        return (0 if sent else credit) if pool_id == "0x" + pools[0].hash_part.hex() else 0

    async def balance(address):
        assert address == pools[0]
        return 100 * stage_a.NANO + (credit - stage_a.NANO if sent else 0)

    async def send(wallet, *, dest, amount, body, label):
        nonlocal sent
        assert wallet.address == wallets[0] and dest == pools[0]
        sent = True

    async def retry(fn, *, predicate, **kwargs):
        value = await fn()
        assert predicate(value)
        return value

    async def recovery_body(label):
        return (stage_a.Builder().store_uint(0x47657424, 32)
                .store_uint(78, 64).end_cell())

    async def reply(index, query_id, **kwargs):
        assert (index, query_id) == (0, 78)
        return 0xF96F7324, 0

    monkeypatch.setattr(rehearsal, "runmethod_int", runmethod)
    monkeypatch.setattr(rehearsal, "balance", balance)
    monkeypatch.setattr(rehearsal, "send_from_wallet", send)
    monkeypatch.setattr(rehearsal, "retry", retry)
    monkeypatch.setattr(rehearsal, "recovery_body", recovery_body)
    monkeypatch.setattr(rehearsal, "wait_pq_pool_elector_reply", reply)
    monkeypatch.setattr(rehearsal, "publish_allocation_evidence", lambda status: None)
    monkeypatch.setattr(rehearsal, "zero_state_evidence", lambda: {"fixture": True})
    monkeypatch.setattr(rehearsal, "validator_identity_evidence", lambda index: {
        "validator_index": index + 1,
        "operator_wallet_raw": stage_a.raw_address(wallets[index]),
        "pool_stake_owner_raw": stage_a.raw_address(pools[index]),
    })

    recovered = asyncio.run(rehearsal.recover_experiment_stakes(500))
    rollover = rehearsal.election_allocations[400]["validators"]["1"]
    evidence = rehearsal.allocation_evidence("complete")
    if case == "insufficient":
        assert recovered == 0 and sent is False
        assert rollover["recovery_status"] == "retained-settlement-rollover"
        assert evidence["reconciliation"]["matured_retained_unrecovered_allocations"] == [
            {"election_id": 400, "validator_index": 1},
        ]
        assert evidence["reconciliation"]["outstanding_allocations"] >= 1
        assert evidence["status"] == "partial-settlement"
    else:
        assert recovered == 1 and sent is True
        assert rollover["recovery_status"] in ("recovered", "recovered-in-aggregate")
        assert rollover["recovered_despite_retained_rollover"] is True
        assert evidence["reconciliation"]["retained_settlement_rollover_allocations"] == 0
        record = rehearsal.recovery_records[0]
        assert record["principal_nanotos"] == expected_principal
        if case == "mixed":
            assert record["candidate_election_ids"] == [100, 400]
            assert record["pool_aggregate_attribution_status"] == "EXACT"
            assert record["per_election_reward_attribution_status"] == "NOT_ATTRIBUTABLE"
            assert rollover["reward_attribution_status"] == "NOT_ATTRIBUTABLE"
        else:
            assert record["candidate_election_ids"] == [400]
            assert record["per_election_reward_attribution_status"] == "EXACT"


def test_v4_reconciliation_keeps_exact_pool_credits_and_retained_rollover_separate(
    tmp_path,
):
    experiment_profile = stage_a.ExperimentProfile(
        duration_seconds=10_800,
        settlement_tail_seconds=900,
        rpc_host="127.0.0.1",
        rpc_base_port=8111,
    )
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path,
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=experiment_profile,
    )
    rehearsal.validator_identity_evidence = lambda index: {  # type: ignore[method-assign]
        "validator_index": index + 1,
        "operator_wallet_raw": f"-1:{index + 1:064x}",
        "pool_stake_owner_raw": f"-1:{index + 11:064x}",
    }
    rehearsal.zero_state_evidence = lambda: {"fixture": True}  # type: ignore[method-assign]
    rehearsal.election_allocations = {
        100: {
            "election_id": 100,
            "purpose": "primary-window",
            "validators": {
                "1": {
                    "selection_status": "selected",
                    "recovery_status": "recovered",
                },
                "2": {
                    "selection_status": "selected",
                    "recovery_status": "recovered",
                },
                "3": {
                    "selection_status": "selected",
                    "recovery_status": "recovered",
                },
                "4": {
                    "selection_status": "selected",
                    "recovery_status": "recovered",
                },
            },
        },
        400: {
            "election_id": 400,
            "purpose": "settlement-rollover",
            "config34_cell_hash": 2,
            "validators": {
                "1": {
                    "selection_status": "selected",
                    "recovery_status": "retained-settlement-rollover",
                }
            },
        },
    }
    rehearsal.recovery_records = [
        {
            "validator_index": 1,
            "principal_nanotos": 10_000_000_000_000,
            "credit_nanotos": 10_000_123_456_789,
            "reward_nanotos": 123_456_789,
        },
        *(
            {
                "validator_index": index,
                "principal_nanotos": 10_000_000_000_000,
                "credit_nanotos": 10_000_000_000_000,
                "reward_nanotos": 0,
            }
            for index in range(2, 5)
        ),
    ]
    rehearsal.experiment_current_config34_since = 400
    rehearsal.experiment_current_config34_hash = 2
    rehearsal.experiment_last_chain_timestamp = 600
    rehearsal.experiment_past_elections = {
        400: {"unfreeze_at": 450, "vset_hash": 2, "stake_held": 180},
    }

    evidence = rehearsal.allocation_evidence("complete")

    assert evidence["schema_version"] == 4
    assert evidence["status"] == "complete"
    assert evidence["reconciliation"]["total_reward_nanotos"] == 123_456_789
    assert evidence["reconciliation"]["outstanding_allocations"] == 0
    assert evidence["reconciliation"]["retained_settlement_rollover_allocations"] == 1
    assert "equal-share inference" in evidence["elector"]["allocation_basis"]
    assert "pool-level" in evidence["elector"]["allocation_basis"]


def test_past_elections_list_parser_reads_actual_unfreeze_and_rejects_unknown_shape():
    output = (
        "result: [ ([100 280 12345 180] [400 700 67890 180]) ]\n"
        "remote result (not to be trusted): [ () ]"
    )
    assert stage_a.parse_past_elections_list(output) == {
        100: {"unfreeze_at": 280, "vset_hash": 12345, "stake_held": 180},
        400: {"unfreeze_at": 700, "vset_hash": 67890, "stake_held": 180},
    }
    with pytest.raises(ValueError, match="unparsed record"):
        stage_a.parse_past_elections_list(
            "result: [ ([100 280 12345]) ]\nremote result (not to be trusted): [ () ]"
        )


@pytest.mark.parametrize(
    ("current_set", "actual_unfreeze_at", "expected_state", "expected_outstanding"),
    [
        (400, 450, "active-retained", 0),
        (700, 650, "retired-frozen", 0),
        (700, 480, "matured-unrecovered", 1),
    ],
)
def test_retained_rollover_uses_current_set_and_real_elector_unfreeze(
    tmp_path, current_set, actual_unfreeze_at, expected_state, expected_outstanding,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 900, "127.0.0.1", 8111),
    )
    rehearsal.validator_identity_evidence = lambda index: {  # type: ignore[method-assign]
        "validator_index": index + 1,
        "operator_wallet_raw": f"-1:{index + 1:064x}",
        "pool_stake_owner_raw": f"-1:{index + 11:064x}",
    }
    rehearsal.zero_state_evidence = lambda: {"fixture": True}  # type: ignore[method-assign]
    rehearsal.election_allocations = {
        400: {
            "election_id": 400,
            "purpose": "settlement-rollover",
            "config34_cell_hash": 12345,
            # Deliberately already in the past in all cases: this estimate is
            # never authority for maturity after Elector changes active sets.
            "initial_unfreeze_estimate": 450,
            "validators": {"1": {
                "selection_status": "selected",
                "recovery_status": "retained-settlement-rollover",
            }},
        },
    }
    rehearsal.experiment_last_chain_timestamp = 500
    rehearsal.experiment_current_config34_since = current_set
    rehearsal.experiment_current_config34_hash = (
        12345 if current_set == 400 else 67890
    )
    rehearsal.experiment_past_elections = {
        400: {"unfreeze_at": actual_unfreeze_at, "vset_hash": 12345, "stake_held": 180},
    }

    evidence = rehearsal.allocation_evidence("complete")
    retained = evidence["validators"][0]["elections"][0]
    reconciliation = evidence["reconciliation"]
    assert retained["retention_state"] == expected_state
    assert evidence["elections"][0]["on_chain_unfreeze_at"] == actual_unfreeze_at
    assert reconciliation["outstanding_allocations"] == expected_outstanding
    assert reconciliation["active_retained_allocations"] == (
        [{"election_id": 400, "validator_index": 1}]
        if expected_state == "active-retained" else []
    )
    assert reconciliation["matured_retained_unrecovered_allocations"] == (
        [{"election_id": 400, "validator_index": 1}]
        if expected_state == "matured-unrecovered" else []
    )
    assert evidence["status"] == (
        "partial-settlement" if expected_outstanding else "complete"
    )


def test_retained_rollover_refuses_a_config34_past_election_hash_mismatch(tmp_path):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path, base_port=36_000, build_dir=REPO / "build",
        sample_interval=10, profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(600, 900, "127.0.0.1", 8111),
    )
    rehearsal.election_allocations = {
        400: {"config34_cell_hash": 12345},
    }
    rehearsal.experiment_last_chain_timestamp = 500
    rehearsal.experiment_current_config34_since = 400
    rehearsal.experiment_current_config34_hash = 67890
    rehearsal.experiment_past_elections = {
        400: {"unfreeze_at": 450, "vset_hash": 12345, "stake_held": 180},
    }
    assert rehearsal.experiment_retention_state(400) == "unmeasured"
    rehearsal.experiment_current_config34_hash = 12345
    assert rehearsal.experiment_retention_state(400) == "active-retained"


def test_missing_primary_candidates_are_explicit_outstanding_and_fail_completion(
    tmp_path,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path,
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(
            duration_seconds=10_800,
            settlement_tail_seconds=900,
            rpc_host="127.0.0.1",
            rpc_base_port=8111,
        ),
    )
    rehearsal.validator_identity_evidence = lambda index: {  # type: ignore[method-assign]
        "validator_index": index + 1,
        "operator_wallet_raw": f"-1:{index + 1:064x}",
        "pool_stake_owner_raw": f"-1:{index + 11:064x}",
    }
    rehearsal.zero_state_evidence = lambda: {"fixture": True}  # type: ignore[method-assign]
    rehearsal.election_allocations = {
        100: {
            "election_id": 100,
            "purpose": "primary-window",
            "submission_status": "waiting-for-recovery-funds",
            "selection_status": "pending",
            "validators": {},
        }
    }

    evidence = rehearsal.allocation_evidence("complete")
    reconciliation = evidence["reconciliation"]

    assert evidence["status"] == "partial-settlement"
    assert reconciliation["expected_primary_candidate_allocations"] == 4
    assert reconciliation["candidate_allocations"] == 0
    assert reconciliation["missing_primary_candidate_count"] == 4
    assert reconciliation["outstanding_allocations"] == 4
    assert evidence["elections"][0]["missing_validator_indices"] == [1, 2, 3, 4]
    assert {
        item["reward_attribution_status"]
        for item in reconciliation["missing_primary_candidate_allocations"]
    } == {"NOT_ATTRIBUTABLE"}
    assert {
        item["recovery_status"]
        for item in reconciliation["missing_primary_candidate_allocations"]
    } == {"OUTSTANDING"}

    assert rehearsal.set_experiment_final_status(4) == "partial-settlement"
    assert rehearsal.report_status() == "fail"
    with pytest.raises(RuntimeError, match="4 outstanding allocations"):
        rehearsal.require_complete_experiment_settlement(4)


def test_multi_election_credit_is_exact_only_at_pool_aggregate():
    single = stage_a.recovery_attribution([100])
    aggregate = stage_a.recovery_attribution([100, 400])

    assert single == {
        "attribution_status": "exact-single-election",
        "pool_aggregate_attribution_status": "EXACT",
        "per_election_reward_attribution_status": "EXACT",
    }
    assert aggregate == {
        "attribution_status": "pool-exact-multi-election-aggregate",
        "pool_aggregate_attribution_status": "EXACT",
        "per_election_reward_attribution_status": "NOT_ATTRIBUTABLE",
    }
    with pytest.raises(ValueError, match="at least one election"):
        stage_a.recovery_attribution([])


@pytest.mark.parametrize(
    "final_status",
    [None, "running", "partial-settlement", "failed", "unexpected"],
)
def test_experiment_report_and_exit_code_fail_closed_without_complete_status(
    tmp_path,
    final_status,
):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path,
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(
            duration_seconds=10_800,
            settlement_tail_seconds=900,
            rpc_host="127.0.0.1",
            rpc_base_port=8111,
        ),
    )
    rehearsal.experiment_final_status = final_status

    assert rehearsal.report_status() == "fail"
    assert rehearsal.completion_exit_code() == 1


def test_only_complete_failure_free_experiment_reports_pass_and_exits_zero(tmp_path):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path,
        base_port=36_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
        experiment=stage_a.ExperimentProfile(
            duration_seconds=10_800,
            settlement_tail_seconds=900,
            rpc_host="127.0.0.1",
            rpc_base_port=8111,
        ),
    )
    rehearsal.experiment_final_status = "complete"

    assert rehearsal.report_status() == "pass"
    assert rehearsal.completion_exit_code() == 0

    rehearsal.failures.append("postcondition failed")
    assert rehearsal.report_status() == "fail"
    assert rehearsal.completion_exit_code() == 1


def test_launch_gate_report_and_exit_code_keep_failure_only_semantics(tmp_path):
    rehearsal = stage_a.ValidatorElectionRehearsal(
        run_dir=tmp_path,
        base_port=26_000,
        build_dir=REPO / "build",
        sample_interval=10,
        profile=stage_a.PROFILES["a"],
    )

    assert rehearsal.experiment_final_status is None
    assert rehearsal.report_status() == "pass"
    assert rehearsal.completion_exit_code() == 0

    rehearsal.failures.append("launch gate failed")
    assert rehearsal.report_status() == "fail"
    assert rehearsal.completion_exit_code() == 1

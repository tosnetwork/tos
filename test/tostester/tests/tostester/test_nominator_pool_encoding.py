"""Cross-checks on how a nominator pool is addressed and spoken to.

Two independent implementations build the same bytes: the operator tool in
Rust, which deploys and resolves pools, and the lifecycle end-to-end script in
Python, which drives one through a round. A disagreement between them is not a
test failure that shows up as a test failure -- it shows up as deposits sent to
an address where no pool exists, or as a stake message the contract rejects
without saying why. So the encodings are pinned on both sides against the same
constants.
"""

import base64
import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytosiq_core import Address, Builder, Cell, CurrencyCollection, InternalMsgInfo, MessageAny
from tostester.zerostate import NetworkConfig

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


def test_openfox_manifest_binds_exactly_eight_unique_agents(tmp_path):
    manifest = {
        "schema": "tos.openfox.eight-agent-market-campaign.v1",
        "agents": [
            {
                "name": f"agent-{index}",
                "agent_id": f"agent:test:{index}",
                "wallet": f"0:{index:064x}",
                "target": f"0:{index + 100:064x}",
            }
            for index in range(8)
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    bindings, digest = lifecycle.load_agent_bindings(path)

    assert len(bindings) == 8
    assert bindings[3].agent_id == "agent:test:3"
    assert bindings[3].campaign_wallet_label == f"0:{3:064x}"
    assert bindings[3].campaign_account_address == f"0:{103:064x}"
    assert digest.startswith("sha256:") and len(digest) == 71


@pytest.mark.parametrize(
    "mutation", ["short", "duplicate-name", "duplicate-agent-id", "duplicate-target"]
)
def test_openfox_manifest_rejects_incomplete_or_ambiguous_bindings(tmp_path, mutation):
    agents = [
        {
            "name": f"agent-{index}",
            "agent_id": f"agent:test:{index}",
            "target": f"0:{index + 100:064x}",
        }
        for index in range(8)
    ]
    if mutation == "short":
        agents.pop()
    elif mutation == "duplicate-name":
        agents[-1]["name"] = agents[0]["name"]
    elif mutation == "duplicate-agent-id":
        agents[-1]["agent_id"] = agents[0]["agent_id"]
    else:
        agents[-1]["target"] = agents[0]["target"]
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema": "tos.openfox.eight-agent-market-campaign.v1",
                "agents": agents,
            }
        )
    )

    with pytest.raises(ValueError):
        lifecycle.load_agent_bindings(path)


def test_openfox_manifest_rejects_another_schema(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema": "wrong.v1", "agents": [{}] * 8}))
    with pytest.raises(ValueError, match="schema"):
        lifecycle.load_agent_bindings(path)


def test_campaign_run_id_is_exact_and_reported(tmp_path):
    campaign_run_id = "round4-20260902T013022Z-a1"
    assert lifecycle.validate_campaign_run_id(campaign_run_id) == campaign_run_id

    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id=campaign_run_id,
    )
    runner.write_report()

    report = json.loads((tmp_path / "report.json").read_text())
    assert report["campaign_run_id"] == campaign_run_id


def test_evidence_attempt_invalidates_old_pass_until_durable_finalization(tmp_path):
    campaign_run_id = "round4-evidence-attempt-test"
    evidence = tmp_path / "validator-evidence.json"
    evidence.write_text('{"passed":true,"old":true}\n')

    attempt = lifecycle.begin_evidence_attempt(evidence, campaign_run_id)

    assert evidence.read_text() == '{"passed":true,"old":true}\n'
    assert attempt.marker_path == tmp_path / ".validator-evidence.json.in-progress"
    marker = json.loads(attempt.marker_raw)
    assert marker["schema"] == lifecycle.EVIDENCE_ATTEMPT_MARKER_SCHEMA
    assert marker["campaign_run_id"] == campaign_run_id
    assert len(marker["attempt_id"]) == 64
    with pytest.raises(RuntimeError, match="evidence attempt lock is already held"):
        lifecycle.begin_evidence_attempt(evidence, campaign_run_id)

    lifecycle.finalize_evidence_attempt(
        evidence,
        attempt,
        '{"passed":false,"old":false}\n',
    )

    assert evidence.read_text() == '{"passed":false,"old":false}\n'
    assert not attempt.marker_path.exists()


def test_evidence_attempt_refuses_to_clear_a_changed_marker(tmp_path):
    evidence = tmp_path / "validator-evidence.json"
    attempt = lifecycle.begin_evidence_attempt(evidence, "round4-marker-change-test")
    attempt.marker_path.write_text("replaced\n")

    with pytest.raises(RuntimeError, match="changed before finalization"):
        lifecycle.finalize_evidence_attempt(evidence, attempt, "{}\n")

    assert attempt.marker_path.exists()
    assert not evidence.exists()
    lifecycle.release_evidence_attempt_lock(attempt)

    with pytest.raises(RuntimeError, match="unresolved evidence attempt marker"):
        lifecycle.begin_evidence_attempt(evidence, "round4-marker-change-test")


@pytest.mark.parametrize(
    "campaign_run_id",
    [
        "short",
        " leading-id",
        "trailing-id ",
        "slash/id",
        "dot-ended.",
        "unicode-中文-id",
        "x" * 129,
    ],
)
def test_campaign_run_id_rejects_ambiguous_or_unbounded_values(campaign_run_id):
    with pytest.raises(ValueError, match="campaign run id"):
        lifecycle.validate_campaign_run_id(campaign_run_id)


def test_campaign_run_id_is_a_required_cli_binding(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["nominator-pool-lifecycle-e2e.py", "--agent-manifest", str(manifest)],
    )
    with pytest.raises(SystemExit):
        lifecycle.parse_args()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "nominator-pool-lifecycle-e2e.py",
            "--agent-manifest",
            str(manifest),
            "--campaign-run-id",
            "round4-cli-binding",
        ],
    )
    assert lifecycle.parse_args().campaign_run_id == "round4-cli-binding"


def test_reward_delta_is_exact_only_after_both_ledger_snapshots():
    nominator = lifecycle.Nominator(index=0, wallet=None, key=None)
    assert nominator.reward is None
    nominator.principal_before_recovery = 999_000_000_000
    assert nominator.reward is None
    nominator.principal_after_recovery = 1_001_000_000_000
    assert nominator.reward == 2_000_000_000


def test_nominator_funding_observation_rejects_transient_unknown_balance():
    nominator = lifecycle.Nominator(
        index=0,
        wallet=None,
        key=None,
        funded_balance=-1,
        wallet_balance_before_deposit=1_100 * lifecycle.NANO - 1_000,
        wallet_balance_after_deposit=100 * lifecycle.NANO - 35_082,
    )
    assert lifecycle.valid_nominator_funding_observation(nominator) is False

    nominator.funded_balance = nominator.wallet_balance_before_deposit
    assert lifecycle.valid_nominator_funding_observation(nominator) is True


def test_election_reward_floor_excludes_post_stake_control_and_keeper_value():
    active = {index: 999_000_000_000 for index in range(8)}
    active[8] = 0  # deposited after stake; pending for the next round
    gross, validator, nominators, floors = lifecycle.election_reward_distribution(
        returned_credit=lifecycle.NETWORK_MIN_STAKE + 80_000_000_000,
        stake_amount_sent=lifecycle.NETWORK_MIN_STAKE,
        validator_reward_share_bps=4000,
        active_principal=active,
    )

    assert gross == 80_000_000_000
    assert validator == 32_000_000_000
    assert nominators == 48_000_000_000
    assert [floors[index] for index in range(8)] == [6_000_000_000] * 8
    assert floors[8] == 0


def test_election_reward_floor_rejects_invalid_economics():
    with pytest.raises(ValueError):
        lifecycle.election_reward_distribution(1, 1, 10_001, {0: 1})
    with pytest.raises(ValueError):
        lifecycle.election_reward_distribution(1, 1, 4000, {0: -1})


@pytest.mark.asyncio
async def test_solvency_skips_a_control_without_a_pool_position(tmp_path, monkeypatch):
    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id="round4-solvency-test",
    )
    runner.pool_address = Address((-1, bytes(32)))
    active = lifecycle.Nominator(
        index=0,
        wallet=None,
        key=None,
        deposited=999 * lifecycle.NANO,
    )
    control = lifecycle.Nominator(index=8, wallet=None, key=None)
    runner.nominators = [active, control]
    queried = []

    async def balance(_address):
        return lifecycle.MIN_TOS_FOR_STORAGE + active.deposited

    async def nominator_amount(nominator):
        queried.append(nominator)
        if nominator is control:
            raise AssertionError("an absent control position must not be queried")
        return nominator.deposited

    monkeypatch.setattr(runner, "balance", balance)
    monkeypatch.setattr(runner, "nominator_amount", nominator_amount)

    await runner.check_solvency()

    assert queried == [active]
    assert runner.report.checks[-1]["passed"] is True


def _integrated_fixture():
    bindings = []
    profiles = {}
    for index in range(lifecycle.OPENFOX_AGENT_COUNT):
        profile_name = f"campaign-agent-{index}"
        target = f"0:{index + 1:064x}"
        binding = lifecycle.AgentBinding(
            name=f"agent-{index}",
            agent_id=f"agent:test:{index}",
            campaign_wallet_label=profile_name,
            campaign_account_address=target,
        )
        bindings.append(binding)
        profiles[profile_name] = {
            "wallet": {
                "key": {"name": f"owner-vault-key-{index}"},
                "workchain": 0,
            },
            "controller_key": {"name": f"controller-vault-key-{index}"},
            "agent_account_address": target,
            "agent_account_deployment_id": f"{index + 11:064x}",
            "policy": {
                "max_per_tx": 10 * lifecycle.NANO,
                "daily_limit": 100 * lifecycle.NANO,
                "default_task_timeout_secs": 600,
            },
            "runtime": {"economic_custody_journal_directory": "/old/path"},
        }
    return bindings, {"agent_wallets": profiles, "wallets": {}, "agent_tasks": {"old": {}}}


def test_integrated_global_id_is_unique_per_attempt_and_never_legacy_three():
    campaign_run_id = "round5-global-domain-a"
    first_attempt = "a" * 64
    second_attempt = "b" * 64
    first = lifecycle.integrated_network_global_id(campaign_run_id, first_attempt)
    repeated = lifecycle.integrated_network_global_id(campaign_run_id, first_attempt)
    second = lifecycle.integrated_network_global_id(campaign_run_id, second_attempt)

    assert first == repeated
    assert first != second
    assert first not in (0, lifecycle.LEGACY_LOCAL_GLOBAL_ID)
    assert second not in (0, lifecycle.LEGACY_LOCAL_GLOBAL_ID)
    assert 0 < first <= (1 << 31) - 1
    first_binding = lifecycle.integrated_genesis_attempt_binding(campaign_run_id, first_attempt)
    second_binding = lifecycle.integrated_genesis_attempt_binding(campaign_run_id, second_attempt)
    assert first_binding != second_binding
    assert first_attempt not in first_binding


def test_zerostate_global_id_is_explicit_without_changing_the_legacy_default():
    assert NetworkConfig().global_id == lifecycle.LEGACY_LOCAL_GLOBAL_ID
    assert NetworkConfig(global_id=1_234_567_890).global_id == 1_234_567_890


def test_integrated_working_configs_reuse_references_but_clear_addresses(tmp_path):
    bindings, source = _integrated_fixture()
    profiles, configs = lifecycle.prepare_integrated_working_configs(
        source,
        bindings,
        tmp_path / "working",
        ["127.0.0.1:23000", "127.0.0.1:23001", "127.0.0.1:23002"],
        "round5-integrated-config-test",
    )

    assert len(profiles) == lifecycle.OPENFOX_AGENT_COUNT
    assert len(configs) == lifecycle.INTEGRATED_RPC_COUNT
    assert len({config.operator_provenance for config in configs}) == 3
    custody_paths = set()
    for index, config in enumerate(configs):
        assert config.path.stat().st_mode & 0o777 == 0o600
        document = json.loads(config.path.read_text())
        rpc_origin = f"http://127.0.0.1:{23000 + index}"
        rpc_locator = f"{rpc_origin}/jsonRPC"
        assert document["chain_rpc"]["urls"] == [rpc_locator]
        assert config.rpc_url == rpc_locator
        assert config.rpc_url not in {rpc_origin, f"{rpc_origin}/"}
        assert not config.rpc_url.endswith("/")
        assert document["agent_tasks"] == {}
        for profile_index, profile in enumerate(profiles):
            copied = document["agent_wallets"][profile.profile_name]
            assert copied["agent_account_address"] is None
            assert copied["agent_account_deployment_id"] == profile.deployment_id
            assert copied["controller_key"]["name"] == (f"controller-vault-key-{profile_index}")
            assert document["wallets"][profile.owner_wallet_alias]["key"]["name"] == (
                f"owner-vault-key-{profile_index}"
            )
            custody_paths.add(copied["runtime"]["economic_custody_journal_directory"])
    assert len(custody_paths) == 3 * lifecycle.OPENFOX_AGENT_COUNT


@pytest.mark.asyncio
async def test_integrated_ready_rpc_views_match_exact_config_locators(tmp_path, monkeypatch):
    bindings, source = _integrated_fixture()
    _, configs = lifecycle.prepare_integrated_working_configs(
        source,
        bindings,
        tmp_path / "working",
        ["127.0.0.1:23000", "127.0.0.1:23001", "127.0.0.1:23002"],
        "round5-integrated-ready-rpc-test",
    )
    evidence = tmp_path / "evidence.json"
    attempt = lifecycle.begin_evidence_attempt(evidence, "round5-integrated-ready-rpc-test")
    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id="round5-integrated-ready-rpc-test",
        evidence_out=evidence,
        evidence_attempt=attempt,
        integrated_source_config=tmp_path / "source.json",
        tosctl_path=tmp_path / "tosctl",
        rpc_base_port=23000,
        ready_out=tmp_path / "ready.json",
    )
    root_hash = bytes.fromhex("11" * 32)
    file_hash = bytes.fromhex("22" * 32)
    runner.network = SimpleNamespace(
        zerostate=SimpleNamespace(
            masterchain=SimpleNamespace(root_hash=root_hash, file_hash=file_hash)
        )
    )
    runner.working_configs = configs

    def fake_json_rpc_call(address, method, params=None):
        assert address in {config.rpc_address for config in configs}
        if method == "getMasterchainInfo":
            return {
                "result": {
                    "init": {
                        "root_hash": base64.b64encode(root_hash).decode(),
                        "file_hash": base64.b64encode(file_hash).decode(),
                    }
                }
            }
        assert method == "getConfigParam"
        assert params == {"param": 19}
        return {"result": {"config": {"bytes": "unused-by-test"}}}

    monkeypatch.setattr(lifecycle, "json_rpc_call", fake_json_rpc_call)
    monkeypatch.setattr(
        runner, "config_global_id_from_rpc", lambda _response: runner.network_global_id
    )

    await runner.wait_integrated_rpc_readiness()

    configured_locators = [
        json.loads(config.path.read_text())["chain_rpc"]["urls"][0] for config in configs
    ]
    ready_locators = [view["url"] for view in runner.rpc_readiness]
    assert len(configured_locators) == lifecycle.INTEGRATED_RPC_COUNT
    assert ready_locators == configured_locators
    assert all(locator.endswith("/jsonRPC") for locator in ready_locators)
    assert all(not locator.endswith("/") for locator in ready_locators)
    assert all(
        locator not in {f"http://{config.rpc_address}", f"http://{config.rpc_address}/"}
        for locator, config in zip(ready_locators, configs, strict=True)
    )
    lifecycle.release_evidence_attempt_lock(attempt)


def test_integrated_working_config_rejects_manifest_target_mismatch(tmp_path):
    bindings, source = _integrated_fixture()
    source["agent_wallets"][bindings[0].campaign_wallet_label]["agent_account_address"] = (
        f"0:{999:064x}"
    )
    with pytest.raises(ValueError, match="not the manifest campaign account"):
        lifecycle.prepare_integrated_working_configs(
            source,
            bindings,
            tmp_path / "working",
            ["127.0.0.1:23000", "127.0.0.1:23001", "127.0.0.1:23002"],
            "round5-integrated-target-test",
        )


def test_integrated_action_id_binds_every_economic_and_network_field():
    domain = {
        "network_id": lifecycle.INTEGRATED_NETWORK_ID,
        "global_id": lifecycle.integrated_network_global_id("round5-action-id-test", "c" * 64),
        "workchain_id": 0,
        "zero_state_root_hash": "sha256:" + "1" * 64,
        "zero_state_file_hash": "sha256:" + "2" * 64,
    }
    arguments = {
        "campaign_run_id": "round5-action-id-test",
        "network_domain": domain,
        "deployment_id": "3" * 64,
        "agent_id": "agent:test:0",
        "pool_address": "-1:" + "4" * 64,
        "action": "deposit",
        "amount_nanotos": 5 * lifecycle.NANO,
        "body_hash": "tvm-cell-sha256:" + "5" * 64,
    }
    baseline = lifecycle.integrated_action_id(**arguments)
    mutations = [
        {"campaign_run_id": "round5-action-id-other"},
        {"network_domain": {**domain, "global_id": domain["global_id"] + 1}},
        {"deployment_id": "6" * 64},
        {"agent_id": "agent:test:1"},
        {"pool_address": "-1:" + "7" * 64},
        {"action": "withdraw"},
        {"amount_nanotos": lifecycle.NANO},
        {"body_hash": "tvm-cell-sha256:" + "8" * 64},
    ]
    assert len(baseline) == 64
    assert all(
        lifecycle.integrated_action_id(**{**arguments, **mutation}) != baseline
        for mutation in mutations
    )


@pytest.mark.asyncio
async def test_integrated_task_send_keeps_masterchain_target_in_one_option_token(
    tmp_path, monkeypatch
):
    evidence = tmp_path / "evidence.json"
    attempt = lifecycle.begin_evidence_attempt(evidence, "round5-masterchain-target-test")
    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id="round5-masterchain-target-test",
        evidence_out=evidence,
        evidence_attempt=attempt,
        integrated_source_config=tmp_path / "source.json",
        tosctl_path=tmp_path / "tosctl",
        rpc_base_port=23000,
        ready_out=tmp_path / "ready.json",
    )
    runner.pool_address = Address((-1, bytes.fromhex("ab" * 32)))
    runner.network_domain = {
        "network_id": lifecycle.INTEGRATED_NETWORK_ID,
        "global_id": runner.network_global_id,
        "workchain_id": 0,
        "zero_state_root_hash": "sha256:" + "1" * 64,
        "zero_state_file_hash": "sha256:" + "2" * 64,
    }
    binding = lifecycle.AgentBinding(
        "agent-0",
        "agent:test:0",
        "campaign-agent-0",
        "0:" + "cd" * 32,
    )
    nominator = lifecycle.Nominator(
        index=0,
        wallet=None,
        key=None,
        agent=binding,
        address=Address(binding.campaign_account_address),
        agent_profile_name=binding.campaign_wallet_label,
        tosctl_config=tmp_path / "primary.json",
        deployment_id="3" * 64,
    )
    calls = []

    async def fake_tosctl(config, *args, **_kwargs):
        calls.append((config, args))
        return ""

    async def fake_finalized(*_args, **_kwargs):
        return {"finalized_transaction": {"status": "observed"}}

    monkeypatch.setattr(runner, "tosctl", fake_tosctl)
    monkeypatch.setattr(runner, "await_finalized_agent_action", fake_finalized)

    await runner.send_nominator(
        nominator,
        amount=5 * lifecycle.NANO,
        body=lifecycle.text_command("d"),
        label="regression-deposit",
        action="deposit",
    )

    assert len(calls) == 1
    config, args = calls[0]
    assert config == nominator.tosctl_config
    target = lifecycle.raw_address(runner.pool_address)
    assert f"--target={target}" in args
    assert "--target" not in args
    assert target not in args
    for option in ("--wallet", "--value", "--body-boc", "--valid-until", "--action-id"):
        assert option not in args
    lifecycle.release_evidence_attempt_lock(attempt)


def _task_send_resolution_fixture():
    source = "0:" + "1" * 64
    destination = "-1:" + "2" * 64
    body = Builder().store_uint(ord("d"), 8).end_cell()
    info = InternalMsgInfo(
        True,
        False,
        False,
        Address(source),
        Address(destination),
        CurrencyCollection(tomis=5 * lifecycle.NANO),
        0,
        0,
        123,
        456,
    )
    original_message = (
        Builder().store_cell(info.serialize()).store_bit(0).store_bit(1).store_ref(body).end_cell()
    )
    parsed_message = MessageAny.deserialize(original_message.begin_parse())
    exact_outbound_hash = "tvm-cell-sha256:" + original_message.hash.hex()
    body_hash = "tvm-cell-sha256:" + body.hash.hex()
    transaction_hash = "sha256:" + "3" * 64
    transaction = {
        "endpoint": "http://127.0.0.1:23000",
        "locator_identity_digest": "sha256:" + f"{4:064x}",
        "transaction_hash": transaction_hash,
        "transaction_lt": 1234,
        "transaction_utime": 1_800_000_000,
        "transaction_boc_digest": "sha256:" + "5" * 64,
        "block_workchain": 0,
        "block_shard": -(1 << 63),
        "block_seqno": 77,
        "block_root_hash": "sha256:" + "6" * 64,
        "block_file_hash": "sha256:" + "7" * 64,
        "observed_masterchain_seqno": 80,
        "outbound_message_cell_hash": exact_outbound_hash,
        "outbound_body_hash": body_hash,
        "finalized_controller_epoch": 0,
        "finalized_seqno": 1,
    }
    observations = [
        {
            **transaction,
            "endpoint": f"http://127.0.0.1:{23000 + index}",
            "locator_identity_digest": "sha256:" + f"{index + 4:064x}",
            "observed_masterchain_seqno": 80 + index,
        }
        for index in range(lifecycle.INTEGRATED_RPC_COUNT)
    ]
    resolution = {
        "schema": lifecycle.TASK_SEND_FINALIZED_SCHEMA,
        "wallet": "campaign-agent-0",
        "action_id": "8" * 64,
        "source_account": source,
        "deployment_id": "9" * 64,
        "controller_epoch": 0,
        "seqno": 0,
        "finalized_controller_epoch": 0,
        "finalized_seqno": 1,
        "destination": destination,
        "amount_nanotos": 5 * lifecycle.NANO,
        "body_hash": body_hash,
        "exact_signed_boc_digest": "sha256:" + "a" * 64,
        "submitted_message_cell_hash": "tvm-cell-sha256:" + "b" * 64,
        "network_domain": {
            "network_id": "tos:global-id:12345",
            "global_id": 12345,
            "zero_state_root_hash": "sha256:" + "c" * 64,
            "zero_state_file_hash": "sha256:" + "d" * 64,
            "workchain_id": 0,
        },
        "quorum": {"members": 3, "threshold": 2, "agreeing": 3},
        "process_view_scope": lifecycle.TASK_SEND_PROCESS_VIEW_SCOPE,
        "independent_operator_domains_proven": False,
        "transaction": transaction,
        "observations": observations,
        "state": "resolved",
    }
    finalized = {
        "account": source,
        "transaction_lt": "1234",
        "transaction_cell_hash": "tvm-cell-sha256:" + "3" * 64,
        "transaction_boc_digest": "sha256:" + "5" * 64,
        "out_message_cell_hash": exact_outbound_hash,
        "source": source,
        "target": destination,
        "value_nanotos": 5 * lifecycle.NANO,
        "body_hash": body_hash,
        "block_checkpoint": {
            "workchain": 0,
            "shard": str(-(1 << 63)),
            "seqno": 77,
            "root_hash": "sha256:" + "6" * 64,
            "file_hash": "sha256:" + "7" * 64,
        },
    }
    expected = {
        "expected_wallet": resolution["wallet"],
        "expected_action_id": resolution["action_id"],
        "expected_source_account": source,
        "expected_deployment_id": resolution["deployment_id"],
        "expected_destination": destination,
        "expected_amount_nanotos": resolution["amount_nanotos"],
        "expected_body_hash": body_hash,
        "expected_network_domain": resolution["network_domain"],
    }
    return resolution, finalized, expected, original_message, parsed_message


def test_task_send_by_ref_body_retains_exact_on_chain_message_cell():
    resolution, finalized, expected, original, parsed = _task_send_resolution_fixture()

    assert parsed.cell is not None
    assert parsed.cell.hash == original.hash
    assert parsed.body.hash == original.refs[0].hash
    assert parsed.serialize().hash != original.hash
    assert len(original.refs) == 1
    assert len(parsed.serialize().refs) == 0
    assert (
        lifecycle.task_send_resolution_mismatches(
            resolution,
            finalized_transaction=finalized,
            **expected,
        )
        == []
    )


@pytest.mark.parametrize(
    ("mutation", "expected_field"),
    [
        ("wrong_body", "effect.body_hash"),
        ("wrong_target", "effect.destination"),
        ("wrong_value", "effect.amount_nanotos"),
        ("wrong_transaction_hash", "effect.transaction_hash"),
        ("wrong_outbound_cell", "effect.outbound_message_identity"),
    ],
)
def test_task_send_resolution_reports_exact_mismatch_field(mutation, expected_field):
    resolution, finalized, expected, _original, _parsed = _task_send_resolution_fixture()
    resolution = copy.deepcopy(resolution)
    finalized = copy.deepcopy(finalized)
    if mutation == "wrong_body":
        finalized["body_hash"] = "tvm-cell-sha256:" + "e" * 64
    elif mutation == "wrong_target":
        finalized["target"] = "-1:" + "e" * 64
    elif mutation == "wrong_value":
        finalized["value_nanotos"] += 1
    elif mutation == "wrong_transaction_hash":
        resolution["transaction"]["transaction_hash"] = "sha256:" + "e" * 64
        for observation in resolution["observations"]:
            observation["transaction_hash"] = "sha256:" + "e" * 64
    elif mutation == "wrong_outbound_cell":
        resolution["transaction"]["outbound_message_cell_hash"] = "tvm-cell-sha256:" + "e" * 64
        for observation in resolution["observations"]:
            observation["outbound_message_cell_hash"] = "tvm-cell-sha256:" + "e" * 64
    else:  # pragma: no cover - the parametrization above is exhaustive
        raise AssertionError(mutation)

    mismatches = lifecycle.task_send_resolution_mismatches(
        resolution,
        finalized_transaction=finalized,
        **expected,
    )

    assert expected_field in mismatches


@pytest.mark.asyncio
async def test_integrated_deposit_journal_resolves_before_withdrawal_task_send(
    tmp_path, monkeypatch
):
    campaign_run_id = "round5-task-send-resolver-order"
    evidence = tmp_path / "evidence.json"
    attempt = lifecycle.begin_evidence_attempt(evidence, campaign_run_id)
    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id=campaign_run_id,
        evidence_out=evidence,
        evidence_attempt=attempt,
        integrated_source_config=tmp_path / "source.json",
        tosctl_path=tmp_path / "tosctl",
        rpc_base_port=23000,
        ready_out=tmp_path / "ready.json",
    )
    runner.pool_address = Address((-1, bytes.fromhex("ab" * 32)))
    runner.network_domain = {
        "network_id": lifecycle.INTEGRATED_NETWORK_ID,
        "global_id": runner.network_global_id,
        "workchain_id": 0,
        "zero_state_root_hash": "sha256:" + "1" * 64,
        "zero_state_file_hash": "sha256:" + "2" * 64,
    }
    runner.working_configs = [
        lifecycle.IntegratedWorkingConfig(
            tmp_path / f"view-{index}.json",
            f"127.0.0.1:{23000 + index}",
            f"http://127.0.0.1:{23000 + index}/",
            "sha256:" + f"{index + 1:064x}",
        )
        for index in range(lifecycle.INTEGRATED_RPC_COUNT)
    ]
    binding = lifecycle.AgentBinding(
        "agent-0", "agent:test:0", "campaign-agent-0", "0:" + "cd" * 32
    )
    nominator = lifecycle.Nominator(
        index=0,
        wallet=None,
        key=None,
        agent=binding,
        address=Address(binding.campaign_account_address),
        agent_profile_name=binding.campaign_wallet_label,
        tosctl_config=runner.working_configs[0].path,
        deployment_id="3" * 64,
    )
    checkpoint = {
        "workchain": 0,
        "shard": "-9223372036854775808",
        "seqno": 77,
        "root_hash": "sha256:" + "d" * 64,
        "file_hash": "sha256:" + "e" * 64,
    }
    finalized = {
        "account": binding.campaign_account_address,
        "transaction_lt": "1234",
        "transaction_cell_hash": "tvm-cell-sha256:" + "a" * 64,
        "transaction_boc_digest": "sha256:" + "b" * 64,
        "out_message_cell_hash": "tvm-cell-sha256:" + "c" * 64,
        "source": binding.campaign_account_address,
        "target": lifecycle.raw_address(runner.pool_address),
        "value_nanotos": 0,
        "body_hash": "",
        "block_checkpoint": checkpoint,
    }
    actions = {}
    calls = []

    def option(args, name):
        prefix = name + "="
        return next(value.removeprefix(prefix) for value in args if value.startswith(prefix))

    async def fake_tosctl(_config, *args, **_kwargs):
        command = args[2]
        calls.append((command, args))
        action_id = option(args, "--action-id")
        if command == "task-send":
            assert all(item["status"] == "resolved" for item in actions.values())
            actions[action_id] = {
                "status": "broadcasting",
                "amount": int(float(option(args, "--value")) * lifecycle.NANO),
            }
            return ""
        assert command == "task-send-resolve"
        assert actions[action_id]["status"] == "broadcasting"
        assert "--quorum-config" in args
        assert str(runner.working_configs[1].path) in args
        assert str(runner.working_configs[2].path) in args
        assert not any(
            value == "--yes" or value.startswith("--target") or value.startswith("--body-boc")
            for value in args
        )
        actions[action_id]["status"] = "resolved"
        body_hash = actions[action_id]["body_hash"]
        amount = actions[action_id]["amount"]
        transaction_evidence = {
            "endpoint": "http://127.0.0.1:23000/",
            "locator_identity_digest": "sha256:" + f"{1:064x}",
            "transaction_hash": "sha256:" + "a" * 64,
            "transaction_lt": 1234,
            "transaction_utime": 1_800_000_000,
            "transaction_boc_digest": finalized["transaction_boc_digest"],
            "outbound_message_cell_hash": finalized["out_message_cell_hash"],
            "outbound_body_hash": body_hash,
            "block_workchain": checkpoint["workchain"],
            "block_shard": int(checkpoint["shard"]),
            "block_seqno": checkpoint["seqno"],
            "block_root_hash": checkpoint["root_hash"],
            "block_file_hash": checkpoint["file_hash"],
            "observed_masterchain_seqno": 80,
            "finalized_controller_epoch": 1,
            "finalized_seqno": len(actions),
        }
        observations = [
            {
                **transaction_evidence,
                "endpoint": f"http://127.0.0.1:{23000 + index}/",
                "locator_identity_digest": "sha256:" + f"{index + 1:064x}",
                "observed_masterchain_seqno": 80 + index,
            }
            for index in range(3)
        ]
        return json.dumps(
            {
                "schema": "tos.agent-account.task-send-finalized.v1",
                "wallet": binding.campaign_wallet_label,
                "action_id": action_id,
                "source_account": binding.campaign_account_address,
                "deployment_id": nominator.deployment_id,
                "controller_epoch": 1,
                "seqno": len(actions) - 1,
                "finalized_controller_epoch": 1,
                "finalized_seqno": len(actions),
                "destination": lifecycle.raw_address(runner.pool_address),
                "amount_nanotos": amount,
                "body_hash": body_hash,
                "exact_signed_boc_digest": "sha256:" + "8" * 64,
                "submitted_message_cell_hash": "tvm-cell-sha256:" + "9" * 64,
                "network_domain": {
                    "network_id": f"tos:global-id:{runner.network_global_id}",
                    "global_id": runner.network_global_id,
                    "zero_state_root_hash": runner.network_domain["zero_state_root_hash"],
                    "zero_state_file_hash": runner.network_domain["zero_state_file_hash"],
                    "workchain_id": 0,
                },
                "quorum": {"members": 3, "threshold": 2, "agreeing": 3},
                "process_view_scope": (
                    "distinct RPC process views; no independent-operator or "
                    "Byzantine-finality claim"
                ),
                "independent_operator_domains_proven": False,
                "transaction": transaction_evidence,
                "observations": observations,
                "state": "resolved",
            }
        )

    async def finalized_with_resolution(selected, *, action_id, action, amount, body_hash):
        actions[action_id]["body_hash"] = body_hash
        current = {**finalized, "value_nanotos": amount, "body_hash": body_hash}
        resolution = await runner.resolve_finalized_agent_action(
            selected,
            action_id=action_id,
            amount=amount,
            body_hash=body_hash,
            finalized_transaction=current,
        )
        assert actions[action_id]["status"] == "resolved"
        return {
            "action": action,
            "action_id": action_id,
            "finalized_transaction": current,
            "task_send_resolution": resolution,
        }

    monkeypatch.setattr(runner, "tosctl", fake_tosctl)
    monkeypatch.setattr(runner, "await_finalized_agent_action", finalized_with_resolution)

    await runner.send_nominator(
        nominator,
        amount=5 * lifecycle.NANO,
        body=lifecycle.text_command("d"),
        label="deposit",
        action="deposit",
    )
    assert list(actions.values())[0]["status"] == "resolved"
    await runner.send_nominator(
        nominator,
        amount=lifecycle.NANO,
        body=lifecycle.text_command("w"),
        label="withdraw",
        action="withdraw",
    )

    assert [command for command, _ in calls] == [
        "task-send",
        "task-send-resolve",
        "task-send",
        "task-send-resolve",
    ]
    assert all(item["status"] == "resolved" for item in actions.values())
    lifecycle.release_evidence_attempt_lock(attempt)


def test_agent_state_identity_commits_every_stateinit_field():
    state_boc = Builder().store_uint(7, 8).end_cell().to_boc()
    state = {
        "address": "0:" + "1" * 64,
        "workchain": 0,
        "owner": "0:" + "2" * 64,
        "controller_pubkey": "3" * 64,
        "deployment_id": "4" * 64,
        "max_per_tx": 5 * lifecycle.NANO,
        "daily_limit": 20 * lifecycle.NANO,
        "default_task_timeout_secs": 600,
        "metadata_hash": "5" * 64,
        "service_endpoint_hash": None,
        "code_hash": "6" * 64,
        "data_hash": "7" * 64,
        "state_init_boc": base64.b64encode(state_boc).decode(),
    }

    identity = lifecycle.canonical_agent_state_identity(state)

    assert identity["address"] == state["address"]
    assert identity["deployment_id"] == state["deployment_id"]
    assert identity["policy"]["max_per_tx"] == 5 * lifecycle.NANO
    assert identity["state_init_boc_digest"].startswith("sha256:")
    assert "state_init_boc" not in identity


def test_file_vault_preflight_fails_closed_without_changing_permissions(tmp_path, monkeypatch):
    vault = tmp_path / "vault.json"
    vault.write_text("{}")
    vault.chmod(0o664)
    monkeypatch.setenv("VAULT_URL", vault.as_uri())

    with pytest.raises(ValueError, match="mode 0600"):
        lifecycle.validate_inherited_vault_environment()
    assert vault.stat().st_mode & 0o777 == 0o664

    vault.chmod(0o600)
    lifecycle.validate_inherited_vault_environment()


def test_integrated_cli_is_explicit_and_complete(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    source = tmp_path / "source.json"
    tosctl = tmp_path / "tosctl"
    ready = tmp_path / "ready.json"
    evidence = tmp_path / "evidence.json"
    base = [
        "nominator-pool-lifecycle-e2e.py",
        "--agent-manifest",
        str(manifest),
        "--campaign-run-id",
        "round5-integrated-cli-test",
    ]
    monkeypatch.setattr(sys, "argv", [*base, "--integrated-source-config", str(source)])
    with pytest.raises(SystemExit):
        lifecycle.parse_args()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            *base,
            "--integrated-source-config",
            str(source),
            "--tosctl",
            str(tosctl),
            "--ready-out",
            str(ready),
            "--evidence-out",
            str(evidence),
            "--rpc-base-port",
            "24000",
        ],
    )
    args = lifecycle.parse_args()
    assert args.integrated_source_config == source
    assert args.tosctl == tosctl
    assert args.ready_out == ready
    assert args.rpc_base_port == 24000


def test_integrated_claim_limits_name_scripted_custody_and_single_host(tmp_path):
    evidence = tmp_path / "evidence.json"
    attempt = lifecycle.begin_evidence_attempt(evidence, "round5-integrated-claims")
    runner = lifecycle.PoolLifecycle(
        None,
        tmp_path,
        0,
        campaign_run_id="round5-integrated-claims",
        evidence_out=evidence,
        evidence_attempt=attempt,
        integrated_source_config=tmp_path / "source.json",
        tosctl_path=tmp_path / "tosctl",
        rpc_base_port=23000,
        ready_out=tmp_path / "ready.json",
    )
    runner.network_domain = {
        "network_id": lifecycle.INTEGRATED_NETWORK_ID,
        "global_id": runner.network_global_id,
        "workchain_id": 0,
        "zero_state_root_hash": "sha256:" + "1" * 64,
        "zero_state_file_hash": "sha256:" + "2" * 64,
    }
    target = "0:" + "9" * 64
    runner.all_nominators = [
        lifecycle.Nominator(
            index=0,
            wallet=None,
            key=None,
            agent=lifecycle.AgentBinding("agent-0", "agent:test:0", "campaign-agent-0", target),
            address=Address(target),
            funded_balance=29 * lifecycle.NANO,
            deposit_message_value=5 * lifecycle.NANO,
        )
    ]
    runner.write_report()
    report = json.loads((tmp_path / "report.json").read_text())

    assert report["network"] == lifecycle.INTEGRATED_NETWORK
    assert report["evidence_class"] == lifecycle.INTEGRATED_EVIDENCE_CLASS
    assert report["claim_limits"][0] == (
        "The delegation wallets are the campaign Agent Accounts on the same genesis used "
        "for campaign payments."
    )
    assert lifecycle.INTEGRATED_OPERATOR_ACTION_LIMIT in report["claim_limits"]
    assert lifecycle.INTEGRATED_SINGLE_HOST_LIMIT in report["claim_limits"]
    assert (
        report["agent_nominator_rewards"][0]["configured_deploy_message_value_nanotos"]
        == 30 * lifecycle.NANO
    )
    assert report["agent_nominator_rewards"][0]["wallet_funding_nanotos"] == (29 * lifecycle.NANO)

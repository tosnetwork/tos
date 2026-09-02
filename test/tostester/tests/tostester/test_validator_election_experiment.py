"""Unit coverage for the validator-election experiment control surface."""

import importlib.util
import sys
from pathlib import Path

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


def test_default_cli_preserves_launch_gate_profile():
    args = stage_a.parse_args([])

    assert args.mode == "launch-gate"
    assert args.stage == "a"
    assert args.base_port == 26_000
    assert args.output_root is None


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


def test_experiment_wallet_funding_supports_three_concurrent_unrecovered_stakes(
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
    assert experiment.validator_wallet_funding() == 30_030 * stage_a.NANO
    assert (
        experiment.validator_wallet_funding()
        == stage_a.EXPERIMENT_VALIDATOR_WALLET_FUNDING
    )
    assert (
        experiment.validator_wallet_funding() - 3 * stage_a.STAKE_MESSAGE_VALUE
        == 27 * stage_a.NANO
    )
    assert (
        experiment.validator_wallet_funding() - 2 * stage_a.STAKE_MESSAGE_VALUE
        >= stage_a.STAKE_MESSAGE_VALUE + 2 * stage_a.NANO
    )
    assert (
        launch_gate.validator_wallet_funding() - 2 * stage_a.STAKE_MESSAGE_VALUE
        < stage_a.STAKE_MESSAGE_VALUE + 2 * stage_a.NANO
    )

    launch_config = stage_a.NetworkConfig()
    experiment_config = stage_a.NetworkConfig()
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
        + stage_a.EXPERIMENT_FAUCET_FEE_RESERVE
    )


def test_v3_reconciliation_keeps_exact_credits_and_retained_rollover_separate(
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
        "reward_wallet_raw": f"-1:{index + 1:064x}",
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

    evidence = rehearsal.allocation_evidence("complete")

    assert evidence["schema_version"] == 3
    assert evidence["status"] == "complete"
    assert evidence["reconciliation"]["total_reward_nanotos"] == 123_456_789
    assert evidence["reconciliation"]["outstanding_allocations"] == 0
    assert evidence["reconciliation"]["retained_settlement_rollover_allocations"] == 1
    assert "equal-share inference" in evidence["elector"]["allocation_basis"]


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
        "reward_wallet_raw": f"-1:{index + 1:064x}",
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


def test_multi_election_credit_is_exact_only_at_wallet_aggregate():
    single = stage_a.recovery_attribution([100])
    aggregate = stage_a.recovery_attribution([100, 400])

    assert single == {
        "attribution_status": "exact-single-election",
        "wallet_aggregate_attribution_status": "EXACT",
        "per_election_reward_attribution_status": "EXACT",
    }
    assert aggregate == {
        "attribution_status": "wallet-exact-multi-election-aggregate",
        "wallet_aggregate_attribution_status": "EXACT",
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

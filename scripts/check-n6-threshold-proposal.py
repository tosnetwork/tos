#!/usr/bin/env python3
"""Keep the N6 threshold proposal tied to authoritative source facts."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"N6_THRESHOLD_PROPOSAL_FAILURE: {message}", file=sys.stderr)
    raise SystemExit(1)


def collapsed(path: Path) -> str:
    """Return source text with formatting-only whitespace made irrelevant."""
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).strip()


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]).resolve()
proposal_path = root / "doc/pq-native/N6-ACCEPTANCE-CRITERIA-PROPOSAL.json"
criteria_path = root / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json"
proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
criteria = json.loads(criteria_path.read_text(encoding="utf-8"))

if proposal.get("status") != "REVIEW_PROPOSAL_NOT_ACCEPTANCE_CRITERIA":
    fail("proposal can be mistaken for accepted launch criteria")
if set(proposal.get("owner_decisions", {})) != {"release_hardware_profile", "headroom_fractions"}:
    fail("proposal must leave exactly hardware profile and headroom fractions to the owner")
hardware = proposal["owner_decisions"]["release_hardware_profile"]
if hardware.get("status") != "PROVISIONING_REQUIRED" or set(hardware.get("required_fields", [])) != {
    "cpu_model",
    "cpu_governor",
    "turbo_or_boost_enabled",
    "memory",
    "storage",
    "network_link",
}:
    fail("release hardware proposal does not pin CPU governor and turbo/boost policy")
requirements = hardware.get("provisioning_requirements", {})
expected_requirements = {
    "cpu_model": "record the actual model for every provisioned host",
    "physical_cores_min": 8,
    "cpu_governor": "performance",
    "turbo_or_boost_enabled": False,
    "memory_gib_min": 16,
    "storage": "NVMe SSD",
    "network_link_gbps_min": 1,
    "virtualization_allowed": False,
}
if hardware.get("required_host_count") != 21 or hardware.get("topology") != (
    "one validator per bare-metal host"
):
    fail("release hardware proposal does not require 21 one-validator bare-metal hosts")
for field, expected in expected_requirements.items():
    actual = requirements.get(field)
    if actual != expected:
        fail(
            f"release hardware provisioning field {field} changed: "
            f"expected={expected!r} actual={actual!r}"
        )
extra_requirement_fields = sorted(set(requirements) - set(expected_requirements))
if extra_requirement_fields:
    fail(f"release hardware provisioning has unexpected fields: {extra_requirement_fields}")
if "throttling" not in hardware.get("rationale", "") or "thermals" not in hardware.get(
    "rationale", ""
):
    fail("release hardware proposal does not explain why frequency policy affects timing evidence")
observed_host = hardware.get("observed_nonqualifying_host", {})
if observed_host.get("network_link") != (
    "100 Mbps symmetric (In 100.0 Mbps / Out 100.0 Mbps), "
    "MAC fa:16:3e:7c:0e:03, /23 subnet"
):
    fail("release hardware proposal does not retain the owner-supplied network link")
if (
    observed_host.get("platform") != "KVM guest"
    or observed_host.get("cpu_governor") != "unobservable from guest"
    or observed_host.get("turbo_or_boost_enabled") != "unobservable from guest"
):
    fail("nonqualifying KVM host no longer records its unobservable frequency policy")
expected_paths = [
    "provision 21 bare-metal hosts meeting this specification",
    "change required_scales explicitly with written and machine-enforced extrapolation",
    "virtual machines cannot produce release evidence because their host frequency policy is unobservable",
]
if hardware.get("available_paths") != expected_paths:
    fail("release hardware proposal no longer states all three explicit cost choices")

headroom = proposal["owner_decisions"]["headroom_fractions"]
expected_headroom = {
    "finality_window": 0.50,
    "block_signature_timeout": 0.50,
    "lite_query_timeout": 0.50,
    "authority_slot": 0.80,
    "cpu": 0.35,
    "rss": 0.30,
    "network": 0.50,
    "disk_busy": 0.40,
    "finalization_backpressure": 0.90,
}
if headroom.get("status") != "OWNER_ACCEPTED" or headroom.get("values") != expected_headroom:
    fail("owner-accepted headroom fractions changed or are not marked accepted")
if set(headroom.get("rationale", {})) != {
    "timing_windows",
    "authority_slot",
    "resources",
    "finalization_backpressure",
}:
    fail("owner-accepted headroom fractions do not carry the required rationale")

required_criteria = set(criteria) - {"threshold_rationale"}
proposed_criteria = proposal.get("proposed_criteria", {})
if set(proposed_criteria) != required_criteria:
    missing = sorted(required_criteria - set(proposed_criteria))
    extra = sorted(set(proposed_criteria) - required_criteria)
    fail(f"criteria coverage differs: missing={missing} extra={extra}")
for name, entry in proposed_criteria.items():
    if not isinstance(entry, dict) or not entry.get("rationale"):
        fail(f"{name} has no threshold rationale")

positive_fields = [
    name
    for name in required_criteria
    if name.startswith("max_") and name != "max_unbounded_memory_slope_bytes_per_hour"
]
if criteria.get("release_hardware_profile") != "OWNER_REVIEW_REQUIRED":
    fail("live criteria no longer carry the owner-review hardware sentinel")
for name in positive_fields:
    if criteria.get(name) != 0:
        fail(f"live criteria field {name} was populated before owner review")

facts = proposal["source_facts"]
expected_facts = {
    "simplex_target_rate_ms": 400,
    "simplex_first_block_timeout_ms": 1000,
    "simplex_slots_per_leader_window": 4,
    "simplex_first_leader_window_ms": 2600,
    "simplex_standstill_timeout_ms": 10000,
    "block_signature_context_timeout_ms": 2000,
    "lite_query_timeout_ms": 10000,
    "maximum_boxed_finality_carrier_bytes": 984260,
    "pending_finality_public_carrier_shares": 16,
    "pending_finality_validator_carrier_shares": 400,
    "pending_finality_minimum_charge_bytes": 4096,
    "pending_finality_total_bytes": 409452160,
    "pending_finality_maximum_candidates": 99963,
    "launch_validator_cap": 21,
    "simplex_fork_point_commit": "628506c9e",
    "simplex_files_at_fork_point": 16,
    "upstream_production_committee_approx": 400,
}
if facts != expected_facts:
    fail("recorded source facts or their arithmetic changed without review")

if criteria.get("required_scales") != [facts["launch_validator_cap"]]:
    fail("live required scales do not equal the enforced launch ceiling")
if proposed_criteria["required_scales"].get("proposal") != [facts["launch_validator_cap"]]:
    fail("proposed required scales do not equal the enforced launch ceiling")

launch_policy = json.loads((root / "config/pq-launch-limits.json").read_text(encoding="utf-8"))
for field in ("max_total_validators", "max_masterchain_committee", "max_shard_committee"):
    if launch_policy.get(field) != facts["launch_validator_cap"]:
        fail(f"launch policy field {field} no longer enforces the proposed scale")

fork_tree = subprocess.run(
    [
        "git",
        "-C",
        str(root),
        "ls-tree",
        "-r",
        "--name-only",
        facts["simplex_fork_point_commit"],
        "--",
        "validator/consensus/simplex",
    ],
    check=False,
    capture_output=True,
    text=True,
)
if fork_tree.returncode != 0:
    fail(
        "cannot verify inherited Simplex at fork point "
        f"{facts['simplex_fork_point_commit']}: {fork_tree.stderr.strip()}"
    )
simplex_files = [line for line in fork_tree.stdout.splitlines() if line]
if len(simplex_files) != facts["simplex_files_at_fork_point"]:
    fail(
        "inherited Simplex fork-point file count changed: "
        f"expected {facts['simplex_files_at_fork_point']}, got {len(simplex_files)}"
    )

config_contract = collapsed(root / "crypto/smartcont/config-code.fc")
for marker in (
    "max_validators > pq_launch::max_total_validators",
    "max_main_validators > pq_launch::max_masterchain_committee",
    "shard_validators_num <= pq_launch::max_shard_committee",
):
    if marker not in config_contract:
        fail(f"on-chain launch-cap enforcement changed: {marker}")
node_config = collapsed(root / "crypto/block/mc-config.cpp")
for marker in (
    "max_validators > tos::pq::launch_limits::max_total_validators",
    "max_main_validators > tos::pq::launch_limits::max_masterchain_committee",
    "shard_validators_num > tos::pq::launch_limits::max_shard_committee",
):
    if marker not in node_config:
        fail(f"node launch-cap admission changed: {marker}")
if "validate_pq_launch_resource_config()" not in collapsed(root / "validator/manager.cpp"):
    fail("validator manager no longer applies node launch-cap admission")
if "21 21 4 config.validator_num!" not in collapsed(root / "crypto/smartcont/gen-zerostate.fif"):
    fail("production Genesis no longer constructs the enforced 21-validator ceiling")
test_genesis = collapsed(root / "test/tostester/src/tostester/zerostate.py")
if "validator_count > MAX_MASTERCHAIN_COMMITTEE" not in test_genesis:
    fail("tostester Genesis no longer refuses committees above the launch ceiling")

zerostate = collapsed(root / "crypto/smartcont/gen-zerostate.fif")
if zerostate.count("<b 400 32 u, b> <s 0 rot 8 udict! drop") != 2:
    fail("authoritative masterchain/shard target_rate is no longer 400 ms")
if zerostate.count("<b 1000 32 u, b> <s 1 rot 8 udict! drop") != 2:
    fail("authoritative masterchain/shard first_block_timeout is no longer 1000 ms")
if zerostate.count("<b x{22} s, 0 5 u, 2 2 u, 1 1 u, 4 32 u, swap dict, b>") != 2:
    fail("authoritative masterchain/shard Simplex v2 leader-window configuration changed")

types = collapsed(root / "tos/tos-types.h")
if "duration_fn(8, standstill_timeout, 10'000)" not in types:
    fail("ConfigParam30 standstill timeout source changed")
manager = (root / "validator/manager.cpp").read_text(encoding="utf-8")
if not re.search(
    r'create_actor<ValidateBroadcast>\("broadcast-sigcheck".*?Timestamp::in\(2\.0\)', manager, re.S
):
    fail("production block-signature context timeout is no longer two seconds")
lite = (root / "lite-client/lite-client.cpp").read_text(encoding="utf-8")
if not re.search(r'ExtClient::send_query, "query".*?Timestamp::in\(10\.0\)', lite, re.S):
    fail("production lite query timeout is no longer ten seconds")
limits = collapsed(root / "crypto/block/pq-signature-limits.h")
if "pq_block_finality_broadcast_max_bytes = 984260" not in limits:
    fail("maximum boxed finality carrier source changed")
policy = collapsed(root / "validator/finality-cache-policy.h")
for marker in (
    "pending_finality_minimum_charge_bytes = 4096",
    "pending_finality_public_candidate_slots = 16",
    "pending_finality_max_validator_senders = tos::pq::PQConsensusLimits{}.max_certificate_signers",
):
    if marker not in policy:
        fail(f"pending-finality resource derivation source changed: {marker}")
pq_consensus = collapsed(root / "crypto/pq/pq-consensus.h")
if "max_certificate_signers = 400" not in pq_consensus:
    fail("structural validator-reserved sender count changed")

if (
    proposed_criteria["max_pending_finality_bytes"]["proposal"]
    != facts["pending_finality_total_bytes"]
):
    fail("pending-finality byte proposal is not the enforced two-pool bound")
if (
    proposed_criteria["max_pending_finality_candidates"]["proposal"]
    != facts["pending_finality_maximum_candidates"]
):
    fail(
        "pending-finality candidate proposal is not derived from the byte pools and minimum charge"
    )

expected_resolved_proposals = {
    "max_p99_persisted_finality_ms": (1300, "floor(2600 * (1 - headroom_fractions.finality_window))"),
    "max_p99_block_signature_verify_ms": (
        1000,
        "floor(2000 * (1 - headroom_fractions.block_signature_timeout))",
    ),
    "max_p99_lite_verify_ms": (5000, "floor(10000 * (1 - headroom_fractions.lite_query_timeout))"),
    "max_authority_classification_p99_ms": (
        80,
        "floor(400 * (1 - headroom_fractions.authority_slot))",
    ),
    "max_finalized_height_stall_ms": (5000, "floor(10000 * (1 - headroom_fractions.finality_window))"),
    "max_cpu_fraction": (0.65, "1 - headroom_fractions.cpu"),
    "max_rss_fraction": (0.70, "1 - headroom_fractions.rss"),
    "max_network_fraction": (0.50, "1 - headroom_fractions.network"),
    "max_disk_busy_fraction": (0.60, "1 - headroom_fractions.disk_busy"),
    "max_finalization_backpressure_fraction": (0.10, "1 - headroom_fractions.finalization_backpressure"),
}
for name, (value, formula) in expected_resolved_proposals.items():
    entry = proposed_criteria[name]
    if entry.get("proposal") != value or entry.get("formula") != formula:
        fail(f"{name} no longer matches the owner-accepted headroom derivation")

print(
    "N6_THRESHOLD_PROPOSAL_OK: owner-accepted headroom is resolved; live criteria remain hardware-profile blocked"
)

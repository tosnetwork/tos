#!/usr/bin/env python3
"""Check control-update ordering and retained admission policy boundaries."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


SKIP = (
    "    if (processed_external_messages_.find(ext_msg_ref->hash_norm())) {\n"
    "      continue;\n"
    "    }\n"
    "    processed_external_messages_ = processed_external_messages_.insert(ext_msg_ref->hash_norm(), td::Unit{});\n"
)
CARRY_IN = "  processed_external_messages_ = params_.processed_external_messages;\n"
CARRY_OUT = ".processed_external_messages = processed_external_messages_"
PRODUCER_PASS = "            .processed_external_messages = processed_external_messages,\n"
PRODUCER_ADOPT = (
    "        processed_external_messages = generated_candidate->processed_external_messages;\n"
)
PRODUCER_USED = "      if (generated_candidate.has_value()) {\n"
BRIDGE_GENERATED = "run_collate_query_generated(std::move(params), manager_,"


def validate_collator(collator: str, producer: str, bridge: str) -> None:
    """The pool removes every entry under a refused normalized hash, so a message already taken in
    this leader window must be skipped, unreported, by every later collation of the window."""
    loop = collator.split("td::actor::Task<bool> Collator::process_inbound_external_messages()", 1)[
        1
    ]
    loop = loop.split("\n}\n", 1)[0]
    skip = loop.find(SKIP)
    assert skip >= 0, (
        "the collator must skip, then record, a normalized hash taken earlier in the window"
    )
    backpressure = loop.index("++stats_.ext_msgs_skipped_backpressure;")
    assert backpressure < skip, "as upstream, the backpressure skip precedes the duplicate skip"
    reports = [m.start() for m in re.finditer(r"bad_ext_msgs_\.emplace_back", loop)]
    assert reports, "the collator must report refused external messages"
    assert skip < min(reports), "refusals must be reported only after the duplicate skip"
    assert skip < loop.index("register_external_message("), (
        "skip duplicates before registering them"
    )
    assert collator.count(CARRY_IN) == 1, "the collator must start from the window's processed set"
    assert collator.count(CARRY_OUT) == 1, "the collator must return its processed set"
    assert producer.count(PRODUCER_PASS) == 1, "each slot's collation must receive the window's set"
    assert producer.count(PRODUCER_ADOPT) == 1, (
        "the producer must keep the set of the candidate it uses"
    )
    # Only a candidate the producer actually uses may contribute its set: not an empty block, a
    # timed-out collation or a failed one.
    used = producer.find(PRODUCER_USED)
    assert used >= 0, "the producer's used-candidate branch was not found"
    branch_end = producer.find("\n      } else {\n", used)
    adopt = producer.find(PRODUCER_ADOPT)
    assert used < adopt < branch_end, (
        "the set must be adopted only inside the used-candidate branch"
    )
    # The leader's collations must return the set; the BlockCandidate form drops it.
    assert BRIDGE_GENERATED in bridge, (
        "the consensus bridge must collate with the set-returning form"
    )


def validate(engine: str, manager: str, role: str) -> None:
    handler = engine.split(
        "void ValidatorEngine::run_control_query(tos::tos_api::engine_validator_setExtMessagePoolOptions",
        1,
    )[1]
    handler = handler.split("void ValidatorEngine::process_control_query", 1)[0]
    permission = handler.index("perm & ValidatorEnginePermissions::vep_modify")
    started = re.search(r"if\s*\(!started_\)", handler)
    assert started is not None, "pool option updates must refuse before startup"
    unpack = handler.index("ExtMessagePoolOptions::unpack")
    persist = handler.index("config_.ext_message_pool_config")
    assert permission < started.start() < unpack < persist, (
        "check authorization/startup before changing pool options"
    )
    query = manager.split("ValidatorManagerImpl::new_external_message_query(", 1)[1]
    query = query.split("ValidatorManagerImpl::new_external_message_query_cont(", 1)[0]
    assert "local_ls_message_priority" in query, "local queries must use the configured priority"
    assert "std::move(source_peer)" in query, "local queries must retain source attribution"
    assert "mempool-num" not in role, (
        "retired mempool option must not be forwarded by the role wrapper"
    )
    assert not re.search(r'add_checked_option\(\s*\'m\'\s*,\s*"mempool-num"', engine), (
        "retired option must not have a compatibility shim"
    )


def main() -> None:
    engine = (ROOT / "validator-engine/validator-engine.cpp").read_text()
    manager = (ROOT / "validator/manager.cpp").read_text()
    role = (ROOT / "docker/validator-role.sh").read_text()
    validate(engine, manager, role)
    collator = (ROOT / "validator/impl/collator.cpp").read_text()
    producer = (ROOT / "validator/consensus/block-producer.cpp").read_text()
    bridge = (ROOT / "validator/consensus/bridge.cpp").read_text()
    validate_collator(collator, producer, bridge)
    for target, text in [
        (SKIP, "collator"),
        (CARRY_IN, "collator"),
        (CARRY_OUT, "collator"),
        (PRODUCER_PASS, "producer"),
        (PRODUCER_ADOPT, "producer"),
        (PRODUCER_USED, "producer"),
        (BRIDGE_GENERATED, "bridge"),
    ]:
        source = {"collator": collator, "producer": producer, "bridge": bridge}[text]
        assert source.count(target) == 1, f"collator guard mutation target not found: {target!r}"
    adopt_before_use = producer.replace(PRODUCER_ADOPT, "").replace(
        PRODUCER_USED, PRODUCER_ADOPT + PRODUCER_USED
    )
    collator_mutants = [
        (collator.replace(SKIP, ""), producer, bridge),
        (collator.replace(SKIP, SKIP.replace("if (processed", "if (!processed")), producer, bridge),
        (collator.replace(SKIP, SKIP.replace("      continue;\n", "")), producer, bridge),
        (collator.replace(CARRY_IN, ""), producer, bridge),
        (collator.replace(CARRY_OUT, ""), producer, bridge),
        (collator, producer.replace(PRODUCER_PASS, ""), bridge),
        (collator, producer.replace(PRODUCER_ADOPT, ""), bridge),
        (collator, adopt_before_use, bridge),
        (
            collator,
            producer,
            bridge.replace(BRIDGE_GENERATED, "run_collate_query(std::move(params), manager_,"),
        ),
    ]
    for index, inputs in enumerate(collator_mutants):
        try:
            validate_collator(*inputs)
        except AssertionError:
            continue
        raise AssertionError(f"collator guard mutation {index} did not fail")
    mutants = [
        (re.sub(r"if\s*\(!started_\)", "if (false)", engine), manager, role),
        (engine, manager.replace("local_ls_message_priority", "ignored_priority"), role),
        (engine, manager, role + "\nmempool-num\n"),
    ]
    for index, inputs in enumerate(mutants):
        try:
            validate(*inputs)
        except AssertionError:
            continue
        raise AssertionError(f"source guard mutation {index} did not fail")
    print("External admission release source guards and 12 red controls passed")


if __name__ == "__main__":
    main()

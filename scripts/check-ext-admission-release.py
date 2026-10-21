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


def validate_collator(collator: str, producer: str) -> None:
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
    validate_collator(collator, producer)
    for target, text in [
        (SKIP, "collator"),
        (CARRY_IN, "collator"),
        (CARRY_OUT, "collator"),
        (PRODUCER_PASS, "producer"),
        (PRODUCER_ADOPT, "producer"),
    ]:
        source = collator if text == "collator" else producer
        assert source.count(target) == 1, f"collator guard mutation target not found: {target!r}"
    collator_mutants = [
        (collator.replace(SKIP, ""), producer),
        (collator.replace(SKIP, SKIP.replace("if (processed", "if (!processed")), producer),
        (collator.replace(SKIP, SKIP.replace("      continue;\n", "")), producer),
        (collator.replace(CARRY_IN, ""), producer),
        (collator.replace(CARRY_OUT, ""), producer),
        (collator, producer.replace(PRODUCER_PASS, "")),
        (collator, producer.replace(PRODUCER_ADOPT, "")),
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
    print("External admission release source guards and 10 red controls passed")


if __name__ == "__main__":
    main()

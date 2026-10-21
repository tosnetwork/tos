#!/usr/bin/env python3
"""Check control-update ordering and retained admission policy boundaries."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    print("External admission release source guards and 3 red controls passed")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Guard the early liteServer-query error-to-answer boundary in the manager."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(f"LITE_QUERY_ERROR_RESPONSE_FAILURE: {message}")


def main(root: Path) -> None:
    source = (root / "validator/manager.cpp").read_text(encoding="utf-8")
    start = source.find("void ValidatorManagerImpl::run_ext_query(")
    end = source.find("void ValidatorManagerImpl::execute_ext_query(", start)
    if start < 0 or end < 0:
        fail("manager liteServer-query entry or execution boundary is missing")
    body = re.sub(r"//[^\n]*", "", source[start:end])
    body = " ".join(body.split())
    wrapper = re.search(
        r"promise\s*=\s*td::PromiseCreator::lambda\s*\(\s*"
        r"\[reply\s*=\s*std::move\(promise\)\]",
        body,
    )
    if wrapper is None:
        fail("early liteServer-query errors do not pass through the reply wrapper")
    first_refusal = body.find("if (!started_")
    if first_refusal < 0 or wrapper.start() > first_refusal:
        fail("liteServer-query reply wrapper is installed after the first refusal")
    wrapper_body = body[wrapper.start() : first_refusal]
    required = {
        "result.is_error()": "error branch is missing",
        "create_serialize_tl_object<lite_api::liteServer_error>": "error is not a liteServer_error",
        "reply.set_value": "error answer is not sent as a value",
        "result.move_as_ok()": "successful answer is not forwarded",
    }
    for marker, reason in required.items():
        if marker not in wrapper_body:
            fail(reason)
    if wrapper_body.count("reply.set_value") != 2:
        fail("liteServer-query wrapper does not answer both error and success paths")
    print(
        "LITE_QUERY_ERROR_RESPONSE_OK: manager installs an error-to-liteServer_error "
        "answer wrapper before every early query refusal"
    )


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            fail("expected repository root argument")
        main(Path(sys.argv[1]))
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error

#!/usr/bin/env python3
"""Remove one admission protection, require its executed regression to fail,
then restore and require the same regression to pass. Use an isolated checkout.
"""

import argparse
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "http-reuse": (
        "http/http-inbound-connection.h",
        "read_next_request_ = response_finished_ && !close_after_write_;",
        "read_next_request_ = false;",
        "test-http-server-limits",
        ["--filter", "completing_an_upload_after_the_early_answer"],
        "early.request_ok",
    ),
    "http-source": (
        "validator-engine/json-rpc-http-policy.h",
        "max_connections == 0 ? 128 : adnl::default_source_share(max_connections)",
        "0",
        "test-json-rpc-transport",
        ["--filter", "connections_of_one_source_leave_other_sources_capacity"],
        "excess.drains_to_close",
    ),
    "keyless-close": (
        "validator-engine/json-rpc-server.cpp",
        "http::HttpServer::Admission::admit(false)",
        "http::HttpServer::Admission::admit()",
        "test-json-rpc-transport",
        ["--filter", "keyless_endpoints_close_even_when_keepalive_is_requested"],
        "client.drains_to_close",
    ),
    "request-close": (
        "http/http-inbound-connection.cpp",
        "request_persistent_ = cur_request_->keep_alive();",
        "request_persistent_ = true;",
        "test-json-rpc-transport",
        ["--filter", "rpc_response_honors_connection_close"],
        "client.drains_to_close",
    ),
    "adnl-source": (
        "adnl/adnl-source-share.h",
        "used > per_source_limit_ || amount > per_source_limit_ - used",
        "false",
        "test-adnl-ext-output-backpressure",
        ["source-share"],
        "source overflow did not close",
    ),
    "adnl-deadline": (
        "adnl/adnl-ext-connection.hpp",
        "if (output_deadline_ && output_deadline_.is_in_past())",
        "if (false)",
        "test-adnl-ext-output-backpressure",
        ["output-deadline"],
        "keepalives renewed the output deadline",
    ),
    "adnl-renewal": (
        "adnl/adnl-ext-connection.hpp",
        "if (!output_deadline_)",
        "if (true)",
        "test-adnl-ext-output-backpressure",
        ["trickle-deadline"],
        "partial writes moved the original output deadline",
    ),
    "quic-lifetime": (
        "quic/quic-sender.cpp",
        "state.absolute_deadline = td::Timestamp::in(inbound_stream_lifetime_);",
        "state.absolute_deadline = td::Timestamp::never();",
        "test-quic-sender",
        [
            "-p",
            "54000",
            "-d",
            "mutation-quic-lifetime",
            "-f",
            "TrickleDataCannotRenewTheTotalLifetime",
        ],
        "absolute lifetime expired before the renewed inactivity window",
    ),
    "quic-fairness": (
        "quic/quic-sender.cpp",
        "inbound_budget_->request_reclaim(it->second.source);",
        "",
        "test-quic-sender",
        [
            "-p",
            "56000",
            "-d",
            "mutation-quic-fairness",
            "-f",
            "MultipleFullSourcesAllowANewSourceAcrossServers",
        ],
        "overrepresented source was displaced on another server",
    ),
    "quic-reservation": (
        "quic/quic-inbound-budget.h",
        "slot_limit -= 1;",
        "",
        "test-quic-sender",
        [
            "-p",
            "58000",
            "-d",
            "mutation-quic-reservation",
            "-f",
            "MultipleFullSourcesAllowANewSourceAcrossServers",
        ],
        "displaced source cannot take the reserved retry slot",
    ),
    "quic-reset": (
        "quic/quic-sender.cpp",
        "shutdown.connections.push_back(state->cid);",
        "",
        "test-quic-sender",
        [
            "-p",
            "60000",
            "-d",
            "mutation-quic-reset",
            "-f",
            "AResetWithoutPeerAcknowledgementReleasesTheConnection",
        ],
        "unacknowledged reset released connection and slot",
    ),
    "quic-fin": (
        "quic/quic-sender.cpp",
        "      options.timeout = state.absolute_deadline;\n      options.timeout_seconds = inbound_stream_lifetime_;",
        "      options.timeout = td::Timestamp::never();\n      options.timeout_seconds = inbound_stream_lifetime_;",
        "test-quic-sender",
        [
            "-p",
            "62000",
            "-d",
            "mutation-quic-fin",
            "-f",
            "InputFinCannotDiscardTheLifetimeOfAHeldSlot",
        ],
        "input FIN did not remove the held slot lifetime",
    ),
}


def run_case(name, build, logs, jobs):
    file, before, after, target, arguments, expected = CASES[name]
    path = ROOT / file
    original = path.read_bytes()
    text = original.decode()
    if text.count(before) != 1:
        raise RuntimeError(f"{name}: mutation target is not unique")

    def build_target(phase):
        with (logs / f"{name}-{phase}-build.log").open("w") as log:
            subprocess.run(
                ["cmake", "--build", str(build), "--parallel", str(jobs), "--target", target],
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )

    def test(phase):
        with (logs / f"{name}-{phase}.log").open("w") as log:
            result = subprocess.run(
                [str(build / target), *arguments],
                cwd=build,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=90,
            )
        return result, (logs / f"{name}-{phase}.log").read_text(errors="replace")

    try:
        path.write_text(text.replace(before, after))
        build_target("red")
        result, output = test("red")
        if result.returncode == 0 or expected not in output:
            raise RuntimeError(f"{name}: regression did not fail for its named reason; see {logs}")
    finally:
        path.write_bytes(original)
    build_target("green")
    result, output = test("green")
    executed = (
        "test(s) passed" in output
        or "B02_BACKPRESSURE_TESTS passed=" in output
        or (
            target == "test-quic-sender"
            and "Run test [name:Test_" in output
            and arguments[-1] in output
        )
    )
    if result.returncode != 0 or not executed:
        raise RuntimeError(f"{name}: restored regression failed or executed no tests; see {logs}")
    print(f"{name}: removed control detected; restored regression passed", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--case", choices=list(CASES), action="append")
    args = parser.parse_args()
    args.log_dir.mkdir(parents=True, exist_ok=True)
    branch = subprocess.check_output(
        ["git", "branch", "--show-current"], cwd=ROOT, text=True
    ).strip()
    if branch in {"main", "master", "testnet"}:
        raise SystemExit("refusing to mutate a shared branch; use an isolated checkout")
    for name in args.case or CASES:
        run_case(name, args.build_dir.resolve(), args.log_dir.resolve(), args.jobs)

#!/usr/bin/env python3
"""Require all five ADNL external-query correlation points to keep their id."""

from __future__ import annotations

import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(f"ADNL_QUERY_ID_TRACE_FAILURE: {message}")


def segment(root: Path, path: str, start: str, end: str) -> str:
    source = (root / path).read_text(encoding="utf-8")
    first = source.find(start)
    last = source.find(end, first + len(start))
    if first < 0 or last < 0:
        fail(f"{path} lost the {start} trace boundary")
    return " ".join(source[first:last].split())


def require(stage: str, body: str, *markers: str) -> None:
    missing = [marker for marker in markers if marker not in body]
    if missing:
        fail(f"{stage} no longer records {missing}")


def main(root: Path) -> None:
    client = segment(root, "adnl/adnl-ext-client.hpp", "void send_query(std::string name", "void destroy_query(")
    require(
        "client create",
        client,
        "ADNL_EXT_QUERY client_create id=",
        "q_id.to_hex()",
        "function_id=",
        "connection_present=",
        "connection_alive=",
        "deadline_monotonic=",
    )
    require("client transmit", client, "ADNL_EXT_QUERY client_transmit id=", "AdnlOutboundConnection::send")
    require(
        "client disconnected refusal",
        client,
        "conn_.empty() || !conn_.is_alive()",
        "ADNL_EXT_QUERY client_refuse id=",
        "ErrorCode::cancelled, \"conn not ready\"",
        "pending_queries=",
    )
    if client.index("conn_.empty() || !conn_.is_alive()") > client.index("out_queries_.emplace("):
        fail("disconnected refusal no longer precedes timed-query creation")
    server = segment(
        root,
        "adnl/adnl-ext-server.cpp",
        "AdnlInboundConnection::process_packet(",
        "void AdnlInboundConnection::log_dropped_query(",
    )
    require(
        "server ingress and admission",
        server,
        "ADNL_EXT_QUERY server_ingress id=",
        "admission=drop reason=per-connection-limit",
        "admission=drop reason=server-or-per-ip-limit",
        "admission=accepted",
        "peer=",
    )
    completion = segment(root, "adnl/adnl-ext-server.cpp", "AdnlInboundConnection::query_finished(", "process_init_packet(")
    require(
        "server completion",
        completion,
        "ADNL_EXT_QUERY server_completion id=",
        "outcome=error response_sent=false",
        "outcome=success response_ready=true",
        "bool enqueued = send(",
        "ADNL_EXT_QUERY server_answer_enqueue id=",
        "enqueued=",
    )
    if completion.index("ADNL_EXT_QUERY server_answer_enqueue id=") < completion.index("bool enqueued = send("):
        fail("answer enqueue trace precedes the send queue result")
    answer = segment(root, "adnl/adnl-ext-client.cpp", "AdnlOutboundConnection::process_packet(", "AdnlExtMultiClientImpl::start_up(")
    require("client answer", answer, "ADNL_EXT_QUERY client_answer id=", "F->query_id_.to_hex()")
    query = (root / "adnl/adnl-query.cpp").read_text(encoding="utf-8")
    require(
        "client completion and timeout",
        query,
        "ADNL_EXT_QUERY client_timeout id=",
        "ADNL_EXT_QUERY client_complete id=",
        "elapsed_ms=",
        "id_.to_hex()",
    )
    print("ADNL_QUERY_ID_TRACE_OK: client create/refuse/transmit, server ingress/completion/answer enqueue, and client answer/timeout retain id-tagged debug events")


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            fail("expected repository root argument")
        main(Path(sys.argv[1]))
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error

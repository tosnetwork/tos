"""Opt-in raw HTTP body capture for the local E03 JSON-RPC/TOSCAN route.

Only the E03 verifier sets this environment variable. The bodies are retained
verbatim so a route assertion can be checked against what the server returned.
"""

import json
import os
from pathlib import Path


def record(url: str, request_body: bytes | None, status: int, response_body: bytes) -> None:
    destination = os.environ.get("E03_HTTP_TRANSCRIPT")
    if not destination:
        return
    entry = {
        "url": url,
        "request_body": request_body.decode() if request_body is not None else None,
        "status": status,
        "response_body": response_body.decode(),
    }
    with Path(destination).open("a", encoding="utf-8") as output:
        output.write(json.dumps(entry, separators=(",", ":")) + "\n")

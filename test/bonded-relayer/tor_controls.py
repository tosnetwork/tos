#!/usr/bin/env python3
"""Remove privacy guards in isolated copies and require runtime assertion failures."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
T = "tools/bonded-relayer/tor_transport.py"
C = "tools/bonded-relayer/relay_client.py"
S = "tools/bonded-relayer/relay_service.py"
MUTATIONS = [
    (
        T,
        'if decoded[34:] != b"\\x03" or decoded[32:34] != checksum:',
        "if False:",
        "OnionEncodingTests.test_canonical_v3_origin_and_checksum",
    ),
    (
        T,
        'connection.connect(("127.0.0.1", self.port))',
        'socket.getaddrinfo(endpoint.host, endpoint.port)\n            connection.connect(("127.0.0.1", self.port))',
        "OnionHTTPTests.test_quote_submit_status_use_only_socks_no_dns_or_environment_proxy",
    ),
    (
        T,
        'if _read(connection, 2, deadline) != b"\\x05\\x02":',
        'if _read(connection, 2, deadline) == b"\\x00\\x00":',
        "OnionHTTPTests.test_authentication_downgrade_has_specific_refusal",
    ),
    (
        S,
        'if self.server.onion is not None and headers["host"] != self.server.onion.authority:',
        "if False:",
        "OnionHTTPTests.test_host_pin_refuses_before_quote_allocation_and_does_not_log",
    ),
    (
        C,
        'if tor is None and parsed.hostname.endswith(".onion"):',
        "if False:",
        "OnionHTTPTests.test_onion_cannot_be_used_without_tor_or_with_loopback_mode",
    ),
    (
        C,
        "lifetime: int = 300",
        "lifetime: int = 120",
        "OnionHTTPTests.test_quote_submit_status_use_only_socks_no_dns_or_environment_proxy",
    ),
]


def run(root, test):
    return subprocess.run(
        [sys.executable, "-m", "unittest", "-v", "test_tor_transport." + test],
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        cwd=root / "test/bonded-relayer",
        capture_output=True,
        text=True,
        timeout=30,
    )


def main():
    receipts = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for directory in ("tools/bonded-relayer", "test/bonded-relayer"):
            (root / directory).mkdir(parents=True)
            for source in (ROOT / directory).glob("*.py"):
                shutil.copyfile(source, root / directory / source.name)
        for file, old, new, test in MUTATIONS:
            path = root / file
            original = path.read_text()
            if original.count(old) != 1:
                raise RuntimeError(f"mutation anchor changed: {test}")
            baseline = run(root, test)
            if baseline.returncode:
                raise RuntimeError(f"baseline failed: {test}\n{baseline.stderr}")
            try:
                path.write_text(original.replace(old, new))
                result = run(root, test)
                if (
                    result.returncode == 0
                    or "AssertionError" not in result.stderr
                    or "FAIL:" not in result.stderr
                ):
                    raise RuntimeError(
                        f"missing designated assertion failure: {test}\n{result.stderr}"
                    )
            finally:
                path.write_text(original)
            restored = run(root, test)
            if restored.returncode:
                raise RuntimeError(f"restored test failed: {test}\n{restored.stderr}")
            receipts.append(
                {
                    "test": test,
                    "source": file,
                    "sha256": hashlib.sha256(original.encode()).hexdigest(),
                    "baseline": 0,
                    "mutation": result.returncode,
                    "restored": 0,
                }
            )
    print(json.dumps({"schema": "tos.br1.tor.controls.v1", "controls": receipts}, indent=2))


if __name__ == "__main__":
    main()

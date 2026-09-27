#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"

python3 - "$root/CMakeLists.txt" "$root/test/net/test-quic-sender.cpp" <<'PY'
import pathlib
import re
import sys

cmake = pathlib.Path(sys.argv[1]).read_text()
source = pathlib.Path(sys.argv[2]).read_text()
names = (
    "quic-inbound-stream-timeout",
    "quic-outbound-query-deadline",
    "quic-connection-count-cap",
)
ports = []
roots = []
for name in names:
    match = re.search(
        rf"add_test\(NAME {re.escape(name)} COMMAND test-quic-sender\s+"
        rf"-p ([0-9]+) -d ([^\s]+) -f [^)]+\)",
        cmake,
    )
    if not match:
        raise SystemExit(
            f"QUIC_CTEST_ISOLATION_SOURCE_FAILURE: {name} lacks an explicit port range and database root"
        )
    ports.append(int(match.group(1)))
    roots.append(match.group(2))

if len(set(ports)) != len(ports):
    raise SystemExit("QUIC_CTEST_ISOLATION_SOURCE_FAILURE: filtered QUIC entries share a port base")
if len(set(roots)) != len(roots):
    raise SystemExit("QUIC_CTEST_ISOLATION_SOURCE_FAILURE: filtered QUIC entries share a database root")
if min(abs(a - b) for i, a in enumerate(ports) for b in ports[i + 1 :]) < 2000:
    raise SystemExit("QUIC_CTEST_ISOLATION_SOURCE_FAILURE: QUIC port ranges overlap NODE_PORT_OFFSET headroom")
if 'g_config.db_root + "-adnl"' not in source or 'g_config.db_root + "-raw"' not in source:
    raise SystemExit("QUIC_CTEST_ISOLATION_SOURCE_FAILURE: a QUIC runner still uses a process-shared directory")

print("QUIC_CTEST_ISOLATION_SOURCE_OK: three filtered processes have disjoint directories and port ranges")
PY

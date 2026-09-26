# Q01 current-tree offline preflight

Q01 and Q02 remain OPEN. PG's cumulative `84a30e426..275a79b0a` seven-file change applied without conflict after the local X01/A03 commits. The imported diff SHA-256 is `902ec63bfc5bcda7b78d426f22bc13e837b0c4d24a1c91d3ea0eb40f929e2e0c`. This is offline source/checker integration only: no Lite caller/server attempt, socket/PID binding, raw five-point run or Q02 cause has been established on this tree.

Local checks on the same working source bytes:

| Check | Result |
| --- | --- |
| `python3 -m unittest discover -s test/pq-native -p test_q01_query_evidence.py -v` | 17/17, exit 0; raw `test/integration/.q01-offline-current-20260925/q01-unittest.typescript` SHA-256 `f0d0cbf38a33a6faf2cda65731ce32cc8867e5c3f36f4507fb81b81024108318` |
| `python3 scripts/check-adnl-query-id-trace.py .` | exit 0; raw `q01-source-guard.typescript` SHA-256 `94291a684edec64c45210e0fb9d34e6b5720f1f0e17dbd01fab41d16fde77d89` |
| `ninja -C build adnl/CMakeFiles/adnl.dir/adnl-ext-server.cpp.o adnl/CMakeFiles/adnl.dir/adnl-ext-connection.cpp.o adnl/CMakeFiles/adnllite.dir/adnl-ext-connection.cpp.o` | 3 object compiles, exit 0 |
| `ninja -C build adnl adnllite` | static library link exit 0; `libadnl.a` SHA-256 `e39d44789ec8ca29a747f24e4fe85962150a6b7d02c07b3b2be55b8955aaa7b7`, `libadnllite.a` SHA-256 `e8c76cb1065de701739c62b8c0b8ccd0a8f4e28225cdf95d42bb948ac3fb6d8b` |
| `Q01_CHECKER_SOURCE=/datax/tos-pg-q01-answer-gate-evidence/q01-answer-guard-mutant.py python3 -m unittest discover -s test/pq-native -p test_q01_query_evidence.py` | exit 1 specifically at `test_fail_fast_no_connection_is_separate`: all fail-fast wrongly passes under mutant |

The cumulative controls keep a full seven-stage answered attempt separate from pre-send `client_no_connection_fail_fast`, require distinct 64-hex IDs and retry predecessor, match raw client/server PID and endpoint, and distinguish server answer *enqueue* from socket flush. This is not transport-delivery proof. `server_ingress peer` is the host IP, while the client local socket endpoint retains its port. PG's three retained evidence indexes all rehashed with `sha256sum -c` exit 0: `/datax/tos-pg-q01-evidence/SHA256SUMS` SHA `57ea5187129e6fc58d48bd202eb1364e954e81e86165cd2e1848ac89646aa22e`, `/datax/tos-pg-q01-peer-ip-evidence/SHA256SUMS` SHA `e903bb29f158a75ece889bf39327b73309493171610c50a3f7870b46aa50448e`, and `/datax/tos-pg-q01-answer-gate-evidence/SHA256SUMS` SHA `0b9f9fe04d5b2c8acf718db4d4ae74774c58bdf2ba50a5bda4841c9cceee9cd4`.

Next acceptance boundary: a fixed committed tree and linked caller/server binaries, one controlled Lite query with caller attempt/retry transcript, independent OS socket/PID→binary map and raw journald on both ends. The strict checker must show at least one complete answered attempt and classify any no-connection attempt separately. A green retry alone cannot explain Q02 timeouts.

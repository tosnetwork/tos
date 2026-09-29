# C09 private broker projection witness (development candidate)

This successor adds a read-only, service-token-authenticated `GET /v1/control/projection-health` on the **private control Unix socket**, not the public TCP query router. It compares the durable Q projection cursor with M's global `observations` high-water and checks the configured M database's network and file identity. It reports the broker's latched conflict and the last-import caught-up flag. It does not import M rows, issue a grant, run a query, or call AURA. Its M read is a bounded read-only SQLite transaction with a 100 ms busy timeout and no process-row scan.

The endpoint's `caught_up` is a sampled cursor/head relationship, **not** a claim that an AURA query succeeded, that all retained parents remain valid since the last import, or that the 72-hour gate passed. A concurrent M append may make the sampled lag transient. `conflict`, `source_unavailable`, and identity/watermark mismatch return HTTP 503; `lagging` and `uninitialized` remain explicit non-healthy statuses even when HTTP 200. An operator must inspect `projection_status` and `lag_global_m_seq`, not merely the HTTP status or probe exit code.

The optional stdlib-only `scripts/sample-broker-projection.py --socket <private-control.sock> --token-file <0600-service-token-file>` makes one bounded request, emits a fixed JSON summary without the token, and cannot create a grant. It returns exit 0 for a schema-valid response **including** a reported conflict; `probe_ok` means the instrument spoke, not that the broker is query-ready. The script rejects malformed or oversized replies, false `caught_up`, and insecure token files. Its total alarm is 3 seconds. This is suitable for a low-rate additional soak witness after the candidate broker is deployed; it is not a substitute for a separately bounded fixed-grant query probe.

The currently running supervisor-owned `soak_sample.py` and existing live broker were **not** changed or restarted. Their ongoing stream records M process age and service activity only. Until this candidate is reviewed, deployed, and the sampler is wired, that stream must not be counted as a QueryService/AURA availability pass. No external model API, business node, or Edge was touched.

## Exact source and test receipts

Starting HEAD: `14bb30d0c8d599d56ce0963a2e7a6949c56353da`. Restored SHA-256:

| File under `tools/node-health-monitor/` | SHA-256 |
| --- | --- |
| `crates/health-services/src/manager_query_source.rs` | `5be597e10e025e867cf9e512768cba73e1264967da658bcce82a6db0348cb962` |
| `crates/health-services/src/observability.rs` | `03f3d060c1ee1d7ba5b72271a9a9de864a1dbfadcf7f212230588446fdeb75c0` |
| `crates/health-services/tests/manager_query_source.rs` | `e2a21de134de22b47f0fa21e55222e153a20731c17a40afd7c0034c073c26a30` |
| `scripts/sample-broker-projection.py` | `6e2f27613762756b1b5f06b4ddfbbb2d0462cd3ed5489b5d3707600e42a8a0e5` |
| `scripts/test-sample-broker-projection.py` | `65de5d08023774e831464604e017e5cf00328b724729debbfb0d33fdca20cbbf` |

Raw logs under `/home/tomi/nhm-c08-mcp-evidence/`:

| Log | SHA-256 | Natural result |
| --- | --- | --- |
| `c09-projection-health-baseline.log` | `d8db1ddf833218246a1fd96b5982219d1f9afebc4977bd26bb44c3509695e1d8` | Actual private-router test exit 0 |
| `c09-projection-health-lag-mutant.log` | `9bb431fb6e66b283f4c2eef0e95c2c54f79939e67ebd9df1551956a670358a4e` | Compiled mutation of lag guard, exit 101 at intended `caught_up` versus `lagging` assertion |
| `c09-projection-health-restored.log` | `270c0c5c361e009dbd1f848d5d2b256d30272df7a02726c0a0100bec3e6c2c48` | Restored private-router test exit 0 |
| `c09-projection-health-closure-first.log` | `df993ee5548e407021590511989a1fae76056093d2df2e342884f275d5a0ebdc` | Python sampler tests 3/3, `py_compile`, locked fmt/Clippy, and locked workspace tests: exit 0 |

The mutation changed only the `lag_global_m_seq == "0"` caught-up guard in `observability.rs`; mutant source SHA-256 was `e9004ef218d2b154d422dd5d93dd1d5c8a3f365d92486695802779c855cce916`, and the restored file hash is listed above. The private-router test checks unauthorized 401, no public route, initial caught-up, an M append detected as lag without a new import, and retained-source corruption latched as conflict. Python tests use a fake Unix HTTP receiver and test response/schema/secret boundaries. Neither test family proves that the current deployed broker exposes this new route.

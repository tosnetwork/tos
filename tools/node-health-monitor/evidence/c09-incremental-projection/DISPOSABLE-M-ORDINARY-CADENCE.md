# C09 ordinary-append grant cadence: controlled negative

This follow-up isolates the availability cause seen in `LIVE-M-GRANT-CADENCE.md`. The test creates its own M evidence SQLite database and Q ledger, inserts one initial process record, then inserts **15 additional valid unique process records** at two-second intervals. It never inserts a quarantine row, rewrites/deletes an existing record, contacts a running service, or calls a synchronous import from the grant route. It explicitly imports at seconds 0, 15, and 30; each second invokes the actual `control_router` grant endpoint and revokes any successful grant.

Restored source SHA-256: `observability.rs` `053f5799f1a48c2e7eec011c4d0b69e7a3b7eb82b93ac50e4967689fd2e101cc`; `tests/manager_query_source.rs` `2628f6a0992d6eb67ff2ff813aec5b2833c351875d3763f1bb04f1b26dacddba`.

Actual 31-second baseline and restored runs, both exit 0: **4 HTTP 200 / 27 HTTP 503**, with exactly 3 imports and `quarantined` row count 0. The 200s occurred before the first append and just after the two scheduled refreshes; after each ordinary append, the grant route denied new grants until an import. The test checks the Q projection-read counter before/after every grant to exclude a hidden synchronous import.

Changed-property sensitivity: a temporary compiled mutant removed **both** the `manager_validated_data_version == current_version` requirement and `cursor.watermark == M.global_m_seq` check from grant; source SHA-256 `4babbebba60bb696a47597eeca62bd46e6dcc7c5ec3454c29ef897da7e695a8e`. It exited 101 at the intended assertion at second 2: actual 200 versus required 503 immediately after the first ordinary append. This mutation was diagnostic only, never deployed; source was restored byte-for-byte and the 31-second test then exited 0 again. A mutant that removes only one guard would be masked by the other and is not claimed as evidence that either single guard alone causes the denial.

Run from `tools/node-health-monitor`:

```sh
CARGO_TARGET_DIR=/home/tomi/nhm-c09-grant-lock-build cargo test --locked -j2 \
  -p tos-health-services --test manager_query_source \
  ordinary_m_appends_deny_grants_between_fifteen_second_imports \
  -- --exact --ignored --nocapture
```

The earlier ordinary live-M witness found all 45 stable 503 responses with **both** version and head mismatch. This controlled synthetic control removes the possible quarantine/rewrite confounder: ordinary append alone is sufficient for the same denial. It does not justify removing both checks: same-W quarantine and exact retained-parent tamper controls still require fail-closed behavior. C09 availability remains RED; a reviewed append-versus-integrity distinction is needed before deployment.

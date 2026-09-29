# C09 local process bridge checkpoint (2026-09-29)

Scope: six already-running local Edge instances and the local M service only. This is **not** a production or AURA-model acceptance receipt. No business node was restarted, no model API was called, and no direct `edge_probe` observation was relabelled `process`.

## Implemented and tested

- `health-collector` accepts an optional, separately pinned `ingest_identity_file`. It uses the existing read identity for Edge (and O retained-cache) GET and the ingest identity for M POST. The existing one-identity configuration remains supported.
- Six local, no-secret collector configuration examples identify the approved Edge endpoints, M route, CA, and role-separated identity/token file **paths**. These are not enabled service units or a deployment.
- Actual TLS ingress test proves an EdgeReader identity alone cannot archive a process source; the separate ManagerIngest identity archives a typed Edge snapshot, and M's process projection returns that source while `edge_probe` remains absent.
- An ignored local diagnostic reads Edge1's real snapshot and archives it only into disposable M state. The real snapshot has *distinct* native and process epoch namespaces and the current explicit native-process binding validates them. The same test also passed using a consistent clone of the live M evidence database; that clone was deleted after testing.
- A second ignored, C09-host-only control reads **all six** running Edge snapshots and archives them into one disposable M database. It asserts six distinct node IDs in the resulting process projection, without touching the live M database or starting any business process.

## Live failure and cause

One one-shot collector against running Edge1 / M exited naturally but got M snapshot-ingest HTTP **503**. Live M still has only `edge_probe` evidence, no process source. The deployed `health-state` SHA-256 is `99a363eb901b5f3aa37adcc9b1bd5f31c69b455d60ea1d959e14a012f4e858cc`, bound by `deployment-public.json` to source `35ba59c111dd74518e6e661bcd1984598d493907`. That source's `EdgeSnapshot::validate` rejects differing native/process epochs as "mixed process epochs". Actual Edge1 reports native epoch `f72a52b2f44cc45ff59cd6d8ceeeee0c` and process epoch `b6a0413d-dea2-4074-95ef-6462ce861899:2526870:30370417`. Current source validates this through `native_process_binding`; the identical real snapshot archives and projects in isolated M, including with a clone of live evidence data. The old deployed M validation is the identified compatibility gap. This does **not** justify changing or restarting business nodes.

The supervisor owns the C09 local observability deployment. A current `health-state` build is staged at `/home/tomi/nhm-c08-build/debug/health-state` (SHA-256 `c6e0726b54ffc66b54800f7be7d14704a499fdb5305b8985b11502288608d94e`), but has **not** replaced or restarted the running service. After a coordinated M-only update, re-run the six collectors, verify six `process` projections and unknown/error controls, then exercise the pinned AURA fixed grant against those real rows. Until then, AURA real-node monitoring is not achieved.

## Evidence (external raw logs, SHA-256)

| Exact evidence | Result | SHA-256 |
| --- | --- | --- |
| `/home/tomi/nhm-c08-mcp-evidence/c09-live-collector-validator1-diagnostic.log` | real M returned 503 | `92a321de1c5bb5ddcaa68d1a4f8b4fed90722894cda766d5d710152a2403e0ba` |
| `/home/tomi/nhm-c08-mcp-evidence/c09-live-edge-isolated-m-final.log` | real Edge1 to isolated M process projection: 1/1, exit 0 | `218142cd4ee1ea71a0356b1a720261493ef2594bb8fb8c4b84ee53feacf1e671` |
| `/home/tomi/nhm-c08-mcp-evidence/c09-six-real-edge-isolated-m-distinct.log` | six real Edge snapshots to isolated M, six distinct process nodes, exit 0 | `6724f49fb929d886fe8fc75350f10a90756af57219aaea7e8c82c7789245fd80` |
| `/home/tomi/nhm-c08-mcp-evidence/c09-split-identity-final-tests.log` | ingress 8, manager 9 (+1 ignored), projection 8; exit 0 | `62c2b67ec09eec7119c11a5d3a45c413a790b945e95dbae924d6243e6c26edb5` |
| `/home/tomi/nhm-c08-mcp-evidence/c09-split-identity-fmt-clippy.log` | `cargo fmt --all --check` and locked workspace Clippy `-D warnings`, exit 0 | `2983638b6dc55eeadea1759f80885f9755433267679aaf831df4594f8bcd297d` |

Current source SHA-256: `collector.rs` `e94ed101f365ce098bd9e0f651678509c04066b880d8acdba70d10813e0eab56`; `tests/ingress.rs` `9c0528f76b7d77dcbbcf0d071450f318e94eeca8cca0a5f5b77068b5b7570b56`; `tests/manager.rs` `266175f7c0146be1fe1822b92c1502eed2bf5ae5e3c1ab2f0043de603db790e5`.

Remaining limits: all six were live-sampled **read-only** but only into disposable M; no live M `process` row yet, no deployed six-node query projection, no live AURA six-tool or model judgment, no continuous collector supervised unit, and no C09 performance/soak acceptance.

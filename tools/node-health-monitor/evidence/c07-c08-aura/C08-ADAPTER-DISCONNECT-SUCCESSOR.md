# C08 AURA adapter disconnect successor (2026-09-29)

Base: `07bb9198ac73c843fb1ca02e76f6824745becfe2`. This narrowly closes two transport/test races without changing grants, query semantics, credentials, the five-second tool deadline or 180-second whole-run deadline. Existing historical red logs and prior receipts were not deleted or rewritten.

- `aura_stdio.rs` now waits up to two seconds for the one-use 0600 handoff file to disappear, checking for premature adapter exit each iteration. It no longer assumes that a just-spawned child has already been scheduled.
- `tos-nhm-aura-stdio` selects between stdin work and the Unix HTTP connection task. A connection that ends while stdin remains open causes immediate generic refusal and no further tool forwarding; other exits still abort and await the connection task. No credential, RPC frame or body is echoed.
- New real Unix socket control initializes the adapter, drops the server-side connection while keeping adapter stdin open, and requires nonzero adapter exit within three seconds, stdout EOF and only the existing generic stderr line.

Raw receipts (external to the repository, SHA-256):

| Path | Outcome | SHA-256 |
| --- | --- | --- |
| `/home/tomi/nhm-c08-mcp-evidence/c08-stdio-connection-death-successor.log` | `cargo test --locked -j2 -p tos-health-services --features mcp --test aura_stdio`: 4/4 pass, exit 0 | `1003dd93805be75ed26246ac2263254421d51b96df67037c81f603edb84ad9e8` |
| `/home/tomi/nhm-c08-mcp-evidence/c08-pinned-aura-after-disconnect-fix.log` | pinned AURA 0.12 real stdio six-tool fixture calls and cancellation: 1/1 pass, exit 0; metric/block are honest error outputs | `88d48a3c5067569acdccaf81de866ebb6665c0a9cdbbd85caf18f70f3e6c2311` |
| `/home/tomi/nhm-c08-mcp-evidence/c08-stdio-connection-death-fmt-clippy.log` | `cargo fmt --all --check` and locked strict Clippy on adapter/test, exit 0 | `d31eecf3a97b79ecb4de9e1b45791c09d4b03bdf24bd9400cdca49550b5c1b27` |

Source SHA-256: adapter `75abab57074fab8ed1f8369ae9f1b9652bf7aac8730eef785b810ca9d6eb1ecd`; test `ba2e601225a91bdfede01a3259c4874d7bc848f4347e44b6c604a7a769f72e85`.

The pinned AURA fixture control validates transport, not a model diagnosis. Broker-owned revoke/replacement and supervised continuous monitoring remain separate C09 gates.

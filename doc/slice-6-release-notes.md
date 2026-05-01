# Slice 6 Release Notes

Slice 6 adds the repo-side foundation for protocol-heavy actor features:

- canonical delivery-failure and dead-letter helper surfaces;
- masterchain-seqno scheduled-message shapes and Tol time helpers;
- monitor/link notification helpers using `OP_MONITOR_DOWN`;
- restart-intensity and non-atomic supervision stdlib helpers;
- public capability grants with canonical constraint hashing;
- safe payment/refund helpers for author-facing value dispatch;
- bounded failure trace schema and release-package checker coverage.

Production protocol activation remains separate for validator scheduled
delivery and BackPressure emission. The repo-side package is ready for
contract author testing and system-contract dogfood, but mainnet-style
activation still needs the Stage 8 activation and rollback plan.

Run:

```sh
python3 scripts/check-slice-6-release-package.py
```

The checker validates required stdlib surfaces, release documents,
example budget declarations, no caller-controlled or Unix-time scheduling
into masterchain-seqno APIs, no unsafe `SEND_MODE_REGULAR` value dispatch
in Slice 6 production examples, no `extra_flags` bit-3 activation, and no
reusable public bearer capability token pattern.

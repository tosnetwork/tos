# Slice 4 Bounded Postponement Guide

Status: release-package surrogate, 2026-04-30.

Bounded postponement is explicit contract storage. It does not scan a
protocol mailbox, schedule wakeups, widen message flags, or emit
`ErrorClass.BackPressure`.

Use `@stdlib/postponement` when a message is valid but too early for
the current contract state:

1. Declare a `PostponedQueue` field in storage.
2. Declare a `PostponementBudget` with nonzero `maxItems`,
   `maxAgeSeconds`, `maxDrainItems`, and `maxCellDepth`.
3. Enqueue only after the message body has been parsed and classified
   as postponable.
4. Use `queryId` as the replay key for query messages. For non-query
   messages, pass an explicit author idempotency key.
5. Drain with an explicit bound. If a drain callback throws, the
   transaction aborts and the queue item remains at the same nonce.

Reference implementation:

```sh
tol --check-only examples/slice4/postponed-auction.tol
cd tol-tester && FIFTPATH=../crypto/fift/lib \
  FIFT_EXECUTABLE=../build/crypto/fift \
  TOL_EXECUTABLE=../build/tol/tol \
  python3 tol-tester.py tests slice4-postponed-auction
```

The compiler rejects direct writes to `PostponedQueue` accounting fields
and rejects external-message enqueue attempts. Raw map-based
postponement remains warning-only for legacy code.

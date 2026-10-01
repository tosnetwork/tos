# C09 local development: 30-minute observation gate

On 2026-09-30 the user set **30 minutes** as the development-stage continuous
sampling requirement. The R4 72-hour production soak remains a future
production requirement; it is not a blocker for this development result.

`DEV-30M-RECEIPT.json` was produced by
`scripts/verify-c09-dev-30m.py` (SHA-256
`3a74acf15e4e1a89736c5606f4f6398e7d6e743e760744472bc55f9215292f08`).
Its immutable private inputs are:

| Input | Private frozen path | SHA-256 |
| --- | --- | --- |
| Functional v2 | `$HOME/nhm-supervision/c09-local/reviews/dev-30m/functional.frozen.jsonl` | `11fd8736ab6b9504edb0a7b8e3d81dbff1826308bdd0e5ba0e420dbe97590245` |
| Q-aware | `$HOME/nhm-supervision/c09-local/reviews/dev-30m/q-aware.frozen.jsonl` | `2b8f85072eebf32dd4b1565a72697dbc6fc637ffbbc66787dc606d53220fa40a` |

The functional samples ran from 03:32:01 to 04:32:16 UTC: 13 passing rows,
one boot/window identity, 60 minutes 14.991 seconds of BOOTTIME coverage,
maximum gap 301.993 seconds, checked fixed-grant process queries, a passing
cross-scope negative control, and confirmed cleanup. The Q-aware samples
inside that interval ran from 03:32:17 to 04:31:34 UTC: 57 passing rows,
59 minutes 17.113 seconds of BOOTTIME coverage, maximum gap 70.017 seconds,
six fresh process sources, seven active units with zero restarts, and private
projection-head HTTP 200 with matching source identity and no conflict.
The sampled global M lag reached 21 rows; continuous caught-up status is **not**
claimed. A disposable mutation of one Q row from `fresh` to `stale` made the
verifier reject it with `q_node_freshness`.

After freezing the inputs, the functional, Q-aware, and two 72-hour stop
timers were stopped at approximately 04:33 UTC. The local M and Q services and
six supervised collectors remain running. No business node was restarted.

This passes the **local 30-minute development observation gate** only. It does
not assert AURA model diagnosis, complete consensus health, retention cleanup,
production performance, rollback/credential rotation, or production acceptance.

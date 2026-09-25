# X02 8f66 directed cut: transport-coverage failure

The fixed `8f66f63845bfba211c63c8cf50837c8dc2b55de4` run retained its
new Stage A readiness and policy at
`test/integration/.x02-stage-a-8f66f6384-retry-20260925/20260925T211247Z/`.
Readiness SHA-256 is
`0da36c383c43cf6c0fed545e217d7d154996113e966cb3fd823846eb057ab12e`;
policy SHA-256 is
`ba295cb3de643de017585d0bc9c7188ebfb471d27fb61d2d108ba1522e6bce79`.
The exact directed runner exited 1, result `failed`: its first two-of-four
sample had common finalized H43, while the next had H46. The four new node3
rules had positive drop counts (952, 803, 253, 244) at that second sample.
The runner restored `lo` to `noqueue` with no egress filters. Its ten
per-filter fallback deletes nevertheless returned exit 255, because the
frozen remove argv omitted `flower`; deleting clsact cleared those rules.
The 20 retained runner files have SHA index
`test/integration/.x02-stage-a-8f66f6384-retry-20260925/20260925T211247Z/x02-directed-SHA256SUMS`
(index SHA-256 `cbc6cac5b4a4022687622f3d6a7b9c86c68b653b4810b137d19b284ce8e84e25`).

This is **not** a two-of-four consensus safety counterexample. The policy
covered only the four ADNL UDP sockets 26602/05/08/11. The same validator
PIDs owned QUIC UDP sockets 27602/05/08/11; production
`quic/quic-sender.h`/`.cpp` derives that port using offset 1000. Native
node1 log records QUIC starting on 27602 and peer connections to 27605/08/11.
Read-only packet headers after the cut show all three node1 QUIC peer flows
(`udp-276xx-headers.raw`, SHA-256
`a5beb08a47ef5ffe41e0672cef55636179d141b5cdd01a76daec9776f21e6b6d`).
That capture is **after** cut cleanup; it is not asserted to be a cut-time
packet receipt. The failed snapshots and full native markers H44–H47 are
preserved. Stage A's separate reward-allocation report is not an X02 verdict.

The next fixed policy must cover both UDP transports with exact PID/socket
ownership and per-direction hit/drop; TCP JSON-RPC must remain untouched.
The next runner pre-refuses any initial root qdisc other than loopback
`noqueue`, uses typed `flower` deletion, and fixes a 30-second post-cut drain
*before* its 60-second two-of-four no-progress observation. The drain limit is
precommitted, and its native bytes remain in the first observation sample;
no failed sample may be skipped after inspection. These are offline controls
only until a new exact-tree real run and independent review. X02 remains OPEN;
partial packet loss is a separate unsatisfied slice.

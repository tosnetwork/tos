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
The retained result JSON SHA-256 is
`029a32d61078d93ab299ffe1005841b6dac20142885de485d3278e4c09670b1c`.
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
preserved. The enclosing 900-second Stage A ended independently with exit 1
and eight outstanding reward allocations; its console SHA-256 is
`32e7e5f60686cd4bf003bf092b79350b8db23b41daf2eeb09f0acabcce0981c4`,
and report SHA-256 is
`de5c8fb2f4706a6d5d77c54aa41d8fb455c208a4f8e27a13a4327c8d42d5d713`.
This settlement failure is not an X02 fault-window verdict. The supervisor's
49-file raw evidence index is
`/datax/n6-supervisor-x02-8f6-evidence/SHA256SUMS` (SHA-256
`52fb509b18766d454ef2c7cf92a8b2761261d5aa3935d367d4d3c16b076e36ef`).

The next fixed policy must cover both UDP transports with exact PID/socket
ownership and per-direction hit/drop; TCP JSON-RPC must remain untouched.
The next runner pre-refuses any initial root qdisc other than loopback
`noqueue`, uses typed `flower` deletion, and fixes a 30-second post-cut drain
*before* its 60-second two-of-four no-progress observation. The drain limit is
precommitted, and its native bytes remain in the first observation sample;
the standalone verifier also checks that the first 2/4 snapshot starts at
least 30 seconds after the last node3 rule install completes. A synthetic
1.99-second gap is rejected; removing only that verifier guard lets the same
short-gap fixture pass. A separate network-namespace `tc` control retained at
`/datax/n6-supervisor-x02-8f6-evidence/tc-flower-delete-netns.raw`
(SHA-256 `46c4e16f70d00a62c1eb5dd6efaea0a15ad35fd923ec9e3c44a665e354486d30`)
proves the typed `flower` delete succeeds and leaves no filter, but not that
all 20 rules can be removed after a real fault run. No failed sample may be
skipped after inspection. These are offline controls only until a new
exact-tree real run and independent review. X02 remains OPEN;
partial packet loss is a separate unsatisfied slice.

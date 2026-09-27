# E10 composed route first-run boundary — 2026-09-25

Status: OPEN; this is a failed, incomplete local-chain run, not an accepted
E10 result. The exact committed source was
`47aa1ae513b3130451be634a823a6df81d3097a2` with a clean tracked tree.
It ran `script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-economy-composed-e2e.py' test/integration/.e10-composed-47aa1ae51-20260925-console.typescript`
and exited 1. The four controller action sites, two observer configs and
same-zerostate preflight passed; happy-task accept/result and the Service
Actor mid-task call passed. The script then stopped inside the first
`settle without attestation rejected` control with
`RuntimeError: ... multiple new wallet transactions`. It did **not** reach
that control's contract VM-code check, the happy payout or the contested route.
No contract refusal or E10 completion is claimed from this result.

The console SHA-256 is
`a5914636958c2745f916ff59386d7cf8a11d40f974d8236f25dd19396639bacc`.
The complete original node/config data are retained under
`test/integration/.e10-composed-47aa1ae51-20260925-network/` with manifest
SHA-256 `ace252a9837d5f03e7e00983c03bd6918a042de5603babf3ce62f40a12722292`,
RPC transcript `953f7d0ec46cef0eebc459515b373620a2b32e54a5adffd46e30e8ec54535980`,
and CLI transcript `a7467ccdad4d96288b5d022e511b09be46f2924f9edcffd0fe1904af5b5c60ec`.
The manifest binds script SHA-256
`ac8f48e90589a091ae01b117e739dbda3dad82ebec4278f00c898aa1e78b0a63`
and validator-engine/DHT/tosctl SHA-256 values
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
`bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local node/test processes have exited. Before another network run, decode
the saved wallet transaction page and target contract page to classify the
extra row by exact message hash and source; do not relax the refusal or
resend on the basis of transaction count alone.

## Read-only retained-chain diagnosis

The retained validator DB was copied with reflinks to
`test/integration/.e10-composed-47aa1ae51-20260925-forensic/node1-copy`.
Only that disposable copy was started with loopback `--json-rpc-readonly`;
the original node DB was not restarted or modified. Its target
`getTransactions` raw response is retained as
`test/integration/.e10-composed-47aa1ae51-20260925-forensic/target-transactions.raw.json`
(SHA-256 `37b3c56066b22b466b30f456d82097cf4360d50b5023799ccc4c509d6971f1d1`).

The original RPC wallet page has exactly two new rows above baseline
LT 86000003. Wallet LT 211000001 has one outbound to Task Escrow
`0:38fb29228924a6c829371e61e638a41f633240328bcc3c4bd1550d495b932643`,
hash `VMh4+na3DTQXyba0VgS2I4FxnXSIDci+IXcRt46M8JE=`. The cold-copy
target LT 211000003 has that exact inbound hash and wallet source; it
aborted at VM exit 9. Its only outbound is a bounced message back to the
same wallet, hash `YUPoYbRuMDVJzbf5dPLNtdtkXEvfu0aXpKWp6mSyXd4=`.
Wallet LT 211000005 receives that exact hash from the target with
`bounced=true` and no outbound. Thus the extra wallet row is the refund,
not a second payment. The old count check was the sole observed failure
in this control; this diagnosis does not establish that the rest of E10
would have passed.

The replacement control selects exactly one successful wallet send with
one target outbound; requires the target's matching inbound, exact VM
exit, one bounced target outbound and a matching bounced wallet credit;
rejects unrelated/duplicate wallet rows. The exact-bounce unit test is
old-red (`multiple new wallet transactions`) and new-green; wrong hash,
duplicate bounce and extra wallet outbound are negative controls. Old
source SHA-256 `ac8f48e90589a091ae01b117e739dbda3dad82ebec4278f00c898aa1e78b0a63`,
red log SHA-256 `b2002863fa651d5613440907c38eaafc69ab791286fe314d4eacf50c5f3b90d5`;
green log SHA-256 `b454ccaba8a208aeafbb8a94016e87c423bd315e8e6f889d4f0f5cbe4418fcba`.
E10 remains OPEN pending a new committed-tree real-chain run and
independent review.

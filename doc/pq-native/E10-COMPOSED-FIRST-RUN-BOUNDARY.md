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

# `list_proposals` answers from a running node

Both files are verbatim `runGetMethodStd` responses from the local development
network's node 1 (`http://127.0.0.1:8011/`) for the configuration contract
`-1:5555555555555555555555555555555555555555555555555555555555555555`, requested
with an empty stack. They pin how the node's serializer renders the getter's
result: `null()` (no proposal registered) as an empty `tvm.stackEntryList`, and a
non-empty cons list of `[phash, proposal]` pairs as nested two-element
`tvm.stackEntryTuple`s ending in that same empty list, never as a list.

| File | Masterchain block | SHA-256 |
| --- | --- | --- |
| `empty-live.json` | 125669 | `2726dce435e8f87852056905bb6d74c85c1d1b093f33c92c4e07e440dfc24f64` |
| `two-live.json` | 127595 | `f0da2e559822a38834fd6614d0954e5ce5b10acf7be014d62e3d6d2b829524e8` |

Between the two captures, two proposals were registered for this purpose with
`tosctl vote offer create --param <p> --remove --expires-in 1000000 --wallet <w> --yes`
from a scratch masterchain wallet: non-critical removals of the unused
parameters 1000 (hash
`472b34cc4214f8c3d028bc1f47dcc7d8c2e040b093a9b32f4afe2485be597cc9`, expiring at
1792326266) and 1001 (hash
`caf342eb8fdd9adc97379f44c7740735097dd210430f79dc410a3690639888f0`, expiring at
1792326268). No vote was cast; voted lists are covered by the sandbox
(`tests/config_list_proposals_sandbox.rs`). These are public chain data from a
disposable development network; nothing in them is secret.

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

## `config-code.boc`

The configuration contract's code as the generated zerostate deploys it and as
the development network ran it (both representation hash
`2774a7cc7850cfb8dd1023b725c1e44182a9bae39da547fb8724b2f72562ff7a`; file SHA-256
`be9df077e55e56f66d5e5b00ffd8a2a77e6c112eb667d2dc545ff21bf281ca36`). The
stored-state reader interprets storage only under this code;
`config_list_proposals_sandbox.rs` checks the fixture against the zerostate.

## Read-path limits and measurements

The proposal getters are read on a dedicated worker thread behind a JSON depth
preflight, and only flat results leave it
(`src/config_contract/proposal_transport.rs`).

| Limit | Value | Where it comes from |
| --- | --- | --- |
| Response body | 1 MiB | the HTTP client's transport limit |
| JSON depth | 19,724 levels | 3 levels per 160-byte voter cons cell, the cheapest nesting a decodable answer can buy, plus 64 |
| Workers | 2, 30 s admission | taken before any response of the read is buffered (the checkpoint included), released when the worker ends |
| Worker stack | 128 MiB release, 256 MiB debug | measured need of the whole pipeline: 5.9 MiB release, 34.6 MiB debug |
| Getter gas | 300,000 on the node | `list_proposals` returns exit 13 at about 130 proposals |

Stack needs come from `measure_worker_stack` and timings from
`measure_refusal_times` in `tests/proposal_read_workers.rs` (run with
`--release --ignored --nocapture`), rustc 1.97.1, release profile, one local
read each including the HTTP round trips, median of five:

| Input | Bytes | SHA-256 | Outcome | Median |
| --- | --- | --- | --- | --- |
| deepest valid answer (6,428 voters) | 1,048,390 | `8c6e4d8741890cca190a40979124e7b853876459a784d1e21eb3a0bcccdbe6e1` | decoded | 150 ms |
| malformed, at the depth limit | 39,802 | `74eed4c2542706d1224ab31c3f4746e9e7e207a85af8374200f3345956dcbe07` | refused | 127 ms |
| deep valid prefix, cut at 90 % | 943,551 | `61fde8467a5d4e8ffcfb1b436cdffedd7478370d887952f37f84e9a4731c71ae` | refused | 481 ms |
| deep stack conversion, refused by the decoder | 1,044,920 | `8beb7f0cff07a2f19b615e4bb4f30054162907c659d07ab3bda9b91bb9f5b86e` | refused | 153 ms |

The duplicate-key check keeps an ordered set of the keys seen. For an unused
object of 60,000 distinct keys inside a list answer (`wide_object_answer`,
650,636 bytes; 650,647 with the last key repeated, which is refused), the whole
read takes 119 ms (97 ms for the refused one) in release; with the earlier
linear scan of previous keys it took 5.3 s (6.1 s).

These are recorded, not gated: the tests assert each refusal's reason and run
under a 300 s watchdog for hangs.

Capacity: the getter serves at most about 130 small proposals before exit 13;
the stored account is far more compact (a minimal proposal adds about 110 bytes
to it). No state bound exists in the contract, so a dictionary too large for
both representations is an explicit error. Paginated or incremental state reads
are the remaining capacity work.

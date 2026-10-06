# `get_proposal` answers from a running node

Both files are verbatim `runGetMethodStd` responses from the local development
network's node 1 (`http://127.0.0.1:8011/`) for the configuration contract
`-1:5555555555555555555555555555555555555555555555555555555555555555`. They pin
how the node's serializer renders the getter's two results: `null()` as an empty
`tvm.stackEntryList`, and a present proposal as a nine-element
`tvm.stackEntryTuple` whose null fields (the voter list of a proposal nobody has
voted for, and the value of a removal proposal) are also empty lists.

| File | Request stack | Masterchain block | SHA-256 |
| --- | --- | --- | --- |
| `absent-live.json` | `[["num","12345"]]` | 116250 | `513453323ab99f7f6d06a34cdef3e253b54d1e34778f872a86615e67b6c56720` |
| `present-live.json` | the proposal hash below, as a decimal `num` | 117243 | `75bb5bac396300086dfb5ae5b69a0d75b17743ab7153c0b169b9bf1973ac8c53` |

The present proposal was registered for the capture with
`tosctl vote offer create --param 1000 --remove --expires-in 1000000 --wallet <w> --yes`
from a scratch masterchain wallet: a non-critical removal of an unused parameter,
proposal hash `472b34cc4214f8c3d028bc1f47dcc7d8c2e040b093a9b32f4afe2485be597cc9`,
expiring at 1792321804. No vote was cast for it. These are public chain data from a
disposable development network; nothing in them is secret.

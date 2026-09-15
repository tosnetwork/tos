# Native configuration account context

`NativeConfigContext` is an immutable C++/Rust authority input for the successor of
an independently authenticated masterchain parent. It does not mutate the native
account or authorize an invocation supplied by a contract.

The constructor authenticates the full parent state, head, network, genesis and
chain domain through native history admission. It reads Config0 and requires the
same nonzero address in McStateExtra.ConfigParams. It selects the actual active,
ticking account from native ShardAccounts and checks the stored account address.
Anycast and absent code/data are rejected. Code and data must have native level zero; the private c4 root must be ordinary. The account's code, data and library hashes become immutable
invocation inputs; a contract's C7 tuple cannot substitute them.

The private configuration c4 layout is:

```
config_data cfgdict:^Cell seqno:uint32 public_key:bits256
            votes:(HashmapE 256 ConfigProposalStatus) checkpoint:^NativeRegistryCheckpoint
```

The root has exactly 289 bits and two references when votes are absent, three when
present. The votes representation and contract voting behavior remain governed by
the native configuration contract. The owned config dictionary must equal the
parent's authenticated global config dictionary. The checkpoint must restore to
that parent's Config46 and exact masterchain coordinate, including every derived
index. A previously validated registry cache is accepted only if its coordinate,
complete checkpoint hash and Config46 hash all match independently. Matching the
public registry root alone cannot authenticate private derived indexes.

The same native parent supplies the full masterchain committee and catchain
sequence. Invocation binding checks workchain, address, code, data and library.
Later transactions in the same block will need the factory's accepted account data
and registry prefix; reusing the original parent data for them is insufficient.
Only real native transaction commit may advance that accepted prefix. This
context is not yet attached to compute/action/commit or an installed contract.

The shared 22-case corpus includes actual native account lookup, misplaced config
addresses, tick removal, changed owned dictionaries, missing/trailing c4 fields,
corrupted checkpoint indexes and independently valid but mismatched caches. Each
invocation field has a substitution case. Twelve compiled C++ and twelve compiled
Rust guard removals fail named assertions. Ubuntu/ARM full-dependency ASan, UBSan
and LSan exports equal the ordinary native exports.

# Getter result serialization budget — measurement

Evidence for `doc/elector-participant-list-read.md` §2 and Appendix A.

- Revision: `main` at `6da705c8a` (`crypto/vm`, `crypto/smc-envelope` and
  `validator/impl/liteserver.cpp` as at that revision).
- What it measures: the operations the lite server's result-stack serialization
  (`vm::FakeVmStateLimits fstate(1000)`, `validator/impl/liteserver.cpp:1556`) spends
  on the results of `participant_list_extended` and `list_proposals`, and the
  largest list that fits. It runs the production sequence `Stack::serialize` →
  `finalize_to` → `std_boc_serialize` under a counting `VmStateInterface` and under
  the lite server's budget.
- Two sources, required to agree on every case:
  1. synthetic stacks of the documented shapes, each tuple built directly from its
     components (`StackEntry{std::vector<StackEntry>{...}}`) and every arity asserted;
  2. the real getters executed with `tos::SmartContract`: the elector account saved
     from the local development network at an open election (`elector-snapshot/`; its
     member book is re-filled to N members, each a copy of a real member under a
     hashed 256-bit key), and the genesis configuration contract with proposal sets
     written by the sandbox exporter. Each result's shape is checked, its cost must
     equal the formula and the synthetic stack's, and the emulated elector result for
     the saved state must equal the lite client's answer at the same block.

## Inputs

`elector-snapshot/` — committed because the state cannot be regenerated once the
election has moved on. Saved with the lite client, all at the block in
`elector-block.txt`: `saveaccountcode`, `saveaccountdata` and
`runmethod <elector> <block> participant_list_extended` (`elector-real-dump.txt`, its `result:` line with trailing whitespace removed).

The configuration BOCs are regenerated, not committed. Append
`export_list_proposals_states.rs` to
`tosctl/src/node-control/contracts/tests/config_list_proposals_sandbox.rs` and run, from
`tosctl/src`:

```sh
EXPORT_DIR=<config-dir> TOS_ROOT=<repository root with build/> \
  cargo test -p contracts --test config_list_proposals_sandbox -- --ignored export_list_proposals_states
```

Two runs produced byte-identical files:

```
be9df077e55e56f66d5e5b00ffd8a2a77e6c112eb667d2dc545ff21bf281ca36  config-code.boc
6eb013f3da3f0ffe61dd9a0888893590c226a4edfc1a0d2b80ec429502b9492f  config-data-unvoted-0.boc
d13fc0d14bffc14ae063a90a598f119cb8ca583522eab477bf17081829fc1038  config-data-unvoted-1.boc
9a81dba073890ca8d06b6b0f5dc41e9a15a7fabc5558a405760936f0939818ae  config-data-unvoted-2.boc
0f50f2791296d898a1a1308599a2d99ff96e86ca04a7a6e28115096ca22cc9db  config-data-unvoted-61.boc
4c116340b29f03ace6b88d467a0568404979058cd2e34f819c6d2a1284d1ee48  config-data-unvoted-62.boc
70e7709922a3f0ad98755a47497fc0d668ba3124c0d844e6d784e35522603127  config-data-unvoted-63.boc
e6d43349a59e1bdb412972abc4a2bcb7014b84709047049f707273931c7b7957  config-data-valued-1.boc
a3cb9a1a856ee38f8c487cd924bceeefee5351f7a74321595c1a60f109200ddf  config-data-valued-61.boc
29324d919a7c473d13958e939d972561709d9df374530b0c674ff67417186556  config-data-valued-62.boc
ca5cef45a6e0e6c292efc6a05f190638a1a7a5462f89f2238b032b279141e00e  config-data-valued-63.boc
da534cdfc6c0201cdc73411966c93bd10c79c99ff8aa661a9e9fc5df99b53e0a  config-data-voters21-16.boc
32f304d73c7e37220ef47bcb73cabdceac417eb0bf7ae8c664a4beb73e31a274  config-data-voters21-17.boc
87de8ad09a70d3f731c8cba7719006288d0eea8a4e4a0f2bf72b7a25a02dc318  config-data-voters21-18.boc
46f74aba9668b7475f8e1c2147953b6b605eded6aa82d78743ac643c15886142  config-data-voters21-1.boc
```

## Build and run

From the repository root, with a configured build in `build/`:

```sh
LIBS=$(find build/crypto build/tdactor build/tddb build/tdutils build/third-party build/common \
            build/keys build/tl build/tl-utils build/adnl build/tdnet -name '*.a' | grep -v -E 'test|fuzz')
clang++-21 -std=c++20 -O1 -Icrypto -Ibuild/crypto -Itdutils -Ibuild/tdutils -Itdactor -Itddb \
  -Itl -Ibuild/tl -Itl/generate -Icommon -I. -Ithird-party/abseil-cpp \
  doc/evidence/getter-serialization-budget/probe.cpp -o probe \
  -Wl,--start-group $LIBS -Wl,--end-group -ldl -lpthread -lz -lssl -lcrypto -lsodium
./probe doc/evidence/getter-serialization-budget/elector-snapshot <config-dir>
```

The probe exits non-zero on the first failed check and prints `ALL CHECKS PASSED`
otherwise. Output: `result.txt`.

## Result

| Getter result | Operations | Largest that fits in 1,000 |
| --- | --- | --- |
| `participant_list_extended`, N participants | 10N + 8 | 99 (100 → 1,008) |
| `list_proposals`, P proposals, V voter entries in total | 16P + 2V + 2 | 62 with no voters (63 → 1,010); 17 with 21 voters each (18 → 1,046) |

The formulas hold for every synthetic size (participants 0–300, proposals 0–100 with
0, 1, 5 and 21 voters each) and for every real case; proposals carrying a value cost
the same as proposals without. `std_boc_serialize` adds no operations. With a 10^9
budget, 300 participants and 300 proposals with 21 voters each serialize, so the
budget, not cell depth, binds.

Gas of the real getters on the node's C++ VM (see `result.txt`): the cloned elector
book needs 131,621 at 99 members and 345,395 at 256; `list_proposals` 138,773 at 62
unvoted proposals and 209,145 at 17 proposals with 21 voters each. At the lite
server's 300,000 gas limit, serialization is therefore the binding public limit for
both getters.

## Sensitivity

- Reintroducing the defect of the previous revision of this probe — building each
  cons cell as `make_tuple_ref(std::vector<StackEntry>{head, tail})`, a one-element
  tuple around the intended one — makes the probe fail (`cons cell has arity 2, got
  1`, exit 1).
- Changing one digit of `elector-real-dump.txt` makes it fail (`emulated result
  equals the lite server's answer at the saved block`, exit 1).

## Elector getter budgets

`elector-budget.cpp` (build like `probe.cpp`; run `./elector-budget
doc/evidence/getter-serialization-budget/elector-snapshot`) grows the saved elector
along each dimension its getters walk: the member book (0–256, with hashed keys, on
the deepest path, and on the deepest path with a maximum stake), the retained past
elections (1–16, each with 21 or 256 frozen entries cloned under hashed keys) and the
credits dictionary (0–65,536 random keys, plus 257 keys forming the deepest 256-level
path). It checks each result's shape — elections and frozen-entry counts, the
credited and absent wallets' amounts — and records gas and the native frozen-walk
time in `elector-budget-result.txt`:

- `participant_list_extended`: 345,395 gas at 256 members with hashed keys and
  1,114,595 when the keys form the deepest 256-level path; a maximum stake
  (2^120 − 1) costs the same. Every case asserts the 7-value result, the participant
  count and each tuple's arity (and, for the maximum-stake book, the returned stake);
  that assertion caught a probe revision whose rebuilt book had silently kept the
  hashed shape.
- `past_elections`: about 0.9k gas per retained election (15,953 at 16), independent
  of frozen entries, which are returned as a cell; walking 4,096 frozen entries
  natively takes about 2 ms.
- `compute_returned_stake`: 2,896 gas at 65,536 random credits, 26,804 on the deepest
  path.

These probes run with `tos::SmartContract`'s convenience context: they validate the
getters' shapes, serialization cost and gas, not the exact production c7 parity the
implementation must show separately.

## Hashes (SHA-256)

```
2d7b1ac70018659cd2d4caeb2d4d9c064dce1cbd4da1f5ea8b28380d17ce0952  probe.cpp
dbd990074dd284ec5bb8c6200fe5679d026e9a8f92a9b1eff84709587534c1da  elector-budget.cpp
c251375e03c5e73fe12eb269d77ec398345b713ee9010175c53a2d471ce6c7dc  export_list_proposals_states.rs
7e1825e9300bb24efc368234897062c54ad4c552679ae18ea7e2444b6b8037b2  result.txt
b5891369a05e1ad62e31141e8937fc5c3ddd8736530991c28e9e7426816f4698  elector-budget-result.txt
cfebf996d613089bdae5f3b0db8f17c3d0b6c9ebc7b1a768dd193a139fd4552a  elector-snapshot/elector-block.txt
60d9e0b113f8d88f681438f99bbdf5873bd360f734fe8ce746764d1a82f93adf  elector-snapshot/elector-code.boc
3150c331f4c317786a8f3308a535a4713abcfc9f20921a30047e0d1c27764d9a  elector-snapshot/elector-data.boc
a1456f519919fce25a1a32950343acb102ee78e6e5bdd1caeb06e7e8ec282837  elector-snapshot/elector-real-dump.txt
```

# Private I13 registration merge boundary

The tested merge is `eea0e04dfc53fa1c55a62296119ff747402f4b47`, with parents
`395ae489b182367b309b45d8a8cf4c490f2289c3` and
`ad4ff21eb685e05934031f5c4659889d9494dc5a`. The no-fast-forward merge preserves
the source commits and authors. The fetched remote branch ended at `1f650d58c`;
the authorized local source branch already contained `ad4ff21eb`. The actual
merged range also includes `a0cca7b2a`, not just the four commits named in the
scheduling message. No later source-branch changes are claimed here.

## Registration-only comparison

Before and after the merge, the same temporary directory was configured with:

```sh
cmake -S /home/tomi/tos -B /tmp/uno-i13-merge-registration-Tg5Kvb \
  -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PROJECT_TOS_INCLUDE=/home/tomi/tos/crypto/test/workchain-construction-isolation.cmake
ctest --test-dir /tmp/uno-i13-merge-registration-Tg5Kvb -L i13 --show-only=json-v1
python3 .github/scripts/check-i13-results.py registered REGISTRATION_JSON
```

`registration-before.json` contains zero tests; its checker exits 1 with the
recorded explicit count error. `registration-after.json` contains exactly the
three expected names and driver paths; its checker exits 0. The construction
module includes the other two modules, so they must not also be included a
second time. **No private harness is executed by `--show-only`.**

## Ordinary regression scope

The ordinary build previously cached the opt-in include. It was removed with
`cmake -S . -B build -UCMAKE_PROJECT_TOS_INCLUDE`, before building `all-tests`
with `-j32`. The resulting ordinary registration contains 127 tests and none
of the three private I13 tests. `TOS_UNO_CRYPTO_NODE_LINK=OFF`,
`TOS_UNO_CRYPTO_PROTOTYPE_TESTS=ON`, and `UNO_CRYPTO_BUILD_JOBS=32` were retained.

The ordinary run uses `ctest --test-dir build --output-on-failure
--no-tests=error --output-junit /tmp/i13-merged-standard.xml`. Its complete
result is archived in `ordinary-ctest.log` and `ordinary-results.xml`: exit 0,
127 executed and passed, zero failures or skipped cases, 919.64 seconds total.
The XML names exactly match the 127 registered names and exclude the three
private names. `final-checks.json` records these checks and artifact hashes.
A successful ordinary regression
does **not** establish execution of the merged private harnesses or durable
publication acceptance. Their CI entry point is the intentionally manual-only
`workflow_dispatch` workflow, not this merge gate. No hosted CI run is claimed.

No activation gate or consensus-judgement file was changed by this merge.

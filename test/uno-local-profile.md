# Independent local UNO network

`UNO_WORKCHAIN_PROFILE=1 NETWORK_GLOBAL_ID=4 scripts/setup-testnet.sh` selects
an independent local profile. It requires version 16, excludes mainnet ID 1 and
the isolated Counter ID -23903, and does not enable Counter registration.
Existing non-UNO local profiles keep their default version until explicitly
selected. The production descriptor constructor provides basic=1, active=1,
accept_msgs=0 (0xc000), zero reserved flags and the exported production engine
key. Param84 is installed in the same genesis; create-state issues the ledger
from the final serialized configuration.

This is a network that carries wc=2, not one that executes its account batches.
Its validators use `--not-all-shards` and explicitly monitor basechain shard 0.
Masterchain monitoring is inherent. Requesting the default all-active-workchain
execution role correctly fails readiness because there is no registered UNO
engine. Neither the readiness predicate nor any execution gate is weakened.

Setup checks generated tosapi modules, Python imports and the native toslib
library before its cleanup section. A missing generator output is an error with
an explicit generation command, never an excuse to delete data and fail later.
The extra shard zerostate is also included in each exported node's static files.

The standalone `test/uno-local-profile.py` runs a separate three-validator/DHT
network under a fresh directory and uses the real node binaries. It records the
zerostate and ledger, verifies block progress and then requires a restarted
node to reach a strictly newer height. It does not modify an existing /data
network, install system services or treat log text as an acceptance oracle.

# =============================================================================
# mapper.jq — translate hive's genesis.json into a TOS zerostate seed.
# =============================================================================
#
# Invoked from tos.cmd:
#     jq -f mapper.jq --arg chain_id <n> --arg network_id <n> <hive-genesis>
#
# Hive genesis schema (subset we care about):
#   {
#     "config": {
#       "chainId": 1, "homesteadBlock": 0, "byzantiumBlock": 0,
#       "constantinopleBlock": 0, "petersburgBlock": 0, "istanbulBlock": 0,
#       "berlinBlock": 0, "londonBlock": 0, "shanghaiTime": 0,
#       "cancunTime": 0, "terminalTotalDifficulty": 0
#     },
#     "alloc": { "0xaddr": { "balance": "0x...", "code": "0x..", "storage": {...} } },
#     "coinbase": "0x..", "difficulty": "0x..", "extraData": "0x..",
#     "gasLimit": "0x..", "nonce": "0x..", "mixhash": "0x..",
#     "parentHash": "0x..", "timestamp": "0x.."
#   }
#
# TOS zerostate schema (what tos-create-state actually consumes) is a TL-B
# encoded boc, not JSON. So the long-term shape of this mapper is:
#
#   1. emit a JSON document describing genesis (chain_id, gas_limit, alloc...)
#   2. tos.cmd hands it to a small helper that calls tos-create-state to
#      produce the actual binary zerostate + writes its file_hash to
#      tos-global.json.
#
# For Phase G.3 this is a STUB. It produces a JSON document that passes
# straight through; it does not yet drive tos-create-state. See README's
# "What's still missing" for the gap.
# =============================================================================

. as $genesis
| {
    "@type": "tos.zerostate.evm.v0",
    "chain_id":   ($chain_id   | tonumber),
    "network_id": ($network_id | tonumber),

    # Hive may provide config, but we extract the headline values defensively.
    "fork_config": (
        ($genesis.config // {})
        | {
            chainId,
            homesteadBlock, byzantiumBlock, constantinopleBlock,
            petersburgBlock, istanbulBlock, berlinBlock,
            londonBlock, mergeNetsplitBlock,
            shanghaiTime, cancunTime, pragueTime,
            terminalTotalDifficulty
          }
    ),

    "genesis_block": {
        "coinbase":    ($genesis.coinbase   // "0x0000000000000000000000000000000000000000"),
        "difficulty":  ($genesis.difficulty // "0x0"),
        "extraData":   ($genesis.extraData  // "0x"),
        "gasLimit":    ($genesis.gasLimit   // "0x1c9c380"),
        "nonce":       ($genesis.nonce      // "0x0000000000000000"),
        "mixHash":     ($genesis.mixhash    // ($genesis.mixHash // "0x0000000000000000000000000000000000000000000000000000000000000000")),
        "parentHash":  ($genesis.parentHash // "0x0000000000000000000000000000000000000000000000000000000000000000"),
        "timestamp":   ($genesis.timestamp  // "0x0"),
        "baseFeePerGas": ($genesis.baseFeePerGas // null),
        "blobGasUsed":   ($genesis.blobGasUsed   // null),
        "excessBlobGas": ($genesis.excessBlobGas // null)
    },

    # Pre-funded accounts. tos-create-state will need these encoded into the
    # initial state cell tree; for now we just pass them through verbatim.
    "alloc": ($genesis.alloc // {}),

    # TODO(phase-g.3):
    #   - emit `validators[]` derived from a deterministic test key (hive
    #     does not provide validator keys; we synthesise one).
    #   - emit `dht.static_nodes[]` for the in-container DHT (single node).
    #   - emit `zerostate.root_hash` / `file_hash` after tos-create-state runs.
    "validators": [],
    "_todo": [
        "wire mapper output into tos-create-state",
        "synthesise single validator key from HIVE_TESTNET_SEED",
        "fill dht.static_nodes with localhost:30001",
        "compute and embed zerostate hashes"
    ]
}

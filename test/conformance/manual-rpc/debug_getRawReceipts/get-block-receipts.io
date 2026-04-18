// debug_getRawReceipts always returns a JSON array (empty for missing /
// txless blocks, otherwise one canonical Ethereum-RLP receipt per tx).
// We assert against an unknown block so the result is deterministically
// empty regardless of head state.
>> {"jsonrpc":"2.0","id":1,"method":"debug_getRawReceipts","params":["0xffffffffff"]}
<< {"jsonrpc":"2.0","id":1,"result":[]}

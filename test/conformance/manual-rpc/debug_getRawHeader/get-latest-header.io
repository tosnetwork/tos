// debug_getRawHeader("latest") returns the canonical Ethereum-RLP of the
// current head's BlockHeader (yellow paper §4.3 + Cancun + Prague trailing
// fields). Chain-state-dependent; shape-match on a non-null hex string.
>> {"jsonrpc":"2.0","id":1,"method":"debug_getRawHeader","params":["latest"]}
<< {"jsonrpc":"2.0","id":1,"result":"0x00"}
// Unknown block must yield null.
>> {"jsonrpc":"2.0","id":2,"method":"debug_getRawHeader","params":["0xffffffffff"]}
<< {"jsonrpc":"2.0","id":2,"result":null}

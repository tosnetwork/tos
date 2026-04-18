// debug_getRawBlock("latest") returns the canonical Ethereum-RLP of the
// current head block (header + transactions + uncles + withdrawals).
// Chain-state-dependent, so we shape-match on a non-null hex string.
>> {"jsonrpc":"2.0","id":1,"method":"debug_getRawBlock","params":["latest"]}
<< {"jsonrpc":"2.0","id":1,"result":"0x00"}
// Unknown block tag (way past head) must yield null.
>> {"jsonrpc":"2.0","id":2,"method":"debug_getRawBlock","params":["0xffffffffff"]}
<< {"jsonrpc":"2.0","id":2,"result":null}

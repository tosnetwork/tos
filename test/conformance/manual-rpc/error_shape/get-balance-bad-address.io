// Pins JSON-RPC 2.0 spec error envelope for eth_getBalance with a malformed
// address.  Pre-fix the server returned `{"ok":false, "error":"<str>", "code":N}`
// which crashed Blockscout's `EthereumJSONRPC.HTTP.standardize_error/1` with
// FunctionClauseError.  Spec demands `{"error":{"code":N,"message":"<str>"}}`.
// See test/conformance/blockscout/README.md, BUG #1.
>> {"jsonrpc":"2.0","id":7,"method":"eth_getBalance","params":["0xnotanaddress","latest"]}
<< {"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"invalid address parameter"}}

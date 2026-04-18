// Pins JSON-RPC 2.0 batch dispatch.  Pre-fix the server returned a single
// error `{"ok":false,"error":"Batch requests are not supported","code":-32600}`
// which made Blockscout crash on the first catchup poll (it always batches
// 10-50 calls per HTTP roundtrip).  See test/conformance/blockscout/README.md
// BUG #2.
>> [{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}]
<< [{"jsonrpc":"2.0","id":1,"result":"0x544f53"},{"jsonrpc":"2.0","id":2,"result":"0x544f53"}]

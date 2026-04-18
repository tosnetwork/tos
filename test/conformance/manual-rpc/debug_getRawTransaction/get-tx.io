// debug_getRawTransaction(<txHash>) returns the canonical Ethereum-RLP of
// the signed transaction (envelope + payload, including the EIP-2718 type
// byte for typed txs). Equivalent to eth_getRawTransactionByHash.
//
// Unknown tx must yield null (matches geth/erigon).
>> {"jsonrpc":"2.0","id":1,"method":"debug_getRawTransaction","params":["0x0000000000000000000000000000000000000000000000000000000000000000"]}
<< {"jsonrpc":"2.0","id":1,"result":null}

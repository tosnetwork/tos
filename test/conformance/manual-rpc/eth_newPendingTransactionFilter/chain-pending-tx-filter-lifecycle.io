// chain test: create a pending-tx-hash filter, poll changes, uninstall.
>> {"jsonrpc":"2.0","id":1,"method":"eth_newPendingTransactionFilter"}
<< {"jsonrpc":"2.0","id":1,"result":"0x1"}
>> {"jsonrpc":"2.0","id":2,"method":"eth_getFilterChanges","params":["${RESULT_0}"]}
<< {"jsonrpc":"2.0","id":2,"result":[]}
>> {"jsonrpc":"2.0","id":3,"method":"eth_uninstallFilter","params":["${RESULT_0}"]}
<< {"jsonrpc":"2.0","id":3,"result":true}

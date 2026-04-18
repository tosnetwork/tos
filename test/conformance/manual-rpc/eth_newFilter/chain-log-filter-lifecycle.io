// chain test: create a log filter, poll changes, uninstall.
// ${RESULT_N} expands to the result of the Nth (0-indexed) prior step.
// shape-only equality on result; uninstall must be exactly true.
>> {"jsonrpc":"2.0","id":1,"method":"eth_newFilter","params":[{"fromBlock":"0x0","toBlock":"latest"}]}
<< {"jsonrpc":"2.0","id":1,"result":"0x1"}
>> {"jsonrpc":"2.0","id":2,"method":"eth_getFilterChanges","params":["${RESULT_0}"]}
<< {"jsonrpc":"2.0","id":2,"result":[]}
>> {"jsonrpc":"2.0","id":3,"method":"eth_uninstallFilter","params":["${RESULT_0}"]}
<< {"jsonrpc":"2.0","id":3,"result":true}

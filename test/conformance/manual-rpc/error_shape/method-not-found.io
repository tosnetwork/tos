// Pins method-not-found error shape (spec-compliant).  Pre-fix the dispatcher
// returned `'params' must be an object` for unknown methods called with array
// params, masking the real reason.  See README BUG #1 secondary note.
>> {"jsonrpc":"2.0","id":3,"method":"txpool_content","params":[]}
<< {"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found: txpool_content"}}

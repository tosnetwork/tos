// Pins JSON-RPC 2.0 spec semantics for a notification (request with no `id`):
// server MUST NOT respond.  An all-notification batch returns HTTP 204 with
// an empty body.  See JSON-RPC 2.0 spec section 6 "Batch".
//
// Special test marker: the expected response uses `__http_status__` to assert
// against the HTTP status code rather than a JSON body.
>> [{"jsonrpc":"2.0","method":"eth_chainId","params":[]}]
<< {"__http_status__":204,"__empty_body__":true}

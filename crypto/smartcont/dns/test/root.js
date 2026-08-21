const {funcer} = require("./funcer");
const {
    makeStorageRoot, FC_ROOT, DNS_NEXT_RESOLVER_PREFIX, TON, COLLECTION_ADDRESS, USER_ADDRESS
} = require("./utils");

const storage = () => {
    return makeStorageRoot({});
}

funcer({'logVmOps': false, 'logFiftCode': false}, {
    'path': './func/',
    'fc': FC_ROOT,
    'data': storage(),
    'in_msgs': [ // just fill-up
        {
            "sender": '0:' + USER_ADDRESS,
            "amount": 10 * TON,
            "body": [],
            "new_data": storage(),
            "exit_code": 0,
            "out_msgs": []
        },
    ],
    "get_methods": [
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('tos\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 3 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('\0tos\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 4 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('tos\0alice\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 3 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('tos\0alice\0')],
                ['int', '123']
            ],
            "output": [
                ["int", 3 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('\0tos\0alice\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 4 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('\0tos\0alice\0sub')],
                ['int', '0']
            ],
            "output": [
                ["int", 4 * 8],
                ["cell", [
                    'uint16', DNS_NEXT_RESOLVER_PREFIX,
                    'Address', '0:' + COLLECTION_ADDRESS
                ],
                ]
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('vip\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 0],
                ["null", 'null']
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('\0vip\0ali$e\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 0],
                ["null", 'null']
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 8],
                ["null", 'null']
            ]
        },
        {
            // ".ton" is not an alias for ".tos": the TOS root serves only the
            // `tos` zone and must not resolve the inherited TON suffixes.
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('ton\0alice\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 0],
                ["null", 'null']
            ]
        },
        {
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('me\0t\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 0],
                ["null", 'null']
            ]
        },
        {
            // "tos" must match as a complete component: "tosx\0..." shares the
            // first three bytes but is a different TLD and cannot resolve.
            "name": "dnsresolve",
            "args": [
                ['bytes', new TextEncoder().encode('tosx\0alice\0')],
                ['int', '0']
            ],
            "output": [
                ["int", 0],
                ["null", 'null']
            ]
        },
    ],
});

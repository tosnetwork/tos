const {funcer} = require("./funcer");

// A swap naming the zero destination would lock native coins forever while
// the wrapped coins are minted to an unspendable account. Both the binary and
// the text entry points must refuse it before any state changes.
const makeStorage = (totalLocked) => {
    return [
        "uint8", 0, // state_flags
        "coins", totalLocked, // total_locked
        "Address", "0:e53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a", // collector_address
        "coins", 2*1e9, // flat_reward
        "coins", 3*1e9, // network_fee
        "uint14", 0, // factor
    ];
}

funcer({}, {
    'path': './func/',
    'fc': [
        'stdlib.fc',
        'text_utils.fc',
        'message_utils.fc',
        'bridge-config.fc',
        'bridge_code.fc',
    ],
    "configParams": {
        71: [
            'cell', [
                "uint256", "0x13dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8", // bridge_address
                "uint256", "0x23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8", // oracles_address
                "uint256->any", { // oracles
                    "0x33dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8": []
                }
            ]
        ]
    },
    'data': makeStorage(0),
    'in_msgs': [
        { // binary entry point
            "sender": "-1:43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 10*1e9,
            "body": [
                "uint32", 3, // op
                "uint64", 123, // query_id
                "uint160", 0, // zero destination_address
            ],
            "exit_code": 307
        },
        { // text entry point
            "sender": "-1:43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 10*1e9,
            "body": [
                "comment", "swapTo#0x0000000000000000000000000000000000000000"
            ],
            "exit_code": 307
        },
        { // a non-zero destination still passes
            "sender": "-1:43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 10*1e9,
            "body": [
                "uint32", 3, // op
                "uint64", 123, // query_id
                "uint160", "0xbba57dF6B628803C445d27e8904BE49C69A95ff3", // destination_address
            ],
            "new_data": makeStorage(5*1e9),
            "out_msgs": [
                {
                    "type": "External",
                    "to": "0x00000000000000000000000000000000000000000000000000000000c0470ccf",
                    "sendMode": 0,
                    "body": [
                        "uint160", "0xbba57dF6B628803C445d27e8904BE49C69A95ff3", // destination_address
                        "uint64", 5*1e9 // amount - fees
                    ],
                },
                {
                    "type": "Internal",
                    "to": "-1:43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8", // sender
                    "amount": 100000000,
                    "sendMode": 3,
                    "body": [
                        "uint32", 0x10000 + 3, // swap response
                        "uint64", 123, // query_id
                        "uint256", 0 // body
                    ],
                }
            ]
        },
    ]
});

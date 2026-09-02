const {funcer} = require("./funcer");

// The bridge pays a fixed 0.1 receipt from its own balance on every accepted
// swap, so the network fee has a floor of 0.11 (receipt plus headroom). A fee
// vote below the floor must be rejected, or every swap would drain the bridge.
const makeStorage = (flatReward, networkFee, factor) => {
    return [
        "uint8", 0, // state_flags
        "coins", 0, // total_locked
        "Address", "0:e53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a", // collector_address
        "coins", flatReward,
        "coins", networkFee,
        "uint14", factor,
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
    'data': makeStorage(2*1e9, 3*1e9, 0),
    'in_msgs': [
        { // an all-zero fee schedule makes every swap lossy and must not pass
            "sender": "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 0.1*1e9,
            "body": [
                "uint32", 4, // execute_voting
                "uint8", 6, // change fees
                "coins", 0, // flat_reward
                "coins", 0, // network_fee
                "uint14", 0, // factor
            ],
            "exit_code": 392
        },
        { // one unit below the floor is still below the floor
            "sender": "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 0.1*1e9,
            "body": [
                "uint32", 4, // execute_voting
                "uint8", 6, // change fees
                "coins", 0, // flat_reward
                "coins", 109999999, // network_fee, floor - 1
                "uint14", 0, // factor
            ],
            "exit_code": 392
        },
        { // the exact floor is a valid configuration
            "sender": "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "amount": 0.1*1e9,
            "body": [
                "uint32", 4, // execute_voting
                "uint8", 6, // change fees
                "coins", 0, // flat_reward
                "coins", 110000000, // network_fee, receipt cost + headroom
                "uint14", 0, // factor
            ],
            "new_data": makeStorage(0, 110000000, 0),
            "out_msgs": []
        },
    ]
});

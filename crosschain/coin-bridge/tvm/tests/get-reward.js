const {funcer} = require("./funcer");

const makeStorage = (totalLocked) => {
    return [
        "uint8", 0, // state_flags
        "coins", totalLocked, // total_locked
        "uint3", 4, // collector_address, prefix
        "int8", 0, // collector_address, wc
        "uint256", "0xe53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a", // collector_address
        "coins", 2*1e9, // flat_reward
        "coins", 3*1e9, // network_fee
        "uint14", 0, // factor
    ];
}

const MULTISIG = "23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const REWARD_BASECHAIN = "0:73dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const REWARD_MASTERCHAIN = "-1:83dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";

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
    'data': makeStorage(10 * 1e9),
    'in_msgs': [
        // The vote names the reward address; the sweep goes there and never
        // to the multisig that relayed the vote.
        ...[REWARD_BASECHAIN, REWARD_MASTERCHAIN].map((reward) => ({
            "sender": `-1:${MULTISIG}`,
            "amount": 0.1*1e9,
            "contract_balance": 11*1e9,
            "body": [
                "uint32", 4, // execute_voting
                "uint8", 5, // get reward
                "Address", reward,
            ],
            "new_data":makeStorage(10 * 1e9),
            "out_msgs": [
                {
                    "type":"Reserve",
                    "amount":`${(10) * 1e9 + 100e9}`,
                    "mode":2
                },
                {
                    "type": "Internal",
                    "to": reward,
                    "amount": 0,
                    "sendMode": 128,
                    "body": [
                    ],
                },
            ]
        })),
        // A reward address must be a standard address on the basechain or
        // the masterchain, and not the zero account (exit code 308).
        ...[
            "0:0000000000000000000000000000000000000000000000000000000000000000",
            "-1:0000000000000000000000000000000000000000000000000000000000000000",
            "5:e53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a",
        ].map((reward) => ({
            "sender": `-1:${MULTISIG}`,
            "amount": 0.1*1e9,
            "contract_balance": 11*1e9,
            "body": [
                "uint32", 4, // execute_voting
                "uint8", 5, // get reward
                "Address", reward,
            ],
            "exit_code": 308,
        })),
    ]
});

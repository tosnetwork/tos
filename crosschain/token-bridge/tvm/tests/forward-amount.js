// A swap whose forward amount is non-zero must be rejected by the bridge
// itself, not merely discouraged in documentation. A non-zero forward amount
// is the only action the receiving wallet can fail on, and the mint spans
// three transactions with no atomicity between them.
const {funcer} = require("./funcer");

const ORACLES_ADDRESS = "0x23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const BRIDGE_ADDRESS = "0x13dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const MINT_FEE = 0.1 * 1e9;

// ConfigParam 79: prefix, bridge, oracles multisig, oracle map, state flags,
// and the fee schedule in a reference cell.
const bridgeConfig = {
  79: [
    "cell", [
      "uint8", 0,
      "uint256", BRIDGE_ADDRESS,
      "uint256", ORACLES_ADDRESS,
      "uint256->any", {
        "0x33dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8": [],
      },
      "uint8", 0,
      "cell", [
        "coins", 0.2 * 1e9,
        "coins", MINT_FEE,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
      ],
    ],
  ],
};

// collector_address, jetton_minter_code, jetton_wallet_code
const bridgeStorage = [
  "Address", "0:e53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a",
  "cell", ["uint8", 1],
  "cell", ["uint8", 2],
];

const swapBody = (forwardAmount) => [
  "uint32", 4,            // op::execute_voting
  "uint64", 100500,       // query_id
  "uint8", 0,             // op::execute_voting::swap
  "uint256", "0x43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8", // ext chain tx
  "int16", 0,             // internal index
  "uint256", "0x53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8", // destination
  "coins", 1000,          // mint amount
  "cell", [
    "uint32", 1,          // EVM chain id, must equal MY_CHAIN_ID
    "uint160", "0x76A797A59Ba2C17726896976B7B3747BfD1d220f",
    "uint8", 6,
  ],
  "coins", forwardAmount,
];

funcer({}, {
  path: "./func/",
  fc: ["jetton-bridge.fc"],
  configParams: bridgeConfig,
  data: bridgeStorage,
  in_msgs: [
    {
      // error::forward_amount_not_zero
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(1),
      exit_code: 398,
    },
    {
      // The same swap with a zero forward amount must proceed, so the check
      // is proven to be targeted rather than rejecting every swap.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(0),
    },
  ],
});

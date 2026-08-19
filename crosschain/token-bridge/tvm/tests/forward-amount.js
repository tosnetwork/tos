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
  // paid_swaps: the set of swaps whose mint fee is paid and unspent.
  "uint1", 0,
];


// The swap key the contract derives, computed the same way here so a payment
// can name the swap a vote is for. A TON cell's hash is sha256 over its two
// descriptor bytes and its data; this cell is 272 bits with no references.
const crypto = require("crypto");
const swapKey = (extChainHash, internalIndex) => {
  const data = Buffer.alloc(34);
  Buffer.from(extChainHash.replace(/^0x/, ""), "hex").copy(data, 0);
  data.writeInt16BE(internalIndex, 32);
  const bits = 272;
  const d1 = 0;                                  // no refs, not exotic, level 0
  const d2 = Math.floor(bits / 8) + Math.ceil(bits / 8);
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from([d1, d2]), data]))
    .digest("hex");
};

// Paying the mint fee, which the swap vote now spends.
const payBody = (extChainHash, internalIndex) => [
  "uint32", 8, // op::pay_swap
  "uint64", 100499,
  "uint256", "0x" + swapKey(extChainHash, internalIndex),
];

const EXT_CHAIN_HASH = "0x43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";

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
      // The mint fee, paid in its own transaction by whoever wants the swap.
      // Without it the vote below is refused: nothing on chain connected the
      // two, and the multisig would have minted out of its own balance.
      sender: "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: payBody(EXT_CHAIN_HASH, 0),
      out_msgs: [
        {
          // LOG_SWAP_PAID, so the payment is observable off chain as well as
          // recorded on it.
          type: "External",
          to: "0x" + "c0550ccf".padStart(64, "0"),
          sendMode: 0,
          body: ["uint256", "0x" + swapKey(EXT_CHAIN_HASH, 0)],
        },
      ],
    },
    {
      // error::forward_amount_not_zero
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(1),
      exit_code: 398,
    },
    {
      // The same swap with a zero forward amount must proceed, and it must
      // actually mint: asserting only a zero exit code would pass even if the
      // contract returned early and emitted nothing at all.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(0),
      out_msgs: [
        {
          // The mint: it deploys the deterministic minter, so it must carry a
          // StateInit, and its body must name the destination and amounts the
          // vote asked for, and its destination must be the address that
          // StateInit deploys to.
          type: "Internal",
          amount: MINT_FEE,
          sendMode: 0,
          stateInit: true,
          stateInitMatchesDestination: true,
          body: [
            "uint32", 21,        // op::mint
            "uint64", 100500,
            "Address", "0:53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "coins", 1000,       // minted amount
            "coins", 0,          // forward amount, required to be zero
          ],
        },
        {
          // The receipt back to the oracle multisig.
          type: "Internal",
          to: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
          amount: 0,
          sendMode: 64,
          stateInit: false,
          body: [
            "uint32", 0x10009,
            "uint64", 100500,
            "uint256", 0,      // send_receipt_message writes this when body >= 0
          ],
        },
      ],
    },
  ],
});

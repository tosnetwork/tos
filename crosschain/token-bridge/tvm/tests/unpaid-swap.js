// A mint whose fee nobody paid must be refused by the bridge.
//
// pay_swap takes the fee in one transaction and the vote arrives in another,
// with nothing on chain connecting them. Before this check the bridge minted
// on the vote alone, so an oracle set that did not look would have the multisig
// pay for every mint out of its own balance — repeatedly, and without anything
// failing.
//
// The check cannot live in an oracle. Two operators disagreeing about whether a
// payment counts produce no rejection, only a quorum that never forms; and an
// oracle that checks is enforcing a rule the contract does not, which is
// exactly the arrangement that makes operators diverge. The contract derives
// the swap's identity from the vote it already holds, so a payer cannot make a
// payment point at a different swap.
const { funcer } = require("./funcer");

const ORACLES_ADDRESS = "0x23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const BRIDGE_ADDRESS = "0x13dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const MINT_FEE = 0.1 * 1e9;
const EXT_CHAIN_HASH = "0x43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";

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

const bridgeStorage = [
  "Address", "0:e53bddefb065373732ec25d5f9af0b3f7a3be358ea87ec285b4b6330a67d8c6a",
  "cell", ["uint8", 1],
  "cell", ["uint8", 2],
  // paid_swaps: nothing has been paid for.
  "uint1", 0,
];

// The swap key the contract derives, computed the same way here. A TON cell's
// hash is sha256 over its two descriptor bytes and its data; this cell is 272
// bits with no references.
const crypto = require("crypto");
const swapKey = (extChainHash, internalIndex) => {
  const data = Buffer.alloc(34);
  Buffer.from(extChainHash.replace(/^0x/, ""), "hex").copy(data, 0);
  data.writeInt16BE(internalIndex, 32);
  const bits = 272;
  const d1 = 0;
  const d2 = Math.floor(bits / 8) + Math.ceil(bits / 8);
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([Buffer.from([d1, d2]), data]))
    .digest("hex");
};

const payBody = (swapId) => [
  "uint32", 8, // op::pay_swap
  "uint64", 100499,
  "uint256", swapId,
];

const swapBody = (extChainHash, internalIndex) => [
  "uint32", 4,            // op::execute_voting
  "uint64", 100500,
  "uint8", 0,             // op::execute_voting::swap
  "uint256", extChainHash,
  "int16", internalIndex,
  "uint256", "0x53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
  "coins", 1000,
  "cell", [
    "uint32", 1,          // EVM chain id
    "uint160", "0x76A797A59Ba2C17726896976B7B3747BfD1d220f",
    "uint8", 6,
  ],
  "coins", 0,
];

funcer({}, {
  path: "./func/",
  fc: ["jetton-bridge.fc"],
  configParams: bridgeConfig,
  data: bridgeStorage,
  in_msgs: [
    {
      // error::swap_not_paid. Nobody has paid, and the bridge refuses rather
      // than minting on the vote alone.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(EXT_CHAIN_HASH, 0),
      exit_code: 396,
    },
    {
      // A payment for a different swap does not pay for this one. The contract
      // derives the key from the vote, so a payer cannot aim a payment at a
      // swap of their choosing.
      sender: "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: payBody("0x" + swapKey(EXT_CHAIN_HASH, 7)),
      out_msgs: [
        {
          type: "External",
          to: "0x" + "c0550ccf".padStart(64, "0"),
          sendMode: 0,
          body: ["uint256", "0x" + swapKey(EXT_CHAIN_HASH, 7)],
        },
      ],
    },
    {
      // Still refused: the payment above named index 7, and this vote is for
      // index 0.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(EXT_CHAIN_HASH, 0),
      exit_code: 396,
    },
    {
      // The right payment.
      sender: "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: payBody("0x" + swapKey(EXT_CHAIN_HASH, 0)),
      out_msgs: [
        {
          type: "External",
          to: "0x" + "c0550ccf".padStart(64, "0"),
          sendMode: 0,
          body: ["uint256", "0x" + swapKey(EXT_CHAIN_HASH, 0)],
        },
      ],
    },
    {
      // And now the vote goes through, minting and acknowledging.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(EXT_CHAIN_HASH, 0),
    },
    {
      // The fee paid for one mint. Voting again finds the key spent, which is
      // what stops one payment from covering a second mint.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(EXT_CHAIN_HASH, 0),
      exit_code: 396,
    },
  ],
});

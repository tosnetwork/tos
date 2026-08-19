// Each configuration slot compiles its own MY_CHAIN_ID, and the bridge must
// mint only for the counterparty that slot names. This is the gate that keeps
// a swap signed for one chain from being executed against another, and it is
// the only place the Tron chain id — which is not a registered EVM chain id —
// is exercised.
const {funcer} = require("./funcer");

const ORACLES_ADDRESS = "0x23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const BRIDGE_ADDRESS = "0x13dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const MINT_FEE = 0.1 * 1e9;

// A chain id that no slot in this repository uses.
const FOREIGN_CHAIN_ID = 424242;

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
  // paid_swaps: the set of swaps whose mint fee is paid and unspent.
  "uint1", 0,
];

// The destination is a 20-byte counterparty address. Tron addresses are also
// 20 bytes inside its virtual machine, so this field carries them unchanged.
const DESTINATION_TOKEN = "0x76A797A59Ba2C17726896976B7B3747BfD1d220f";


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

const swapBody = (queryId, tokenData) => [
  "uint32", 4,            // op::execute_voting
  "uint64", queryId,
  "uint8", 0,             // op::execute_voting::swap
  "uint256", "0x43dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
  "int16", 0,
  "uint256", "0x53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
  "coins", 1000,
  "cell", tokenData,
  "coins", 0,
];

const nativeToken = [
  "uint32", 1,          // EVM chain id
  "uint160", DESTINATION_TOKEN,
  "uint8", 6,
];

const foreignToken = [
  "uint32", FOREIGN_CHAIN_ID,
  "uint160", DESTINATION_TOKEN,
  "uint8", 6,
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
      // error::wrong_external_chain_id: a swap naming another counterparty
      // chain must not mint here, whatever slot this tree was built for.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(100501, foreignToken),
      exit_code: 410,
    },
    {
      // The counterparty this slot does name is accepted, which is what proves
      // the compiled MY_CHAIN_ID is the value the parameter file declares. The
      // actions are asserted too: a zero exit code alone would also be
      // produced by a contract that accepted the swap and then did nothing.
      sender: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
      amount: MINT_FEE,
      body: swapBody(100502, nativeToken),
      out_msgs: [
        {
          type: "Internal",
          amount: MINT_FEE,
          sendMode: 0,
          stateInit: true,
          stateInitMatchesDestination: true,
          body: [
            "uint32", 21,        // op::mint
            "uint64", 100502,
            "Address", "0:53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
            "coins", 1000,
            "coins", 0,
          ],
        },
        {
          type: "Internal",
          to: "-1:23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8",
          amount: 0,
          sendMode: 64,
          stateInit: false,
          body: [
            "uint32", 0x10009,
            "uint64", 100502,
            "uint256", 0,
          ],
        },
      ],
    },
  ],
});

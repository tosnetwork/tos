// A burn names where to release on the counterparty chain. The zero address is
// not a destination: the ERC-20 transfer that would release the tokens there
// reverts, and by then the jettons on this side are already destroyed.
//
// This is the one check that has to live in the contract rather than in an
// oracle. An oracle applying it would be applying it *after* the burn, when the
// user's tokens are already gone and refusing only strands them — and a rule
// one operator applies and another does not produces a quorum that never forms
// rather than a rejection. Refusing at the burn entry is the last point at
// which the user still has their tokens.
const {funcer} = require("./funcer");

const OWNER = "0:53dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const MINTER = "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const ORACLES_ADDRESS = "0x23dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const BRIDGE_ADDRESS = "0x13dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const BURN_FEE = 0.2 * 1e9;

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
        "coins", BURN_FEE,
        "coins", 0.1 * 1e9,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
        "coins", 0.01 * 1e9,
      ],
    ],
  ],
};

// A wallet holding a balance, owned by OWNER, issued by MINTER.
const walletStorage = [
  "coins", 1000,
  "Address", OWNER,
  "Address", MINTER,
  "cell", [],
];

// op::burn, with the counterparty destination in the custom payload.
const burnBody = (destination) => [
  "uint32", 0x595f07bc,
  "uint64", 100500,
  "coins", 500,
  "Address", OWNER,
  // load_dict reads a Maybe(^Cell): the bit, then the reference.
  "uint1", 1,
  "cell", [
    "uint160", destination,
  ],
];

funcer({}, {
  path: "./func/",
  fc: ["jetton-wallet.fc"],
  configParams: bridgeConfig,
  data: walletStorage,
  in_msgs: [
    {
      // error::zero_destination. Refused before the balance is reduced, so
      // the user keeps their jettons.
      sender: OWNER,
      amount: BURN_FEE,
      body: burnBody(0),
      exit_code: 397,
    },
    {
      // The same burn to a real destination still works, so the check has not
      // closed the path it was meant to narrow.
      sender: OWNER,
      amount: BURN_FEE,
      body: burnBody("0x1111111111111111111111111111111111111111"),
      out_msgs: [
        {
          // The burn notification to the minter, carrying the destination the
          // wallet accepted. Asserting the body is what makes this positive
          // case worth having: without it the test would pass on a contract
          // that silently dropped the burn.
          type: "Internal",
          to: MINTER,
          amount: 0,
          sendMode: 64,
          stateInit: false,
          body: [
            "uint32", 0x7bdd97de,   // op::burn_notification
            "uint64", 100500,
            "coins", 500,
            "Address", OWNER,       // who burned
            "Address", OWNER,       // response address
            "uint160", "0x1111111111111111111111111111111111111111",
          ],
        },
      ],
    },
  ],
});

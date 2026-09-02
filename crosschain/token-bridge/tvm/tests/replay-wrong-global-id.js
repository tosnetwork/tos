// The multisig's oracle keys may serve more than one network, and two
// networks bootstrapped from the same StateInit share the multisig address
// and wallet id. Each signed query therefore carries the id of the network
// it was signed for, and this test proves the contract enforces it:
//
//   1. a correctly signed query naming a different network is refused with
//      exit code 44 before anything is dispatched or recorded;
//   2. the same query naming this network is accepted, dispatched, and
//      marked processed;
//   3. repeating the accepted query is refused as already processed (35).
const {funcer, CellWriter} = require("./funcer");
const crypto = require("crypto");

// This network's id, staged in the config below. Negative on purpose: real
// network ids are often negative, so the signed 32-bit path is exercised end
// to end (the JS writer, the harness encoding, and the contract's read).
const GLOBAL_ID = -239;
const WALLET_ID = 0x45544831;
const QUERY_ID = (1628090356n + 3600n) << 32n; // the harness clock, one hour out
const DEST = "0x55dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const SENDER = "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";

// A deterministic oracle key: the test must not depend on a random seed.
// The DER prefix is the standard PKCS8 wrapper for a raw Ed25519 seed.
const SEED = Buffer.alloc(32, 7);
const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), SEED]),
    format: "der",
    type: "pkcs8",
});
const spki = crypto.createPublicKey(privateKey).export({format: "der", type: "spki"});
const publicKey = spki.subarray(spki.length - 32);

// The message the query asks the multisig to dispatch: value 0 to DEST.
const innerMsg = new CellWriter()
    .u(0x18, 6)              // internal, ihr disabled, bounceable, source none
    .u(4, 3)                 // std address, no anycast
    .i(0, 8)                 // workchain
    .u(BigInt(DEST), 256)
    .u(0, 4)                 // value 0
    .u(0, 107);              // fees, lt, created_at, no state init, body in place

const innerMsgJson = [
    "uint6", 0x18,
    "uint3", 4,
    "int8", 0,
    "uint256", DEST,
    "coins", 0,
    "uint107", 0,
];

// What the root oracle signs: everything after its own signature.
const signedPart = (globalId) => new CellWriter()
    .u(0, 8)                 // root signer index
    .u(0, 1)                 // no further signatures
    .u(WALLET_ID, 32)
    .i(globalId, 32)         // the network the query is meant for
    .u(QUERY_ID, 64)
    .u(0, 8)                 // send mode of the inner message
    .ref(innerMsg);

const queryBody = (globalId) => {
    const signature = crypto.sign(null, signedPart(globalId).hash(), privateKey);
    return [
        // The 512-bit signature, in two halves: integers are at most 257 bits.
        "uint256", "0x" + signature.subarray(0, 32).toString("hex"),
        "uint256", "0x" + signature.subarray(32).toString("hex"),
        "uint8", 0,          // root signer index
        "uint1", 0,          // no further signatures
        "uint32", WALLET_ID,
        "int32", globalId,
        "uint64", QUERY_ID.toString(),
        "uint8", 0,          // send mode
        "cell", innerMsgJson,
    ];
};

const ownerInfos = {
    "0": ["uint256", "0x" + publicKey.toString("hex"), "uint8", 0],
};

funcer({}, {
    path: "./func/",
    fc: ["multisig.fc"],
    configParams: {
        19: ["cell", ["int32", GLOBAL_ID]],
    },
    data: [
        "uint32", WALLET_ID,
        "uint8", 1,          // n
        "uint8", 1,          // k
        "uint64", 0,         // last_cleaned
        "uint8->any", ownerInfos,
        "uint1", 0,          // no pending queries
        "uint32", 0,         // lock_until
    ],
    in_msgs: [
        {
            // Replayed from a network whose id differs: the signature is
            // valid over the body it carries, but the body names the wrong
            // network, so nothing may execute.
            sender: SENDER,
            amount: 0.1 * 1e9,
            body: queryBody(GLOBAL_ID + 1),
            exit_code: 44,
        },
        {
            // The same query signed for this network is accepted: the inner
            // message goes out and the query is recorded as processed.
            sender: SENDER,
            amount: 0.1 * 1e9,
            body: queryBody(GLOBAL_ID),
            new_data: [
                "uint32", WALLET_ID,
                "uint8", 1,
                "uint8", 1,
                "uint64", 1, // first accepted query marks the wallet started
                "uint8->any", ownerInfos,
                "uint64->any", {[QUERY_ID.toString()]: ["uint1", 0]},
                "uint32", 0,
            ],
            out_msgs: [
                {
                    type: "Internal",
                    to: `0:${DEST.slice(2)}`,
                    amount: 0,
                    sendMode: 0,
                    stateInit: false,
                    body: [],
                },
                {
                    // The fee-return message to whoever relayed the query.
                    type: "Internal",
                    to: SENDER,
                    amount: 0,
                    sendMode: 64 + 2,
                    stateInit: false,
                    body: [],
                },
            ],
        },
        {
            // Same-network replay of the executed query: already processed.
            sender: SENDER,
            amount: 0.1 * 1e9,
            body: queryBody(GLOBAL_ID),
            exit_code: 35,
        },
    ],
});

// An owner key anyone can sign for must not authorize anything. Two such keys
// are the identity and the order-2 point spelled with the sign bit set: x = 0,
// so the bit names no other point, the y range check does not catch them, and
// the verifier accepts a signature R = identity, S = 0 that needs no secret.
// This multisig holds both next to two real oracle keys (a hand-built
// StateInit, since create_init_state refuses them), and the test proves:
//
//   1. each weak owner's forged signature is refused as root (exit 45);
//   2. each weak owner's forged co-signature is refused before it counts
//      toward k, even next to a valid root (exit 45, nothing recorded);
//   3. two real oracles still execute a query (the control).
const {funcer, CellWriter} = require("./funcer");
const crypto = require("crypto");

const GLOBAL_ID = -239;
const WALLET_ID = 0x45544831;
const NOW = 1628090356n; // the harness clock
const DEST = "0x55dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const SENDER = "0:63dfd552e63729b472fcbcc8c45ebcc6691702558b68ec7527e1ba403a0f31a8";
const ERR_WEAK_OWNER = 45;

const oracle = (fill) => {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, fill)]),
        format: "der",
        type: "pkcs8",
    });
    const spki = crypto.createPublicKey(privateKey).export({format: "der", type: "spki"});
    return {privateKey, publicKey: spki.subarray(spki.length - 32)};
};
const strong = [oracle(7), oracle(8)];
const IDENTITY_ALIAS = Buffer.from("0100000000000000000000000000000000000000000000000000000000000080", "hex");
const ORDER2_ALIAS = Buffer.from("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "hex");
const owners = [strong[0].publicKey, strong[1].publicKey, IDENTITY_ALIAS, ORDER2_ALIAS];

// R = identity, S = 0 verifies under A exactly when -[k]A is the identity,
// k = SHA-512(R || A || message) mod L: always for the identity, and for the
// order-2 point whenever k is even. Returns null when this message admits none.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const R_IDENTITY = Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex");
const forge = (publicKey, message) => {
    const digest = crypto.createHash("sha512").update(Buffer.concat([R_IDENTITY, publicKey, message])).digest();
    let k = 0n;
    for (let i = digest.length - 1; i >= 0; i--) k = (k << 8n) | BigInt(digest[i]);
    k %= L;
    const forgeable = publicKey.equals(IDENTITY_ALIAS) || (publicKey.equals(ORDER2_ALIAS) && k % 2n === 0n);
    return forgeable ? Buffer.concat([R_IDENTITY, Buffer.alloc(32)]) : null;
};

const innerMsg = new CellWriter()
    .u(0x18, 6).u(4, 3).i(0, 8).u(BigInt(DEST), 256).u(0, 4).u(0, 107);
const innerMsgJson = ["uint6", 0x18, "uint3", 4, "int8", 0, "uint256", DEST, "coins", 0, "uint107", 0];

// What every co-signer signs: the query after the signatures.
const coSigned = (queryId) => new CellWriter()
    .u(WALLET_ID, 32).i(GLOBAL_ID, 32).u(queryId, 64).u(0, 8).ref(innerMsg);

const coSignatureCell = (index, signature) => new CellWriter()
    .u(BigInt("0x" + signature.subarray(0, 32).toString("hex")), 256)
    .u(BigInt("0x" + signature.subarray(32).toString("hex")), 256)
    .u(index, 8).u(0, 1);

// What the root signs: its index, the co-signatures, then the query.
const rootSigned = (root, co, queryId) => {
    const w = new CellWriter().u(root, 8);
    if (co) w.u(1, 1).ref(coSignatureCell(co.index, co.signature)); else w.u(0, 1);
    return w.u(WALLET_ID, 32).i(GLOBAL_ID, 32).u(queryId, 64).u(0, 8).ref(innerMsg);
};

const hex = (buffer) => "0x" + buffer.toString("hex");
const body = (rootSignature, root, co, queryId) => [
    "uint256", hex(rootSignature.subarray(0, 32)),
    "uint256", hex(rootSignature.subarray(32)),
    "uint8", root,
    ...(co ? ["uint1", 1, "cell", [
        "uint256", hex(co.signature.subarray(0, 32)),
        "uint256", hex(co.signature.subarray(32)),
        "uint8", co.index,
        "uint1", 0,
    ]] : ["uint1", 0]),
    "uint32", WALLET_ID,
    "int32", GLOBAL_ID,
    "uint64", queryId.toString(),
    "uint8", 0,
    "cell", innerMsgJson,
];

let nextQuery = ((NOW + 7200n) << 32n) + 1n;
const queryIds = function* () { while (true) yield nextQuery++; };

// A query whose root (owner `root`) signs with a forged signature.
const forgedRoot = (root) => {
    for (const queryId of queryIds()) {
        const signature = forge(owners[root], rootSigned(root, null, queryId).hash());
        if (signature) return body(signature, root, null, queryId);
    }
};

// A query signed by real oracle 0 as root, co-signed by owner `index`.
const withCoSigner = (index, coSign) => {
    for (const queryId of queryIds()) {
        const coSignature = coSign(coSigned(queryId).hash());
        if (!coSignature) continue;
        const co = {index, signature: coSignature};
        const rootSignature = crypto.sign(null, rootSigned(0, co, queryId).hash(), strong[0].privateKey);
        return body(rootSignature, 0, co, queryId);
    }
};

const ownerInfos = {};
owners.forEach((key, index) => { ownerInfos[String(index)] = ["uint256", hex(key), "uint8", 0]; });

const refused = (queryBody) => ({sender: SENDER, amount: 0.1 * 1e9, body: queryBody, exit_code: ERR_WEAK_OWNER});

funcer({}, {
    path: "./func/",
    fc: ["multisig.fc"],
    configParams: {
        19: ["cell", ["int32", GLOBAL_ID]],
    },
    data: [
        "uint32", WALLET_ID,
        "uint8", owners.length, // n
        "uint8", 2,             // k
        "uint64", 0,            // last_cleaned
        "uint8->any", ownerInfos,
        "uint1", 0,             // no pending queries
        "uint32", 0,            // lock_until
    ],
    in_msgs: [
        refused(forgedRoot(2)),
        refused(forgedRoot(3)),
        refused(withCoSigner(2, (message) => forge(IDENTITY_ALIAS, message))),
        refused(withCoSigner(3, (message) => forge(ORDER2_ALIAS, message))),
        {
            // Two real oracles reach k = 2: the query executes.
            sender: SENDER,
            amount: 0.1 * 1e9,
            body: withCoSigner(1, (message) => crypto.sign(null, message, strong[1].privateKey)),
            out_msgs: [
                {type: "Internal", to: `0:${DEST.slice(2)}`, amount: 0, sendMode: 0, stateInit: false, body: []},
                {type: "Internal", to: SENDER, amount: 0, sendMode: 64 + 2, stateInit: false, body: []},
            ],
        },
    ],
});

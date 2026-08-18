// These tests execute the contracts inside Tron's virtual machine, which the
// Hardhat suite cannot do: it runs an EVM. They exist to settle the two
// assumptions the ConfigParam 83 slot rests on — what Tron's CHAINID actually
// returns to a contract, and whether ecrecover behaves as the signature
// checker requires.
const {ethers} = require("ethers");

const Bridge = artifacts.require("Bridge");

// Locally funded TRE keys. These are published in the image's startup banner
// and hold nothing outside this throwaway node.
const ORACLE_KEYS = [
  "c2579f5dadf92636f5aa07b8e7a410ec260882ed4f5f8f2ac76d43a15a345881",
  "86beca53c4a8ddaf3d5ccbf0b0d6c75508081f209258b197529768c6e469bec4",
  "233b97ebfc80d2e90396c18d998cf6f4eec0c8890e3b277624931358c2ee57cb",
];

// Tron derives an account's 20 bytes exactly as Ethereum does and only adds a
// 0x41 network byte outside the virtual machine, so a key's EVM address is the
// value a contract compares against.
const oracleWallets = ORACLE_KEYS.map((k) => new ethers.Wallet(k));
const oracleAddresses = oracleWallets.map((w) => w.address);

const SWAP = {
  receiver: oracleWallets[0].address,
  token: "0x76A797A59Ba2C17726896976B7B3747BfD1d220f",
  amount: "1000000",
  tx: {
    address_hash: "0x" + "11".repeat(32),
    tx_hash: "0x" + "22".repeat(32),
    lt: "19459352000003",
  },
};

// tronWeb encodes tuples positionally, so structs cross the boundary as
// arrays in declaration order.
let SWAP_TUPLE;

const localDigest = (bridgeHex, chainId) =>
  ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      ["uint256", "address", "uint256", "address", "address", "uint256", "bytes32", "bytes32", "uint64"],
      [0xda7a, bridgeHex, chainId, SWAP.receiver, SWAP.token, SWAP.amount,
        SWAP.tx.address_hash, SWAP.tx.tx_hash, SWAP.tx.lt]
    )
  );

// A Tron address is the 0x41 network byte followed by the same 20 bytes an
// EVM address holds. tronWeb speaks the base58 form; the virtual machine and
// this contract's ABI see the 20 bytes.
const toEvmAddress = (tronAddress) =>
  ethers.utils.getAddress("0x" + tronWeb.address.toHex(tronAddress).slice(2));

const toTronAddress = (evmAddress) =>
  tronWeb.address.fromHex("41" + evmAddress.slice(2).toLowerCase());

contract("Tron VM behaviour", () => {
  let bridge;
  let bridgeEvm;

  before(async () => {
    bridge = await Bridge.new(oracleAddresses.map(toTronAddress), []);
    bridgeEvm = toEvmAddress(bridge.address);
    SWAP_TUPLE = [
      toTronAddress(SWAP.receiver),
      toTronAddress(SWAP.token),
      SWAP.amount,
      [SWAP.tx.address_hash, SWAP.tx.tx_hash, SWAP.tx.lt],
    ];
  });

  it("reports a CHAINID a contract can bind a digest to", async () => {
    const onChain = await bridge.getSwapDataId(SWAP_TUPLE);
    const observed = typeof onChain === "string" ? onChain : onChain.toString();

    // Tron's CHAINID is documented as the last four bytes of the genesis
    // block id rather than a registered chain id. Derive that value from the
    // node and require it to be what the contract actually saw, which is the
    // rule ConfigParam 83's chain id is chosen by.
    const genesis = await tronWeb.trx.getBlock(0);
    const derived = parseInt(genesis.blockID.slice(-8), 16);
    const expected = localDigest(bridgeEvm, derived);

    console.log(`    genesis block id:  ${genesis.blockID}`);
    console.log(`    derived chain id:  ${derived}`);
    console.log(`    on-chain digest:   ${observed}`);

    assert.strictEqual(
      observed.toLowerCase(),
      expected.toLowerCase(),
      `CHAINID did not equal the last four bytes of the genesis block id (${derived}); ` +
      `whatever it returns is what ConfigParam 83's chain id must be set to`
    );
  });

  it("verifies an oracle quorum's signatures through a state-changing vote", async () => {
    // This is the path that matters: _generalVote runs checkSignature for
    // every signature, so a successful vote proves ecrecover behaves on Tron
    // exactly as the checker requires — canonical v, low s, and a recovered
    // address equal to the oracle's.
    const digest = await bridge.getNewLockStatusId(true, 1);
    const raw = typeof digest === "string" ? digest : digest.toString();

    const signed = await Promise.all(
      oracleWallets.map(async (wallet) => ({
        signer: wallet.address,
        signature: await wallet.signMessage(ethers.utils.arrayify(raw)),
      }))
    );
    // The contract requires strictly ascending signers.
    signed.sort((a, b) => (BigInt(a.signer) < BigInt(b.signer) ? -1 : 1));

    // Three oracles means a ceiling two-thirds quorum of two.
    const quorum = signed.slice(0, 2).map((s) => [toTronAddress(s.signer), s.signature]);

    assert.strictEqual(await bridge.allowLock(), false, "locking must start disabled");
    await bridge.voteForSwitchLock(true, 1, quorum);
    assert.strictEqual(await bridge.allowLock(), true, "the quorum's vote must take effect");
  });

  // A rejected state-changing call does not throw here: TronBox reports the
  // transaction as sent even when the virtual machine reverts it. Negative
  // cases must therefore assert on state, never on a thrown error — asserting
  // on a throw would pass whether or not the contract rejected anything.
  const voteAndReadLock = async (status, nonce, wallets) => {
    const digest = await bridge.getNewLockStatusId(status, nonce);
    const raw = typeof digest === "string" ? digest : digest.toString();
    const signed = await Promise.all(
      wallets.map(async (wallet) => ({
        signer: wallet.address,
        signature: await wallet.signMessage(ethers.utils.arrayify(raw)),
      }))
    );
    signed.sort((a, b) => (BigInt(a.signer) < BigInt(b.signer) ? -1 : 1));
    try {
      await bridge.voteForSwitchLock(
        status, nonce, signed.map((s) => [toTronAddress(s.signer), s.signature]));
    } catch (err) {
      // Either outcome is fine; the state assertion is what decides.
    }
    return bridge.allowLock();
  };

  it("does not count a non-oracle signature toward the quorum", async () => {
    const outsider = new ethers.Wallet("4".repeat(64));
    assert.strictEqual(await bridge.allowLock(), true, "precondition: locking enabled");
    const after = await voteAndReadLock(false, 2, [oracleWallets[0], outsider]);
    assert.strictEqual(after, true, "an outsider must not help disable locking");
  });

  it("does not accept a single signature when the quorum is two", async () => {
    assert.strictEqual(await bridge.allowLock(), true, "precondition: locking enabled");
    const after = await voteAndReadLock(false, 3, [oracleWallets[0]]);
    assert.strictEqual(after, true, "one signature must not reach the quorum");
  });

  it("accepts the quorum again once it is genuinely met", async () => {
    const after = await voteAndReadLock(false, 4, oracleWallets.slice(0, 2));
    assert.strictEqual(after, false, "a real quorum must be able to disable locking");
  });
});

#!/usr/bin/env node

const assert = require("assert");
const Web3 = require("web3");
const artifact = require("../build/contracts/Bridge.json");
const vector = require("./vectors/chain-id-domain-separation.json");

let web3A;
let web3B;
let utils;

const LEGACY_TYPES = {
  swap: ["int", "address", "address", "uint256", "int8", "bytes32", "bytes32", "uint64"],
  set: ["int", "address", "int", "address[]"],
  burn: ["int", "address", "bool", "int"],
};

function legacySwapDigest(data, target) {
  return utils.hashData(web3A.eth.abi.encodeParameters(LEGACY_TYPES.swap, [
    0xDA7A,
    target,
    data.receiver,
    data.amount,
    data.tx.address_.workchain,
    data.tx.address_.address_hash,
    data.tx.tx_hash,
    data.tx.lt,
  ]));
}

function legacySetDigest(setHash, set, target) {
  return utils.hashData(web3A.eth.abi.encodeParameters(
    LEGACY_TYPES.set,
    [0x5E7, target, setHash, set],
  ));
}

function legacyBurnDigest(status, nonce, target) {
  return utils.hashData(web3A.eth.abi.encodeParameters(
    LEGACY_TYPES.burn,
    [0xB012, target, status, nonce],
  ));
}

async function deploy(web3, accounts) {
  return new web3.eth.Contract(artifact.abi)
    .deploy({
      data: artifact.bytecode,
      arguments: ["Wrapped TOS Coin", "TOSCOIN", [accounts[0], accounts[5], accounts[6]]],
    })
    .send({from: accounts[0], gas: 6500000});
}

async function expectRevert(label, action) {
  try {
    await action();
  } catch (error) {
    assert.match(
      String(error && error.message ? error.message : error),
      /revert/i,
      `${label}: transaction failed for a reason other than EVM rejection`,
    );
    return;
  }
  assert.fail(`${label}: expected the chain-B vote to revert`);
}

async function signaturesForDigest(digest, accounts) {
  return utils.sortedSignatures(await Promise.all([
    utils.signHash(digest, accounts[0]),
    utils.signHash(digest, accounts[5]),
  ]));
}

async function proveSignatures(bridge, digest, signatures) {
  for (const signature of signatures) {
    await bridge.methods.checkSignature(digest, signature).call();
  }
}

async function main() {
  web3A = new Web3(process.env.CHAIN_A_RPC || "http://127.0.0.1:8546");
  web3B = new Web3(process.env.CHAIN_B_RPC || "http://127.0.0.1:8547");
  // The shared test helpers intentionally require an explicit chain ID. Point
  // their signing transport at chain A; ABI encoding is provider-independent.
  global.web3 = web3A;
  utils = require("./utils/utils.js");

  const [accountsA, accountsB, chainIdA, chainIdB] = await Promise.all([
    web3A.eth.getAccounts(),
    web3B.eth.getAccounts(),
    web3A.eth.getChainId(),
    web3B.eth.getChainId(),
  ]);
  assert.deepStrictEqual(accountsA, accountsB, "both domains must use the same oracle keys");
  assert.notStrictEqual(String(chainIdA), String(chainIdB), "test domains must have distinct chain IDs");

  const [bridgeA, bridgeB] = await Promise.all([
    deploy(web3A, accountsA),
    deploy(web3B, accountsB),
  ]);
  assert.strictEqual(
    bridgeA.options.address.toLowerCase(),
    bridgeB.options.address.toLowerCase(),
    "deployments must collide at the same contract address",
  );

  // Stable vectors are the signer/contract protocol artifact. They use a
  // fixed address and chain ID so implementations in other languages can
  // reproduce the values without running a chain.
  assert.strictEqual(
    utils.hashData(utils.encodeSwapData(vector.swap, vector.verifyingContract, vector.chainId)),
    vector.expected.swapDigest,
  );
  assert.strictEqual(
    utils.hashData(utils.encodeSet(vector.oracleSetHash, vector.oracleSet, vector.verifyingContract, vector.chainId)),
    vector.expected.oracleSetDigest,
  );
  assert.strictEqual(
    utils.hashData(utils.encodeBurnStatus(vector.burnStatus, vector.burnStatusNonce, vector.verifyingContract, vector.chainId)),
    vector.expected.burnStatusDigest,
  );

  const target = bridgeA.options.address;
  const swap = {
    receiver: accountsA[9],
    amount: "1000000000",
    tx: {
      address_: {
        workchain: -1,
        address_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      tx_hash: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      lt: "19459352000003",
    },
  };
  const newSet = [accountsA[0], accountsA[5], accountsA[6]];

  const swapDigestA = utils.hashData(utils.encodeSwapData(swap, target, chainIdA));
  const setDigestA = utils.hashData(utils.encodeSet(100, newSet, target, chainIdA));
  const burnDigestA = utils.hashData(utils.encodeBurnStatus(true, 100, target, chainIdA));

  // This is the contract/signer agreement half of the golden-vector gate.
  assert.strictEqual(await bridgeA.methods.getSwapDataId(swap).call(), swapDigestA);
  assert.strictEqual(await bridgeA.methods.getNewSetId(100, newSet).call(), setDigestA);
  assert.strictEqual(await bridgeA.methods.getNewBurnStatusId(true, 100).call(), burnDigestA);

  const swapSignaturesA = await signaturesForDigest(swapDigestA, accountsA);
  const setSignaturesA = await signaturesForDigest(setDigestA, accountsA);
  const burnSignaturesA = await signaturesForDigest(burnDigestA, accountsA);
  await proveSignatures(bridgeA, swapDigestA, swapSignaturesA);
  await proveSignatures(bridgeA, setDigestA, setSignaturesA);
  await proveSignatures(bridgeA, burnDigestA, burnSignaturesA);

  await expectRevert("swap replay", () => bridgeB.methods
    .voteForMinting(swap, swapSignaturesA).send({from: accountsB[1], gas: 6500000}));
  await expectRevert("oracle-set replay", () => bridgeB.methods
    .voteForNewOracleSet(100, newSet, setSignaturesA).send({from: accountsB[1], gas: 6500000}));
  await expectRevert("burn-status replay", () => bridgeB.methods
    .voteForSwitchBurn(true, 100, burnSignaturesA).send({from: accountsB[1], gas: 6500000}));

  const legacySwap = legacySwapDigest(swap, target);
  const legacySet = legacySetDigest(100, newSet, target);
  const legacyBurn = legacyBurnDigest(true, 100, target);
  const legacySwapSignatures = await signaturesForDigest(legacySwap, accountsA);
  const legacySetSignatures = await signaturesForDigest(legacySet, accountsA);
  const legacyBurnSignatures = await signaturesForDigest(legacyBurn, accountsA);
  await proveSignatures(bridgeB, legacySwap, legacySwapSignatures);
  await proveSignatures(bridgeB, legacySet, legacySetSignatures);
  await proveSignatures(bridgeB, legacyBurn, legacyBurnSignatures);

  await expectRevert("legacy swap", () => bridgeB.methods
    .voteForMinting(swap, legacySwapSignatures).send({from: accountsB[1], gas: 6500000}));
  await expectRevert("legacy oracle set", () => bridgeB.methods
    .voteForNewOracleSet(100, newSet, legacySetSignatures).send({from: accountsB[1], gas: 6500000}));
  await expectRevert("legacy burn status", () => bridgeB.methods
    .voteForSwitchBurn(true, 100, legacyBurnSignatures).send({from: accountsB[1], gas: 6500000}));

  assert.strictEqual(await bridgeB.methods.totalSupply().call(), "0");
  assert.strictEqual(await bridgeB.methods.lastOracleSetHash().call(), "0");
  assert.strictEqual(await bridgeB.methods.lastBurnStatusNonce().call(), "0");
  assert.strictEqual(await bridgeB.methods.allowBurn().call(), false);

  console.log(
    `Chain-ID replay rejection passed for all three digests (${chainIdA} -> ${chainIdB}) at ${target}.`,
  );
  console.log("Legacy-format rejection and three committed golden vectors passed.");
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}

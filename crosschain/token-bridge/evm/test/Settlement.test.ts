import { expect } from "chai";
import { ethers, network } from "hardhat";
import { parseUnits } from "ethers/lib/utils";
import { BigNumber } from "ethers";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import Web3 from "web3";
import { Account } from "web3/eth/accounts";
import * as fs from "fs";
import * as path from "path";
import { TOS_ADDRESS_HASH } from "./utils/constants";
import { signNewGeneration, signRefundLock, signUpdateLockStatus } from "./utils/utils";
import type { Bridge, TestToken } from "../typechain-types";

const web3 = new Web3();

// Fields shared with the TOS sandbox
// (tosctl/src/node-control/contracts/tests/token_bridge/source.rs).
const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../tests/vectors/source-events.json"), "utf8")
);

const MAX_U64 = BigNumber.from(2).pow(64).sub(1);

async function rejects(call: Promise<any>, reason: string) {
  try {
    await call;
  } catch (err: any) {
    expect(err.toString()).to.have.string(reason);
    return;
  }
  expect.fail(`expected a refusal: ${reason}`);
}

describe("Bridge source generations, lock nonces and refunds", () => {
  let owner: SignerWithAddress;
  let bridge: Bridge;
  let token: TestToken;
  const oracles: Account[] = [0, 1, 2, 3].map(() => web3.eth.accounts.create() as unknown as Account);
  const tosBridge = "0x" + "22".repeat(32);

  async function deploy(from?: SignerWithAddress) {
    const Bridge = await ethers.getContractFactory("Bridge", from);
    const b = (await Bridge.deploy(oracles.map((o) => o.address), [])) as Bridge;
    await b.deployed();
    await b.voteForSwitchLock(true, 1, signUpdateLockStatus(true, 1, oracles, b.address));
    return b;
  }

  async function activate(b: Bridge, generation: number, nonce: number, life = 5, tos = tosBridge) {
    return b.voteForNewGeneration(generation, tos, life, nonce, signNewGeneration(generation, tos, life, nonce, oracles, b.address));
  }

  async function lockOne(amount = parseUnits("1")) {
    await token.approve(bridge.address, amount);
    const tx = await bridge.lock(token.address, amount, TOS_ADDRESS_HASH);
    const receipt = await tx.wait();
    const event = receipt.events!.find((e) => e.event === "Lock")!;
    return event.args!;
  }

  async function refund(n: any, signers = oracles) {
    const record = await bridge.locks(n);
    return bridge.refundLock(n, signRefundLock(n, record.generation, record.locker, record.token, record.amount, signers, bridge.address));
  }

  beforeEach(async () => {
    [owner] = await ethers.getSigners();
    bridge = await deploy();
    const TestToken = await ethers.getContractFactory("TestToken");
    token = (await TestToken.deploy(parseUnits("1000000"))) as TestToken;
    await token.deployed();
  });

  it("refuses every lock until a generation is active", async () => {
    await token.approve(bridge.address, parseUnits("1"));
    await rejects(bridge.lock(token.address, parseUnits("1"), TOS_ADDRESS_HASH), "No active generation");
    await activate(bridge, 1, 1);
    const lock = await lockOne();
    expect(lock.nonce).to.equal(0);
    expect(lock.generation).to.equal(1);
  });

  it("numbers locks densely and records each for a refund", async () => {
    await activate(bridge, 1, 1);
    for (let i = 0; i < 3; i++) {
      const lock = await lockOne(parseUnits(String(i + 1)));
      expect(lock.nonce).to.equal(i);
      const record = await bridge.locks(i);
      expect(record.locker).to.equal(owner.address);
      expect(record.token).to.equal(token.address);
      expect(record.amount).to.equal(parseUnits(String(i + 1)));
      expect(record.generation).to.equal(1);
      expect(record.status).to.equal(1);
    }
    expect(await bridge.lockNonce()).to.equal(3);
  });

  it("allocates the last nonce and then refuses, never wrapping", async () => {
    await activate(bridge, 1, 1);
    await lockOne();
    await lockOne();
    // find lockNonce's storage slot: the only slot holding 2
    let slot = -1;
    for (let i = 0; i < 32; i++) {
      const value = await ethers.provider.getStorageAt(bridge.address, i);
      if (BigNumber.from(value).eq(2)) {
        expect(slot, "one slot holds the nonce").to.equal(-1);
        slot = i;
      }
    }
    expect(slot).to.not.equal(-1);
    const max = await bridge.MAX_LOCK_NONCE();
    expect(max).to.equal(MAX_U64.sub(1));
    await network.provider.send("hardhat_setStorageAt", [
      bridge.address,
      ethers.utils.hexValue(slot),
      ethers.utils.hexZeroPad(max.toHexString(), 32),
    ]);
    const last = await lockOne();
    expect(last.nonce).to.equal(max);
    expect(await bridge.lockNonce()).to.equal(MAX_U64);
    await token.approve(bridge.address, parseUnits("1"));
    await rejects(bridge.lock(token.address, parseUnits("1"), TOS_ADDRESS_HASH), "Lock nonces exhausted");
  });

  it("starts each generation above every allocated lock, and only moves forward", async () => {
    await activate(bridge, 1, 1);
    await lockOne();
    await lockOne();
    await rejects(activate(bridge, 3, 2), "Generation must follow the current one");
    await rejects(activate(bridge, 1, 2), "Generation must follow the current one");
    await rejects(activate(bridge, 2, 2, 0), "Generation names no TOS bridge");
    await rejects(activate(bridge, 2, 2, 5, ethers.constants.HashZero), "Generation names no TOS bridge");
    await activate(bridge, 2, 2, 9);
    const g = await bridge.generations(2);
    expect(g.start).to.equal(2);
    expect(g.tosLife).to.equal(9);
    // a generation vote signed for an older nonce stays stale
    await rejects(activate(bridge, 3, 1), "Stale generation nonce");
    const lock = await lockOne();
    expect(lock.nonce).to.equal(2);
    expect(lock.generation).to.equal(2);
    expect((await bridge.locks(0)).generation).to.equal(1);
  });

  it("refunds a cancelled lock once, only to its locker, and only for its own fields", async () => {
    await activate(bridge, 1, 1);
    const amount = parseUnits("7");
    await lockOne(amount);
    await lockOne(parseUnits("3"));
    const before = await token.balanceOf(owner.address);
    // signatures over another lock's fields, another amount or another generation
    const record = await bridge.locks(0);
    for (const forged of [
      signRefundLock(1, 1, record.locker, record.token, record.amount, oracles, bridge.address),
      signRefundLock(0, 1, record.locker, record.token, record.amount.add(1), oracles, bridge.address),
      signRefundLock(0, 2, record.locker, record.token, record.amount, oracles, bridge.address),
    ]) {
      await rejects(bridge.refundLock(0, forged), "Wrong signature");
    }
    await rejects(refund(0, oracles.slice(0, 2)), "Not enough signatures");
    await expect(refund(0)).to.emit(bridge, "LockRefunded").withArgs(0, owner.address, token.address, amount);
    expect(await token.balanceOf(owner.address)).to.equal(before.add(amount));
    expect((await bridge.locks(0)).status).to.equal(2);
    await rejects(refund(0), "Lock is not refundable");
    await rejects(refund(5), "Lock is not refundable");
  });

  it("T-Z1: after a new generation, an old cancelled lock refunds once and a consumed one never", async () => {
    await activate(bridge, 1, 1);
    await lockOne(parseUnits("2")); // 0: consumed on TOS, no cancellation was logged
    await lockOne(parseUnits("5")); // 1: cancelled on TOS
    await activate(bridge, 2, 2, 11, "0x" + "33".repeat(32));
    // the only quorum signatures that exist are for the cancelled lock
    const r1 = await bridge.locks(1);
    const cancelled = signRefundLock(1, r1.generation, r1.locker, r1.token, r1.amount, oracles, bridge.address);
    await rejects(bridge.refundLock(0, cancelled), "Wrong signature");
    await bridge.refundLock(1, cancelled);
    await rejects(bridge.refundLock(1, cancelled), "Lock is not refundable");
    expect((await bridge.locks(0)).status).to.equal(1);
    expect((await bridge.locks(1)).generation).to.equal(1);
  });

  it("emits the fields the TOS sandbox votes on (shared vectors)", async () => {
    const signers = await ethers.getSigners();
    const deployer = signers[99];
    expect(await deployer.getTransactionCount(), "the vector deployer is unused").to.equal(0);
    const b = await deploy(deployer);
    const TestToken = await ethers.getContractFactory("TestToken", deployer);
    const t = (await TestToken.deploy(parseUnits("1000000"))) as TestToken;
    await t.deployed();
    expect(b.address).to.equal(ethers.utils.getAddress(VECTORS.evm_bridge));
    expect(t.address).to.equal(ethers.utils.getAddress(VECTORS.token));
    expect((await ethers.provider.getNetwork()).chainId).to.equal(VECTORS.evm_chain_id);
    expect(await t.decimals()).to.equal(VECTORS.decimals);

    const a = VECTORS.activation;
    await expect(
      b.connect(deployer).voteForNewGeneration(
        a.generation, a.tos_bridge, a.tos_life, a.nonce,
        signNewGeneration(a.generation, a.tos_bridge, a.tos_life, a.nonce, oracles, b.address)
      )
    ).to.emit(b, "NewGeneration").withArgs(a.generation, a.tos_bridge.toLowerCase(), a.tos_life, a.start);

    for (const lock of VECTORS.locks) {
      await t.connect(deployer).approve(b.address, lock.amount);
      await expect(b.connect(deployer).lock(t.address, lock.amount, lock.to))
        .to.emit(b, "Lock")
        .withArgs(deployer.address, t.address, lock.to.toLowerCase(), lock.amount, BigNumber.from(lock.amount).add(
          VECTORS.locks.filter((l: any) => BigNumber.from(l.n).lt(lock.n)).reduce((s: BigNumber, l: any) => s.add(l.amount), BigNumber.from(0))
        ), VECTORS.decimals, lock.n, a.generation);
    }
  });
});

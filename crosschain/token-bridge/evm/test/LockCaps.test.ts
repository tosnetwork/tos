import { expect } from "chai";
import { ethers, network } from "hardhat";
import { BigNumber, Contract } from "ethers";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import Web3 from "web3";
import { Account } from "web3/eth/accounts";
import { TOS_ADDRESS_HASH, TOS_TX_LT } from "./utils/constants";
import {
  MAX_LOCK_CAP,
  prepareSwapData,
  signLockCap,
  signNewGeneration,
  signRefundLock,
  signSwapData,
  signUpdateLockStatus,
} from "./utils/utils";
import type { Bridge } from "../typechain-types";

const web3 = new Web3();
const HOUR = 3600;
const DAY = 86400;

async function rejects(call: Promise<any>, reason: string) {
  try {
    await call;
  } catch (err: any) {
    expect(err.toString()).to.have.string(reason);
    return;
  }
  expect.fail(`expected a refusal: ${reason}`);
}

type Caps = { total: BigNumber; perLock: BigNumber; hourly: BigNumber; daily: BigNumber };

const caps = (total: any, perLock: any, hourly: any, daily: any): Caps => ({
  total: BigNumber.from(total),
  perLock: BigNumber.from(perLock),
  hourly: BigNumber.from(hourly),
  daily: BigNumber.from(daily),
});

// The two kinds of token the bridge must carry: a standard ERC-20, and a
// 6-decimal token whose transfer returns nothing and has a fee switch (left
// at zero here; the fee-on-transfer case below turns it on).
const KINDS = [
  { name: "a standard ERC-20", contract: "TestToken", decimals: 18 },
  { name: "a 6-decimal no-return token with a fee switch", contract: "TestFeeToken", decimals: 6 },
];

describe("Bridge lock caps", () => {
  let owner: SignerWithAddress;
  let bridge: Bridge;
  const oracles: Account[] = [0, 1, 2, 3].map(() => web3.eth.accounts.create() as unknown as Account);
  const tosBridge = "0x" + "44".repeat(32);
  const nonces = new Map<string, number>();
  let unlockSeq = 0;

  async function deployToken(contract: string, supply: BigNumber = BigNumber.from(10).pow(30)) {
    const Token = await ethers.getContractFactory(contract);
    const t = await Token.deploy(supply);
    await t.deployed();
    await t.approve(bridge.address, ethers.constants.MaxUint256);
    return t;
  }

  function signCaps(tokenAddress: string, c: Caps, nonce: number, signers = oracles, target = bridge.address) {
    return signLockCap(tokenAddress, c.total, c.perLock, c.hourly, c.daily, nonce, signers, target);
  }

  async function setCaps(tokenAddress: string, c: Caps) {
    const nonce = (nonces.get(tokenAddress) ?? 0) + 1;
    nonces.set(tokenAddress, nonce);
    return bridge.voteForLockCap(tokenAddress, c.total, c.perLock, c.hourly, c.daily, nonce, signCaps(tokenAddress, c, nonce));
  }

  async function lock(t: Contract, amount: any) {
    const tx = await bridge.lock(t.address, amount, TOS_ADDRESS_HASH);
    const receipt = await tx.wait();
    return receipt.events!.find((e) => e.event === "Lock")!.args!;
  }

  async function unlock(t: Contract, amount: any) {
    unlockSeq += 1;
    const data = prepareSwapData(owner.address, t.address, amount, TOS_ADDRESS_HASH,
      ethers.utils.hexZeroPad(ethers.utils.hexlify(unlockSeq), 32), TOS_TX_LT);
    return bridge.unlock(data, signSwapData(data, oracles, bridge.address));
  }

  // The next block's timestamp is `at`; the call is mined in it.
  async function at(timestamp: number, call: () => Promise<any>) {
    await time.setNextBlockTimestamp(timestamp);
    return call();
  }

  async function nextBoundary(period: number) {
    const now = await time.latest();
    return (Math.floor(now / period) + 1) * period;
  }

  beforeEach(async () => {
    [owner] = await ethers.getSigners();
    nonces.clear();
    // Start every test ten seconds into a fresh hour, so that no test
    // depends on the wall-clock hour: each one that does not travel in time
    // itself runs inside one hour bucket and one day bucket.
    await time.increaseTo((await nextBoundary(HOUR)) + 10);
    const Bridge = await ethers.getContractFactory("Bridge");
    bridge = (await Bridge.deploy(oracles.map((o) => o.address), [])) as Bridge;
    await bridge.deployed();
    await bridge.voteForSwitchLock(true, 1, signUpdateLockStatus(true, 1, oracles, bridge.address));
    await bridge.voteForNewGeneration(1, tosBridge, 1, 1, signNewGeneration(1, tosBridge, 1, 1, oracles, bridge.address));
  });

  for (const kind of KINDS) {
    describe(`for ${kind.name}`, () => {
      let token: Contract;
      const unit = BigNumber.from(10).pow(kind.decimals);
      const u = (n: number) => unit.mul(n);
      // total 1000, per lock 100, hourly 300, daily 500
      let c: Caps;

      beforeEach(async () => {
        token = await deployToken(kind.contract);
        c = caps(u(1000), u(100), u(300), u(500));
        await setCaps(token.address, c);
      });

      it("locks within its caps and records the usage", async () => {
        await expect(bridge.lock(token.address, u(40), TOS_ADDRESS_HASH))
          .to.emit(bridge, "Lock")
          .withArgs(owner.address, token.address, TOS_ADDRESS_HASH.toLowerCase(), u(40), u(40), kind.decimals, 0, 1);
        const state = await bridge.getLockCapState(token.address);
        expect(state.cap.total).to.equal(c.total);
        expect(state.cap.perLock).to.equal(c.perLock);
        expect(state.cap.hourly).to.equal(c.hourly);
        expect(state.cap.daily).to.equal(c.daily);
        expect(state.hourUsed).to.equal(u(40));
        expect(state.dayUsed).to.equal(u(40));
        expect(state.available).to.equal(u(100));
        expect(await token.balanceOf(bridge.address)).to.equal(u(40));
      });

      it("accepts a lock at the per-lock cap and refuses one unit more", async () => {
        await rejects(bridge.lock(token.address, c.perLock.add(1), TOS_ADDRESS_HASH), "lock: over the per-lock cap");
        const lockEvent = await lock(token, c.perLock);
        expect(lockEvent.value).to.equal(c.perLock);
      });

      it("accepts a balance at the token cap, refuses one unit more, and frees room on unlock", async () => {
        // Rate caps wide enough that only the token cap binds.
        await setCaps(token.address, caps(u(250), u(100), u(1000), u(1000)));
        await lock(token, u(100));
        await lock(token, u(100));
        await lock(token, u(50)); // the balance is now exactly the token cap
        expect(await token.balanceOf(bridge.address)).to.equal(u(250));
        expect((await bridge.getLockCapState(token.address)).available).to.equal(0);
        await rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: over the token cap");
        // The token cap bounds what the bridge holds, so an unlock frees room;
        // the rate windows keep what they were charged.
        await unlock(token, u(30));
        await rejects(bridge.lock(token.address, u(30).add(1), TOS_ADDRESS_HASH), "lock: over the token cap");
        await lock(token, u(30));
        const state = await bridge.getLockCapState(token.address);
        expect(state.hourUsed).to.equal(u(280));
      });

      it("fills the hourly bucket exactly and opens the next one at the hour boundary", async () => {
        // An hour boundary inside one day, so that only the hourly cap binds.
        const boundary = (await nextBoundary(DAY)) + HOUR;
        await at(boundary - 10, () => lock(token, u(100)));
        await lock(token, u(100));
        await lock(token, u(100)); // the hour has used exactly its cap
        await at(boundary - 1, () =>
          rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: over the hourly cap"));
        // The first second of the next hour is a new bucket. This is the
        // documented bound of fixed buckets: 2 * hourly within seconds.
        await at(boundary, () => lock(token, u(100)));
        const state = await bridge.getLockCapState(token.address);
        expect(state.hourUsed).to.equal(u(100));
        expect(state.dayUsed).to.equal(u(400));
      });

      it("fills the daily bucket across hours and opens the next one at the day boundary", async () => {
        const boundary = (await nextBoundary(DAY)) + DAY;
        await at(boundary - 3 * HOUR, () => lock(token, u(100)));
        await lock(token, u(100));
        await lock(token, u(100)); // that hour is full
        await at(boundary - 2 * HOUR, () => lock(token, u(100)));
        await lock(token, u(100)); // the day has used exactly its cap
        await rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: over the daily cap");
        // Unlocks do not give rate back.
        await unlock(token, u(100));
        await rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: over the daily cap");
        // The day's last second is still the full bucket; its first second
        // after the boundary is a new one.
        await at(boundary - 1, () =>
          rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: over the daily cap"));
        await at(boundary, () => lock(token, u(100)));
        const state = await bridge.getLockCapState(token.address);
        expect(state.hourUsed).to.equal(u(100));
        expect(state.dayUsed).to.equal(u(100));
      });

      it("refuses locks before any cap is set and after a vote sets every cap to zero", async () => {
        const fresh = await deployToken(kind.contract);
        await rejects(bridge.lock(fresh.address, 1, TOS_ADDRESS_HASH), "lock: token has no lock cap");
        expect((await bridge.getLockCapState(fresh.address)).available).to.equal(0);
        await lock(token, u(1));
        await setCaps(token.address, caps(0, 0, 0, 0));
        await rejects(bridge.lock(token.address, 1, TOS_ADDRESS_HASH), "lock: token has no lock cap");
        expect((await bridge.getLockCapState(token.address)).available).to.equal(0);
      });

      it("refuses the lock that crosses a cap when two land in one block", async () => {
        await network.provider.send("evm_setAutomine", [false]);
        try {
          const first = await bridge.lock(token.address, u(100), TOS_ADDRESS_HASH, { gasLimit: 500000 });
          const second = await bridge.lock(token.address, u(100), TOS_ADDRESS_HASH, { gasLimit: 500000 });
          const third = await bridge.lock(token.address, u(100), TOS_ADDRESS_HASH, { gasLimit: 500000 });
          const fourth = await bridge.lock(token.address, 1, TOS_ADDRESS_HASH, { gasLimit: 500000 });
          await network.provider.send("evm_mine");
          const receipts = await Promise.all([first, second, third, fourth].map((tx) =>
            ethers.provider.getTransactionReceipt(tx.hash)));
          expect(new Set(receipts.map((r) => r.blockNumber)).size).to.equal(1);
          expect(receipts.map((r) => r.status)).to.eql([1, 1, 1, 0]);
        } finally {
          await network.provider.send("evm_setAutomine", [true]);
        }
        expect((await bridge.getLockCapState(token.address)).hourUsed).to.equal(u(300));
      });
    });
  }

  it("keeps the caps of two tokens independent", async () => {
    const a = await deployToken("TestToken");
    const b = await deployToken("TestFeeToken");
    await setCaps(a.address, caps(1000, 100, 200, 400));
    await setCaps(b.address, caps(50, 10, 20, 30));
    await lock(a, 100);
    await lock(a, 100);
    await rejects(bridge.lock(a.address, 1, TOS_ADDRESS_HASH), "lock: over the hourly cap");
    // a's full hour does not touch b
    await lock(b, 10);
    await lock(b, 10);
    await rejects(bridge.lock(b.address, 1, TOS_ADDRESS_HASH), "lock: over the hourly cap");
    expect((await bridge.getLockCapState(a.address)).hourUsed).to.equal(200);
    expect((await bridge.getLockCapState(b.address)).hourUsed).to.equal(20);
    // changing b's caps leaves a's caps and nonce alone
    await setCaps(b.address, caps(50, 10, 30, 30));
    await lock(b, 10);
    expect((await bridge.lockCaps(a.address)).hourly).to.equal(200);
    expect(await bridge.lastLockCapNonce(a.address)).to.equal(1);
    expect(await bridge.lastLockCapNonce(b.address)).to.equal(2);
  });

  it("changes caps by a valid vote, and a lowered cap binds at once", async () => {
    const t = await deployToken("TestToken");
    const first = caps(1000, 100, 300, 500);
    await expect(bridge.voteForLockCap(t.address, first.total, first.perLock, first.hourly, first.daily, 7,
      signCaps(t.address, first, 7)))
      .to.emit(bridge, "LockCapSet")
      .withArgs(t.address, first.total, first.perLock, first.hourly, first.daily, 7);
    expect(await bridge.lastLockCapNonce(t.address)).to.equal(7);
    await lock(t, 100);
    await lock(t, 100);
    // what the hour already used stays charged under the lower cap
    const lower = caps(1000, 50, 200, 500);
    await bridge.voteForLockCap(t.address, lower.total, lower.perLock, lower.hourly, lower.daily, 8,
      signCaps(t.address, lower, 8));
    const stored = await bridge.lockCaps(t.address);
    expect(stored.perLock).to.equal(50);
    expect(stored.hourly).to.equal(200);
    await rejects(bridge.lock(t.address, 1, TOS_ADDRESS_HASH), "lock: over the hourly cap");
    const raised = caps(1000, 50, 300, 500);
    await bridge.voteForLockCap(t.address, raised.total, raised.perLock, raised.hourly, raised.daily, 9,
      signCaps(t.address, raised, 9));
    await rejects(bridge.lock(t.address, 51, TOS_ADDRESS_HASH), "lock: over the per-lock cap");
    await lock(t, 50);
  });

  it("refuses a cap vote with too few, duplicate, unauthorized, foreign or replayed signatures", async () => {
    const t = await deployToken("TestToken");
    const other = await deployToken("TestToken");
    const c = caps(1000, 100, 300, 500);
    const vote = (signatures: any, nonce = 1, token = t.address, v = c) =>
      bridge.voteForLockCap(token, v.total, v.perLock, v.hourly, v.daily, nonce, signatures);

    // four oracles need three signatures
    await rejects(vote(signCaps(t.address, c, 1, oracles.slice(0, 2))), "Not enough signatures");
    const dup = signCaps(t.address, c, 1, [oracles[0], oracles[0], oracles[1]]);
    await rejects(vote(dup), "Signatures are not sorted");
    const stranger = web3.eth.accounts.create() as unknown as Account;
    await rejects(vote(signCaps(t.address, c, 1, [stranger, ...oracles.slice(0, 2)])), "Unauthorized signer");
    // signatures for another bridge, another token, other caps or another nonce
    const Bridge = await ethers.getContractFactory("Bridge");
    const elsewhere = await Bridge.deploy(oracles.map((o) => o.address), []);
    await rejects(vote(signCaps(t.address, c, 1, oracles, elsewhere.address)), "Wrong signature");
    await rejects(vote(signCaps(other.address, c, 1)), "Wrong signature");
    await rejects(vote(signCaps(t.address, caps(1000, 100, 300, 600), 1)), "Wrong signature");
    await rejects(vote(signCaps(t.address, c, 2), 1), "Wrong signature");
    expect((await bridge.lockCaps(t.address)).total).to.equal(0);

    // a signed but unexecuted older vote never undoes a newer one
    const older = caps(5000, 1000, 2000, 3000);
    const olderSignatures = signCaps(t.address, older, 1);
    await vote(signCaps(t.address, c, 2), 2);
    await rejects(vote(olderSignatures, 1, t.address, older), "Stale lock cap nonce");
    // the executed vote cannot be replayed
    await rejects(vote(signCaps(t.address, c, 2), 2), "Vote is already finished");
    expect((await bridge.lockCaps(t.address)).total).to.equal(1000);
    // nothing reached the other token
    expect((await bridge.lockCaps(other.address)).total).to.equal(0);
    await rejects(bridge.lock(other.address, 1, TOS_ADDRESS_HASH), "lock: token has no lock cap");
  });

  it("refuses a cap vote signed for another token", async () => {
    // The oracles sign the digest the bridge itself computes, as they do in
    // production, so this test holds the token's place in that digest.
    const a = await deployToken("TestToken");
    const b = await deployToken("TestToken");
    const c = caps(1000, 100, 300, 500);
    const digest = await bridge.getNewLockCapId(a.address, c.total, c.perLock, c.hourly, c.daily, 1);
    const signatures = oracles
      .map((o) => ({ signer: o.address, signature: o.sign(digest).signature }))
      .sort((x, y) => (BigInt(x.signer) < BigInt(y.signer) ? -1 : 1));
    await rejects(bridge.voteForLockCap(b.address, c.total, c.perLock, c.hourly, c.daily, 1, signatures),
      "Wrong signature");
    expect((await bridge.lockCaps(b.address)).total).to.equal(0);
    // the same signatures are valid for the token they name
    await bridge.voteForLockCap(a.address, c.total, c.perLock, c.hourly, c.daily, 1, signatures);
    expect((await bridge.lockCaps(a.address)).total).to.equal(1000);
  });

  // Caps bound new locks only. Payouts of locks already taken never read
  // them: an unlock of a recorded burn and the refund of a cancelled lock
  // must go through whatever the caps say now.
  async function payoutsSurvive(after: Caps) {
    const t = await deployToken("TestToken");
    await setCaps(t.address, caps(1000, 100, 300, 500));
    await lock(t, 100);
    await lock(t, 100);
    await lock(t, 100);
    await setCaps(t.address, after);
    await rejects(bridge.lock(t.address, 1, TOS_ADDRESS_HASH), after.total.isZero()
      ? "lock: token has no lock cap" : "lock: over the token cap");
    const before = await t.balanceOf(owner.address);
    await unlock(t, 60);
    const record = await bridge.locks(1);
    await expect(bridge.refundLock(1, signRefundLock(1, record.generation, record.locker, record.token,
      record.amount, oracles, bridge.address)))
      .to.emit(bridge, "LockRefunded").withArgs(1, owner.address, t.address, 100);
    expect(await t.balanceOf(owner.address)).to.equal(before.add(160));
    expect(await t.balanceOf(bridge.address)).to.equal(140);
    expect((await bridge.locks(1)).status).to.equal(2);
  }

  it("pays out by unlock and refundLock after the caps are voted to zero", async () => {
    await payoutsSurvive(caps(0, 0, 0, 0));
  });

  it("pays out by unlock and refundLock after the total cap is voted below the balance", async () => {
    await payoutsSurvive(caps(200, 100, 300, 500));
  });

  it("refuses partly zero, unordered, oversized and token-less caps", async () => {
    const t = await deployToken("TestToken");
    let nonce = 0;
    const tryCaps = (v: Caps, token = t.address) => {
      nonce += 1;
      return bridge.voteForLockCap(token, v.total, v.perLock, v.hourly, v.daily, nonce,
        signCaps(token, v, nonce));
    };
    await rejects(tryCaps(caps(0, 100, 300, 500)), "Lock cap is partly zero");
    await rejects(tryCaps(caps(1000, 0, 300, 500)), "Lock cap is partly zero");
    await rejects(tryCaps(caps(1000, 100, 0, 500)), "Lock caps are not ordered");
    await rejects(tryCaps(caps(1000, 100, 300, 0)), "Lock caps are not ordered");
    await rejects(tryCaps(caps(1000, 301, 300, 500)), "Lock caps are not ordered");
    await rejects(tryCaps(caps(1000, 100, 501, 500)), "Lock caps are not ordered");
    const over = MAX_LOCK_CAP.add(1);
    await rejects(tryCaps(caps(over, 100, 300, 500)), "Lock cap over the supply bound");
    await rejects(tryCaps(caps(1000, 100, 300, over)), "Lock cap over the supply bound");
    const huge = ethers.constants.MaxUint256;
    await rejects(tryCaps(caps(huge, huge, huge, huge)), "Lock cap over the supply bound");
    await rejects(tryCaps(caps(1000, 100, 300, 500), ethers.constants.AddressZero), "Lock cap names no token");
    // the widest accepted caps are stored exactly
    await tryCaps(caps(MAX_LOCK_CAP, MAX_LOCK_CAP, MAX_LOCK_CAP, MAX_LOCK_CAP));
    const stored = await bridge.lockCaps(t.address);
    expect(stored.total).to.equal(MAX_LOCK_CAP);
    expect(stored.daily).to.equal(MAX_LOCK_CAP);
  });

  it("caps a fee-on-transfer token by the received amount", async () => {
    const t = await deployToken("TestFeeToken");
    await t.setFee(100); // 1%
    await setCaps(t.address, caps(10000, 990, 1980, 5000));
    // 1000 requested, 990 received: exactly the per-lock cap
    const lockEvent = await lock(t, 1000);
    expect(lockEvent.value).to.equal(990);
    expect((await bridge.locks(0)).amount).to.equal(990);
    let state = await bridge.getLockCapState(t.address);
    expect(state.hourUsed).to.equal(990);
    expect(state.dayUsed).to.equal(990);
    // 1010 requested, 1000 received (rounding down the fee): over the cap
    await rejects(bridge.lock(t.address, 1010, TOS_ADDRESS_HASH), "lock: over the per-lock cap");
    // the hour holds 1980 received, which 2000 requested reach exactly
    await lock(t, 1000);
    state = await bridge.getLockCapState(t.address);
    expect(state.hourUsed).to.equal(1980);
    await rejects(bridge.lock(t.address, 2, TOS_ADDRESS_HASH), "lock: over the hourly cap");
    expect(await t.balanceOf(bridge.address)).to.equal(1980);
  });

  it("refuses at the supply bound and the cap sums, never by an arithmetic panic", async () => {
    const t = await deployToken("TestToken", MAX_LOCK_CAP.add(10));
    await setCaps(t.address, caps(MAX_LOCK_CAP, MAX_LOCK_CAP, MAX_LOCK_CAP, MAX_LOCK_CAP));
    const day = await nextBoundary(DAY);
    await at(day + 10, () => lock(t, MAX_LOCK_CAP));
    let state = await bridge.getLockCapState(t.address);
    expect(state.hourUsed).to.equal(MAX_LOCK_CAP);
    expect(state.available).to.equal(0);
    await rejects(bridge.lock(t.address, 1, TOS_ADDRESS_HASH), "Max token totalSupply 2 ** 120 - 1");
    // With the balance unlocked the token cap has room, but the hour and day
    // already hold 2 ** 120 - 1: the sum exceeds the cap and is refused.
    await unlock(t, MAX_LOCK_CAP);
    expect(await t.balanceOf(bridge.address)).to.equal(0);
    await rejects(bridge.lock(t.address, 1, TOS_ADDRESS_HASH), "lock: over the hourly cap");
    // the next hour's bucket starts empty; the day still holds its sum
    await time.increaseTo(day + HOUR);
    state = await bridge.getLockCapState(t.address);
    expect(state.hourUsed).to.equal(0);
    expect(state.dayUsed).to.equal(MAX_LOCK_CAP);
    await rejects(bridge.lock(t.address, 1, TOS_ADDRESS_HASH), "lock: over the daily cap");
  });
});

require("chai")
  .use(require("chai-shallow-deep-equal"))
  .use(require("chai-as-promised"))
  .should();

let utils = require("./utils/utils.js");
let Bridge = artifacts.require("Bridge");

let bridge;
let chainId;

contract("Bridge", ([oracle1, not_oracle, oracle2, oracle3, oracle4, oracle5, extra1, extra2, extra3, user]) => {
  before(async () => {
    chainId = String(await web3.eth.getChainId());
  });
  describe("Bridge::instance", () => {
    it("", async() => {
      bridge = await Bridge.new("Wrapped TOS Coin", "TOSCOIN", [oracle1, oracle2, oracle3]);
    });
  });
  describe("Bridge::construction", () => {
    it("rejects an initial set too small to reach quorum", async () => {
      await Bridge.new("Wrapped TOS Coin", "TOSCOIN", []).should.be.rejected;
      await Bridge.new("Wrapped TOS Coin", "TOSCOIN", [oracle1]).should.be.rejected;
      await Bridge.new("Wrapped TOS Coin", "TOSCOIN", [oracle1, oracle2]).should.be.rejected;
    });

    it("rejects a duplicate member in the initial set", async () => {
      await Bridge.new("Wrapped TOS Coin", "TOSCOIN", [oracle1, oracle1, oracle2]).should.be.rejected;
    });

    it("rejects the zero address in the initial set", async () => {
      await Bridge.new("Wrapped TOS Coin", "TOSCOIN",
        [oracle1, oracle2, "0x0000000000000000000000000000000000000000"]).should.be.rejected;
    });
  });

  describe("Bridge::threshold", () => {
    // The threshold must be a true two-thirds majority at every set size, not
    // a floor that collapses to half when the size is not a multiple of three.
    const expected = {3: 2, 4: 3, 5: 4, 6: 4, 7: 5, 8: 6};

    it("requires a ceiling two-thirds majority at each set size", async () => {
      const pool = [oracle1, oracle2, oracle3, oracle4, oracle5, extra1, extra2, extra3];
      for (const size of Object.keys(expected).map(Number)) {
        const set = pool.slice(0, size);
        const instance = await Bridge.new("Wrapped TOS Coin", "TOSCOIN", set);
        const need = expected[size];
        const data = utils.prepareSwapData(user, 1e9);
        const sign = async (n) => utils.sortedSignatures(await Promise.all(
          set.slice(0, n).map((o) => utils.signData(data, o, instance.address, chainId))));

        await instance.voteForMinting(data, await sign(need - 1)).should.be.rejected;
        await instance.voteForMinting(data, await sign(need)).should.be.fulfilled;
        (await instance.balanceOf(user)).toString().should.be.equal(String(1e9));
      }
    });
  });
  describe("WrappedTOS::minting", () => {
   it("one random address can't mint tokens", async () => {
      let user = oracle5;
      let data = utils.prepareSwapData(user, 1e9);
      await bridge.voteForMinting(data, [await utils.signData(data, not_oracle, bridge.address, chainId)], { from: not_oracle }).should.not.be.fulfilled;
    });
   it("random address can't add signatures to authorized ones", async () => {
      let user = oracle5;
      let data = utils.prepareSwapData(user, 1e9);
      let not_oracle2 = oracle4;
      let not_oracle3 = oracle5;
      await bridge.voteForMinting(data, [await utils.signData(data, oracle1, bridge.address, chainId),
                                         await utils.signData(data, not_oracle, bridge.address, chainId),
                                         await utils.signData(data, not_oracle2, bridge.address, chainId),
                                         await utils.signData(data, not_oracle3, bridge.address, chainId),], { from: oracle1 }).should.not.be.fulfilled;
    });
    it("2/3 of the set of oracles can mint tokens", async () => {
      let user = oracle5;
      let data = utils.prepareSwapData(user, 1e9);
      let balance = await bridge.balanceOf(user);
      balance.toString().should.be.equal("0");
      let signatureSet = [await utils.signData(data, oracle1, bridge.address, chainId),
                          await utils.signData(data, oracle2, bridge.address, chainId)];
      await bridge.voteForMinting(data, signatureSet, { from: oracle1 }).should.be.fulfilled;
      balance = await bridge.balanceOf(user);
      balance.toString().should.be.equal(String(1e9));
      let isFinished = await bridge.finishedVotings(utils.hashData(utils.encodeSwapData(data, bridge.address, chainId)));
      isFinished.should.be.true;
      await bridge.voteForMinting(data, signatureSet, { from: oracle1 }).should.be.rejected;
    });
    it("check duplications in signature set", async () => {
      let user = oracle5;
      let data = utils.prepareSwapData(user, 1e9);
      let signatureSet = [await utils.signData(data, oracle1, bridge.address, chainId),
                          await utils.signData(data, oracle1, bridge.address, chainId)];
      await bridge.voteForMinting(data, signatureSet, { from: oracle1 }).should.be.rejected;
      signatureSet = [await utils.signData(data, oracle1, bridge.address, chainId),
                          await utils.signData(data, oracle2, bridge.address, chainId),
                          await utils.signData(data, oracle1, bridge.address, chainId)];
      await bridge.voteForMinting(data, signatureSet, { from: oracle1 }).should.be.rejected;
    });

    it("check unsorted signature set", async () => {
      let user = oracle5;
      let data = utils.prepareSwapData(user, 1e9);
      let signatureSet = [await utils.signData(data, oracle2, bridge.address, chainId),
                          await utils.signData(data, oracle1, bridge.address, chainId)];
      await bridge.voteForMinting(data, signatureSet, { from: oracle1 }).should.be.rejected;
    });

  });

  describe("WrappedTOS::oracles_rotation", () => {
    it("check initial oracles", async () => {
      // list
      let _oracle1 = await bridge.oraclesSet(0);
      _oracle1.toString().should.be.equal(String(oracle1));
      let _oracle2 = await bridge.oraclesSet(1);
      _oracle2.toString().should.be.equal(String(oracle2));
      let _oracle3 = await bridge.oraclesSet(2);
      _oracle3.toString().should.be.equal(String(oracle3));
      await bridge.oraclesSet(3).should.be.rejected;
      // mapping
      isOracle = await bridge.isOracle(oracle1);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(oracle2);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(oracle3);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(not_oracle);
      isOracle.should.be.false;
    });
    it("initial oracles can set new set", async () => {
      let newSet = [oracle3, oracle4, oracle5];
      let signatureSet = [await utils.signSet(13, newSet, oracle1, bridge.address, chainId),
                          await utils.signSet(13, newSet, oracle2, bridge.address, chainId)];
      await bridge.voteForNewOracleSet(13, newSet, signatureSet, { from: oracle1 }).should.be.fulfilled;

      await bridge.voteForNewOracleSet(14, newSet, [await utils.signSet(14, newSet, oracle1, bridge.address, chainId),
          await utils.signSet(14, newSet, oracle2, bridge.address, chainId)], { from: oracle1 }).should.be.rejected;

      await bridge.voteForNewOracleSet(14, newSet, [await utils.signSet(14, newSet, oracle3, bridge.address, chainId),
          await utils.signSet(14, newSet, oracle5, bridge.address, chainId)], { from: oracle1 }).should.be.fulfilled;
    });
    it("check correctness of new set", async () => {
      // list
      let _oracle1 = await bridge.oraclesSet(0);
      _oracle1.toString().should.be.equal(String(oracle3));
      let _oracle2 = await bridge.oraclesSet(1);
      _oracle2.toString().should.be.equal(String(oracle4));
      let _oracle3 = await bridge.oraclesSet(2);
      _oracle3.toString().should.be.equal(String(oracle5));
      await bridge.oraclesSet(3).should.be.rejected;
      // mapping
      isOracle = await bridge.isOracle(oracle1);
      isOracle.should.not.be.true;
      isOracle = await bridge.isOracle(oracle2);
      isOracle.should.not.be.true;
      isOracle = await bridge.isOracle(oracle3);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(oracle4);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(oracle5);
      isOracle.should.be.true;
      isOracle = await bridge.isOracle(not_oracle);
      isOracle.should.be.false;
    });
  });
  describe("WrappedTOS::burn control", () => {
    it("stop burning", async () => {
      let isBurnAllowed = await bridge.allowBurn();
      isBurnAllowed.should.be.false;
      /*
      let user = oracle5;
      let signatureSet = [await utils.signBurnStatus(0, 12, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(0, 12, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(0, 12, signatureSet, { from: oracle1 }).should.be.fulfilled;
      await bridge.burn("1", {workchain:-1, address_hash:"0x00"}, { from: user }).should.be.rejected;
      */
    });
    it("restore burning", async () => {
      let user = oracle5;
      let signatureSet = [await utils.signBurnStatus(1, 13, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(1, 13, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(1, 13, signatureSet, { from: oracle1 }).should.be.fulfilled;
      await bridge.burn("1", {workchain: utils.TOS_WORKCHAIN, address_hash: utils.TOS_ADDRESS_HASH}, { from: user }).should.be.fulfilled;
    });
    it("check replay protection", async () => {
      let user = oracle5;
      // Burn-status nonces must strictly increase; 13 was consumed above.
      let signatureSet = [await utils.signBurnStatus(0, 15, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(0, 15, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(0, 15, signatureSet, { from: oracle1 }).should.be.fulfilled;
      await bridge.burn("1", {workchain: utils.TOS_WORKCHAIN, address_hash: utils.TOS_ADDRESS_HASH}, { from: user }).should.be.rejected;

      signatureSet = [await utils.signBurnStatus(1, 16, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(1, 16, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(1, 16, signatureSet, { from: oracle1 }).should.be.fulfilled;
      await bridge.burn("1", {workchain: utils.TOS_WORKCHAIN, address_hash: utils.TOS_ADDRESS_HASH}, { from: user }).should.be.fulfilled;

      signatureSet = [await utils.signBurnStatus(0, 15, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(0, 15, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(0, 15, signatureSet, { from: oracle1 }).should.be.rejected;

      // A signature produced earlier but never executed must not survive a
      // later vote either: this is what finishedVotings alone cannot stop.
      signatureSet = [await utils.signBurnStatus(0, 17, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(0, 17, oracle5, bridge.address, chainId)];
      let laterSet = [await utils.signBurnStatus(1, 18, oracle4, bridge.address, chainId),
                          await utils.signBurnStatus(1, 18, oracle5, bridge.address, chainId)];
      await bridge.voteForSwitchBurn(1, 18, laterSet, { from: oracle1 }).should.be.fulfilled;
      await bridge.voteForSwitchBurn(0, 17, signatureSet, { from: oracle1 }).should.be.rejected;
      let isBurnAllowed = await bridge.allowBurn();
      isBurnAllowed.should.be.true;
      await bridge.burn("1", {workchain: utils.TOS_WORKCHAIN, address_hash: utils.TOS_ADDRESS_HASH}, { from: user }).should.be.fulfilled;
    });

  });
});

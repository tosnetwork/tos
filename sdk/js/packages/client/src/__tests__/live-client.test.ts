/**
 * Live integration tests for TosClient against a local TOS node.
 *
 * These tests are automatically skipped when no node is reachable at
 * http://localhost:8081. Run a local TOS node first, then execute:
 *
 *   pnpm vitest run --filter client -- --testPathPattern='live'
 */

import { describe, it, expect, beforeAll } from "vitest";
import { TosClient, Networks } from "../index.js";
import type {
  MasterchainInfo,
  ConsensusBlock,
  ReadyzResult,
  OutMsgQueueSize,
  BlockIdExt,
  BlockHeader,
  AccountInfo,
  ConfigAll,
  RunResult,
  Transaction,
  ShardInfo,
} from "../index.js";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const client = new TosClient({ ...Networks.local, timeout: 5_000, retry: 0 });

/**
 * Probe the local node. Returns true when the node responds to
 * getMasterchainInfo within the timeout window.
 */
async function isNodeUp(): Promise<boolean> {
  try {
    await client.getMasterchainInfo();
    return true;
  } catch {
    return false;
  }
}

// Resolve once at module level so describe.skipIf gets a boolean.
const nodeAvailable = await isNodeUp();

// Well-known addresses on any TOS-compatible chain
const CONFIG_ADDRESS =
  "-1:5555555555555555555555555555555555555555555555555555555555555555";
const ELECTOR_ADDRESS =
  "-1:3333333333333333333333333333333333333333333333333333333333333333";
const MC_SHARD = "-9223372036854775808"; // 0x8000000000000000 (masterchain full shard)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!nodeAvailable)("TosClient live integration", () => {
  // Cache masterchain info for dependent tests
  let masterchainInfo: MasterchainInfo;

  beforeAll(async () => {
    masterchainInfo = await client.getMasterchainInfo();
  });

  // ----- Masterchain info -----

  it("getMasterchainInfo() returns valid MasterchainInfo with seqno > 0", async () => {
    const info = await client.getMasterchainInfo();
    expect(info).toBeDefined();
    expect(info["@type"]).toBe("blocks.masterchainInfo");
    expect(info.last).toBeDefined();
    expect(info.last.seqno).toBeGreaterThan(0);
    expect(info.last.workchain).toBe(-1);
    expect(info.last.root_hash).toBeTruthy();
    expect(info.last.file_hash).toBeTruthy();
    expect(info.state_root_hash).toBeTruthy();
  });

  // ----- Consensus block -----

  it("getConsensusBlock() returns a valid consensus block", async () => {
    const block: ConsensusBlock = await client.getConsensusBlock();
    expect(block).toBeDefined();
    expect(block["@type"]).toBe("ext.blocks.consensusBlock");
    expect(typeof block.consensus_block).toBe("number");
    expect(block.consensus_block).toBeGreaterThan(0);
    expect(typeof block.timestamp).toBe("number");
    expect(block.timestamp).toBeGreaterThan(0);
  });

  // ----- Shards -----

  it("getShards() returns shard information", async () => {
    const shards: ShardInfo = await client.getShards(masterchainInfo.last.seqno);
    expect(shards).toBeDefined();
    expect(shards["@type"]).toBe("blocks.shards");
    expect(Array.isArray(shards.shards)).toBe(true);
  });

  // ----- Readyz -----

  // isReady() may not be available on all node versions — skip if method not found
  it("isReady() returns readiness info", async () => {
    try {
      const result: ReadyzResult = await client.isReady();
      expect(result).toBeDefined();
    } catch (e: unknown) {
      // Method not found is acceptable — not all nodes expose isReady
      const err = e as { rpcCode?: number };
      expect([-32601, -32603]).toContain(err.rpcCode);
    }
  });

  // ----- Balance -----

  it("getBalance(configAddress) returns a non-negative balance string", async () => {
    const balance: string = await client.getBalance(CONFIG_ADDRESS);
    expect(balance).toBeDefined();
    expect(typeof balance).toBe("string");
    const value = BigInt(balance);
    expect(value >= 0n).toBe(true);
  });

  // ----- Address information -----

  it("getAddressInformation(configAddress) returns AccountInfo with state", async () => {
    const info: AccountInfo = await client.getAddressInformation(CONFIG_ADDRESS);
    expect(info).toBeDefined();
    expect(info["@type"]).toBe("raw.fullAccountState");
    expect(info.state).toBeTruthy();
    expect(typeof info.balance).toBe("string");
    expect(info.block_id).toBeDefined();
  });

  // ----- Config param -----

  it("getConfigParam(0) returns config with bytes field", async () => {
    const result = await client.getConfigParam(0);
    expect(result).toBeDefined();
    expect(result.config).toBeDefined();
    expect(typeof result.config.bytes).toBe("string");
    expect(result.config.bytes.length).toBeGreaterThan(0);
  });

  // ----- Config all -----

  it("getConfigAll() returns ConfigAll with config bytes", async () => {
    const result: ConfigAll = await client.getConfigAll();
    expect(result).toBeDefined();
    expect(result["@type"]).toBe("configInfo");
    expect(result.config).toBeDefined();
    expect(result.config["@type"]).toBe("tvm.cell");
    expect(typeof result.config.bytes).toBe("string");
    expect(result.config.bytes.length).toBeGreaterThan(0);
  });

  // ----- Out message queue size -----

  it("getOutMsgQueueSize() returns queue size info", async () => {
    const result: OutMsgQueueSize = await client.getOutMsgQueueSize();
    expect(result).toBeDefined();
    expect(result["@type"]).toBe("blocks.outMsgQueueSizes");
    expect(Array.isArray(result.shards)).toBe(true);
  });

  // ----- Lookup block -----

  it("lookupBlock(-1, shard, 1) returns a BlockIdExt for masterchain block 1", async () => {
    const block: BlockIdExt = await client.lookupBlock(-1, MC_SHARD, 1);
    expect(block).toBeDefined();
    expect(block["@type"]).toBe("tos.blockIdExt");
    expect(block.workchain).toBe(-1);
    expect(block.seqno).toBe(1);
    expect(block.shard).toBeTruthy();
    expect(block.root_hash).toBeTruthy();
    expect(block.file_hash).toBeTruthy();
  });

  // ----- Block header -----

  it("getBlockHeader(-1, shard, seqno) returns a BlockHeader", async () => {
    const { shard, seqno } = masterchainInfo.last;
    const header: BlockHeader = await client.getBlockHeader(-1, shard, seqno);
    expect(header).toBeDefined();
    expect(header["@type"]).toBe("blocks.header");
    expect(header.id).toBeDefined();
    expect(header.id.seqno).toBe(seqno);
    expect(typeof header.global_id).toBe("number");
    expect(typeof header.gen_utime).toBe("number");
    expect(typeof header.start_lt).toBe("string");
  });

  // ----- Transactions -----

  it("getTransactions(address, 5) returns a Transaction[]", async () => {
    const result: Transaction[] = await client.getTransactions(ELECTOR_ADDRESS, 5);
    expect(result).toBeDefined();
    // C++ returns an array directly, not a wrapper object
    expect(Array.isArray(result)).toBe(true);
    if (Array.isArray(result) && result.length > 0) {
      expect(result[0]!["@type"]).toBe("raw.transaction");
    }
  });

  // ----- runGetMethod -----

  it('runGetMethod on elector (active_election_id) returns RunResult', async () => {
    const result: RunResult = await client.runGetMethod(
      ELECTOR_ADDRESS,
      "active_election_id",
    );
    expect(result).toBeDefined();
    expect(result["@type"]).toBe("smc.runResult");
    expect(typeof result.gas_used).toBe("number");
    expect(typeof result.exit_code).toBe("number");
    // exit_code 0 means success
    expect(result.exit_code).toBe(0);
    expect(Array.isArray(result.stack)).toBe(true);
    // Should return at least one stack element (the election id)
    expect(result.stack.length).toBeGreaterThanOrEqual(1);
  });
});

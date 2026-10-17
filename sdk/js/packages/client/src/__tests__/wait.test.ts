/**
 * The confirmation helpers against the answers a testnet node gave during the
 * WAL-01 journey: finding a settled transfer by the hash sendQuery returned,
 * and telling a delivered transfer from one the chain executed but skipped.
 */

import { describe, expect, it } from "vitest";
import {
  ErrorCodes,
  TosError,
  TosNotDeliveredError,
  requireDelivered,
  waitForTransaction,
  waitForTransfer,
} from "../index.js";
import type { Transaction } from "../index.js";
import { WAL01_WALLET, result, rpcError, stubbedClient, wal01 } from "./nodeStub.js";

const FAST = { timeout: 200, pollInterval: 1 };

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("the call did not fail");
}

function base64ToHex(b64: string): string {
  return Array.from(atob(b64), (c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
}

describe("waitForTransaction", () => {
  it("finds the settled transfer by the message hash sendQuery returned", async () => {
    const node = wal01();
    const { client, requests } = stubbedClient([
      result(node.getTransactionsBeforeSettlement),
      result(node.getTransactionsAfterSettlement),
    ]);
    const tx = await waitForTransaction(client, WAL01_WALLET, node.sendQueryTransfer.hash, FAST);
    // The hash sendQuery returns is the inbound message's, not the transaction's.
    expect(tx.in_msg?.hash).toBe(node.sendQueryTransfer.hash);
    expect(tx.transaction_id.hash).toBe("xzsPjRPIkuHhvu28keKHn2Fs3ZgtNWBYpPQTz0GNiSE=");
    expect(tx.transaction_id.hash).not.toBe(node.sendQueryTransfer.hash);
    expect(requests.map((r) => r.method)).toEqual(["getTransactions", "getTransactions"]);
    expect(requests[0]?.params.address).toBe(WAL01_WALLET);
  });

  it("compares bytes, so a hex or base64url spelling of the hash matches", async () => {
    const node = wal01();
    const hash = node.sendQueryTransfer.hash;
    const urlSafe = hash.replace(/\+/g, "-").replace(/\//g, "_").replace(/=$/, "");
    for (const spelling of [base64ToHex(hash), base64ToHex(hash).toUpperCase(), urlSafe]) {
      const { client } = stubbedClient([result(node.getTransactionsAfterSettlement)]);
      const tx = await waitForTransaction(client, WAL01_WALLET, spelling, FAST);
      expect(tx.transaction_id.lt).toBe("547749000001");
    }
  });

  it("does not take a transaction hash for the message hash", async () => {
    const node = wal01();
    const answers = Array.from({ length: 400 }, () => result(node.getTransactionsAfterSettlement));
    const { client } = stubbedClient(answers);
    const err = await rejection(
      waitForTransaction(
        client,
        WAL01_WALLET,
        "xzsPjRPIkuHhvu28keKHn2Fs3ZgtNWBYpPQTz0GNiSE=",
        FAST,
      ),
    );
    expect(err).toBeInstanceOf(TosError);
    expect((err as TosError).code).toBe(ErrorCodes.WAIT_TIMEOUT);
  });

  it("refuses a hash that is not 32 bytes before asking the node", async () => {
    const { client, requests } = stubbedClient([]);
    for (const bad of [
      "",
      "not-a-hash",
      "7hQvTcDxTBPE3ywPGwBdFGyDoGqfKhAxLLzWO288co=",
      "ab".repeat(31),
    ]) {
      const err = await rejection(waitForTransaction(client, WAL01_WALLET, bad, FAST));
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
    expect(requests).toHaveLength(0);
  });

  it("polls through a retryable server error but stops at a permanent one", async () => {
    const node = wal01();
    const transient = stubbedClient([
      rpcError(-32603, "UPSTREAM_UNAVAILABLE", true),
      result(node.getTransactionsAfterSettlement),
    ]);
    const tx = await waitForTransaction(
      transient.client,
      WAL01_WALLET,
      node.sendQueryTransfer.hash,
      FAST,
    );
    expect(tx.transaction_id.lt).toBe("547749000001");

    const permanent = stubbedClient([rpcError(-32602, "INVALID_ARGUMENT", false)]);
    const err = await rejection(
      waitForTransaction(permanent.client, WAL01_WALLET, node.sendQueryTransfer.hash, FAST),
    );
    expect((err as { reason?: string }).reason).toBe("INVALID_ARGUMENT");
    expect(permanent.requests).toHaveLength(1);
  });

  it("refuses an in_msg.hash that is not a hash instead of skipping it", async () => {
    const node = wal01();
    const broken = node.getTransactionsAfterSettlement;
    (broken[0]?.in_msg as Record<string, unknown>).hash = "garbage";
    const { client } = stubbedClient([result(broken)]);
    const err = await rejection(
      waitForTransaction(client, WAL01_WALLET, node.sendQueryTransfer.hash, FAST),
    );
    expect((err as TosError).code).toBe(ErrorCodes.INVALID_RESPONSE);
  });
});

describe("waitForTransfer", () => {
  it("confirms the settled one-message transfer", async () => {
    const node = wal01();
    const { client } = stubbedClient([result(node.getTransactionsAfterSettlement)]);
    const tx = await waitForTransfer(
      client,
      WAL01_WALLET,
      { hash: node.sendQueryTransfer.hash, outMessages: 1 },
      FAST,
    );
    expect(tx.out_msgs).toHaveLength(1);
    expect(tx.out_msgs[0]?.value).toBe("50000000");
  });

  it("confirms the deployment, which creates no outgoing message", async () => {
    const node = wal01();
    const { client } = stubbedClient([result(node.getTransactionsAfterSettlement)]);
    const tx = await waitForTransfer(
      client,
      WAL01_WALLET,
      { hash: node.sendQueryDeploy.hash, outMessages: 0 },
      FAST,
    );
    expect(tx.compute).toMatchObject({ skipped: false, success: true, account_activated: true });
  });

  it("reports the overdraw as not delivered although the transaction succeeded", async () => {
    const node = wal01();
    const { client } = stubbedClient([
      result([node.overdrawTransaction, ...node.getTransactionsAfterSettlement]),
    ]);
    const err = await rejection(
      waitForTransfer(
        client,
        WAL01_WALLET,
        { hash: node.sendQueryOverdraw.hash, outMessages: 1 },
        FAST,
      ),
    );
    expect(err).toBeInstanceOf(TosNotDeliveredError);
    expect((err as TosNotDeliveredError).code).toBe(ErrorCodes.NOT_DELIVERED);
    expect((err as TosNotDeliveredError).reason).toContain(
      "carried 1 outgoing message(s) but the transaction created 0",
    );
    expect(((err as TosNotDeliveredError).transaction as Transaction).fee).toBe("620084");
  });
});

describe("requireDelivered", () => {
  function settledTransfer(): Transaction {
    const node = wal01();
    return node.getTransactionsAfterSettlement[0] as unknown as Transaction;
  }

  function reasonOf(tx: Transaction, expected: number): string {
    try {
      requireDelivered(tx, expected);
    } catch (err) {
      expect(err).toBeInstanceOf(TosNotDeliveredError);
      return (err as TosNotDeliveredError).reason;
    }
    throw new Error("the transaction was accepted as delivered");
  }

  it("accepts the settled transfer for exactly its message count", () => {
    expect(() => requireDelivered(settledTransfer(), 1)).not.toThrow();
    expect(reasonOf(settledTransfer(), 2)).toContain(
      "carried 2 outgoing message(s) but the transaction created 1",
    );
  });

  it("refuses the bounced funding transaction: aborted, compute skipped", () => {
    const funding = wal01().getTransactionsAfterSettlement[2] as unknown as Transaction;
    expect(funding.aborted).toBe(true);
    expect(reasonOf(funding, 0)).toBe("the transaction aborted");
  });

  it("refuses a failed or skipped compute phase", () => {
    const outOfGas = settledTransfer();
    // Out of gas after the contract committed still reports success; the exit code tells.
    outOfGas.compute = {
      skipped: false,
      success: true,
      exit_code: -14,
      vm_steps: 112,
      account_activated: false,
    };
    expect(reasonOf(outOfGas, 1)).toBe("the compute phase failed with exit code -14");

    const failed = settledTransfer();
    failed.compute = {
      skipped: false,
      success: false,
      exit_code: 0,
      vm_steps: 112,
      account_activated: false,
    };
    expect(reasonOf(failed, 1)).toBe("the compute phase failed with exit code 0");

    const skipped = settledTransfer();
    skipped.compute = { skipped: true, skip_reason: 0 };
    expect(reasonOf(skipped, 1)).toBe("the compute phase was skipped (reason 0)");

    const missing = settledTransfer();
    missing.compute = null;
    expect(reasonOf(missing, 1)).toBe("the node reported no compute phase");
  });

  it("refuses a failed or missing action phase", () => {
    const failed = settledTransfer();
    if (!failed.action) throw new Error("fixture has an action phase");
    failed.action.success = false;
    failed.action.result_code = 37;
    expect(reasonOf(failed, 1)).toBe("the action phase failed with result code 37");

    const missing = settledTransfer();
    missing.action = null;
    expect(reasonOf(missing, 1)).toBe("the transaction has no action phase");
  });

  it("refuses an aborted flag the node did not report, and a non-ordinary transaction", () => {
    const unknown = settledTransfer();
    unknown.aborted = null;
    expect(reasonOf(unknown, 1)).toBe("the node did not report whether the transaction aborted");

    const tick = settledTransfer();
    tick.transaction_type = "tick";
    expect(reasonOf(tick, 1)).toBe("the transaction type is tick, not ordinary");
  });

  it("refuses a message count that is not a non-negative integer", () => {
    for (const bad of [-1, 1.5, Number.NaN]) {
      const err = (() => {
        try {
          requireDelivered(settledTransfer(), bad);
        } catch (e) {
          return e;
        }
        return null;
      })();
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
  });
});

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
  waitForReceipt,
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

/** A 32-byte hash, base64, distinct for each index. */
function syntheticHash(index: number): string {
  const bytes = new Uint8Array(32).fill(0xa5);
  bytes[0] = index & 0xff;
  bytes[1] = (index >> 8) & 0xff;
  return btoa(String.fromCharCode(...bytes));
}

/**
 * `count` transactions newer than the settled transfer, in the node's shape:
 * copies of the verbatim settled transfer with their own lt, transaction hash
 * and inbound message hash, newest first.
 */
function intervening(count: number): Array<Record<string, unknown>> {
  const template = wal01().getTransactionsAfterSettlement[0] as Record<string, unknown>;
  return Array.from({ length: count }, (_, i) => {
    const tx = JSON.parse(JSON.stringify(template)) as Record<string, unknown>;
    const lt = (547_800_000_001n + BigInt(count - i) * 1_000_000n).toString();
    tx.transaction_id = { "@type": "internal.transactionId", lt, hash: syntheticHash(1000 + i) };
    tx.in_msg = { hash: syntheticHash(i), kind: "external" };
    tx.in_msg_hash = syntheticHash(i);
    return tx;
  });
}

describe("waitForTransaction paging", () => {
  it("pages back past more than 16 newer transactions to the one looked for", async () => {
    const node = wal01();
    const newer = intervening(20);
    const older = node.getTransactionsAfterSettlement;
    const cursor = newer[15] as { transaction_id: { lt: string; hash: string } };
    // The node answers 16 per page; a page that starts at a cursor repeats it.
    const { client, requests } = stubbedClient([
      result(newer.slice(0, 16)),
      result([...newer.slice(15), ...older]),
    ]);
    const tx = await waitForTransaction(client, WAL01_WALLET, node.sendQueryTransfer.hash, FAST);
    expect(tx.transaction_id.lt).toBe("547749000001");
    expect(requests).toHaveLength(2);
    expect(requests[0]?.params).toEqual({ address: WAL01_WALLET, limit: 16 });
    expect(requests[1]?.params).toEqual({
      address: WAL01_WALLET,
      limit: 16,
      lt: cursor.transaction_id.lt,
      hash: cursor.transaction_id.hash,
    });
  });

  it("stops paging at afterLt, the history before the message was sent", async () => {
    const node = wal01();
    const newer = intervening(20);
    const afterLt = (newer[10] as { transaction_id: { lt: string } }).transaction_id.lt;
    const answers = Array.from({ length: 400 }, () => result(newer.slice(0, 16)));
    const { client, requests } = stubbedClient(answers);
    const err = await rejection(
      waitForTransaction(client, WAL01_WALLET, node.sendQueryTransfer.hash, { ...FAST, afterLt }),
    );
    expect((err as TosError).code).toBe(ErrorCodes.WAIT_TIMEOUT);
    // Every poll read one page only: its oldest transaction is already at or before afterLt.
    expect(requests.every((r) => r.params.lt === undefined)).toBe(true);
  });

  it("waitForTransfer stops at the afterLt the wallet recorded when sending", async () => {
    const node = wal01();
    const newer = intervening(20);
    const afterLt = (newer[10] as { transaction_id: { lt: string } }).transaction_id.lt;
    const answers = Array.from({ length: 400 }, () => result(newer.slice(0, 16)));
    const { client, requests } = stubbedClient(answers);
    const err = await rejection(
      waitForTransfer(
        client,
        WAL01_WALLET,
        { hash: node.sendQueryTransfer.hash, outMessages: 1, afterLt },
        FAST,
      ),
    );
    expect((err as TosError).code).toBe(ErrorCodes.WAIT_TIMEOUT);
    expect(requests.every((r) => r.params.lt === undefined)).toBe(true);
  });

  it("refuses an afterLt that is not a decimal lt", async () => {
    const { client, requests } = stubbedClient([]);
    for (const afterLt of ["", "-1", "12a", "1e9"]) {
      const err = await rejection(
        waitForTransaction(client, WAL01_WALLET, wal01().sendQueryTransfer.hash, {
          ...FAST,
          afterLt,
        }),
      );
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
    expect(requests).toHaveLength(0);
  });

  it("says a timeout leaves the outcome unknown", async () => {
    const node = wal01();
    const { client } = stubbedClient(
      Array.from({ length: 400 }, () => result(node.getTransactionsBeforeSettlement)),
    );
    const err = await rejection(
      waitForTransaction(client, WAL01_WALLET, node.sendQueryTransfer.hash, FAST),
    );
    expect((err as TosError).code).toBe(ErrorCodes.WAIT_TIMEOUT);
    expect((err as Error).message).toContain("outcome is unknown");
    expect((err as Error).message).toContain("do not resend it before then");
  });
});

describe("a partly delivered transfer", () => {
  it("lists the messages that did leave, so only the missing ones are resent", async () => {
    const node = wal01();
    const { client } = stubbedClient([result(node.getTransactionsAfterSettlement)]);
    // The settled transaction created one message; a transfer of two would
    // have had its second skipped.
    const err = await rejection(
      waitForTransfer(
        client,
        WAL01_WALLET,
        { hash: node.sendQueryTransfer.hash, outMessages: 2 },
        FAST,
      ),
    );
    expect(err).toBeInstanceOf(TosNotDeliveredError);
    const notDelivered = err as TosNotDeliveredError;
    expect(notDelivered.createdMessages).toHaveLength(1);
    expect(notDelivered.createdMessages[0]).toMatchObject({
      kind: "internal",
      destination: "EQD7mCj9E4FaMdVtLv66iStmPYp-dBCxSQSitp1hdf0N-Z77",
      value: "50000000",
    });
    expect(notDelivered.message).toContain("1 outgoing message(s) did leave the wallet");
  });

  it("lists none when nothing left", async () => {
    const node = wal01();
    const { client } = stubbedClient([result([node.overdrawTransaction])]);
    const err = await rejection(
      waitForTransfer(
        client,
        WAL01_WALLET,
        { hash: node.sendQueryOverdraw.hash, outMessages: 1 },
        FAST,
      ),
    );
    expect((err as TosNotDeliveredError).createdMessages).toEqual([]);
    expect((err as Error).message).not.toContain("did leave");
  });
});

describe("waitForReceipt", () => {
  it("follows an internal message to the recipient's transaction", async () => {
    const node = wal01();
    // The funding message from the relayer, as the relayer's out_msgs list
    // it, and the wallet's transaction that executed it.
    const funding = node.getTransactionsAfterSettlement[2] as unknown as Transaction;
    const message = funding.in_msg;
    if (message === null) throw new Error("fixture has an inbound message");
    const { client, requests } = stubbedClient([result(node.getTransactionsAfterSettlement)]);
    const receipt = await waitForReceipt(client, message, FAST);
    expect(receipt.transaction_id.lt).toBe("547679000003");
    expect(requests[0]?.params.address).toBe("EQCqo-2kE8Sd-muQY1bOKdNez_X4_cIIJ-be2ATRb_tXAn9i");
  });

  it("refuses a message that is not internal or has no destination", async () => {
    const { client, requests } = stubbedClient([]);
    const external = { hash: wal01().sendQueryTransfer.hash, kind: "external" as const };
    const toWallet = {
      ...external,
      destination: "EQCqo-2kE8Sd-muQY1bOKdNez_X4_cIIJ-be2ATRb_tXAn9i",
    };
    for (const message of [external, toWallet, { ...external, kind: "internal" as const }]) {
      const err = await rejection(waitForReceipt(client, message, FAST));
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
    expect(requests).toHaveLength(0);
  });
});

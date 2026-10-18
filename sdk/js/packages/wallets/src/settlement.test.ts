/**
 * The wallet send path against the answers a testnet node gave during the
 * WAL-01 journey: an undeployed wallet, an unaffordable transfer, a transfer
 * the chain executed but skipped, and the deployment's hash.
 */

import {
  ErrorCodes,
  TosError,
  TosNotDeliveredError,
  TosNotDeployedError,
  open,
  waitForTransfer,
} from "@tos/client";
import type { ContractLike, PendingTransfer, Signer, TosClient } from "@tos/client";
import { Address, type Cell, hexToBytes, toNano } from "@tos/core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WAL01_WALLET, result, stubbedClient, wal01 } from "../../client/src/__tests__/nodeStub.js";
import { WalletV3R2 } from "./WalletV3R2.js";
import { WalletV4R2 } from "./WalletV4R2.js";
import { WalletV5R1 } from "./WalletV5R1.js";
import type { SendTransferArgs } from "./types.js";

// The WAL-01 wallet: WalletV4R2 on network 2.
const PUBLIC_KEY = hexToBytes("b6c305a641601659988bb52ef95dc1e763c6f936b18c088130cd97d8cb28a232");
const NETWORK = 2;
const DESTINATION = Address.parse("EQD7mCj9E4FaMdVtLv66iStmPYp-dBCxSQSitp1hdf0N-Z77");
const SIGNER: Signer = {
  address: Address.parse(WAL01_WALLET),
  sign: async () => new Uint8Array(64),
} as unknown as Signer;
const FAST = { timeout: 200, pollInterval: 1 };

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("the call did not fail");
}

function wal01Wallet() {
  const wallet = WalletV4R2.create({ publicKey: PUBLIC_KEY, networkGlobalId: NETWORK });
  expect(wallet.address.toRawString()).toBe(WAL01_WALLET);
  return wallet;
}

/** The wallet methods these tests call, as open() exposes them. */
interface OpenedWallet {
  getSeqno(): Promise<number>;
  sendTransfer(via: Signer, args: SendTransferArgs): Promise<PendingTransfer>;
  sendDeploy(via: Signer, value: bigint): Promise<PendingTransfer>;
}

function openWallet(client: TosClient): OpenedWallet {
  return open(wal01Wallet() as unknown as ContractLike, client) as unknown as OpenedWallet;
}

/** The node answers sendTransfer reads before signing, at the overdraw step. */
function beforeOverdraw() {
  const node = wal01();
  return {
    node,
    balance: BigInt(node.getAddressInformationBeforeOverdraw.balance),
    reads: [
      result(node.runGetMethodSeqnoBeforeOverdraw),
      result(node.getAddressInformationBeforeOverdraw),
    ],
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("an undeployed wallet", () => {
  it("getSeqno says the wallet is not deployed instead of reading an empty stack", async () => {
    const node = wal01();
    const { client } = stubbedClient([result(node.runGetMethodUndeployed)]);
    const err = await rejection(openWallet(client).getSeqno());
    expect(err).toBeInstanceOf(TosNotDeployedError);
    expect((err as TosNotDeployedError).code).toBe(ErrorCodes.NOT_DEPLOYED);
    expect((err as TosNotDeployedError).address).toBe(WAL01_WALLET);
    expect((err as Error).message).toContain("not deployed");
  });

  it("sendTransfer refuses before signing anything", async () => {
    const node = wal01();
    const { client, requests } = stubbedClient([result(node.runGetMethodUndeployed)]);
    const sign = vi.fn(async () => new Uint8Array(64));
    const err = await rejection(
      openWallet(client).sendTransfer({ ...SIGNER, sign } as Signer, {
        messages: [{ to: DESTINATION, value: toNano("0.05") }],
      }),
    );
    expect(err).toBeInstanceOf(TosNotDeployedError);
    expect(sign).not.toHaveBeenCalled();
    expect(requests.map((r) => r.method)).toEqual(["runGetMethod"]);
  });

  it("refuses any other failed get-method exit instead of reading its stack", async () => {
    const node = wal01();
    const failed = { ...(node.runGetMethodSeqnoBeforeOverdraw as object), exit_code: 11 };
    const { client } = stubbedClient([result(failed)]);
    const err = await rejection(openWallet(client).getSeqno());
    expect((err as TosError).code).toBe(ErrorCodes.CONTRACT_ERROR);
    expect((err as { exitCode?: number }).exitCode).toBe(11);
  });
});

describe("sendDeploy", () => {
  it("returns the node's message hash, with no outgoing message expected", async () => {
    const node = wal01();
    const { client, requests } = stubbedClient([result("uninitialized"), result(node.sendQueryDeploy)]);
    const sent = await openWallet(client).sendDeploy(SIGNER, 0n);
    expect(sent).toEqual({ hash: node.sendQueryDeploy.hash, outMessages: 0 });
    expect(requests.map((r) => r.method)).toEqual(["getAddressState", "sendQuery"]);
    expect(requests[1]?.params.init_code).toBeDefined();
    expect(requests[1]?.params.init_data).toBeDefined();
  });

  it("is confirmed by waitForTransfer once the deployment settled", async () => {
    const node = wal01();
    const { client } = stubbedClient([
      result("uninitialized"),
      result(node.sendQueryDeploy),
      result(node.getTransactionsAfterSettlement),
    ]);
    const opened = openWallet(client);
    const sent = await opened.sendDeploy(SIGNER, 0n);
    const tx = await waitForTransfer(client, WAL01_WALLET, sent, FAST);
    expect(tx.transaction_id.lt).toBe("547701000001");
  });
});

describe("an unaffordable transfer", () => {
  it("balance + 1 TOS, the WAL-01 overdraw, is refused before signing", async () => {
    const { balance, reads } = beforeOverdraw();
    const { client, requests } = stubbedClient(reads);
    const sign = vi.fn(async () => new Uint8Array(64));
    const err = await rejection(
      openWallet(client).sendTransfer({ ...SIGNER, sign } as Signer, {
        messages: [{ to: DESTINATION, value: balance + toNano("1") }],
      }),
    );
    expect(err).toBeInstanceOf(TosError);
    expect((err as TosError).code).toBe(ErrorCodes.INSUFFICIENT_BALANCE);
    expect(sign).not.toHaveBeenCalled();
    expect(requests.map((r) => r.method)).toEqual(["runGetMethod", "getAddressInformation"]);
  });

  it("the whole balance is refused too, and the sum of every message counts", async () => {
    for (const messages of [
      (b: bigint) => [{ to: DESTINATION, value: b }],
      (b: bigint) => [
        { to: DESTINATION, value: b / 2n },
        { to: DESTINATION, value: b - b / 2n },
      ],
    ]) {
      const { balance, reads } = beforeOverdraw();
      const { client } = stubbedClient(reads);
      const err = await rejection(
        openWallet(client).sendTransfer(SIGNER, { messages: messages(balance) }),
      );
      expect((err as TosError).code).toBe(ErrorCodes.INSUFFICIENT_BALANCE);
    }
  });

  it("a message carrying the whole balance (mode 128) is not counted by its value", async () => {
    const { node, balance, reads } = beforeOverdraw();
    const { client } = stubbedClient([...reads, result("active"), result(node.sendQueryOverdraw)]);
    const sent = await openWallet(client).sendTransfer(SIGNER, {
      messages: [{ to: DESTINATION, value: balance * 2n, mode: 128 }],
    });
    expect(sent.outMessages).toBe(1);
  });

  it("one that fits the balance but not its fees is sent, and waitForTransfer reports it undelivered", async () => {
    const { node, balance, reads } = beforeOverdraw();
    const { client, requests } = stubbedClient([
      ...reads,
      result("active"),
      result(node.sendQueryOverdraw),
      result([node.overdrawTransaction, ...node.getTransactionsAfterSettlement]),
    ]);
    const opened = openWallet(client);
    const sent = await opened.sendTransfer(SIGNER, {
      messages: [{ to: DESTINATION, value: balance - 1n }],
    });
    // afterLt is the last transaction the node reported before the send.
    expect(sent).toEqual({ hash: node.sendQueryOverdraw.hash, outMessages: 1, afterLt: "548059000001" });
    expect(requests[2]?.params.address).toBe(WAL01_WALLET);
    expect(requests[3]?.params.init_code).toBeUndefined();
    expect(requests[3]?.params.init_data).toBeUndefined();
    const err = await rejection(waitForTransfer(client, WAL01_WALLET, sent, FAST));
    expect(err).toBeInstanceOf(TosNotDeliveredError);
    expect(requests.map((r) => r.method)).toEqual([
      "runGetMethod",
      "getAddressInformation",
      "getAddressState",
      "sendQuery",
      "getTransactions",
    ]);
  });
});

describe.each([
  ["WalletV3R2", WalletV3R2],
  ["WalletV4R2", WalletV4R2],
  ["WalletV5R1", WalletV5R1],
] as const)("%s signing inputs", (_name, factory) => {
  const wallet = factory.create({ publicKey: PUBLIC_KEY, networkGlobalId: NETWORK });
  const secretKey = new Uint8Array(64);
  const messages = [{ to: DESTINATION, value: toNano("0.05") }];
  const NOW = 1_792_148_000;

  function pinClock(): void {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW * 1000);
  }

  it("refuses a validUntil that is not after the current time", () => {
    pinClock();
    for (const validUntil of [NOW - 60, NOW, 0]) {
      expect(() => wallet.createTransfer({ seqno: 3, secretKey, messages, validUntil })).toThrow(
        /not after the current time/,
      );
    }
    for (const validUntil of [1.5, -1, 0x1_0000_0000]) {
      expect(() => wallet.createTransfer({ seqno: 3, secretKey, messages, validUntil })).toThrow(
        /uint32 UNIX time/,
      );
    }
    expect(() =>
      wallet.createTransfer({ seqno: 3, secretKey, messages, validUntil: NOW + 1 }),
    ).not.toThrow();
  });

  it("refuses it in createTransferAsync too, before calling the signer", async () => {
    pinClock();
    const signer = vi.fn(async () => new Uint8Array(64));
    await expect(
      wallet.createTransferAsync({ seqno: 3, signer, messages, validUntil: NOW - 1 }),
    ).rejects.toThrow(/not after the current time/);
    expect(signer).not.toHaveBeenCalled();
  });

  it("signs the transfer-level sendMode for messages without their own", () => {
    pinClock();
    const modes = (sendMode?: number, mode?: number) =>
      sentModes(
        wallet.createTransfer({
          seqno: 3,
          secretKey,
          validUntil: NOW + 60,
          sendMode,
          messages: [{ to: DESTINATION, value: toNano("0.05"), mode }],
        }),
      );
    expect(modes()).toEqual([3]);
    expect(modes(1)).toEqual([1]);
    expect(modes(1, 64)).toEqual([64]);
    expect(() => modes(256)).toThrow(/send mode/);
  });

  /** The send-mode bytes of a signed transfer, in message order. */
  function sentModes(body: Cell): number[] {
    const slice = body.beginParse();
    if (wallet instanceof WalletV5R1) {
      // opcode, global id, wallet id, valid until, seqno, then the action list
      slice.loadUint(32);
      slice.loadInt(32);
      slice.loadUint(32);
      slice.loadUint(32);
      slice.loadUint(32);
      const action = slice.loadRef().beginParse();
      action.loadRef(); // previous actions
      action.loadUint(32); // action_send_msg
      return [action.loadUint(8)];
    }
    slice.loadBuffer(64); // signature
    slice.loadInt(32);
    slice.loadUint(32);
    slice.loadUint(32);
    slice.loadUint(32);
    if (wallet instanceof WalletV4R2) slice.loadUint(8); // op
    const out: number[] = [];
    while (slice.remainingRefs > 0) {
      out.push(slice.loadUint(8));
      slice.loadRef();
    }
    return out;
  }
});

// An external message pays an import fee for every cell it carries, and an active
// account ignores a StateInit. So a wallet's StateInit rides along only while the
// wallet is not active yet: the deploy (and an unfreeze), never an ordinary send.

import { Address } from "@tos/core";
import { keyPairFromSeed } from "@tos/crypto";
import { type SendTransferArgs, WalletV4R2 } from "@tos/wallets";
import { describe, expect, it } from "vitest";
import type { Signer } from "./Signer.js";
import type { TosProvider } from "./TosProvider.js";
import { type ContractLike, externalStateInit, open } from "./open.js";

const NETWORK = 42;
const KEY_PAIR = keyPairFromSeed(new Uint8Array(32));
const DEST = new Address(0, new Uint8Array(32));
const TRANSFER: SendTransferArgs = { messages: [{ to: DEST, value: 1n }] };

// Signatures are not checked by the stub node; any 64 bytes will do.
const SIGNER = { sign: async () => new Uint8Array(64) } as unknown as Signer;

interface SentQuery {
  address: unknown;
  body: unknown;
  init_code?: unknown;
  init_data?: unknown;
}

interface StubNode {
  provider: TosProvider;
  sent: SentQuery[];
  stateReads: unknown[];
}

// A node that reports `state` for every account and records what is sent to it.
function stubNode(state: string): StubNode {
  const sent: SentQuery[] = [];
  const stateReads: unknown[] = [];
  const provider = {
    async getState(address: unknown) {
      stateReads.push(address);
      return state;
    },
    async runGetMethod() {
      return { gas_used: 0, exit_code: 0, stack: [["num", "0x5"]] };
    },
    async sendQuery(query: SentQuery) {
      sent.push(query);
      return { hash: "aGFzaA==" };
    },
  } as unknown as TosProvider;
  return { provider, sent, stateReads };
}

function onlySent(node: StubNode): SentQuery {
  expect(node.sent).toHaveLength(1);
  const [query] = node.sent;
  if (query === undefined) {
    throw new Error("nothing was sent");
  }
  return query;
}

function wallet(): WalletV4R2 {
  return WalletV4R2.create({ networkGlobalId: NETWORK, publicKey: KEY_PAIR.publicKey });
}

interface OpenedWallet {
  sendDeploy(via: Signer, value: bigint): Promise<void>;
  sendTransfer(via: Signer, args: SendTransferArgs): Promise<unknown>;
}

function opened(w: WalletV4R2, node: StubNode): OpenedWallet {
  return open(w as unknown as ContractLike, node.provider) as unknown as OpenedWallet;
}

describe("open(): StateInit on external messages", () => {
  it("attaches the StateInit to the deploy of a wallet that does not exist yet", async () => {
    const w = wallet();
    const node = stubNode("uninitialized");
    await opened(w, node).sendDeploy(SIGNER, 0n);
    const sent = onlySent(node);
    expect(sent.init_code).toBe(w.init.code);
    expect(sent.init_data).toBe(w.init.data);
  });

  it("sends an active wallet's transfer without a StateInit", async () => {
    const w = wallet();
    const node = stubNode("active");
    await opened(w, node).sendTransfer(SIGNER, TRANSFER);
    const sent = onlySent(node);
    expect(sent).not.toHaveProperty("init_code");
    expect(sent).not.toHaveProperty("init_data");
    expect(node.stateReads).toEqual([w.address.toRawString()]);
  });

  it("attaches the StateInit to a frozen wallet's message, which needs it to unfreeze", async () => {
    const w = wallet();
    const node = stubNode("frozen");
    await opened(w, node).sendTransfer(SIGNER, TRANSFER);
    const sent = onlySent(node);
    expect(sent.init_code).toBe(w.init.code);
    expect(sent.init_data).toBe(w.init.data);
  });

  it("fails the send, submitting nothing, when the account state cannot be read", async () => {
    const w = wallet();
    const node = stubNode("active");
    const failing = {
      ...(node.provider as unknown as Record<string, unknown>),
      async getState() {
        throw new Error("state unavailable");
      },
    } as unknown as TosProvider;
    const opener = open(w as unknown as ContractLike, failing) as unknown as OpenedWallet;
    await expect(opener.sendDeploy(SIGNER, 0n)).rejects.toThrow("state unavailable");
    expect(node.sent).toEqual([]);
  });

  it("does not read the account state for a contract without a StateInit", async () => {
    const node = stubNode("uninitialized");
    const contract = {
      address: DEST,
      async poke(provider: { external(body: string): Promise<unknown> }) {
        return provider.external("te6cckEBAQEAAgAAAEysuc0=");
      },
    };
    await open(contract, node.provider).poke();
    expect(node.stateReads).toEqual([]);
    expect(onlySent(node)).not.toHaveProperty("init_code");
  });
});

describe("externalStateInit", () => {
  it("gives estimateFee the fields the send uses", async () => {
    const w = wallet();
    for (const state of ["active", "uninitialized", "frozen"]) {
      const node = stubNode(state);
      const fields = await externalStateInit(node.provider, w.address, w.init);
      await opened(w, node).sendTransfer(SIGNER, TRANSFER);
      const { address: _address, body: _body, ...sentInit } = onlySent(node);
      expect(sentInit).toEqual(fields);
    }
  });

  it("is empty without a StateInit", async () => {
    const node = stubNode("uninitialized");
    expect(await externalStateInit(node.provider, DEST, undefined)).toEqual({});
    expect(await externalStateInit(node.provider, DEST, {})).toEqual({});
    expect(node.stateReads).toEqual([]);
  });
});

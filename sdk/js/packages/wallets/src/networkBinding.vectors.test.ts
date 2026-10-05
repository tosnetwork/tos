/**
 * Golden vectors binding the SDK's wallet messages to the real contracts.
 *
 * This test rebuilds, deterministically, the signed external messages the SDK
 * produces for V3R2 and V4R2 on network 42 and on network 43 -- a transfer, and
 * the body sendDeploy submits -- and requires them to equal the committed vector
 * file byte for byte. The native emulator test
 * test/auth-extensions/test_sdk_wallet_vectors.py executes the same file against
 * the wallet code compiled from crypto/smartcont: the network-42 messages must
 * be accepted on a network whose ConfigParam 19 is 42 (the deploy body deploying
 * an uninitialized account from its StateInit), and the network-43 ones refused
 * with exit 36. Either side drifting fails one of the two tests.
 *
 * Regenerate after an intended change with UPDATE_VECTORS=1.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { Address, type Cell, bytesToBase64 } from "@tos/core";
import { keyPairFromSeed, sign } from "@tos/crypto";
import { WalletV3R2 } from "./WalletV3R2.js";
import { WalletV4R2 } from "./WalletV4R2.js";

const VECTORS = resolve(__dirname, "../test-vectors/network-bound-transfers.json");
// The emulator test's clock, one hour of validity, and its network.
const NOW = 1_780_000_000;
const VALID_UNTIL = NOW + 3600;
const EMULATED_NETWORK = 42;
const KEY_PAIR = keyPairFromSeed(new Uint8Array(32).fill(0x42));
const DESTINATION = new Address(-1, new Uint8Array(32).fill(0x20));
const VALUE = 1_000_000_000n;

/** The body sendDeploy submits, signed with the real key. */
async function deployBody(wallet: WalletV3R2 | WalletV4R2): Promise<Cell> {
  let body: Cell | undefined;
  await wallet.sendDeploy(
    {
      external: async (cell: Cell) => {
        body = cell;
      },
    } as never,
    { sign: async (hash: Uint8Array) => sign(hash, KEY_PAIR.secretKey) } as never,
    0n,
  );
  if (!body) {
    throw new Error("sendDeploy submitted no external message");
  }
  return body;
}

async function vectors() {
  const out = [];
  for (const [name, factory] of [
    ["V3R2", WalletV3R2],
    ["V4R2", WalletV4R2],
  ] as const) {
    for (const network of [EMULATED_NETWORK, EMULATED_NETWORK + 1]) {
      const wallet = factory.create({
        publicKey: KEY_PAIR.publicKey,
        networkGlobalId: network,
        workchain: -1,
      });
      const body = wallet.createTransfer({
        seqno: 0,
        secretKey: KEY_PAIR.secretKey,
        validUntil: VALID_UNTIL,
        messages: [{ to: DESTINATION, value: VALUE, bounce: false }],
      });
      const { code, data } = wallet.init;
      if (!code || !data) {
        throw new Error(`${name}: StateInit must carry code and data`);
      }
      out.push({
        wallet: name,
        network,
        address: wallet.address.toRawString(),
        code: bytesToBase64(code.toBoc()),
        data: bytesToBase64(data.toBoc()),
        destination: DESTINATION.toRawString(),
        value: VALUE.toString(),
        body: bytesToBase64(body.toBoc()),
        deploy: bytesToBase64((await deployBody(wallet)).toBoc()),
      });
    }
  }
  return { now: NOW, emulated_network: EMULATED_NETWORK, vectors: out };
}

describe("network-bound wallet vectors", () => {
  it("the SDK still produces exactly the committed vectors", async () => {
    const actual = `${JSON.stringify(await vectors(), null, 2)}\n`;
    if (process.env.UPDATE_VECTORS === "1") {
      writeFileSync(VECTORS, actual);
    }
    expect(actual).toBe(readFileSync(VECTORS, "utf-8"));
  });
});

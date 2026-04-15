import { describe, expect, it } from "vitest";
import { Address, beginCell } from "@tos/core";
import { NftItem } from "./NftItem.js";
import type { ContractGetResult, ContractProvider, ContractState, SendConfirmation } from "@tos/client";

const DUMMY_ADDRESS = new Address(0, new Uint8Array(32));

class MockProvider implements ContractProvider {
  constructor(private readonly result: ContractGetResult) {}

  getState(): Promise<ContractState> {
    throw new Error("not implemented");
  }

  get(): Promise<ContractGetResult> {
    return Promise.resolve(this.result);
  }

  internal(): Promise<SendConfirmation> {
    throw new Error("not implemented");
  }

  external(): Promise<SendConfirmation> {
    throw new Error("not implemented");
  }
}

describe("NftItem", () => {
  it("allows a null ownerAddress for uninitialized NFT items", async () => {
    const result: ContractGetResult = {
      gasUsed: 0,
      exitCode: 0,
      stack: {
        readBoolean: () => false,
        readBigNumber: (() => {
          let calls = 0;
          return () => {
            calls += 1;
            return calls === 1 ? 17n : 0n;
          };
        })(),
        readAddress: (() => {
          let calls = 0;
          return () => {
            calls += 1;
            return calls === 1 ? DUMMY_ADDRESS : null;
          };
        })(),
        readCell: () => beginCell().endCell(),
        readCellOpt: () => null,
        readTuple: () => {
          throw new Error("not implemented");
        },
        remaining: 0,
        readNumber: () => 0,
      },
    };

    const item = NftItem.create(DUMMY_ADDRESS);
    const data = await item.getNftData(new MockProvider(result));

    expect(data.initialized).toBe(false);
    expect(data.index).toBe(17n);
    expect(data.collectionAddress).toBe(DUMMY_ADDRESS);
    expect(data.ownerAddress).toBeNull();
  });
});

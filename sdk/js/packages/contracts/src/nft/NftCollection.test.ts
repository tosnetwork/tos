import { describe, expect, it } from "vitest";
import { Address, beginCell } from "@tos/core";
import { NftCollection } from "./NftCollection.js";
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

describe("NftCollection", () => {
  it("parses get_nft_content off-chain URI stored in snake format", async () => {
    const uri = "https://example.com/nft/item/1.json";
    const content = beginCell()
      .storeUint(0x01, 8)
      .storeStringTail(uri)
      .endCell();

    const result: ContractGetResult = {
      gasUsed: 0,
      exitCode: 0,
      stack: {
        readCell: () => content,
        readBigNumber: () => 0n,
        readBoolean: () => false,
        readAddress: () => DUMMY_ADDRESS,
        readCellOpt: () => null,
        readTuple: () => {
          throw new Error("not implemented");
        },
        remaining: 0,
        readNumber: () => 0,
      },
    };

    const collection = NftCollection.create(DUMMY_ADDRESS);
    const parsed = await collection.getNftContent(
      new MockProvider(result),
      0n,
      beginCell().endCell(),
    );

    expect(parsed).toBe(uri);
  });
});

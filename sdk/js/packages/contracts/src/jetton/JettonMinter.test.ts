import { describe, expect, it } from "vitest";
import { Address, beginCell, Cell } from "@tos/core";
import { JettonMinter } from "./JettonMinter.js";
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

describe("JettonMinter", () => {
  it("parses TEP-64 off-chain content stored in snake format", async () => {
    const uri = "https://example.com/jetton/metadata.json";
    const content = beginCell()
      .storeUint(0x01, 8)
      .storeStringTail(uri)
      .endCell();

    const result: ContractGetResult = {
      gasUsed: 0,
      exitCode: 0,
      stack: {
        readBigNumber: () => 1n,
        readBoolean: () => true,
        readAddress: () => DUMMY_ADDRESS,
        readCell: (() => {
          let calls = 0;
          return () => {
            calls += 1;
            return calls === 1 ? content : new Cell();
          };
        })(),
        readCellOpt: () => null,
        readTuple: () => {
          throw new Error("not implemented");
        },
        remaining: 0,
        readNumber: () => 0,
      },
    };

    const minter = JettonMinter.create(DUMMY_ADDRESS);
    const parsed = await minter.getContent(new MockProvider(result));

    expect(parsed).toEqual({ uri });
  });
});

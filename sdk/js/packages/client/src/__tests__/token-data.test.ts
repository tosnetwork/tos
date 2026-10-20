import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { TokenData } from "../index.js";
import { result, stubbedClient } from "./nodeStub.js";

// The three response variants emitted by handle_getTokenData. Wallet data is
// read through get_wallet_data, not returned by this JSON-RPC method.
const answers = [
  {
    "@type": "ext.tokens.tokenMasterData",
    total_supply: "17", mintable: true, admin_address: "0:" + "11".repeat(32),
    token_content: "content-boc", token_wallet_code: "wallet-boc",
    token_name: "Example", token_symbol: "EX", token_decimals: "9",
  },
  {
    "@type": "ext.tokens.nftCollectionData", next_item_index: "-1",
    collection_content: "collection-boc", owner_address: "0:" + "22".repeat(32),
    collection_metadata_uri: "https://example.invalid/collection.json",
  },
  {
    "@type": "ext.tokens.nftItemData", init: true, index: "1",
    collection_address: "0:" + "22".repeat(32), owner_address: "0:" + "11".repeat(32),
    individual_content: "item-boc", nft_name: "Example item",
  },
] satisfies TokenData[];

function content(value: TokenData): string {
  switch (value["@type"]) {
    case "ext.tokens.tokenMasterData": return value.token_content;
    case "ext.tokens.nftCollectionData": return value.collection_content;
    case "ext.tokens.nftItemData": return value.individual_content;
    default: {
      const unhandled: never = value;
      throw new Error(`Unknown token response: ${unhandled}`);
    }
  }
}

describe("getTokenData wire types", () => {
  it.each(answers)("reads and narrows $@type without a compatibility alias", async (answer) => {
    const { client, requests } = stubbedClient([result(answer)]);
    const address = "0:" + "44".repeat(32);
    const received = await client.getTokenData(address);
    expect(received).toEqual(answer);
    expect(content(received)).toMatch(/-boc$/);
    expect(requests).toEqual([{ method: "getTokenData", params: { address } }]);
  });

  it("uses exactly the discriminants present in the server emitter", () => {
    const source = readFileSync(new URL(
      "../../../../../../validator-engine/json-rpc-server-token.cpp", import.meta.url,
    ), "utf8");
    const emitted = [...source.matchAll(/\\"@type\\":\\"(ext\.tokens\.[A-Za-z]+)\\"/g)]
      .map((match) => match[1]);
    expect(emitted.sort()).toEqual(answers.map((answer) => answer["@type"]).sort());
  });
});

/**
 * TosClient against the JSON-RPC wire contract, with a stubbed fetch: the
 * request it sends (named params, typed block coordinates) and how it reads
 * every kind of answer (result, typed error, admission refusal, malformed).
 */

import { describe, expect, it } from "vitest";
import { ErrorCodes, TosClient, TosError, TosRpcError } from "../index.js";

const MC_SHARD = "-9223372036854775808";

interface Captured {
  url: string;
  body: Record<string, unknown>;
}

type Answer =
  | { status: number; body: string }
  | ((id: unknown) => { status: number; body: string });

/** A client whose fetch answers each request with the next entry of `answers`. */
function stubbed(answers: Answer[], retry = 0): { client: TosClient; requests: Captured[] } {
  const requests: Captured[] = [];
  const fetchStub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    requests.push({ url: String(input), body });
    const next = answers.shift();
    if (next === undefined) {
      throw new Error("unexpected request");
    }
    const { status, body: text } = typeof next === "function" ? next(body.id) : next;
    return new Response(text, { status, headers: { "Content-Type": "application/json" } });
  }) as typeof globalThis.fetch;
  const client = new TosClient({
    endpoint: "http://127.0.0.1:8081/jsonRPC",
    fetch: fetchStub,
    retry,
  });
  return { client, requests };
}

function result(value: unknown): Answer {
  return (id) => ({ status: 200, body: JSON.stringify({ jsonrpc: "2.0", id, result: value }) });
}

function rpcError(
  code: number,
  reason: string,
  retryable: boolean,
  status = 200,
  nullId = false,
): Answer {
  return (id) => ({
    status,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: nullId ? null : id,
      error: {
        code,
        message: `message for ${reason}`,
        data: { schema_version: 1, reason, retryable },
      },
    }),
  });
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  throw new Error("the call did not fail");
}

describe("TosClient request shape", () => {
  it("sends a JSON-RPC 2.0 envelope with an id and named params", async () => {
    const { client, requests } = stubbed([result({ ok: "anything" })]);
    await client.getMasterchainInfo();
    expect(requests).toHaveLength(1);
    expect(requests[0]?.body).toEqual({
      jsonrpc: "2.0",
      id: 1,
      method: "getMasterchainInfo",
      params: {},
    });
  });

  it("refuses positional params before sending", async () => {
    const { client, requests } = stubbed([]);
    const err = await rejection(
      client.rawCall("getMasterchainInfo", [] as unknown as Record<string, unknown>),
    );
    expect(err).toBeInstanceOf(TosError);
    expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    expect(requests).toHaveLength(0);
  });

  it("sends shard as a signed decimal string and seqno/workchain as integers", async () => {
    const { client, requests } = stubbed([result({}), result({}), result({})]);
    await client.getBlockHeader(-1, MC_SHARD, 0);
    await client.lookupBlock(0, "6917529027641081856", 12);
    await client.getBlockTransactions(-1, MC_SHARD, 5, { count: 3 });
    expect(requests[0]?.body.params).toEqual({ workchain: -1, shard: MC_SHARD, seqno: 0 });
    expect(requests[1]?.body.params).toEqual({
      workchain: 0,
      shard: "6917529027641081856",
      seqno: 12,
    });
    expect(requests[2]?.body.params).toEqual({
      workchain: -1,
      shard: MC_SHARD,
      seqno: 5,
      count: 3,
    });
  });

  it("sends seqno 0 as block 0 and an absent seqno as latest", async () => {
    const { client, requests } = stubbed([result({}), result({})]);
    await client.getConfigParam(19, { seqno: 0 });
    await client.getConfigParam(19);
    expect(requests[0]?.body.params).toEqual({ param: 19, seqno: 0 });
    expect(requests[1]?.body.params).toEqual({ param: 19 });
  });

  it("lookupBlock sends exactly one selector", async () => {
    const { client, requests } = stubbed([result({}), result({})]);
    await client.lookupBlock(-1, MC_SHARD, null, { utime: 1700000000 });
    await client.lookupBlock(-1, MC_SHARD, undefined, { lt: "123" });
    expect(requests[0]?.body.params).toEqual({
      workchain: -1,
      shard: MC_SHARD,
      unixtime: 1700000000,
    });
    expect(requests[1]?.body.params).toEqual({ workchain: -1, shard: MC_SHARD, lt: "123" });
    for (const call of [
      () => client.lookupBlock(-1, MC_SHARD, null),
      () => client.lookupBlock(-1, MC_SHARD, 1, { lt: "2" }),
      () => client.lookupBlock(-1, MC_SHARD, 1, { utime: 3 }),
    ]) {
      const err = await rejection(call());
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
    expect(requests).toHaveLength(2);
  });

  it("refuses non-canonical coordinates before sending", async () => {
    const { client, requests } = stubbed([]);
    const refused = [
      () => client.getBlockHeader(-1, "9223372036854775808", 1),
      () => client.getBlockHeader(-1, "0x8000000000000000", 1),
      () => client.getBlockHeader(-1, "+1", 1),
      () => client.getBlockHeader(-1, "0", 1),
      () => client.getBlockHeader(-1, MC_SHARD, -1),
      () => client.getBlockHeader(-1, MC_SHARD, 1.5),
      () => client.getBlockHeader(-1, MC_SHARD, 2147483648),
      () => client.getBlockHeader(2147483648, MC_SHARD, 1),
      () => client.getShards(-1),
      () => client.getAddressInformation("0:00", { seqno: -1 }),
      () => client.lookupBlock(-1, MC_SHARD, null, { lt: "-1" }),
      () => client.lookupBlock(-1, MC_SHARD, null, { utime: 2147483648 }),
    ];
    for (const call of refused) {
      const err = await rejection(call());
      expect(err).toBeInstanceOf(TosError);
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_PARAMETER);
    }
    expect(requests).toHaveLength(0);
  });
});

describe("TosClient response handling", () => {
  it("returns the result of a success envelope", async () => {
    const { client } = stubbed([result("1234")]);
    expect(await client.getBalance("0:00")).toBe("1234");
  });

  it("surfaces the typed reason, code and retryable flag of an error", async () => {
    const { client } = stubbed([rpcError(-32004, "CONFIG_PARAM_ABSENT", false)]);
    const err = await rejection(client.getConfigParam(43));
    expect(err).toBeInstanceOf(TosRpcError);
    const rpc = err as TosRpcError;
    expect(rpc.rpcCode).toBe(-32004);
    expect(rpc.reason).toBe("CONFIG_PARAM_ABSENT");
    expect(rpc.retryable).toBe(false);
    expect(rpc.httpStatus).toBe(200);
    expect(rpc.message).toBe("message for CONFIG_PARAM_ABSENT");
    expect(rpc.rpcData).toEqual({
      schema_version: 1,
      reason: "CONFIG_PARAM_ABSENT",
      retryable: false,
    });
  });

  it("does not repeat a request after a retryable error object", async () => {
    const { client, requests } = stubbed([rpcError(-32603, "UPSTREAM_UNAVAILABLE", true)], 3);
    const err = (await rejection(client.getMasterchainInfo())) as TosRpcError;
    expect(err.reason).toBe("UPSTREAM_UNAVAILABLE");
    expect(err.retryable).toBe(true);
    expect(requests).toHaveLength(1);
  });

  it("keeps an unknown reason verbatim", async () => {
    const { client } = stubbed([rpcError(-32050, "SOMETHING_NEW", true)]);
    const err = (await rejection(client.getMasterchainInfo())) as TosRpcError;
    expect(err.reason).toBe("SOMETHING_NEW");
    expect(err.retryable).toBe(true);
  });

  it("reads 401 and 429 refusals carrying the error object with a null id", async () => {
    const { client } = stubbed([
      rpcError(-32000, "UNAUTHORIZED", false, 401, true),
      rpcError(-32005, "RATE_LIMITED", true, 429, true),
    ]);
    const unauthorized = (await rejection(client.getMasterchainInfo())) as TosRpcError;
    expect(unauthorized).toBeInstanceOf(TosRpcError);
    expect(unauthorized.reason).toBe("UNAUTHORIZED");
    expect(unauthorized.httpStatus).toBe(401);
    const limited = (await rejection(client.getMasterchainInfo())) as TosRpcError;
    expect(limited.reason).toBe("RATE_LIMITED");
    expect(limited.retryable).toBe(true);
    expect(limited.httpStatus).toBe(429);
  });

  it("treats an HTTP error without an error object as a transport error", async () => {
    const { client } = stubbed([
      { status: 503, body: "upstream down" },
      { status: 404, body: "" },
    ]);
    const unavailable = (await rejection(client.getMasterchainInfo())) as TosError;
    expect(unavailable.code).toBe(ErrorCodes.RETRY_EXHAUSTED);
    expect((unavailable.cause as TosError).code).toBe(ErrorCodes.NETWORK_ERROR);
    const missing = (await rejection(client.getMasterchainInfo())) as TosError;
    expect(missing.code).toBe(ErrorCodes.CLIENT_ERROR);
  });

  it("refuses malformed envelopes", async () => {
    const data = { schema_version: 1, reason: "INTERNAL_ERROR", retryable: false };
    const malformed: Array<(id: unknown) => unknown> = [
      () => [],
      (id) => ({ id, result: {} }),
      (id) => ({ jsonrpc: "1.0", id, result: {} }),
      () => ({ jsonrpc: "2.0", result: {} }),
      () => ({ jsonrpc: "2.0", id: 999, result: {} }),
      () => ({ jsonrpc: "2.0", id: null, result: {} }),
      (id) => ({ jsonrpc: "2.0", id }),
      (id) => ({ jsonrpc: "2.0", id, ok: true, result: {} }),
      (id) => ({ jsonrpc: "2.0", id, result: {}, error: { code: -32603, message: "m", data } }),
      (id) => ({ jsonrpc: "2.0", id, error: "bad" }),
      (id) => ({ jsonrpc: "2.0", id, error: { code: "-32603", message: "m", data } }),
      (id) => ({ jsonrpc: "2.0", id, error: { code: -32603.5, message: "m", data } }),
      (id) => ({ jsonrpc: "2.0", id, error: { code: -32603, data } }),
      (id) => ({ jsonrpc: "2.0", id, error: { code: -32603, message: "m" } }),
      (id) => ({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "m", data: { ...data, schema_version: 2 } },
      }),
      (id) => ({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "m", data: { ...data, reason: "lower" } },
      }),
      (id) => ({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "m", data: { ...data, retryable: "no" } },
      }),
      (id) => ({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: "m", data: { ...data, reason: "CONFIG_PARAM_ABSENT" } },
      }),
    ];
    for (const build of malformed) {
      const { client } = stubbed([(id) => ({ status: 200, body: JSON.stringify(build(id)) })]);
      const err = await rejection(client.getMasterchainInfo());
      expect(err).toBeInstanceOf(TosError);
      expect(err).not.toBeInstanceOf(TosRpcError);
      expect((err as TosError).code).toBe(ErrorCodes.INVALID_RESPONSE);
    }
    const { client } = stubbed([{ status: 200, body: "not json" }]);
    expect(((await rejection(client.getMasterchainInfo())) as TosError).code).toBe(
      ErrorCodes.INVALID_RESPONSE,
    );
  });
});

/**
 * A TosClient whose fetch replays node answers in order, and the WAL-01
 * fixture: answers a public testnet node gave the SDK (see its `_provenance`).
 * Shared by the client and wallet tests.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { TosClient } from "../index.js";

export interface Captured {
  method: string;
  params: Record<string, unknown>;
}

export type Answer = (id: unknown) => { status: number; body: string };

/** A client that answers each request with the next entry of `answers` and records every request. */
export function stubbedClient(answers: Answer[]): { client: TosClient; requests: Captured[] } {
  const requests: Captured[] = [];
  const fetchStub = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as {
      id: unknown;
      method: string;
      params: Record<string, unknown>;
    };
    requests.push({ method: body.method, params: body.params });
    const next = answers.shift();
    if (next === undefined) {
      throw new Error(`unexpected request ${body.method}`);
    }
    const { status, body: text } = next(body.id);
    return new Response(text, { status, headers: { "Content-Type": "application/json" } });
  }) as typeof globalThis.fetch;
  const client = new TosClient({
    endpoint: "http://127.0.0.1:8081/jsonRPC",
    fetch: fetchStub,
    retry: 0,
  });
  return { client, requests };
}

/** A JSON-RPC result. */
export function result(value: unknown): Answer {
  return (id) => ({ status: 200, body: JSON.stringify({ jsonrpc: "2.0", id, result: value }) });
}

/** A typed JSON-RPC error object, as the node sends it. */
export function rpcError(code: number, reason: string, retryable: boolean): Answer {
  return (id) => ({
    status: 200,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: {
        code,
        message: `message for ${reason}`,
        data: { schema_version: 1, reason, retryable },
      },
    }),
  });
}

export interface Wal01Answers {
  runGetMethodUndeployed: unknown;
  sendQueryDeploy: { status: number; hash: string };
  sendQueryTransfer: { status: number; hash: string };
  getTransactionsBeforeSettlement: Array<Record<string, unknown>>;
  getTransactionsAfterSettlement: Array<Record<string, unknown>>;
  getAddressInformationBeforeOverdraw: { balance: string };
  runGetMethodSeqnoBeforeOverdraw: unknown;
  sendQueryOverdraw: { status: number; hash: string };
  overdrawTransaction: Record<string, unknown>;
}

/** A fresh copy of the WAL-01 node answers. */
export function wal01(): Wal01Answers {
  return JSON.parse(
    readFileSync(resolve(__dirname, "fixtures/wal01-node-answers.json"), "utf-8"),
  ) as Wal01Answers;
}

/** The WAL-01 wallet's raw address. */
export const WAL01_WALLET = "0:aaa3eda413c49dfa6b906356ce29d35ecff5f8fdc20827e6ded804d16ffb5702";

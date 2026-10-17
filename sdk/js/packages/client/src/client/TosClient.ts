/**
 * @tos/client — TosClient implementation.
 *
 * Full JSON-RPC 2.0 client that implements the {@link TosProvider} interface.
 * Uses `globalThis.fetch` for isomorphic HTTP.
 */

import type { TosProvider, AddressLike, CellLike, TupleItemLike, BlockQueryOpts } from "../provider/TosProvider.js";
import type {
  AccountInfo,
  ExtendedAccountInfo,
  WalletInfo,
  FeeEstimate,
  MasterchainInfo,
  ConsensusBlock,
  RunResult,
  LocateResult,
  ReadyzResult,
  OutMsgQueueSize,
  BlockIdExt,
  BlockHeader,
  BlockSignatures,
  ShardInfo,
  ShardBlockProof,
  ConfigAll,
  LibraryEntry,
  TokenData,
  AccountCapability,
  DelegationGrant,
  SessionCapability,
  AgentCapability,
  TransactionIntentRequest,
  TransactionIntent,
  SigningPayloadRequest,
  SigningPayload,
  SubmitSignedRequest,
  SubmissionResult,
  BlockTransactions,
  BlockTransactionsExt,
  Transaction,
  SendBocResult,
  SendBocHashResult,
  SendQueryResult,
} from "../types.js";
import { TosError, TosRpcError, ErrorCodes, ErrorReasons } from "../errors.js";
import type { RpcErrorData } from "../errors.js";
import { Cell, base64ToBytes } from "@tos/core";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface TosClientOptions {
  /** JSON-RPC endpoint URL (required). */
  endpoint: string;
  /** Optional API key sent as `X-API-Key` header. */
  apiKey?: string;
  /** Per-request timeout in milliseconds (default 30 000). */
  timeout?: number;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
  /** Maximum retry attempts on transient failures (default 3, 0 = no retry). */
  retry?: number;
  /** Hook called before each HTTP request. */
  onRequest?: (method: string, params: Record<string, unknown>) => void;
  /** Hook called after a successful HTTP response. */
  onResponse?: (method: string, result: unknown) => void;
  /** Hook called on error. */
  onError?: (method: string, error: Error) => void;
}

// ---------------------------------------------------------------------------
// TosClient
// ---------------------------------------------------------------------------

/**
 * Full JSON-RPC 2.0 client for the TOS blockchain.
 *
 * Implements the {@link TosProvider} interface with automatic retries,
 * configurable timeouts, and optional API key authentication.
 *
 * @example
 * ```typescript
 * const client = new TosClient({ endpoint: "https://rpc.tos.network" });
 *
 * // Query account balance
 * const info = await client.getAddressInformation("0:abc...");
 * console.log(info.balance);
 *
 * // Run a get method
 * const result = await client.runGetMethod("0:abc...", "seqno");
 * ```
 */
export class TosClient implements TosProvider {
  private readonly endpoint: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly maxRetries: number;
  private readonly onRequest?: TosClientOptions["onRequest"];
  private readonly onResponse?: TosClientOptions["onResponse"];
  private readonly onError?: TosClientOptions["onError"];
  private requestId = 0;

  /**
   * Create a new TOS JSON-RPC client.
   *
   * @param options - Client configuration (endpoint is required)
   *
   * @example
   * ```typescript
   * // Simple usage
   * const client = new TosClient({ endpoint: "http://localhost:8081" });
   *
   * // With API key and custom timeout
   * const client = new TosClient({
   *   endpoint: "https://rpc.tos.network",
   *   apiKey: "your-api-key",
   *   timeout: 10_000,
   * });
   *
   * // Using network presets
   * const client = new TosClient({ ...Networks.mainnet, apiKey: "..." });
   * ```
   */
  constructor(options: TosClientOptions) {
    this.endpoint = options.endpoint.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeout ?? 30_000;
    this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.maxRetries = options.retry ?? 3;
    this.onRequest = options.onRequest;
    this.onResponse = options.onResponse;
    this.onError = options.onError;
  }

  // -----------------------------------------------------------------------
  // Low-level JSON-RPC transport
  // -----------------------------------------------------------------------

  /**
   * Execute a raw JSON-RPC call with automatic retry on transient failures.
   *
   * Only transport failures (network errors, timeouts, HTTP 5xx without a
   * JSON-RPC error object) are retried. A server error object is never
   * retried here; its `retryable` flag tells the caller whether repeating the
   * request later may succeed.
   *
   * @param method - The JSON-RPC method name
   * @param params - Named method parameters (an object, never an array)
   * @returns The JSON-RPC result
   * @throws {TosRpcError} On a JSON-RPC error object from the server
   * @throws {TosError} On invalid parameters, an invalid response, timeout or exhausted retries
   *
   * @example
   * ```typescript
   * const info = await client.rawCall("getAddressInformation", { address: "0:abc..." });
   * ```
   */
  async rawCall<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    if (typeof params !== "object" || params === null || Array.isArray(params)) {
      throw new TosError(
        "JSON-RPC params must be an object of named parameters",
        ErrorCodes.INVALID_PARAMETER,
      );
    }
    this.onRequest?.(method, params);

    const id = ++this.requestId;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params,
    });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff: 200ms, 400ms, 800ms, ...
        const delay = Math.min(200 * Math.pow(2, attempt - 1), 5000);
        await sleep(delay);
      }

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);

        let response: Response;
        try {
          response = await this.fetchFn(this.endpoint, {
            method: "POST",
            headers,
            body,
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }

        const responseText = await response.text();
        const outcome = parseJsonRpcResponse(response, responseText, id);

        if (outcome.kind === "error") {
          const rpcErr = new TosRpcError(
            outcome.message,
            outcome.code,
            outcome.data,
            response.status,
          );
          this.onError?.(method, rpcErr);
          throw rpcErr;
        }

        const result = outcome.result as T;
        this.onResponse?.(method, result);
        return result;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Do not retry on RPC errors (they are deterministic).
        if (err instanceof TosRpcError) {
          throw err;
        }

        if (err instanceof TosError && !isRetryableError(err)) {
          throw err;
        }

        // AbortError = timeout
        if (lastError.name === "AbortError") {
          lastError = new TosError(
            `Request to ${method} timed out after ${this.timeoutMs}ms`,
            ErrorCodes.TIMEOUT,
            lastError,
          );
        }

        this.onError?.(method, lastError);

        // Last attempt — don't retry.
        if (attempt === this.maxRetries) {
          break;
        }
      }
    }

    throw new TosError(
      `Request to ${method} failed after ${this.maxRetries + 1} attempts: ${lastError?.message}`,
      ErrorCodes.RETRY_EXHAUSTED,
      lastError,
    );
  }

  // -----------------------------------------------------------------------
  // AccountActions
  // -----------------------------------------------------------------------

  /**
   * Get account information including balance, state, code, and data.
   *
   * @param address - Account address (raw string or AddressLike object)
   * @param opts - Optional block query options (e.g. specific seqno)
   * @returns Account information
   *
   * @example
   * ```typescript
   * const info = await client.getAddressInformation("0:abc...");
   * console.log(info.balance, info.state);
   * ```
   */
  async getAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountInfo> {
    return this.rawCall<AccountInfo>("getAddressInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get extended account information with additional details.
   *
   * @param address - Account address
   * @param opts - Optional block query options
   * @returns Extended account information
   */
  async getExtendedAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<ExtendedAccountInfo> {
    return this.rawCall<ExtendedAccountInfo>("getExtendedAddressInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get wallet-specific information including seqno and wallet type.
   *
   * @param address - Wallet address
   * @param opts - Optional block query options
   * @returns Wallet information including seqno
   */
  async getWalletInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<WalletInfo> {
    return this.rawCall<WalletInfo>("getWalletInformation", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  /**
   * Get the account balance in nanoTOS as a string.
   *
   * @param address - Account address
   * @param opts - Optional block query options
   * @returns Balance string in nanoTOS
   */
  async getBalance(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string> {
    return this.rawCall<string>("getAddressBalance", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getState(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string> {
    return this.rawCall<string>("getAddressState", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getAccountCapability(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountCapability> {
    return this.rawCall<AccountCapability>("getAccountCapability", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
  }

  async getAccountDelegations(address: AddressLike | string, opts?: BlockQueryOpts): Promise<DelegationGrant[]> {
    const result = await this.rawCall<{ delegations: DelegationGrant[] }>("getAccountDelegations", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.delegations ?? [];
  }

  async getAccountSessions(address: AddressLike | string, opts?: BlockQueryOpts): Promise<SessionCapability[]> {
    const result = await this.rawCall<{ sessions: SessionCapability[] }>("getAccountSessions", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.sessions ?? [];
  }

  async getAccountAgents(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AgentCapability[]> {
    const result = await this.rawCall<{ agents: AgentCapability[] }>("getAccountAgents", {
      address: toAddrString(address),
      ...seqnoParam(opts),
    });
    return result.agents ?? [];
  }

  // -----------------------------------------------------------------------
  // BlockActions
  // -----------------------------------------------------------------------

  /**
   * Get the current masterchain block info.
   *
   * @returns Masterchain info including the latest seqno
   *
   * @example
   * ```typescript
   * const info = await client.getMasterchainInfo();
   * console.log(info.last.seqno);
   * ```
   */
  async getMasterchainInfo(): Promise<MasterchainInfo> {
    return this.rawCall<MasterchainInfo>("getMasterchainInfo");
  }

  async getConsensusBlock(): Promise<ConsensusBlock> {
    return this.rawCall<ConsensusBlock>("getConsensusBlock");
  }

  /**
   * Look up a block by exactly one of `seqno`, `opts.lt` or `opts.utime`.
   *
   * @param shard - Signed decimal shard id, e.g. `"-9223372036854775808"`
   * @param seqno - Block height, or `null`/`undefined` when selecting by lt or utime
   */
  async lookupBlock(
    workchain: number,
    shard: string,
    seqno?: number | null,
    opts?: { lt?: string; utime?: number },
  ): Promise<BlockIdExt> {
    const selectors = [seqno, opts?.lt, opts?.utime].filter((value) => value != null).length;
    if (selectors !== 1) {
      throw new TosError(
        "lookupBlock needs exactly one of seqno, lt or utime",
        ErrorCodes.INVALID_PARAMETER,
      );
    }
    return this.rawCall<BlockIdExt>("lookupBlock", {
      workchain: workchainValue(workchain),
      shard: shardValue(shard),
      ...(seqno != null ? { seqno: seqnoValue(seqno) } : {}),
      ...(opts?.lt != null ? { lt: ltValue(opts.lt) } : {}),
      ...(opts?.utime != null ? { unixtime: seqnoValue(opts.utime, "utime") } : {}),
    });
  }

  async getBlockHeader(workchain: number, shard: string, seqno: number): Promise<BlockHeader> {
    return this.rawCall<BlockHeader>("getBlockHeader", blockSelector(workchain, shard, seqno));
  }

  async getShards(seqno: number): Promise<ShardInfo> {
    return this.rawCall<ShardInfo>("shards", { seqno: seqnoValue(seqno) });
  }

  async getMasterchainBlockSignatures(seqno: number): Promise<BlockSignatures> {
    return this.rawCall<BlockSignatures>("getMasterchainBlockSignatures", { seqno: seqnoValue(seqno) });
  }

  async getShardBlockProof(workchain: number, shard: string, seqno: number): Promise<ShardBlockProof> {
    return this.rawCall<ShardBlockProof>("getShardBlockProof", blockSelector(workchain, shard, seqno));
  }

  // -----------------------------------------------------------------------
  // TransactionActions
  // -----------------------------------------------------------------------

  async getTransactions(
    address: AddressLike | string,
    limit: number,
    opts?: { lt?: string; hash?: string; to_lt?: string; archival?: boolean },
  ): Promise<Transaction[]> {
    return this.rawCall<Transaction[]>("getTransactions", {
      address: toAddrString(address),
      limit,
      ...(opts?.lt != null ? { lt: opts.lt } : {}),
      ...(opts?.hash != null ? { hash: opts.hash } : {}),
      ...(opts?.to_lt != null ? { to_lt: opts.to_lt } : {}),
      ...(opts?.archival != null ? { archival: opts.archival } : {}),
    });
  }

  async getBlockTransactions(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactions> {
    return this.rawCall<BlockTransactions>("getBlockTransactions", {
      ...blockSelector(workchain, shard, seqno),
      ...(opts?.count != null ? { count: opts.count } : {}),
      ...(opts?.after_lt != null ? { after_lt: opts.after_lt } : {}),
      ...(opts?.after_hash != null ? { after_hash: opts.after_hash } : {}),
    });
  }

  async getBlockTransactionsExt(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactionsExt> {
    return this.rawCall<BlockTransactionsExt>("getBlockTransactionsExt", {
      ...blockSelector(workchain, shard, seqno),
      ...(opts?.count != null ? { count: opts.count } : {}),
      ...(opts?.after_lt != null ? { after_lt: opts.after_lt } : {}),
      ...(opts?.after_hash != null ? { after_hash: opts.after_hash } : {}),
    });
  }

  async tryLocateTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  async tryLocateResultTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateResultTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  async tryLocateSourceTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult> {
    return this.rawCall<LocateResult>("tryLocateSourceTx", {
      source: toAddrString(source),
      destination: toAddrString(destination),
      created_lt,
    });
  }

  // -----------------------------------------------------------------------
  // ContractActions
  // -----------------------------------------------------------------------

  /**
   * Execute a get-method on a smart contract.
   *
   * @param address - Contract address
   * @param method - Get-method name or numeric ID
   * @param stack - Optional TVM stack arguments
   * @param opts - Optional block query options
   * @returns The get-method result including exit code and stack
   *
   * @example
   * ```typescript
   * const result = await client.runGetMethod("0:abc...", "seqno");
   * console.log(result.exit_code, result.stack);
   * ```
   */
  async runGetMethod(
    address: AddressLike | string,
    method: string | number,
    stack?: TupleItemLike[],
    opts?: BlockQueryOpts,
  ): Promise<RunResult> {
    return this.rawCall<RunResult>("runGetMethod", {
      address: toAddrString(address),
      method,
      stack: serializeStack(stack ?? []),
      ...seqnoParam(opts),
    });
  }

  // -----------------------------------------------------------------------
  // SendActions
  // -----------------------------------------------------------------------

  /**
   * Send a serialized BOC (external message) to the network.
   *
   * @param boc - Serialized message as a Cell, Uint8Array, or base64 string
   * @returns Send result with status
   *
   * @example
   * ```typescript
   * await client.sendBoc(signedMessageCell.toBoc());
   * ```
   */
  async sendBoc(boc: CellLike | Uint8Array | string): Promise<SendBocResult> {
    return this.rawCall<SendBocResult>("sendBoc", {
      boc: toBocString(boc),
    });
  }

  /**
   * Send a serialized BOC and return the transaction hash.
   *
   * @param boc - Serialized message as a Cell, Uint8Array, or base64 string
   * @returns Send result with the message hash
   */
  async sendBocReturnHash(boc: CellLike | Uint8Array | string): Promise<SendBocHashResult> {
    return this.rawCall<SendBocHashResult>("sendBocReturnHash", {
      boc: toBocString(boc),
    });
  }

  async sendQuery(body: {
    address: AddressLike | string;
    body: CellLike | string;
    init_code?: CellLike | string;
    init_data?: CellLike | string;
  }): Promise<SendQueryResult> {
    return this.rawCall<SendQueryResult>("sendQuery", {
      address: toAddrString(body.address),
      body: toBocString(body.body),
      ...(body.init_code != null ? { init_code: toBocString(body.init_code) } : {}),
      ...(body.init_data != null ? { init_data: toBocString(body.init_data) } : {}),
    });
  }

  /**
   * Estimate the fee for a message without actually sending it.
   *
   * The node prices the message `sendQuery` submits for the same arguments,
   * which carries a StateInit exactly when `init_code` or `init_data` is
   * given. Pass them only for an account that is not active yet, as
   * {@link externalStateInit} decides for `open()` sends.
   *
   * @param address - Target contract address
   * @param body - Message body as a Cell or base64 string
   * @param init_code - Init code, for an account that is not active yet
   * @param init_data - Init data, for an account that is not active yet
   * @param ignore_chksig - Whether to ignore signature verification
   * @returns Fee estimate
   */
  async estimateFee(
    address: AddressLike | string,
    body: CellLike | string,
    init_code?: CellLike | string,
    init_data?: CellLike | string,
    ignore_chksig?: boolean,
  ): Promise<FeeEstimate> {
    return this.rawCall<FeeEstimate>("estimateFee", {
      address: toAddrString(address),
      body: toBocString(body),
      ...(init_code != null ? { init_code: toBocString(init_code) } : {}),
      ...(init_data != null ? { init_data: toBocString(init_data) } : {}),
      ...(ignore_chksig != null ? { ignore_chksig } : {}),
    });
  }

  // -----------------------------------------------------------------------
  // IntentActions
  // -----------------------------------------------------------------------

  async buildTransactionIntent(request: TransactionIntentRequest): Promise<TransactionIntent> {
    return this.rawCall<TransactionIntent>("buildTransactionIntent", { ...request });
  }

  async getSigningPayload(request: SigningPayloadRequest): Promise<SigningPayload> {
    return this.rawCall<SigningPayload>("getSigningPayload", { ...request });
  }

  async submitSignedTransaction(request: SubmitSignedRequest): Promise<SubmissionResult> {
    return this.rawCall<SubmissionResult>("submitSignedTransaction", { ...request });
  }

  // -----------------------------------------------------------------------
  // ConfigActions
  // -----------------------------------------------------------------------

  async getConfigParam(param: number, opts?: BlockQueryOpts): Promise<{ config: { bytes: string } }> {
    return this.rawCall<{ config: { bytes: string } }>("getConfigParam", {
      param,
      ...seqnoParam(opts),
    });
  }

  /**
   * The network's global ID (ConfigParam 19, signed int32).
   *
   * Wallets sign it into every external message and their code refuses a
   * message naming another network, so pass this to a wallet's `create`.
   */
  async getNetworkGlobalId(opts?: BlockQueryOpts): Promise<number> {
    const { config } = await this.getConfigParam(19, opts);
    const cells = Cell.fromBoc(base64ToBytes(config.bytes));
    const [cell] = cells;
    if (cells.length !== 1 || cell === undefined) {
      throw new TosError("ConfigParam 19 must be exactly one cell", ErrorCodes.INVALID_RESPONSE);
    }
    const slice = cell.beginParse();
    if (slice.remainingBits < 32) {
      throw new TosError("ConfigParam 19 is shorter than its 32-bit global ID", ErrorCodes.INVALID_RESPONSE);
    }
    return slice.loadInt(32);
  }

  async getConfigAll(opts?: BlockQueryOpts): Promise<ConfigAll> {
    return this.rawCall<ConfigAll>("getConfigAll", {
      ...seqnoParam(opts),
    });
  }

  async getLibraries(libraryList: string[]): Promise<LibraryEntry[]> {
    const result = await this.rawCall<{ result: LibraryEntry[] }>("getLibraries", {
      library_list: libraryList,
    });
    return result.result ?? [];
  }

  async getTokenData(address: AddressLike | string): Promise<TokenData> {
    return this.rawCall<TokenData>("getTokenData", {
      address: toAddrString(address),
    });
  }

  async getOutMsgQueueSize(): Promise<OutMsgQueueSize> {
    return this.rawCall<OutMsgQueueSize>("getOutMsgQueueSize");
  }

  async isReady(): Promise<ReadyzResult> {
    return this.rawCall<ReadyzResult>("readyz");
  }
}

// ---------------------------------------------------------------------------
// JSON-RPC response shape
// ---------------------------------------------------------------------------

type JsonRpcOutcome =
  | { kind: "result"; result: unknown }
  | { kind: "error"; code: number; message: string; data: RpcErrorData };

const ENVELOPE_MEMBERS = new Set(["jsonrpc", "id", "result", "error"]);

/**
 * Validate one answer to the request with `id`.
 *
 * Success is HTTP 200 with exactly `jsonrpc: "2.0"`, the request's `id` and
 * `result`. An error is `jsonrpc`, `id` and an `error` object with an integer
 * `code`, a string `message` and `data: {schema_version: 1, reason, retryable}`;
 * a refusal made before any method ran (HTTP 401/404/405/415/429) carries the
 * same object, possibly with `id: null`. Anything else is an invalid response,
 * except that an HTTP error status without a valid error object stays an HTTP
 * error (5xx retryable, 4xx not).
 */
function parseJsonRpcResponse(response: Response, responseText: string, id: number): JsonRpcOutcome {
  const status = response.status;
  let outcome: JsonRpcOutcome;
  try {
    outcome = parseEnvelope(responseText, id, status);
  } catch (cause) {
    if (status === 200) {
      throw cause;
    }
    // 4xx = client error (not retryable), 5xx = server error (retryable)
    const code = status >= 400 && status < 500 ? ErrorCodes.CLIENT_ERROR : ErrorCodes.NETWORK_ERROR;
    throw new TosError(
      `HTTP ${status} ${response.statusText || "request failed"}`,
      code,
      cause instanceof Error ? cause : undefined,
    );
  }
  if (outcome.kind === "result" && status !== 200) {
    throw new TosError(`HTTP ${status} carried a result`, ErrorCodes.INVALID_RESPONSE);
  }
  return outcome;
}

function parseEnvelope(text: string, id: number, status: number): JsonRpcOutcome {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (cause) {
    throw invalidResponse(`Invalid JSON response (${status})`, cause);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw invalidResponse("JSON-RPC response is not an object");
  }
  const envelope = parsed as Record<string, unknown>;
  if (envelope.jsonrpc !== "2.0") {
    throw invalidResponse("JSON-RPC response must carry jsonrpc \"2.0\"");
  }
  if (!("id" in envelope)) {
    throw invalidResponse("JSON-RPC response has no id");
  }
  if (envelope.id !== id && !(status !== 200 && envelope.id === null)) {
    throw invalidResponse("JSON-RPC response id does not match the request");
  }
  for (const member of Object.keys(envelope)) {
    if (!ENVELOPE_MEMBERS.has(member)) {
      throw invalidResponse(`JSON-RPC response has an unexpected member "${member}"`);
    }
  }
  const hasResult = "result" in envelope;
  const hasError = "error" in envelope;
  if (hasResult === hasError) {
    throw invalidResponse("JSON-RPC response must carry exactly one of result and error");
  }
  if (hasResult) {
    return { kind: "result", result: envelope.result };
  }
  return parseErrorObject(envelope.error);
}

function parseErrorObject(value: unknown): JsonRpcOutcome {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidResponse("JSON-RPC error must be an object");
  }
  const error = value as Record<string, unknown>;
  const code = error.code;
  if (typeof code !== "number" || !Number.isSafeInteger(code)) {
    throw invalidResponse("JSON-RPC error code must be an integer");
  }
  const message = error.message;
  if (typeof message !== "string") {
    throw invalidResponse("JSON-RPC error message must be a string");
  }
  const data = error.data;
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw invalidResponse("JSON-RPC error data must be an object");
  }
  const fields = data as Record<string, unknown>;
  if (fields.schema_version !== 1) {
    throw invalidResponse("JSON-RPC error schema_version must be 1");
  }
  const reason = fields.reason;
  if (typeof reason !== "string" || !/^[A-Z0-9_]{1,64}$/.test(reason)) {
    throw invalidResponse("JSON-RPC error reason must be an upper-case identifier");
  }
  const retryable = fields.retryable;
  if (typeof retryable !== "boolean") {
    throw invalidResponse("JSON-RPC error retryable must be a boolean");
  }
  const known = Object.prototype.hasOwnProperty.call(ErrorReasons, reason)
    ? ErrorReasons[reason as keyof typeof ErrorReasons]
    : undefined;
  if (known && (known.code !== code || known.retryable !== retryable)) {
    throw invalidResponse(`JSON-RPC error ${reason} arrived with an unexpected code or retryable flag`);
  }
  return {
    kind: "error",
    code,
    message: message.slice(0, 512),
    data: { schema_version: 1, reason, retryable },
  };
}

function invalidResponse(message: string, cause?: unknown): TosError {
  return new TosError(message, ErrorCodes.INVALID_RESPONSE, cause instanceof Error ? cause : undefined);
}

function isRetryableError(error: TosError): boolean {
  return error.code === ErrorCodes.NETWORK_ERROR || error.code === ErrorCodes.TIMEOUT;
}

// ---------------------------------------------------------------------------
// Parameter serialization helpers
// ---------------------------------------------------------------------------

function toAddrString(address: AddressLike | string): string {
  if (typeof address === "string") return address;
  return address.toRawString();
}

function toBocString(value: CellLike | Uint8Array | string): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return bytesToBase64(value);
  // CellLike — serialize via toBoc(), then base64-encode the result.
  const boc = value.toBoc();
  // toBoc() may return a Uint8Array (e.g. @tos/core Cell) or an object with
  // toString("base64") (legacy compat).  Handle both without relying on Buffer.
  if (boc instanceof Uint8Array) return bytesToBase64(boc);
  return boc.toString("base64");
}

/** An absent seqno reads the latest state; `seqno: 0` names block 0. */
function seqnoParam(opts?: BlockQueryOpts): Record<string, number> {
  if (opts?.seqno != null) {
    return { seqno: seqnoValue(opts.seqno) };
  }
  return {};
}

function invalidParameter(message: string): TosError {
  return new TosError(message, ErrorCodes.INVALID_PARAMETER);
}

/** A JSON integer in [0, 2147483647], as the server accepts for seqno and unixtime. */
function seqnoValue(value: number, name = "seqno"): number {
  if (!Number.isInteger(value) || value < 0 || value > 2147483647) {
    throw invalidParameter(`${name} must be an integer in [0, 2147483647]`);
  }
  return value;
}

function workchainValue(value: number): number {
  if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
    throw invalidParameter("workchain must be a signed 32-bit integer");
  }
  return value;
}

const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;

/** The canonical signed decimal of a non-zero 64-bit shard id, e.g. "-9223372036854775808". */
function shardValue(value: string): string {
  if (typeof value === "string" && /^-?[1-9][0-9]{0,18}$/.test(value)) {
    const parsed = BigInt(value);
    if (parsed >= INT64_MIN && parsed <= INT64_MAX) {
      return value;
    }
  }
  throw invalidParameter('shard must be the signed decimal shard id, e.g. "-9223372036854775808"');
}

/** A logical time as a canonical non-negative decimal string. */
function ltValue(value: string): string {
  if (typeof value === "string" && /^(0|[1-9][0-9]{0,18})$/.test(value) && BigInt(value) <= INT64_MAX) {
    return value;
  }
  throw invalidParameter("lt must be a non-negative decimal integer string");
}

function blockSelector(workchain: number, shard: string, seqno: number): Record<string, unknown> {
  return {
    workchain: workchainValue(workchain),
    shard: shardValue(shard),
    seqno: seqnoValue(seqno),
  };
}

function serializeStack(stack: TupleItemLike[]): unknown[] {
  return stack.map((item) => {
    switch (item.type) {
      case "int":
        // C++ expects hex-prefixed string for integer stack entries
        return ["num", "0x" + item.value.toString(16)];
      case "cell":
        return ["cell", { bytes: toBocString(item.cell) }];
      case "slice":
        return ["slice", { bytes: toBocString(item.cell) }];
      case "builder":
        return ["builder", { bytes: toBocString(item.cell) }];
      case "null":
        return ["null", ""];
      default:
        return ["null", ""];
    }
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  // Pure-JS base64 encoding -- works in Node.js 16+ and all modern browsers.
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

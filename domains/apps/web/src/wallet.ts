export interface WalletAccount { address: string; network: string }
export interface TransactionMessage { address: string; amount: string; payload?: string }
export interface SendRequest { validUntil: number; network: string; from: string; messages: TransactionMessage[] }

interface Provider {
  connect(version: number, request: { manifestUrl: string; items: Array<{ name: 'tos_addr' }> }): Promise<ConnectPayload>;
  restoreConnection(): Promise<ConnectPayload>;
  disconnect(): Promise<void>;
  sendTransaction(request: { method: 'sendTransaction'; params: [string]; id: string }): Promise<{ boc: string }>;
}

interface ConnectPayload {
  items: Array<{ name: string; address?: string; network?: string }>;
}

declare global {
  interface Window { tos?: { provider?: Provider; providers?: Provider[] } }
}

export class InjectedWallet {
  account: WalletAccount | null = null;
  private provider: Provider | null = null;

  available(): boolean { return this.providers().length > 0; }

  async connect(expectedNetwork: string): Promise<WalletAccount> {
    this.provider = this.providers()[0] ?? null;
    if (!this.provider) throw new Error('No injected TOS wallet was found');
    const payload = await this.provider.connect(2, {
      manifestUrl: new URL('/tos-connect-manifest.json', location.href).href,
      items: [{ name: 'tos_addr' }],
    });
    return this.accept(payload, expectedNetwork);
  }

  async restore(expectedNetwork: string): Promise<WalletAccount | null> {
    this.provider = this.providers()[0] ?? null;
    if (!this.provider) return null;
    try { return this.accept(await this.provider.restoreConnection(), expectedNetwork); }
    catch { return null; }
  }

  async disconnect(): Promise<void> {
    await this.provider?.disconnect();
    this.provider = null;
    this.account = null;
  }

  async send(request: SendRequest): Promise<{ boc: string }> {
    if (!this.provider || !this.account) throw new Error('Connect a wallet first');
    if (request.from !== this.account.address || request.network !== this.account.network) {
      throw new Error('Transaction source or network differs from the connected wallet');
    }
    return this.provider.sendTransaction({
      method: 'sendTransaction', params: [JSON.stringify(request)],
      id: crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`,
    });
  }

  private accept(payload: ConnectPayload, expectedNetwork: string): WalletAccount {
    const item = payload.items.find((candidate) => candidate.name === 'tos_addr');
    if (!item?.address || !item.network) throw new Error('Wallet omitted the requested TOS account');
    if (item.network !== expectedNetwork) throw new Error(`Wallet is on network ${item.network}; expected ${expectedNetwork}`);
    if (!/^-?\d+:[0-9a-fA-F]{64}$/.test(item.address)) throw new Error('Wallet returned an invalid raw address');
    this.account = { address: item.address.toLowerCase(), network: item.network };
    return this.account;
  }

  private providers(): Provider[] {
    if (Array.isArray(window.tos?.providers)) return window.tos.providers;
    return window.tos?.provider ? [window.tos.provider] : [];
  }
}

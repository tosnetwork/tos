import {
  CATEGORY_WALLET, bidBody, bytesToBase64, canonicalizeName, changeRecordBody,
  finishAuctionBody, hexToBytes, labelContractError, labelUiWarnings,
  makeSmcAddressRecord, minPrice, minimumNextBid, parseRawAddress, registerBody,
  releaseBody, secondLevelLabel, serializeBoc, transferBody, type Cell,
} from '@tos-domains/protocol';
import config from './config.json';
import { inspectDomain, type DomainSnapshot, type RpcConfig } from './rpc.js';
import { InjectedWallet } from './wallet.js';
import { loadIntents, newIntent, saveIntents, type DomainAction } from './pending.js';
import './styles.css';

const NETWORK = '-239';
const wallet = new InjectedWallet();
let snapshot: DomainSnapshot | null = null;
let intents = loadIntents();
let canonicalRegistrationInput = false;

const elements = {
  name: byId<HTMLInputElement>('name'), rpc: byId<HTMLInputElement>('rpc'), inspect: byId<HTMLButtonElement>('inspect'),
  connect: byId<HTMLButtonElement>('connect'), account: byId<HTMLElement>('account'), result: byId<HTMLElement>('result'),
  actions: byId<HTMLElement>('actions'), pending: byId<HTMLElement>('pending'), error: byId<HTMLElement>('error'),
};
elements.rpc.value = localStorage.getItem('tos-domains.rpc') ?? config.rpc_endpoint;

elements.inspect.addEventListener('click', () => void refresh());
elements.name.addEventListener('keydown', (event) => { if (event.key === 'Enter') void refresh(); });
elements.connect.addEventListener('click', () => void toggleWallet());
elements.actions.addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('button[data-action]');
  if (button) void transact(button.dataset.action as DomainAction);
});

void wallet.restore(NETWORK).then(renderWallet);
renderPending();

async function refresh(): Promise<void> {
  clearError();
  elements.inspect.disabled = true;
  try {
    const endpoint = elements.rpc.value.trim();
    const canonical = canonicalizeName(elements.name.value);
    canonicalRegistrationInput = elements.name.value.trim() === canonical.name;
    const label = secondLevelLabel(canonical.name);
    const contractError = labelContractError(label);
    if (contractError) throw new Error(contractError);
    localStorage.setItem('tos-domains.rpc', endpoint);
    snapshot = await inspectDomain(rpcConfig(endpoint), label);
    renderSnapshot(snapshot, canonical.caseFolded);
    reconcile(snapshot);
  } catch (error) { showError(error); }
  finally { elements.inspect.disabled = false; }
}

async function toggleWallet(): Promise<void> {
  clearError();
  try {
    if (wallet.account) await wallet.disconnect(); else await wallet.connect(NETWORK);
    renderWallet(wallet.account);
    if (snapshot) renderActions(snapshot);
  } catch (error) { showError(error); }
}

async function transact(action: DomainAction): Promise<void> {
  clearError();
  if (!snapshot || !wallet.account) return showError(new Error('Inspect a name and connect a wallet first'));
  try {
    const tx = prepare(action, snapshot, wallet.account.address);
    const warning = `Wallet confirmation must show\n\nAction: ${action}\nName: ${snapshot.name}\nRaw destination: ${tx.address}\nAmount: ${formatTos(BigInt(tx.amount))} TOS\nNetwork: mainnet (${NETWORK})\n\nThe name is only an alias. Verify every raw value in your wallet.`;
    if (!confirm(warning)) return;
    const intent = newIntent(action, snapshot.name, snapshot.itemAddress, wallet.account.address);
    intents.push(intent); saveIntents(intents); renderPending();
    const response = await wallet.send({ validUntil: intent.validUntil, network: NETWORK, from: wallet.account.address, messages: [tx] });
    if (!response.boc) throw new Error('Wallet returned no signed transaction BOC');
    intent.status = 'submitted'; intent.submittedAt = Math.floor(Date.now() / 1_000);
    saveIntents(intents); renderPending();
    setTimeout(() => void refresh(), 4_000);
  } catch (error) { showError(error); }
}

function prepare(action: DomainAction, domain: DomainSnapshot, account: string): { address: string; amount: string; payload: string } {
  const now = Math.floor(Date.now() / 1_000);
  let body: Cell;
  let destination = domain.itemAddress;
  let amount: bigint;
  switch (action) {
    case 'register':
      if (domain.exists) throw new Error('This name is already registered');
      if (!canonicalRegistrationInput) throw new Error('Registration requires the exact lowercase canonical name');
      if (now <= config.auction_start_time) throw new Error(`Registration opens at ${formatTime(config.auction_start_time)}`);
      destination = config.collection_address; body = registerBody(domain.label);
      amount = requestedAmount(minPrice(new TextEncoder().encode(domain.label).length, now, config.auction_start_time)); break;
    case 'bid':
      if (domain.lifecycle?.state !== 'auction' || !domain.auction) throw new Error('No active auction');
      body = bidBody(); amount = requestedAmount(minimumNextBid(domain.auction.maxBidAmount)); break;
    case 'finalize':
      if (domain.lifecycle?.state !== 'auction-ended-unfinalized') throw new Error('Auction is not ready to finalize');
      body = finishAuctionBody(); amount = 100_000_000n; break;
    case 'renew': requireOwner(domain, account); body = bidBody(); amount = requestedAmount(1_000_000_000n); break;
    case 'release':
      if (domain.lifecycle?.state !== 'releasable') throw new Error('Lease is not releasable');
      body = releaseBody(); amount = requestedAmount(minPrice(new TextEncoder().encode(domain.label).length, now, config.auction_start_time)); break;
    case 'set-wallet':
      requireOwner(domain, account); body = changeRecordBody(CATEGORY_WALLET, makeSmcAddressRecord(parseRawAddress(account))); amount = 100_000_000n; break;
    case 'transfer': {
      requireOwner(domain, account);
      const recipient = prompt('New owner raw address (workchain:64 hex characters)')?.trim() ?? '';
      body = transferBody(parseRawAddress(recipient), parseRawAddress(account)); amount = 100_000_000n; break;
    }
  }
  return { address: destination, amount: amount.toString(), payload: bytesToBase64(serializeBoc(body)) };
}

function requestedAmount(minimum: bigint): bigint {
  const defaultValue = formatTos(minimum);
  const input = prompt(`Amount in TOS (minimum ${defaultValue})`, defaultValue)?.trim();
  if (input === undefined || input === null || !/^\d+(?:\.\d{1,9})?$/.test(input)) throw new Error('Amount must be a non-negative TOS decimal with at most 9 places');
  const [whole, fraction = ''] = input.split('.');
  const amount = BigInt(whole as string) * 1_000_000_000n + BigInt(fraction.padEnd(9, '0'));
  if (amount < minimum) throw new Error(`Amount is below the required minimum of ${defaultValue} TOS`);
  return amount;
}

function renderSnapshot(domain: DomainSnapshot, caseFolded: boolean): void {
  const lifecycle = domain.lifecycle?.state ?? 'available';
  elements.result.innerHTML = `<dl>
    <dt>Canonical name</dt><dd>${esc(domain.name)}${caseFolded ? ' <span class="warn">(case-folded for lookup)</span>' : ''}</dd>
    <dt>Domain Item</dt><dd>${esc(domain.itemAddress)}</dd><dt>State</dt><dd><span class="state ${esc(lifecycle)}">${esc(lifecycle)}</span></dd>
    <dt>Owner</dt><dd>${esc(domain.owner ?? 'none')}</dd>
    <dt>Highest bid</dt><dd>${domain.auction ? `${formatTos(domain.auction.maxBidAmount)} TOS by ${esc(domain.auction.maxBidAddress ?? 'unknown')}` : 'none'}</dd>
    <dt>Auction end</dt><dd>${domain.auction ? formatTime(domain.auction.auctionEndTime) : 'not auctioning'}</dd>
    <dt>Renewal deadline</dt><dd>${domain.lifecycle?.renewalDeadline ? formatTime(domain.lifecycle.renewalDeadline) : 'not assigned'}</dd>
    <dt>Safe to resolve</dt><dd>${domain.lifecycle?.safeToResolve ? 'yes' : '<strong class="err">no</strong>'}</dd>
    <dt>Observed</dt><dd>${formatTime(domain.observedAt)} via live JSON-RPC</dd>
  </dl>${labelUiWarnings(domain.label).map((warning) => `<p class="warn">Warning: ${esc(warning)}</p>`).join('')}`;
  renderActions(domain);
}

function renderActions(domain: DomainSnapshot): void {
  const actions: Array<[DomainAction, string]> = [];
  if (!domain.exists && canonicalRegistrationInput && Math.floor(Date.now() / 1_000) > config.auction_start_time) actions.push(['register', 'Register / open auction']);
  if (domain.lifecycle?.state === 'auction') actions.push(['bid', 'Place bid']);
  if (domain.lifecycle?.state === 'auction-ended-unfinalized') actions.push(['finalize', 'Finalize auction']);
  if (domain.lifecycle?.state === 'releasable') actions.push(['release', 'Release and re-auction']);
  if (wallet.account && domain.owner?.toLowerCase() === wallet.account.address.toLowerCase() && domain.lifecycle?.state === 'leased') {
    actions.push(['renew', 'Renew / top up'], ['set-wallet', 'Set wallet record'], ['transfer', 'Transfer domain NFT']);
  }
  elements.actions.innerHTML = wallet.account
    ? actions.map(([action, label]) => `<button data-action="${action}">${esc(label)}</button>`).join('') || '<p class="note">No action is currently available.</p>'
    : '<p class="note">Connect a mainnet wallet to perform non-custodial actions.</p>';
}

function reconcile(domain: DomainSnapshot): void {
  let changed = false;
  for (const intent of intents) {
    if (intent.name !== domain.name || intent.status !== 'submitted') continue;
    const confirmed = intent.action === 'register' && domain.exists ||
      intent.action === 'bid' && domain.auction?.maxBidAddress?.toLowerCase() === intent.walletAddress.toLowerCase() ||
      intent.action === 'finalize' && domain.lifecycle?.state === 'leased' ||
      intent.action === 'release' && domain.lifecycle?.state === 'auction';
    if (confirmed) { intent.status = 'confirmed'; changed = true; }
  }
  if (changed) saveIntents(intents);
  renderPending();
}

function renderPending(): void {
  elements.pending.innerHTML = intents.length === 0 ? '<p class="note">No locally remembered transactions.</p>' :
    `<ul>${[...intents].reverse().slice(0, 10).map((intent) => `<li><strong>${esc(intent.action)}</strong> ${esc(intent.name)} — ${esc(intent.status)} (${formatTime(intent.createdAt)})</li>`).join('')}</ul>`;
}

function renderWallet(account: { address: string } | null): void {
  elements.connect.textContent = account ? 'Disconnect wallet' : 'Connect wallet';
  elements.account.textContent = account ? account.address : wallet.available() ? 'Injected wallet detected' : 'No injected wallet detected';
}
function rpcConfig(endpoint: string): RpcConfig { return { endpoint, collection: parseRawAddress(config.collection_address), itemCodeHash: hexToBytes(config.item_code_hash), itemCodeDepth: config.item_code_depth }; }
function requireOwner(domain: DomainSnapshot, account: string): void {
  if (domain.owner?.toLowerCase() !== account.toLowerCase()) throw new Error('The connected wallet is not the current on-chain owner');
  if (domain.lifecycle?.state !== 'leased') throw new Error('Owner actions are disabled outside an active lease');
}
function formatTos(value: bigint): string { const whole = value / 1_000_000_000n; const fraction = (value % 1_000_000_000n).toString().padStart(9, '0').replace(/0+$/, ''); return fraction ? `${whole}.${fraction}` : whole.toString(); }
function formatTime(timestamp: number): string { return new Date(timestamp * 1_000).toISOString(); }
function esc(value: string): string { return value.replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] as string); }
function showError(error: unknown): void { elements.error.textContent = error instanceof Error ? error.message : String(error); }
function clearError(): void { elements.error.textContent = ''; }
function byId<T extends HTMLElement>(id: string): T { const value = document.getElementById(id); if (!value) throw new Error(`missing #${id}`); return value as T; }

export type DomainAction = 'register' | 'bid' | 'finalize' | 'renew' | 'release' | 'set-wallet' | 'transfer';

export interface PendingIntent {
  id: string;
  action: DomainAction;
  name: string;
  itemAddress: string;
  walletAddress: string;
  createdAt: number;
  validUntil: number;
  status: 'awaiting-signature' | 'submitted' | 'confirmed' | 'expired';
  submittedAt?: number;
}

const KEY = 'tos-domains.pending.v1';

export function loadIntents(now = Math.floor(Date.now() / 1_000)): PendingIntent[] {
  let parsed: unknown;
  try { parsed = JSON.parse(localStorage.getItem(KEY) ?? '[]'); } catch { return []; }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(validIntent).map((intent) => ({
    ...intent,
    status: intent.status === 'awaiting-signature' && now > intent.validUntil ? 'expired' : intent.status,
  }));
}

export function saveIntents(intents: PendingIntent[]): void {
  localStorage.setItem(KEY, JSON.stringify(intents.slice(-50)));
}

export function newIntent(action: DomainAction, name: string, itemAddress: string, walletAddress: string): PendingIntent {
  const createdAt = Math.floor(Date.now() / 1_000);
  return {
    id: crypto.randomUUID?.() ?? `${createdAt}-${Math.random()}`, action, name, itemAddress,
    walletAddress, createdAt, validUntil: createdAt + 300, status: 'awaiting-signature',
  };
}

function validIntent(value: unknown): value is PendingIntent {
  const item = value as PendingIntent;
  return !!item && typeof item.id === 'string' && typeof item.name === 'string' &&
    typeof item.itemAddress === 'string' && typeof item.walletAddress === 'string' &&
    typeof item.createdAt === 'number' && typeof item.validUntil === 'number' &&
    ['register', 'bid', 'finalize', 'renew', 'release', 'set-wallet', 'transfer'].includes(item.action) &&
    ['awaiting-signature', 'submitted', 'confirmed', 'expired'].includes(item.status);
}

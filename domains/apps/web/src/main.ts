import {
  canonicalizeName,
  deriveItemAddress,
  encodeName,
  formatFriendlyAddress,
  formatRawAddress,
  hexToBytes,
  itemIndex,
  labelContractError,
  labelUiWarnings,
  minPrice,
  parseRawAddress,
  secondLevelLabel,
  utf8,
} from '@tos-domains/protocol';
import config from './config.json';

const input = document.getElementById('name') as HTMLInputElement;
const out = document.getElementById('out') as HTMLDivElement;

const collectionConfig = {
  collection: parseRawAddress(config.collection_address),
  itemCodeHash: hexToBytes(config.item_code_hash),
  itemCodeDepth: config.item_code_depth,
};

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
}

function render(): void {
  const raw = input.value;
  if (!raw.trim()) {
    out.innerHTML = '';
    return;
  }
  try {
    const canonical = canonicalizeName(raw);
    const encoded = encodeName(canonical.name);
    const rows: string[] = [
      `<dt>canonical</dt><dd>${esc(canonical.name)}${canonical.caseFolded ? ' <span class="warn">(case-folded for lookup only)</span>' : ''}</dd>`,
      `<dt>encoded</dt><dd>${encoded.length} bytes</dd>`,
    ];
    if (canonical.labels.length === 2 && canonical.labels[1] === 'tos') {
      const label = secondLevelLabel(canonical.name);
      const contractError = labelContractError(label);
      if (contractError) {
        rows.push(`<dt>registrable</dt><dd class="err">no — ${esc(contractError)}</dd>`);
      } else {
        const addr = deriveItemAddress(collectionConfig, label);
        const warnings = labelUiWarnings(label);
        const now = Math.floor(Date.now() / 1000);
        rows.push(
          `<dt>registrable</dt><dd>yes (contract rule)</dd>`,
          `<dt>item index</dt><dd>0x${itemIndex(label).toString(16).padStart(64, '0')}</dd>`,
          `<dt>item address</dt><dd>${formatRawAddress(addr)}<br>${formatFriendlyAddress(addr)}</dd>`,
          `<dt>min open bid</dt><dd>${(Number(minPrice(utf8(label).length, now, config.auction_start_time)) / 1e9).toLocaleString()} TOS (at the configured launch timestamp)</dd>`,
        );
        for (const w of warnings) {
          rows.push(`<dt class="warn">warning</dt><dd class="warn">${esc(w)}</dd>`);
        }
      }
    } else {
      rows.push(
        `<dt>note</dt><dd class="note">not a second-level .tos name; deeper names resolve through the parent's delegated resolver</dd>`,
      );
    }
    out.innerHTML = `<dl>${rows.join('')}</dl>`;
  } catch (e) {
    out.innerHTML = `<p class="err">${esc(String((e as Error).message ?? e))}</p>`;
  }
}

input.addEventListener('input', render);
render();

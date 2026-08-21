/**
 * .tos name rules.
 *
 * Two distinct layers, per the TOS DNS design (doc/tos-blockchain/DNS.md §4):
 *  - the ON-CHAIN registration rule enforced by the Collection contract
 *    (`check_domain_string` plus length checks): byte-aligned, 4..126 bytes,
 *    lowercase [a-z0-9] or interior hyphen. Leading/trailing hyphens are
 *    rejected on-chain; consecutive interior hyphens and `xn--` register.
 *  - the UI POLICY layer: warnings a registrar frontend shows on labels that
 *    are contract-valid but risky. UI policy must never block resolving or
 *    indexing a name the contract validly registered.
 */

export const MIN_LABEL_BYTES = 4; // Collection: len > 3 * 8
export const MAX_LABEL_BYTES = 126; // Collection: len <= 126 * 8
export const MAX_ENCODED_BYTES = 127; // dnsresolve slice bound (1023-bit cell)
export const MAX_DOTTED_BYTES = MAX_ENCODED_BYTES - 1;
export const TOS_SUFFIX = 'tos';

/** The exact on-chain registration rule. Returns null if valid, else the reason. */
export function labelContractError(label: string): string | null {
  const bytes = utf8(label);
  if (bytes.length < MIN_LABEL_BYTES) {
    return `label is ${bytes.length} bytes; the contract requires at least ${MIN_LABEL_BYTES}`;
  }
  if (bytes.length > MAX_LABEL_BYTES) {
    return `label is ${bytes.length} bytes; the contract allows at most ${MAX_LABEL_BYTES}`;
  }
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i] as number;
    const isDigit = c >= 0x30 && c <= 0x39;
    const isLower = c >= 0x61 && c <= 0x7a;
    const isHyphen = c === 0x2d;
    if (isHyphen) {
      if (i === 0 || i === bytes.length - 1) {
        return 'leading and trailing hyphens are rejected by the contract';
      }
      continue;
    }
    if (!isDigit && !isLower) {
      return `byte ${i} (0x${c.toString(16)}) is outside lowercase [a-z0-9-]`;
    }
  }
  return null;
}

/** Contract-valid but risky: registrar UIs warn (never block resolution). */
export function labelUiWarnings(label: string): string[] {
  const warnings: string[] = [];
  if (utf8(label).length > 63) {
    warnings.push('longer than the 63-byte Internet DNS label convention');
  }
  if (label.startsWith('xn--')) {
    warnings.push('xn-- punycode prefix: potential homograph');
  }
  if (label.includes('--')) {
    warnings.push('consecutive hyphens');
  }
  return warnings;
}

export interface CanonicalName {
  /** lowercase dotted name without trailing dot, e.g. "alice.tos" */
  name: string;
  labels: string[];
  /** true when lowercasing changed the input (lookup-only repair) */
  caseFolded: boolean;
}

/**
 * Canonicalize a human-typed name for LOOKUP. Registration and every signed
 * or durable use must reject non-canonical input instead of repairing it.
 */
export function canonicalizeName(input: string): CanonicalName {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error('empty name');
  }
  if (trimmed.endsWith('.')) {
    // encode_name("x.") yields a leading NUL — a different query, not an
    // alternative spelling. Reject rather than silently strip.
    throw new Error('trailing dot is rejected; ".tos" names have no root dot');
  }
  for (const ch of trimmed) {
    const code = ch.codePointAt(0) as number;
    if (code <= 0x20 || code >= 0x7f || ch === '/' || ch === ':') {
      throw new Error(`forbidden character ${JSON.stringify(ch)} in name`);
    }
  }
  const lower = trimmed.toLowerCase();
  const labels = lower.split('.');
  if (labels.some((l) => l.length === 0)) {
    throw new Error('empty label');
  }
  if (utf8(lower).length > MAX_DOTTED_BYTES) {
    throw new Error(`name is ${utf8(lower).length} bytes; at most ${MAX_DOTTED_BYTES} resolve`);
  }
  return { name: lower, labels, caseFolded: lower !== trimmed };
}

/**
 * Internal reverse zero-delimited encoding:
 *   "translate.alice.tos" -> "tos\0alice\0translate\0"
 * Encoded length is always dotted length + 1 and is bounded at 127 bytes.
 */
export function encodeName(name: string): Uint8Array {
  const { labels } = canonicalizeName(name);
  const parts: number[] = [];
  for (let i = labels.length - 1; i >= 0; i--) {
    for (const b of utf8(labels[i] as string)) {
      parts.push(b);
    }
    parts.push(0);
  }
  if (parts.length > MAX_ENCODED_BYTES) {
    throw new Error(`encoded name is ${parts.length} bytes; at most ${MAX_ENCODED_BYTES} fit a cell`);
  }
  return Uint8Array.from(parts);
}

export function decodeName(encoded: Uint8Array): string {
  if (encoded.length === 0 || encoded[encoded.length - 1] !== 0) {
    throw new Error('encoded name must end with a zero byte');
  }
  const labels: string[] = [];
  let start = 0;
  for (let i = 0; i < encoded.length; i++) {
    if (encoded[i] === 0) {
      if (i === start) {
        throw new Error('empty component in encoded name');
      }
      labels.unshift(new TextDecoder().decode(encoded.subarray(start, i)));
      start = i + 1;
    }
  }
  if (start !== encoded.length) {
    throw new Error('trailing bytes after final zero');
  }
  return labels.join('.');
}

/** Split "label.tos" and validate the suffix; returns the second-level label. */
export function secondLevelLabel(name: string): string {
  const { labels } = canonicalizeName(name);
  if (labels.length !== 2 || labels[1] !== TOS_SUFFIX) {
    throw new Error(`expected a second-level .${TOS_SUFFIX} name`);
  }
  return labels[0] as string;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

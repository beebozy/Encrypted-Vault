/** Version 1 file-vault manifest: byte splitting, parsing, and per-chunk digest binding. */

import { toHex } from './crypto';
import { bottle } from './fiber';
import { normalizeHexBytes, normalizeHexQuantity, normalizeOutpoint } from './offer';

export const VAULT_VERSION = 1;

export type VaultChunk = {
  index: number;
  cipher: 'AES-256-GCM';
  ciphertext: `0x${string}`;
  iv: `0x${string}`;
  invoice: string;
  paymentHash: `0x${string}`;
  lastHop: {
    pubkey: `0x${string}`;
    channel_outpoint: `0x${string}`;
    fee_rate: `0x${string}`;
    tlc_expiry_delta: `0x${string}`;
  };
};

export type VaultManifest = {
  version: 1;
  file: { name: string; mime: string; size: number };
  chunkCount: number;
  chunks: VaultChunk[];
};

type JsonObject = Record<string, unknown>;
const isObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const hexBody = (value: string) => value.replace(/^0x/i, '').toLowerCase();
const byteLength = (value: string) => hexBody(value).length / 2;
const utf8Hex = (value: string) => toHex(new TextEncoder().encode(value));

/** Near-equal ranges: floor(i * length / n) guarantees no empty chunk when n <= length. */
export function splitBytes(bytes: Uint8Array, n: number) {
  if (!Number.isInteger(n) || n < 1 || n > bytes.length) throw new Error('Invalid chunk count.');
  const pieces: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    pieces.push(bytes.slice(Math.floor(i * bytes.length / n), Math.floor((i + 1) * bytes.length / n)));
  }
  return pieces;
}

function canonicalLines(manifest: VaultManifest) {
  const name = utf8Hex(manifest.file.name);
  const mime = utf8Hex(manifest.file.mime);
  const lines = [
    'fiber-encrypted-vault-v1',
    `version=${VAULT_VERSION}`,
    `file.name=${byteLength(name)}:${hexBody(name)}`,
    `file.mime=${byteLength(mime)}:${hexBody(mime)}`,
    `file.size=${manifest.file.size}`,
    `chunkCount=${manifest.chunkCount}`,
  ];
  for (const chunk of manifest.chunks) {
    lines.push(
      `chunk.${chunk.index}.index=${chunk.index}`,
      `chunk.${chunk.index}.cipher=${chunk.cipher}`,
      `chunk.${chunk.index}.ciphertext=${byteLength(chunk.ciphertext)}:${hexBody(chunk.ciphertext)}`,
      `chunk.${chunk.index}.iv=${byteLength(chunk.iv)}:${hexBody(chunk.iv)}`,
      `chunk.${chunk.index}.lastHop.pubkey=${hexBody(chunk.lastHop.pubkey)}`,
      `chunk.${chunk.index}.lastHop.channel_outpoint=${hexBody(chunk.lastHop.channel_outpoint)}`,
      `chunk.${chunk.index}.lastHop.fee_rate=${hexBody(chunk.lastHop.fee_rate)}`,
      `chunk.${chunk.index}.lastHop.tlc_expiry_delta=${hexBody(chunk.lastHop.tlc_expiry_delta)}`,
    );
  }
  return lines;
}

/** SHA-256 over the canonical manifest plus the chunk index this invoice attests to. */
export async function vaultChunkDigest(manifest: VaultManifest, index: number): Promise<`0x${string}`> {
  const lines = [...canonicalLines(manifest), `attestedChunk=${index}`];
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${lines.join('\n')}\n`));
  return toHex(new Uint8Array(digest));
}

/** Parse and normalize an untrusted manifest; invoice and paymentHash are NOT part of the digest. */
export function parseVaultManifest(value: string): VaultManifest {
  const parsed: unknown = JSON.parse(value);
  if (!isObject(parsed) || parsed.version !== VAULT_VERSION) {
    throw new Error(`Create a fresh version ${VAULT_VERSION} vault manifest.`);
  }
  const file = parsed.file;
  if (!isObject(file) || typeof file.name !== 'string' || typeof file.mime !== 'string'
    || !Number.isSafeInteger(file.size) || (file.size as number) < 1) {
    throw new Error('Vault file metadata is missing or invalid.');
  }
  if (!Number.isInteger(parsed.chunkCount) || (parsed.chunkCount as number) < 1 || (parsed.chunkCount as number) > 64) {
    throw new Error('Vault chunk count is invalid.');
  }
  if (!Array.isArray(parsed.chunks) || parsed.chunks.length !== parsed.chunkCount) {
    throw new Error('Vault manifest chunk list does not match chunkCount.');
  }
  const chunks = parsed.chunks.map((raw: unknown, index) => {
    if (!isObject(raw) || raw.index !== index) throw new Error('Vault chunks must be in contiguous index order.');
    if (raw.cipher !== 'AES-256-GCM') throw new Error('Create a fresh AES-256-GCM vault manifest.');
    if (typeof raw.invoice !== 'string' || !raw.invoice.toLowerCase().startsWith('fibt')) {
      throw new Error('Vault chunk is missing a Fiber testnet Invoice.');
    }
    if (!isObject(raw.lastHop)) throw new Error('Vault last-hop hint is missing.');
    const pubkey = normalizeHexBytes(raw.lastHop.pubkey, 'Last-hop public key', 33);
    if (pubkey !== bottle.pubkey) throw new Error('Last-hop hint must identify Bottle.');
    return {
      index,
      cipher: 'AES-256-GCM' as const,
      ciphertext: normalizeHexBytes(raw.ciphertext, 'Ciphertext'),
      iv: normalizeHexBytes(raw.iv, 'AES-GCM IV', 12),
      invoice: raw.invoice as string,
      paymentHash: normalizeHexBytes(raw.paymentHash, 'Invoice payment hash', 32),
      lastHop: {
        pubkey,
        channel_outpoint: normalizeOutpoint(raw.lastHop.channel_outpoint ?? raw.lastHop.channelOutpoint),
        fee_rate: normalizeHexQuantity(raw.lastHop.fee_rate ?? raw.lastHop.feeRate, 'Last-hop fee rate'),
        tlc_expiry_delta: normalizeHexQuantity(raw.lastHop.tlc_expiry_delta ?? raw.lastHop.tlcExpiryDelta, 'Last-hop expiry delta'),
      },
    };
  });
  return {
    version: VAULT_VERSION,
    file: { name: file.name as string, mime: file.mime as string, size: file.size as number },
    chunkCount: parsed.chunkCount as number,
    chunks,
  };
}

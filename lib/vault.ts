/** Seller/buyer operations for the version 1 chunked file vault. */

import type { Channel, FiberBrowserNode } from '@fiber-pay/sdk/browser';
import { decryptBytes, encryptBytes } from './crypto';
import { normalizeHexQuantity, normalizeOutpoint, type EncryptedOffer } from './offer';
import {
  ATTESTATION_PREFIX,
  buildAttestationDescription,
  OfferAuthenticityError,
  OFFER_VERSION,
  readInvoiceAttestation,
  type InvoiceWithAttrs,
} from './offer-attestation';
import { validateOffer } from './payment';
import {
  splitBytes,
  vaultChunkDigest,
  type VaultChunk,
  type VaultManifest,
} from './vault-manifest';

/** Create N encrypted chunks and one authenticated invoice per chunk. */
export async function createVault(
  file: File,
  requestedChunks: number,
  seller: FiberBrowserNode,
  sellerChannel: Channel,
): Promise<string> {
  if (!sellerChannel.channel_outpoint) throw new Error('Seller channel does not have a confirmed outpoint.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!bytes.length) throw new Error('Choose a non-empty file.');
  const count = Math.min(Math.max(1, Math.floor(requestedChunks)), bytes.length);
  const pieces = splitBytes(bytes, count);
  const lastHop: VaultChunk['lastHop'] = {
    pubkey: sellerChannel.pubkey,
    channel_outpoint: normalizeOutpoint(sellerChannel.channel_outpoint),
    fee_rate: normalizeHexQuantity(sellerChannel.tlc_fee_proportional_millionths, 'Last-hop fee rate'),
    tlc_expiry_delta: normalizeHexQuantity(sellerChannel.tlc_expiry_delta, 'Last-hop expiry delta'),
  };

  const keys: string[] = [];
  const chunks: VaultChunk[] = [];
  for (let index = 0; index < pieces.length; index++) {
    const encrypted = await encryptBytes(pieces[index]);
    keys.push(encrypted.key);
    chunks.push({
      index,
      cipher: 'AES-256-GCM',
      ciphertext: encrypted.payload.ciphertext,
      iv: encrypted.payload.iv,
      invoice: '',
      paymentHash: `0x${'00'.repeat(32)}`,
      lastHop,
    });
  }

  const manifest: VaultManifest = {
    version: 1,
    file: { name: file.name, mime: file.type || 'application/octet-stream', size: bytes.length },
    chunkCount: count,
    chunks,
  };

  // Digest excludes invoice/paymentHash, so it can be computed before newInvoice() returns.
  for (let index = 0; index < chunks.length; index++) {
    const digest = await vaultChunkDigest(manifest, index);
    const invoice = await seller.newInvoice({
      amount: '0x5f5e100', // 1 CKB per chunk
      currency: 'Fibt',
      payment_preimage: keys[index] as `0x${string}`,
      hash_algorithm: 'sha256',
      allow_trampoline_routing: true,
      description: buildAttestationDescription(digest),
      expiry: '0xe10',
    });
    chunks[index].invoice = invoice.invoice_address;
    chunks[index].paymentHash = invoice.invoice.data.payment_hash;
  }
  return JSON.stringify(manifest, null, 2);
}

/** Fail closed if any chunk has a modified payload, wrong issuer, or missing attestation. */
export async function assertVaultAuthentic(
  invoice: InvoiceWithAttrs,
  manifest: VaultManifest,
  index: number,
  expectedSellerPubkey: string,
): Promise<void> {
  const { payeePublicKey, description } = readInvoiceAttestation(invoice);
  if (typeof description !== 'string' || typeof payeePublicKey !== 'string'
    || !description.trim() || !payeePublicKey.replace(/^0x/i, '').toLowerCase()) {
    throw new OfferAuthenticityError('Offer is missing a valid authenticity attestation.');
  }
  const match = new RegExp(`^${ATTESTATION_PREFIX}([0-9a-f]{64})$`).exec(description.trim());
  if (!match) throw new OfferAuthenticityError('Offer is missing a valid authenticity attestation.');
  if (payeePublicKey.replace(/^0x/i, '').toLowerCase() !== expectedSellerPubkey.replace(/^0x/i, '').toLowerCase()) {
    throw new OfferAuthenticityError('Offer was not issued by the expected seller.');
  }
  if (match[1] !== (await vaultChunkDigest(manifest, index)).replace(/^0x/i, '')) {
    throw new OfferAuthenticityError('Offer payload was modified. Request a fresh offer.');
  }
}

/** Adapt a vault chunk to the unchanged text-offer validation/payment helpers. */
export function chunkOffer(chunk: VaultChunk): EncryptedOffer {
  return {
    version: OFFER_VERSION,
    cipher: chunk.cipher,
    ciphertext: chunk.ciphertext,
    iv: chunk.iv,
    invoice: chunk.invoice,
    paymentHash: chunk.paymentHash,
    lastHop: chunk.lastHop,
  };
}

/** Authenticate every invoice before any chunk can be paid. */
export async function validateVault(
  node: FiberBrowserNode,
  manifest: VaultManifest,
  sellerPubkey: string,
): Promise<void> {
  for (const chunk of manifest.chunks) {
    const invoice = await validateOffer(node, chunkOffer(chunk));
    await assertVaultAuthentic(invoice, manifest, chunk.index, sellerPubkey);
  }
}

export async function decryptVaultChunk(chunk: VaultChunk, preimage: string) {
  return decryptBytes(chunk, preimage);
}

/** Concatenate chunk plaintexts back into the original file bytes. */
export function reassemble(chunks: Uint8Array[]) {
  const size = chunks.reduce((total, piece) => total + piece.length, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const piece of chunks) {
    result.set(piece, offset);
    offset += piece.length;
  }
  return result;
}

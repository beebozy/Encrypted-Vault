/** Authenticity for version 3 offers. The attestation lives inside the signed Fiber Invoice. */

export const OFFER_VERSION = 3;
export const ATTESTATION_PREFIX = 'encrypted-data-payment:sha256:';

export type AttestedOfferFields = {
  version: number;
  cipher: string;
  ciphertext: `0x${string}`;
  iv: `0x${string}`;
  lastHop: {
    pubkey: `0x${string}`;
    channel_outpoint: `0x${string}`;
    fee_rate: `0x${string}`;
    tlc_expiry_delta: `0x${string}`;
  };
};

export type InvoiceWithAttrs = { data?: { attrs?: readonly Record<string, unknown>[] } };

export class OfferAuthenticityError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'OfferAuthenticityError';
  }
}

const hexBody = (value: string) => value.replace(/^0x/i, '').toLowerCase();
const byteLength = (value: string) => hexBody(value).length / 2;
const toHex = (bytes: Uint8Array) =>
  `0x${Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')}` as `0x${string}`;

/** Deterministic, length-prefixed encoding shared by creation and verification. */
export async function offerDigest(fields: AttestedOfferFields): Promise<`0x${string}`> {
  const lines = [
    'fiber-encrypted-offer-v3',
    `version=${OFFER_VERSION}`,
    `cipher=${fields.cipher}`,
    `ciphertext=${byteLength(fields.ciphertext)}:${hexBody(fields.ciphertext)}`,
    `iv=${byteLength(fields.iv)}:${hexBody(fields.iv)}`,
    `lastHop.pubkey=${hexBody(fields.lastHop.pubkey)}`,
    `lastHop.channel_outpoint=${hexBody(fields.lastHop.channel_outpoint)}`,
    `lastHop.fee_rate=${hexBody(fields.lastHop.fee_rate)}`,
    `lastHop.tlc_expiry_delta=${hexBody(fields.lastHop.tlc_expiry_delta)}`,
  ];
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${lines.join('\n')}\n`));
  return toHex(new Uint8Array(digest));
}

export function buildAttestationDescription(digest: `0x${string}`) {
  return `${ATTESTATION_PREFIX}${hexBody(digest)}`;
}

export function readInvoiceAttestation(invoice: InvoiceWithAttrs) {
  const attrs = invoice?.data?.attrs;
  if (!Array.isArray(attrs)) return {};
  let payeePublicKey: unknown;
  let description: unknown;
  for (const attribute of attrs) {
    if (!attribute || typeof attribute !== 'object') continue;
    if ('payee_public_key' in attribute) payeePublicKey = attribute.payee_public_key;
    if ('description' in attribute) description = attribute.description;
  }
  return { payeePublicKey, description };
}

/** Reject a modified payload or an Invoice issued by anyone other than the expected seller. */
export async function assertOfferAuthentic(
  invoice: InvoiceWithAttrs,
  offer: AttestedOfferFields,
  expectedSellerPubkey: string,
): Promise<void> {
  const { payeePublicKey, description } = readInvoiceAttestation(invoice);
  if (typeof description !== 'string' || typeof payeePublicKey !== 'string'
    || !description.trim() || !hexBody(payeePublicKey)) {
    throw new OfferAuthenticityError('Offer is missing a valid authenticity attestation.');
  }
  const match = new RegExp(`^${ATTESTATION_PREFIX}([0-9a-f]{64})$`).exec(description.trim());
  if (!match) throw new OfferAuthenticityError('Offer is missing a valid authenticity attestation.');
  if (hexBody(payeePublicKey) !== hexBody(expectedSellerPubkey)) {
    throw new OfferAuthenticityError('Offer was not issued by the expected seller.');
  }
  const expected = await offerDigest(offer);
  if (match[1] !== hexBody(expected)) {
    throw new OfferAuthenticityError('Offer payload was modified. Request a fresh offer.');
  }
}

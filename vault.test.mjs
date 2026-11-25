import assert from 'node:assert/strict';
import test from 'node:test';
import { bottle } from './lib/fiber.ts';
import { readVaultProgress, vaultProgressKey } from './lib/progress.ts';
import {
  assertVaultAuthentic,
  createVault,
  decryptVaultChunk,
  reassemble,
  validateVault,
} from './lib/vault.ts';
import {
  parseVaultManifest,
  splitBytes,
  vaultChunkDigest,
} from './lib/vault-manifest.ts';

const bytes = Uint8Array.from({ length: 257 }, (_, index) => index % 251);
const sellerPubkey = `0x03${'77'.repeat(32)}`;
const channel = {
  channel_outpoint: `0x${'11'.repeat(32)}00000000`,
  pubkey: bottle.pubkey,
  tlc_fee_proportional_millionths: '0x3e8',
  tlc_expiry_delta: '0xdbba00',
};

function fakeFile(content = bytes, name = 'report.bin') {
  return {
    name,
    type: 'application/octet-stream',
    arrayBuffer: async () => content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength),
  };
}

/** Capture the preimages and descriptions the seller puts on each invoice. */
async function fixture(content = bytes, requestedChunks = 4) {
  const preimages = [];
  const descriptions = [];
  const seller = {
    newInvoice: async (params) => {
      preimages.push(params.payment_preimage);
      descriptions.push(params.description);
      return {
        invoice_address: `fibt-vault-${preimages.length}`,
        invoice: { data: { payment_hash: `0x${preimages.length.toString(16).padStart(64, '0')}` } },
      };
    },
  };
  const text = await createVault(fakeFile(content), requestedChunks, seller, channel);
  return { manifest: parseVaultManifest(text), text, preimages, descriptions };
}

function invoiceWith(description, payee = sellerPubkey) {
  return { data: { attrs: [{ payee_public_key: payee }, { description }] } };
}

test('splitBytes uses floor boundaries and never emits empty chunks', () => {
  const seven = Uint8Array.from({ length: 7 }, (_, index) => index);
  assert.deepEqual(splitBytes(seven, 4).map((piece) => Array.from(piece)), [[0], [1, 2], [3, 4], [5, 6]]);
  assert.deepEqual(splitBytes(seven, 1).map((piece) => Array.from(piece)), [[0, 1, 2, 3, 4, 5, 6]]);
  assert.throws(() => splitBytes(seven, 8), /Invalid chunk count/);
});

test('whole-file mode (N = 1) round-trips byte-for-byte', async () => {
  const { manifest, preimages } = await fixture(bytes, 1);
  assert.equal(manifest.chunkCount, 1);
  assert.equal(preimages.length, 1);
  const plain = await decryptVaultChunk(manifest.chunks[0], preimages[0]);
  assert.deepEqual(Array.from(reassemble([plain])), Array.from(bytes));
});

test('chunked vault uses distinct keys and digests per chunk and reassembles exactly', async () => {
  const { manifest, preimages } = await fixture(bytes, 4);
  assert.equal(manifest.chunkCount, 4);
  assert.equal(new Set(preimages).size, 4);
  const digests = await Promise.all(manifest.chunks.map((_, index) => vaultChunkDigest(manifest, index)));
  assert.equal(new Set(digests).size, 4);
  const plains = await Promise.all(manifest.chunks.map((chunk, index) => decryptVaultChunk(chunk, preimages[index])));
  assert.deepEqual(Array.from(reassemble(plains)), Array.from(bytes));
  assert.equal(reassemble(plains).length, manifest.file.size);
});

test('requested chunks are clamped to the byte length', async () => {
  const tiny = new Uint8Array([1, 2, 3]);
  const { manifest } = await fixture(tiny, 10);
  assert.equal(manifest.chunkCount, 3);
  assert.deepEqual(manifest.chunks.map((chunk) => chunk.index), [0, 1, 2]);
});

test('a tampered chunk ciphertext invalidates every chunk invoice', async () => {
  const { manifest, descriptions } = await fixture(bytes, 2);
  const tampered = structuredClone(manifest);
  tampered.chunks[1].ciphertext = `0xff${tampered.chunks[1].ciphertext.slice(4)}`;
  for (let index = 0; index < 2; index++) {
    await assert.rejects(
      assertVaultAuthentic(invoiceWith(descriptions[index]), tampered, index, sellerPubkey),
      /Offer payload was modified/,
    );
  }
});

test('an invoice cannot be swapped between chunks or sellers', async () => {
  const { manifest, descriptions } = await fixture(bytes, 2);
  await assert.rejects(
    assertVaultAuthentic(invoiceWith(descriptions[0]), manifest, 1, sellerPubkey),
    /Offer payload was modified/,
  );
  await assert.rejects(
    assertVaultAuthentic(invoiceWith(descriptions[0], `0x03${'44'.repeat(32)}`), manifest, 0, sellerPubkey),
    /expected seller/,
  );
});

test('a missing or malformed attestation fails closed', async () => {
  const { manifest, descriptions } = await fixture(bytes, 1);
  await assert.rejects(assertVaultAuthentic(invoiceWith(''), manifest, 0, sellerPubkey), /missing a valid authenticity attestation/);
  await assert.rejects(
    assertVaultAuthentic(invoiceWith('encrypted-data-payment:not-a-digest'), manifest, 0, sellerPubkey),
    /missing a valid authenticity attestation/,
  );
  await assert.rejects(
    assertVaultAuthentic({ data: { attrs: [] } }, manifest, 0, sellerPubkey),
    /missing a valid authenticity attestation/,
  );
  assert.equal(descriptions[0].startsWith('encrypted-data-payment:sha256:'), true);
});

test('validateVault authenticates every invoice through the unchanged validator', async () => {
  const { manifest, descriptions } = await fixture(bytes, 3);
  const node = {
    parseInvoice: async ({ invoice }) => {
      const index = manifest.chunks.findIndex((chunk) => chunk.invoice === invoice);
      assert.notEqual(index, -1);
      return { invoice: {
        currency: 'Fibt', amount: '0x5f5e100',
        data: { payment_hash: manifest.chunks[index].paymentHash, attrs: [
          { payee_public_key: sellerPubkey }, { description: descriptions[index] },
        ] },
      } };
    },
  };
  await validateVault(node, manifest, sellerPubkey);
  const tampered = structuredClone(manifest);
  tampered.chunks[2].iv = `0x00${tampered.chunks[2].iv.slice(4)}`;
  await assert.rejects(validateVault(node, tampered, sellerPubkey), /Offer payload was modified/);
});

test('parseVaultManifest rejects inconsistent chunk lists and non-Bottle hints', async () => {
  const { manifest } = await fixture(bytes, 2);
  const raw = JSON.parse(JSON.stringify(manifest));
  raw.chunkCount = 3;
  assert.throws(() => parseVaultManifest(JSON.stringify(raw)), /chunk list does not match/);
  raw.chunkCount = 2;
  raw.chunks[1].index = 0;
  assert.throws(() => parseVaultManifest(JSON.stringify(raw)), /contiguous index order/);
  raw.chunks[1].index = 1;
  raw.chunks[0].lastHop.pubkey = `0x03${'00'.repeat(32)}`;
  assert.throws(() => parseVaultManifest(JSON.stringify(raw)), /identify Bottle/);
});

test('partial progress restores paid hashes but never keys', async () => {
  const saved = {
    version: 1, generatedText: '{}', manifestText: '{"version":1}',
    paidHashes: [`0x${'ab'.repeat(32)}`, `0x${'cd'.repeat(32)}`],
  };
  const storage = { getItem: (key) => key === vaultProgressKey ? JSON.stringify(saved) : null };
  const restored = readVaultProgress(storage);
  assert.deepEqual(restored.paidHashes, saved.paidHashes);
  assert.equal(restored.manifestText, saved.manifestText);
  assert.equal(Object.keys(restored).some((key) => /key/i.test(key)), false);
  assert.equal(readVaultProgress({ getItem: () => JSON.stringify({ version: 2 }) }), null);
});

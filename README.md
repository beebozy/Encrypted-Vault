# Encrypted file vault

A browser-only buyer and seller on Fiber + CKB Testnet. A seller encrypts a file into chunks, publishes a public manifest, and the buyer pays one 1 CKB invoice per chunk to unlock the bytes. This is the project's **main and only** README; it covers how to run the app, how the vault works, and how to verify it.

The original tutorial is at https://www.fiber.world/docs/build/encrypted-data-payment. The app still contains the single-text pay-to-decrypt flow above the vault section; the vault is the primary feature and reuses that flow's version 3 authenticity model.

## Run locally

Use Node.js 22.18 or newer and npm. Extract the archive and run these commands inside `encrypted-data-payment`:

```sh
npm install
npm run dev
```

Open http://localhost:3001. Use `localhost` or HTTPS: the WASM runtime requires a secure context, SharedArrayBuffer, Web Locks, and cross-origin isolation. `next.config.mjs` supplies the isolation headers. Browser extensions or a proxy that strips those headers will prevent startup.

## Set up the nodes and channels

1. Start **Buyer A** and **Seller C**. Each node's identity is saved in browser storage.
2. Copy each funding address to the [faucet](https://faucet.nervos.org) and request enough Testnet CKB for a 500 CKB channel plus the on-chain transaction fee. Channel V2 reserves 100 CKB, leaving 400 CKB to meet Bottle's auto-accept minimum.
3. Open a channel on each side. Confirmation can take several minutes; refresh until both report `CHANNEL_READY`.
4. Check the channel balances. Bottle needs inbound liquidity on both sides to route a payment. The **Send / check 5 CKB transfer** button is an optional experiment if that balance is already sufficient, and it checks an existing transfer before sending another.

The **Channel diagnostics** panel lists every open channel to Bottle. One `READY` channel per side is enough; extra or `STALE` channels can hold balances that do not route.

## Use the vault

### Seller

1. In **Encrypted file vault**, choose **Whole file** or **Chunked**, pick a file, and click **Encrypt & create invoices**.
2. Copy the generated manifest JSON and give it to the buyer.

### Buyer

1. Paste the manifest into **Received vault manifest** and click **Validate manifest**. No Pay button appears until every invoice authenticates from Seller C.
2. For each chunk: **Decrypt without key** → **Pay 1 CKB** → **Decrypt chunk**. A failed payment can be retried with the same button.
3. When every chunk shows `decrypted ✓`, click **Download file**. The downloaded bytes match the original file exactly.

### Whole file vs chunked

One pipeline, two presets — not two implementations:

| Mode | Chunks | Payments | Trade-off |
|---|---|---|---|
| Whole file | 1 | 1 × 1 CKB | All-or-nothing, no preview |
| Chunked (default) | 4 | 4 × 1 CKB | Early chunks can be a preview; more clicks and routing fees |

`N = Math.min(requestedChunks, byteLength)`; an empty file is rejected. Chunk boundaries are `start_i = floor(i * L / N)`, `end_i = floor((i + 1) * L / N)`, so no chunk is empty when `N <= L`.

## How it works

### Encryption

Each chunk gets a fresh random 256-bit AES key and 96-bit IV, encrypted with AES-256-GCM. The AES key is used as that invoice's `payment_preimage`, so paying the invoice reveals exactly the key that decrypts that chunk. The settlement preimage is therefore the decryption key — no key is stored by the application.

### Manifest format (version 1)

```json
{
  "version": 1,
  "file": { "name": "report.pdf", "mime": "application/pdf", "size": 12345 },
  "chunkCount": 4,
  "chunks": [
    {
      "index": 0,
      "cipher": "AES-256-GCM",
      "ciphertext": "0x...",
      "iv": "0x...",
      "invoice": "fibt1...",
      "paymentHash": "0x...",
      "lastHop": {
        "pubkey": "0x02b6d4...",
        "channel_outpoint": "0x...",
        "fee_rate": "0x3e8",
        "tlc_expiry_delta": "0xdbba00"
      }
    }
  ]
}
```

`parseVaultManifest()` requires version `1`, `chunkCount === chunks.length`, contiguous indices `0..N-1`, AES-256-GCM, a Bottle last-hop pubkey, and normalized hex fields. It rejects malformed manifests before any payment.

### Authenticity: three independent checks

The text demo originally checked only that an offer was *internally consistent* (currency `Fibt`, amount 1 CKB, `payment_hash` agreement, Bottle last hop). That let a middleman substitute their own invoice and ciphertext and still pass. Version 3 closes the hole by reusing what Fiber already signs:

| Check | What it proves | Where |
|---|---|---|
| Key | `payment_hash = SHA256(AES key)` binds the revealed preimage | `validateOffer()` + Fiber settlement |
| Seller | Invoice `payee_public_key` attr equals `(await sellerNode.nodeInfo()).pubkey` | `assertVaultAuthentic()` |
| Payload | Invoice `description` contains a SHA-256 digest of the signed payload | `assertVaultAuthentic()` |

The description format is `encrypted-data-payment:sha256:<64 lowercase hex>`. No new signature scheme or backend is involved; the attestation lives inside the invoice, which is already signed by its issuer. If an attestation field is missing or malformed, validation fails closed.

Error messages are specific:

- `Offer is missing a valid authenticity attestation.`
- `Offer was not issued by the expected seller.`
- `Offer payload was modified. Request a fresh offer.`

### Digest binding

`lib/offer-attestation.ts` holds the v3 text-offer digest. The vault needs its own digest because a single whole-manifest digest would make invoices interchangeable: a buyer could move `chunks[0].invoice` to `chunks[1]` and pass validation even though its preimage decrypts the wrong bytes. `lib/vault-manifest.ts` therefore hashes the canonical manifest **plus `attestedChunk=<i>`**, so each invoice is bound to its own position. Both creation and verification call the same `vaultChunkDigest()`; never duplicate the encoding.

Canonical input (all hex normalized lowercase `0x…`, variable-length values length-prefixed):

```
fiber-encrypted-vault-v1
version=1
file.name=<utf8ByteLen>:<utf8Hex>
file.mime=<utf8ByteLen>:<utf8Hex>
file.size=<decimal>
chunkCount=<decimal>
chunk.0.index=0
chunk.0.cipher=AES-256-GCM
chunk.0.ciphertext=<byteLen>:<hex>
chunk.0.iv=<byteLen>:<hex>
chunk.0.lastHop.pubkey=<hex>
chunk.0.lastHop.channel_outpoint=<hex>
chunk.0.lastHop.fee_rate=<hex>
chunk.0.lastHop.tlc_expiry_delta=<hex>
...
attestedChunk=<i>
```

`paymentHash` and `invoice` are deliberately **excluded**: the description digest must be computable before `newInvoice()` returns, but the hash comes from that call. The hash is bound separately by `validateOffer()` comparing it to `invoice.data.payment_hash`.

| Modification | Result |
|---|---|
| Edit any `ciphertext` or `iv` | every invoice's digest mismatch |
| Edit `file.name`, `mime`, or `size` | every invoice's digest mismatch |
| Reorder chunks or change an `index` | chunk-index binding mismatch |
| Change `lastHop.*` | digest mismatch |
| Substitute an invoice from another node | `payee_public_key` mismatch |
| Change only `paymentHash` | payment hash mismatch |

### Data flow

```
Seller: file -> N byte ranges -> encryptBytes() per chunk -> build manifest
      -> vaultChunkDigest(manifest, i) -> newInvoice({ payment_preimage: key_i,
             description: 'encrypted-data-payment:sha256:<digest>', 1 CKB })
      -> JSON manifest

Buyer:  parseVaultManifest -> validateOffer() per chunk -> assertVaultAuthentic()
      -> payForOffer() per chunk -> preimage -> decryptBytes() -> reassemble() -> Blob download
```

`lib/payment.ts` and `lib/payment-submission.ts` are unchanged. `chunkOffer()` adapts a vault chunk to the same `EncryptedOffer` shape the text flow uses, so `validateOffer()` and `payForOffer()` are reused directly.

## Resume and troubleshoot

- **Vault progress** lives in `sessionStorage` under `fiber-docs:vault-progress-v1`. It holds the generated manifest, the received manifest, and paid payment hashes — never keys or decrypted bytes. After a reload, start the same saved nodes and click **Check restored payments**: it re-runs authenticity checks, then recovers keys from settled `getPayment()` results. Unpaid chunks stay locked. Failed or missing payment sessions are reported as needing attention, never assumed paid.
- **Text offer progress** uses the separate `fiber-docs:encrypted-data-progress-v1` key. Restart the same saved nodes, revalidate the restored offer, and choose **Check payment status**. A completed or pending attempt is never submitted again; explicit retry is available only after the node confirms failure.
- An expired invoice is blocked before recording a new attempt. If submission is explicitly rejected and no payment record exists, the attempt is cleared; choose **Start another offer** or **Start another vault**. Timeouts, worker failures, and unavailable status reads keep the attempt locked for status checking.
- Keep one tab per saved node. Browser storage holds node identities and public offer/payment progress; clearing it can lose access to funded channels. AES keys and decrypted output are not saved by the application.
- If a 5 CKB transfer was interrupted before its hash returned, the button blocks another transfer. Review the Seller's payment history (`listPayments`) before deliberately clearing its `fiber-docs:encrypted-inbound:<seller identifier>` session entry.
- If a channel is slow, check its status or reconnect it; the existing channel is reused. Do not clear its storage or fund a replacement to resolve a wait.
- Faucet requests and network confirmations can take longer than expected. Check the faucet transaction and refresh channel status once funds arrive.

## Code map

| File | Role |
|---|---|
| `app/page.tsx` | Node/channel controls, text offer UI, and the vault UI |
| `lib/fiber.ts` | Bottle channel open/read helpers and diagnostics |
| `lib/crypto.ts` | Text and byte AES-256-GCM encrypt/decrypt helpers |
| `lib/offer.ts` | Version 3 text offer create/parse and hex normalizers |
| `lib/offer-attestation.ts` | v3 digest, description builder, attestation reader, authenticity errors |
| `lib/vault-manifest.ts` | Manifest v1 types, parsing, splitting, per-chunk digest |
| `lib/vault.ts` | Vault create, validate, decrypt, reassemble |
| `lib/payment.ts` | Invoice checks and payment submission (unchanged) |
| `lib/payment-submission.ts` | Safe payment submission and expiry checks (unchanged) |
| `lib/progress.ts` | Text and vault progress storage helpers |
| `lib/node-session.ts` | Prevents two runtimes from opening the same saved node |
| `payment.test.mjs`, `vault.test.mjs` | Payment safety, authenticity, and vault tests |

## Checks and tests

```sh
npm run typecheck
npm test
npm run build
```

`npm test` needs Node 22.18+ for `--experimental-strip-types`. On Node 20, transpile `lib/*.ts` to `.mjs` with the installed TypeScript and run the same test files. All 23 tests pass.

Manual verification:

| Test | Change | Expected result |
|---|---|---|
| Tamper one chunk | edit one hex char in `chunks[2].ciphertext` | every invoice rejected: `Offer payload was modified.` |
| Swap one invoice | replace `chunks[1].invoice` with one from another node | `Offer was not issued by the expected seller.` |
| Move an invoice | put `chunks[0].invoice` in `chunks[1]` | `Offer payload was modified.` (chunk-index binding) |
| Whole-file mode | `N = 1` | one invoice, one payment, correct file |
| Partial progress | pay 2 of 4 chunks, reload, check restored payments | paid chunks decryptable; unpaid chunks locked |
| Round trip | decrypt all chunks | downloaded bytes equal the original file |

The application displays action errors inline. If a payment outcome is unknown, check the existing attempt instead of starting a replacement.

## Limits and remaining verification

- **Content accuracy.** A released key proves only that the decrypted bytes match the ciphertext, not that the file is what the buyer wanted. Use chunk 1 as a preview.
- **Atomicity.** No all-or-nothing settlement across `N` invoices; a buyer who stops after two chunks keeps two chunks.
- **Router privacy.** A routing node that sees a preimage still cannot decrypt without the ciphertext. Keep the manifest private.
- **Scale.** Browser memory and invoice count grow with `N`; this is a demo-scale design.
- **Live attribute check.** Unit tests use fixture invoices with `payee_public_key` and `description`. Confirm a real testnet invoice exposes both via `parseInvoice().invoice.data.attrs`; if not, the extractor in `lib/offer-attestation.ts` needs the same fix for both the text and vault validators.

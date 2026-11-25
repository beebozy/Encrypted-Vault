'use client';

import { channelFundingGuidance } from '../lib/channel-funding';
import { useEffect, useRef, useState } from 'react';
import { scriptToAddress, type Channel, type FiberBrowserNode, type GetPaymentResult } from '@fiber-pay/sdk/browser';
import { decryptResult, toHex } from '../lib/crypto';
import { chunkOffer, createVault, decryptVaultChunk, reassemble, validateVault } from '../lib/vault';
import { parseVaultManifest, type VaultManifest } from '../lib/vault-manifest';
import { bottle, channelFundingCkb, connectAndOpenChannel, readChannel, readChannels, ready, startRole } from '../lib/fiber';
import { createOffer, parseOffer, type EncryptedOffer } from '../lib/offer';
import { assertOfferAuthentic } from '../lib/offer-attestation';
import { payForOffer, validateOffer } from '../lib/payment';
import { createBrowserNodeSession } from '../lib/node-session';
import { encryptedSessionKey, encryptedBuyerProfile, encryptedSellerProfile, savedNodeIdentifier, readEncryptedProgress, readVaultProgress, vaultProgressKey, type EncryptedLessonProgress, type VaultProgress } from '../lib/progress';

type Role = 'buyer' | 'seller';
type CheckState = 'idle' | 'checking' | 'pass' | 'fail';
type AuthenticityChecks = {
  key: CheckState;      // payment hash = SHA256(AES key) via invoice
  origin: CheckState;   // invoice payee_public_key = Seller C
  payload: CheckState;  // invoice description digest = ciphertext + IV + last hop
  detail: string;
};
const idleChecks: AuthenticityChecks = { key: 'idle', origin: 'idle', payload: 'idle', detail: '' };
const checkLabel = (state: CheckState) => state === 'pass' ? '✓' : state === 'fail' ? '✗' : state === 'checking' ? '…' : '·';
const ckb = (value: string) => `${Number(BigInt(value)) / 100_000_000}`;
const sample = 'Fiber Testnet report\n\nPayment settled. The encrypted result is readable.';

export default function Page() {
  const nodes = useRef<Partial<Record<Role, FiberBrowserNode>>>({});
  const sessions = useRef<Partial<Record<Role, ReturnType<typeof createBrowserNodeSession>>>>({});
  const progress = useRef<EncryptedLessonProgress | null>(null);
  const vaultProgress = useRef<VaultProgress | null>(null);
  const locked = useRef(false);
  const refreshRef = useRef<(role: Role) => Promise<void>>(async () => {});
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [addresses, setAddresses] = useState<Partial<Record<Role, string>>>({});
  const [connected, setConnected] = useState<Partial<Record<Role, boolean>>>({});
  const [channels, setChannels] = useState<Partial<Record<Role, Channel>>>({});
  const [allChannels, setAllChannels] = useState<Partial<Record<Role, Channel[]>>>({});
  const [sellerPubkey, setSellerPubkey] = useState('');
  const [plaintext, setPlaintext] = useState(sample);
  const [generated, setGenerated] = useState('');
  const [received, setReceived] = useState('');
  const [offer, setOffer] = useState<EncryptedOffer | null>(null);
  const [checks, setChecks] = useState<AuthenticityChecks>(idleChecks);
  const [attempt, setAttempt] = useState('');
  const [tested, setTested] = useState(false);
  const [payment, setPayment] = useState<GetPaymentResult | null>(null);
  const [key, setKey] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [vaultMode, setVaultMode] = useState<'whole' | 'chunked'>('chunked');
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [vaultGenerated, setVaultGenerated] = useState('');
  const [vaultReceived, setVaultReceived] = useState('');
  const [vaultManifest, setVaultManifest] = useState<VaultManifest | null>(null);
  const [vaultValidated, setVaultValidated] = useState(false);
  const [vaultPaid, setVaultPaid] = useState<string[]>([]);
  const [vaultTested, setVaultTested] = useState<Record<number, boolean>>({});
  const [vaultKeys, setVaultKeys] = useState<Record<number, string>>({});
  const [vaultPlain, setVaultPlain] = useState<Record<number, Uint8Array>>({});

  useEffect(() => {
    const saved = readEncryptedProgress(sessionStorage, localStorage);
    progress.current = saved;
    if (saved) { setGenerated(saved.generatedOffer); setReceived(saved.buyerOfferText); setAttempt(saved.attemptedPaymentHash); setTested(saved.triedWithoutKey); }
    const savedVault = readVaultProgress(sessionStorage);
    vaultProgress.current = savedVault;
    if (savedVault) {
      setVaultGenerated(savedVault.generatedText);
      setVaultReceived(savedVault.manifestText);
      if (savedVault.manifestText) {
        try { setVaultManifest(parseVaultManifest(savedVault.manifestText)); } catch { /* invalid cache; require a fresh manifest */ }
      }
      setVaultPaid(savedVault.paidHashes);
    }
    setLoaded(true);
    const owned = sessions.current;
    const stop = () => { for (const session of Object.values(owned)) void session.stop().catch(() => {}); };
    window.addEventListener('pagehide', stop);
    return () => { window.removeEventListener('pagehide', stop); stop(); nodes.current = {}; sessions.current = {}; };
  }, []);

  // Keep channel state fresh while the tab is visible, matching the tutorial demo.
  useEffect(() => {
    if (!loaded) return;
    const id = window.setInterval(() => {
      if (document.visibilityState !== 'visible' || locked.current) return;
      for (const role of ['buyer', 'seller'] as const) {
        if (nodes.current[role]) void refreshRef.current(role).catch(() => {});
      }
    }, 5_000);
    return () => window.clearInterval(id);
  }, [loaded]);

  function save(update: Partial<EncryptedLessonProgress>) {
    const buyerId = savedNodeIdentifier(localStorage, encryptedBuyerProfile);
    const sellerId = savedNodeIdentifier(localStorage, encryptedSellerProfile);
    if (!buyerId || !sellerId) throw new Error('Start both saved nodes before continuing.');
    const next = { version: 1 as const, buyerId, sellerId, generatedOffer: '', buyerOfferText: '', attemptedPaymentHash: '', triedWithoutKey: false, ...progress.current, ...update };
    sessionStorage.setItem(encryptedSessionKey, JSON.stringify(next));
    progress.current = next;
  }

  function saveVault(update: Partial<VaultProgress>) {
    const next: VaultProgress = {
      version: 1, generatedText: '', manifestText: '', paidHashes: [],
      ...vaultProgress.current, ...update,
    };
    sessionStorage.setItem(vaultProgressKey, JSON.stringify(next));
    vaultProgress.current = next;
  }

  async function run(action: () => Promise<void>) {
    if (locked.current) return;
    locked.current = true; setBusy(true); setError('');
    try { await action(); }
    catch (failure) { setError(failure instanceof Error ? failure.message : 'Action failed. Check status before retrying a transfer.'); }
    finally { locked.current = false; setBusy(false); }
  }

  async function refresh(role: Role) {
    const node = nodes.current[role];
    if (!node) return;
    const [channel, channels] = await Promise.all([readChannel(node), readChannels(node)]);
    const { peers } = await node.listPeers();
    setConnected((previous) => ({ ...previous, [role]: peers.some(peer => peer.pubkey.replace(/^0x/i, '').toLowerCase() === bottle.pubkey.slice(2)) }));
    setChannels((previous) => ({ ...previous, [role]: channel }));
    setAllChannels((previous) => ({ ...previous, [role]: channels }));
  }
  refreshRef.current = refresh;

  async function start(role: Role) {
    if (nodes.current[role]) return;
    const session = sessions.current[role] ??= createBrowserNodeSession();
    let started: FiberBrowserNode | undefined;
    await session.start(role === 'buyer' ? encryptedBuyerProfile : encryptedSellerProfile, async (track) => {
      started = await startRole(role, track);
    });
    if (!started) return;
    nodes.current[role] = started;
    const info = await started.nodeInfo();
    if (role === 'seller') setSellerPubkey(info.pubkey);
    setAddresses((previous) => ({ ...previous, [role]: scriptToAddress(info.default_funding_lock_script, 'testnet') }));
    if (await readChannel(started)) await started.connectPeer(bottle);
    await refresh(role);
  }

  async function open(role: Role) {
    const node = nodes.current[role];
    if (!node) return;
    const channel = await connectAndOpenChannel(node);
    setChannels((previous) => ({ ...previous, [role]: channel }));
    await refresh(role);
    setStatus(channel && ready(channel) ? 'Channel ready.' : 'Opening submitted. Check channel status after confirmation.');
  }

  async function moveLiquidity() {
    const node = nodes.current.seller;
    if (!node) return;
    const id = savedNodeIdentifier(localStorage, encryptedSellerProfile);
    const storageKey = `fiber-docs:encrypted-inbound:${id}`;
    const existing = sessionStorage.getItem(storageKey);
    if (existing === 'submitting') throw new Error('Transfer outcome unknown. Review payment history before sending again.');
    let result: GetPaymentResult;
    if (existing) result = await node.getPayment({ payment_hash: existing as `0x${string}` });
    else {
      sessionStorage.setItem(storageKey, 'submitting');
      result = await node.sendPayment({ target_pubkey: bottle.pubkey, amount: '0x1dcd6500', keysend: true });
      sessionStorage.setItem(storageKey, result.payment_hash);
    }
    if (!['Success', 'Failed'].includes(result.status)) result = await node.waitForPayment(result.payment_hash, { timeout: 60_000, interval: 1_000 });
    if (result.status === 'Failed') sessionStorage.removeItem(storageKey);
    setStatus(`Liquidity transfer: ${result.status}`);
    await refresh('seller');
  }

  async function makeOffer() {
    if (!nodes.current.seller || !channels.seller || !routeReady || generated || attempt) return;
    const value = await createOffer(nodes.current.seller, channels.seller, plaintext);
    save({ generatedOffer: value }); setGenerated(value); setStatus('Invoice created.');
  }

  async function validate() {
    if (!nodes.current.buyer) return;
    if (!sellerPubkey) throw new Error('Start the Seller node before validating an offer.');
    let stage: 'parse' | 'key' | 'auth' = 'parse';
    setChecks({ key: 'checking', origin: 'idle', payload: 'idle', detail: 'Checking the version 3 offer format.' });
    try {
      const parsed = parseOffer(received);
      stage = 'key';
      setChecks({ key: 'checking', origin: 'idle', payload: 'idle', detail: 'Checking Invoice amount and payment hash.' });
      const invoice = await validateOffer(nodes.current.buyer, parsed);
      stage = 'auth';
      setChecks({ key: 'pass', origin: 'checking', payload: 'checking', detail: 'Checking the seller identity and payload digest.' });
      await assertOfferAuthentic(invoice, parsed, sellerPubkey);
      if (attempt && parsed.paymentHash.toLowerCase() !== attempt.toLowerCase()) throw new Error('Restore the offer for the previous payment.');
      setChecks({ key: 'pass', origin: 'pass', payload: 'pass', detail: 'Verified: Seller C issued this offer and the ciphertext is unchanged.' });
      save({ buyerOfferText: received }); setOffer(parsed); setStatus('Offer validated and verified from Seller C.');
    } catch (failure) {
      const message = failure instanceof Error ? failure.message : 'Offer validation failed.';
      setChecks({
        key: stage === 'parse' ? 'idle' : stage === 'key' ? 'fail' : 'pass',
        origin: stage === 'auth' && /expected seller|missing a valid authenticity attestation/.test(message) ? 'fail' : stage === 'auth' ? 'pass' : 'idle',
        payload: stage === 'auth' && /payload was modified|missing a valid authenticity attestation/.test(message) ? 'fail' : stage === 'auth' ? 'pass' : 'idle',
        detail: message,
      });
      throw failure;
    }
  }

  async function testLock() {
    if (!offer) return;
    try { await decryptResult(offer, toHex(crypto.getRandomValues(new Uint8Array(32)))); }
    catch { save({ triedWithoutKey: true }); setTested(true); setStatus('Decryption rejected: key unavailable.'); }
  }

  async function pay() {
    if (!nodes.current.buyer || !offer || !tested || !routeReady) return;
    const result = await payForOffer(nodes.current.buyer, offer, attempt, (hash) => {
      save({ attemptedPaymentHash: hash }); setAttempt(hash);
    }, payment?.status === 'Failed');
    acceptPayment(result);
    await Promise.all([refresh('buyer'), refresh('seller')]);
  }

  function acceptPayment(result: GetPaymentResult) {
    setPayment(result); setStatus(`Payment: ${result.status}`);
    if (result.status === 'Failed') setError(result.failed_error ?? 'Payment failed. Check channel liquidity before retrying.');
    if (result.status === 'Success' && result.payment_preimage) setKey(result.payment_preimage);
  }

  async function checkPayment() {
    if (!nodes.current.buyer || !offer || !attempt) return;
    await validateOffer(nodes.current.buyer, offer);
    acceptPayment(await nodes.current.buyer.getPayment({ payment_hash: attempt as `0x${string}` }));
  }

  function startAnotherOffer() {
    if (busy || (attempt && payment?.status !== 'Failed')) return;
    save({ generatedOffer: '', buyerOfferText: '', attemptedPaymentHash: '', triedWithoutKey: false, completedSteps: [] });
    setGenerated(''); setReceived(''); setOffer(null); setChecks(idleChecks); setAttempt(''); setTested(false);
    setPayment(null); setKey(''); setDecrypted(''); setError('');
    setStatus('Create a fresh encrypted offer.');
  }

  async function makeVault() {
    if (!nodes.current.seller || !channels.seller || !routeReady || !vaultFile || vaultGenerated) return;
    const text = await createVault(vaultFile, vaultMode === 'whole' ? 1 : 4, nodes.current.seller, channels.seller);
    saveVault({ generatedText: text });
    setVaultGenerated(text);
    setStatus(`Vault created: ${vaultMode === 'whole' ? '1 invoice (whole file)' : '4 invoices'}.`);
  }

  async function validateVaultOffer() {
    if (!nodes.current.buyer || !sellerPubkey || !vaultReceived) return;
    const manifest = parseVaultManifest(vaultReceived);
    await validateVault(nodes.current.buyer, manifest, sellerPubkey);
    const keep = vaultProgress.current?.manifestText === vaultReceived ? vaultProgress.current.paidHashes : [];
    setVaultManifest(manifest); setVaultValidated(true); setVaultPaid(keep);
    setVaultKeys({}); setVaultPlain({}); setVaultTested({});
    saveVault({ manifestText: vaultReceived, paidHashes: keep });
    setStatus(`Vault validated: ${manifest.chunkCount} invoice(s) authenticated from Seller C.`);
  }

  async function testVaultLock(index: number) {
    const chunk = vaultManifest?.chunks[index];
    if (!chunk) return;
    let rejected = false;
    try {
      await decryptVaultChunk(chunk, toHex(crypto.getRandomValues(new Uint8Array(32))));
    } catch { rejected = true; }
    if (!rejected) throw new Error('Chunk decrypted without a key.');
    setVaultTested((previous) => ({ ...previous, [index]: true }));
    setStatus(`Chunk ${index + 1} is locked without its key.`);
  }

  async function payVaultChunk(index: number) {
    if (!nodes.current.buyer || !vaultValidated || !vaultManifest || !routeReady) return;
    const chunk = vaultManifest.chunks[index];
    const attempt = vaultPaid.includes(chunk.paymentHash) ? chunk.paymentHash : '';
    const result = await payForOffer(nodes.current.buyer, chunkOffer(chunk), attempt, (hash) => {
      const next = hash
        ? Array.from(new Set([...vaultPaid, hash]))
        : vaultPaid.filter((value) => value.toLowerCase() !== chunk.paymentHash.toLowerCase());
      saveVault({ paidHashes: next }); setVaultPaid(next);
    }, true);
    if (result.status === 'Success' && result.payment_preimage) {
      setVaultKeys((previous) => ({ ...previous, [index]: result.payment_preimage! }));
    }
    if (result.status === 'Failed') setError(result.failed_error ?? `Chunk ${index + 1} payment failed. Check channel liquidity before retrying.`);
    setStatus(`Chunk ${index + 1} payment: ${result.status}`);
    await Promise.all([refresh('buyer'), refresh('seller')]);
  }

  async function decryptVaultWithKey(index: number) {
    const chunk = vaultManifest?.chunks[index];
    const revealed = vaultKeys[index];
    if (!chunk || !revealed) return;
    const bytes = await decryptVaultChunk(chunk, revealed);
    setVaultPlain((previous) => ({ ...previous, [index]: bytes }));
    setStatus(`Chunk ${index + 1} decrypted (${bytes.length} bytes).`);
  }

  async function checkVaultPayments() {
    if (!nodes.current.buyer || !sellerPubkey || !vaultManifest) return;
    await validateVault(nodes.current.buyer, vaultManifest, sellerPubkey);
    const found: Record<number, string> = {};
    const failed: string[] = [];
    for (const hash of vaultPaid) {
      const index = vaultManifest.chunks.findIndex((chunk) => chunk.paymentHash.toLowerCase() === hash.toLowerCase());
      if (index < 0) continue;
      try {
        const result = await nodes.current.buyer.getPayment({ payment_hash: hash as `0x${string}` });
        if (result.status === 'Success' && result.payment_preimage) found[index] = result.payment_preimage;
        else failed.push(`chunk ${index + 1}`);
      } catch { failed.push(`chunk ${index + 1}`); }
    }
    setVaultKeys((previous) => ({ ...previous, ...found }));
    setVaultValidated(true);
    setStatus(`Restored ${Object.keys(found).length} paid chunk key(s).${failed.length ? ` Needs attention: ${failed.join(', ')}.` : ''}`);
  }

  async function downloadVault() {
    if (!vaultManifest) return;
    const pieces = vaultManifest.chunks.map((_, index) => vaultPlain[index]);
    if (pieces.some((piece) => !piece)) return;
    const bytes = reassemble(pieces as Uint8Array[]);
    const url = URL.createObjectURL(new Blob([bytes.buffer as ArrayBuffer], { type: vaultManifest.file.mime }));
    const link = document.createElement('a');
    link.href = url; link.download = vaultManifest.file.name;
    document.body.appendChild(link); link.click(); link.remove();
    URL.revokeObjectURL(url);
    setStatus(`Downloaded ${vaultManifest.file.name} (${bytes.length} bytes).`);
  }

  function startAnotherVault() {
    if (busy) return;
    saveVault({ generatedText: '', manifestText: '', paidHashes: [] });
    setVaultFile(null); setVaultGenerated(''); setVaultReceived(''); setVaultManifest(null);
    setVaultValidated(false); setVaultPaid([]); setVaultTested({}); setVaultKeys({}); setVaultPlain({});
    setError(''); setStatus('Create a fresh encrypted file vault.');
  }

  const routeReady = Boolean(connected.buyer && connected.seller && channels.buyer && ready(channels.buyer) && BigInt(channels.buyer.local_balance) >= 100_000_000n && channels.seller && ready(channels.seller) && BigInt(channels.seller.remote_balance) >= 100_000_000n);
  const routeNote = routeReady ? '' :
    !channels.buyer || !channels.seller ? 'Open a channel on both sides.' :
    !connected.buyer || !connected.seller ? 'Both nodes must be connected to Bottle.' :
    !ready(channels.buyer) || !ready(channels.seller) ? 'A channel is still opening or STALE — wait or refresh.' :
    BigInt(channels.buyer.local_balance) < 100_000_000n ? 'Buyer has no spendable CKB on A–B.' :
    'Bottle has no spendable CKB on B–C — reopen the Seller channel or send CKB to Bottle.';
  const canSubmit = Boolean(offer && tested && routeReady && !key && (!attempt || payment?.status === 'Failed'));

  return <main>
    <p className="eyebrow">Fiber Testnet</p><h1>Pay to decrypt</h1>
    {status && <p className="status" role="status">{status}</p>}{error && <p role="alert">{error}</p>}
    {!routeReady && routeNote && <p role="status">{routeNote}</p>}
    <div className="grid">{(['buyer', 'seller'] as const).map((role) => <section className="card" key={role}>
      <h2>{role === 'buyer' ? 'Buyer A' : 'Seller C'}</h2>
      {!addresses[role] && <button disabled={!loaded || busy} onClick={() => void run(() => start(role))}>Start node</button>}
      {addresses[role] && <><code>{addresses[role]}</code><a href="https://faucet.nervos.org" target="_blank" rel="noreferrer">Get Testnet CKB ↗</a>
        {!channels[role] && <p>{channelFundingGuidance}</p>}
        <button disabled={busy} onClick={() => void run(() => open(role))}>{channels[role] ? 'Reconnect / check channel' : `Open ${channelFundingCkb} CKB channel`}</button>
        <button disabled={busy} onClick={() => void run(() => refresh(role))}>Refresh channel status</button>
      </>}
      {channels[role] && <><code>{channels[role].state.state_name}</code><p>{role}: {ckb(channels[role].local_balance)} CKB · Bottle: {ckb(channels[role].remote_balance)} CKB</p></>}
    </section>)}</div>
    {(allChannels.buyer?.length || allChannels.seller?.length) ? <details className="card">
      <summary>Channel diagnostics</summary>
      {(['buyer', 'seller'] as const).map((role) => (allChannels[role]?.length ?? 0) > 0 && <div key={role}>
        <strong>{role === 'buyer' ? 'Buyer A' : 'Seller C'}</strong>
        {allChannels[role]!.map((channel) => <p key={channel.channel_id}>
          <code>{channel.state.state_name}</code>{ready(channel) ? ' ✓' : ''}
          {' · you '}{ckb(channel.local_balance)} CKB
          {' · Bottle '}{ckb(channel.remote_balance)} CKB
          {' · '}<code>{channel.channel_id}</code>
          {channel.failure_detail ? ` · ${channel.failure_detail}` : ''}
        </p>)}
      </div>)}
      <p>One READY channel per side is enough. Extra/STALE channels can hold balances that do not route.</p>
    </details> : null}
    <section className="card"><h2>Liquidity</h2><button disabled={busy || !channels.seller || !ready(channels.seller) || BigInt(channels.seller.local_balance) < 500_000_000n} onClick={() => void run(moveLiquidity)}>Send / check 5 CKB transfer</button></section>
    <div className="grid exchange"><section className="card"><h2>Seller</h2>
      <textarea aria-label="Seller result" disabled={busy || Boolean(generated)} value={plaintext} onChange={e => setPlaintext(e.target.value)} />
      <button disabled={busy || !routeReady || !plaintext.trim() || Boolean(generated || attempt)} onClick={() => void run(makeOffer)}>Encrypt & create 1 CKB Invoice</button>
      <textarea aria-label="Generated offer" readOnly value={generated} />
      <button disabled={!generated || busy} onClick={() => void run(async () => { await navigator.clipboard.writeText(generated); setStatus('Offer copied.'); })}>Copy offer</button>
    </section><section className="card"><h2>Buyer</h2>
      <textarea aria-label="Received offer" disabled={busy || Boolean(offer || attempt)} value={received} onChange={e => { setReceived(e.target.value); setTested(false); }} />
      <button disabled={busy || !received || !addresses.buyer || Boolean(offer)} onClick={() => void run(validate)}>Validate offer</button>
      {!tested && <button disabled={busy || !offer} onClick={() => void run(testLock)}>Decrypt without key</button>}
      {canSubmit && <button disabled={busy} onClick={() => void run(pay)}>{attempt ? 'Retry failed payment' : 'Pay 1 CKB'}</button>}
      {attempt && !key && <button disabled={busy || !offer || !addresses.buyer} onClick={() => void run(checkPayment)}>Check payment status</button>}
      <button disabled={busy || !offer || !key || Boolean(decrypted)} onClick={() => void run(async () => { setDecrypted(await decryptResult(offer!, key)); })}>Decrypt with revealed key</button>
    </section></div>
    {checks.key !== 'idle' && <section className="card"><h2>Offer authenticity (v3)</h2>
      <p>Three independent checks run before any payment is sent.</p>
      <p>{checkLabel(checks.key)} Payment hash — Invoice amount and AES key preimage</p>
      <p>{checkLabel(checks.origin)} Seller origin — Invoice payee_public_key is Seller C</p>
      <p>{checkLabel(checks.payload)} Payload binding — description digest covers ciphertext, IV and last hop</p>
      {checks.detail && <p>{checks.detail}</p>}
    </section>}
    {payment?.status === 'Success' && <section className="card"><h2>Receipt</h2><p>Amount: 1 CKB · Fee: {ckb(payment.fee)} CKB · Total: {ckb(`0x${(100_000_000n + BigInt(payment.fee)).toString(16)}`)} CKB</p><code>{payment.payment_hash}</code></section>}
    {decrypted && <section className="result"><h2>Decrypted result</h2><pre>{decrypted}</pre></section>}
    {(generated || received) && (!attempt || payment?.status === 'Failed') && <button disabled={busy} onClick={() => void run(async () => startAnotherOffer())}>Start another offer</button>}
    <section className="card"><h2>Encrypted file vault</h2>
      <p>Pay per chunk and reassemble a file. Whole file issues 1 invoice; chunked issues 4. Every invoice is bound to its own chunk by the Seller C attestation.</p>
      <div className="grid">
        <div className="card"><h3>Seller — create vault</h3>
          <input aria-label="Vault file" type="file" disabled={busy || Boolean(vaultGenerated)} onChange={e => setVaultFile(e.target.files?.[0] ?? null)} />
          <label><input type="radio" name="vault-mode" checked={vaultMode === 'whole'} disabled={busy || Boolean(vaultGenerated)} onChange={() => setVaultMode('whole')} /> Whole file (1 payment)</label>
          <label><input type="radio" name="vault-mode" checked={vaultMode === 'chunked'} disabled={busy || Boolean(vaultGenerated)} onChange={() => setVaultMode('chunked')} /> Chunked (4 payments)</label>
          <button disabled={busy || !routeReady || !vaultFile || Boolean(vaultGenerated)} onClick={() => void run(makeVault)}>Encrypt & create invoices</button>
          <textarea aria-label="Generated vault manifest" readOnly value={vaultGenerated} />
          <button disabled={busy || !vaultGenerated} onClick={() => void run(async () => { await navigator.clipboard.writeText(vaultGenerated); setStatus('Vault manifest copied.'); })}>Copy manifest</button>
        </div>
        <div className="card"><h3>Buyer — unlock vault</h3>
          <textarea aria-label="Received vault manifest" disabled={busy || Boolean(vaultManifest)} value={vaultReceived} onChange={e => { setVaultReceived(e.target.value); setVaultValidated(false); }} />
          <button disabled={busy || !vaultReceived || !addresses.buyer || Boolean(vaultManifest)} onClick={() => void run(validateVaultOffer)}>Validate manifest</button>
          {vaultManifest && !vaultValidated && <button disabled={busy || !sellerPubkey} onClick={() => void run(checkVaultPayments)}>Check restored payments</button>}
          {vaultManifest && <div className="vault-chunks">
            {vaultManifest.chunks.map((chunk, index) => <div key={chunk.index}>
              <code>{`Chunk ${index + 1}`}</code>
              <span>{vaultPlain[index] ? 'decrypted ✓' : vaultKeys[index] ? 'key ready' : vaultPaid.includes(chunk.paymentHash) ? 'payment recorded' : 'locked'}</span>
              {!vaultTested[index] && <button disabled={busy || !vaultValidated} onClick={() => void run(() => testVaultLock(index))}>Decrypt without key</button>}
              {vaultTested[index] && !vaultKeys[index] && <button disabled={busy || !vaultValidated || !routeReady} onClick={() => void run(() => payVaultChunk(index))}>Pay 1 CKB</button>}
              {vaultKeys[index] && !vaultPlain[index] && <button disabled={busy} onClick={() => void run(() => decryptVaultWithKey(index))}>Decrypt chunk</button>}
            </div>)}
          </div>}
          <button disabled={busy || !vaultManifest || vaultManifest.chunks.some((_, index) => !vaultPlain[index])} onClick={() => void run(downloadVault)}>Download file</button>
        </div>
      </div>
      {(vaultGenerated || vaultReceived) && <button disabled={busy} onClick={() => void run(async () => startAnotherVault())}>Start another vault</button>}
    </section>
  </main>;
}

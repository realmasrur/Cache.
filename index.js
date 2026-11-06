'use strict';
require('dotenv').config();

const fs = require('node:fs');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite'); // built into Node >=22.13, no native build step
const { ethers } = require('ethers');
const {
  Client, GatewayIntentBits, REST, Routes, Events, MessageFlags,
  SlashCommandBuilder, ModalBuilder, TextInputBuilder, TextInputStyle,
  ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder, AttachmentBuilder,
} = require('discord.js');
const { renderQr } = require('./qr');

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */
const env = process.env;
const need = (k) => {
  if (!env[k]) { console.error(`Missing required env var ${k}`); process.exit(1); }
  return env[k];
};
const TOKEN = need('DISCORD_TOKEN');
const CLIENT_ID = need('DISCORD_CLIENT_ID');
const RPC_URLS = need('RPC_URL').split(',').map((s) => s.trim()).filter(Boolean); // comma-separated = fallback list
const MASTER_SECRET = need('MASTER_SECRET');
if (MASTER_SECRET.length < 32) {
  console.error('MASTER_SECRET must be at least 32 characters (try: openssl rand -hex 32)');
  process.exit(1);
}
const GUILD_ID = env.GUILD_ID || null;
const DB_PATH = env.DB_PATH || './wallets.db';
const SYMBOL = env.NATIVE_SYMBOL || 'ETH';
const EXPLORER_TX = env.EXPLORER_TX_URL || '';           // e.g. https://sepolia.etherscan.io/tx/
const LOGO_PATH = env.LOGO_PATH || '';                   // optional PNG for the QR centre; default = bot avatar
const CONFIRMATIONS = Number(env.CONFIRMATIONS ?? 2);
const POLL_MS = Number(env.POLL_MS || 12000);

const MAX_ATTEMPTS = 5;
const BASE_LOCK_MS = 15 * 60 * 1000;
const MAX_LOCK_MS = 24 * 60 * 60 * 1000;
const SEND_TTL_MS = 2 * 60 * 1000;
const MAX_BLOCKS_PER_TICK = 20;
const PIN_RE = /^\d{6,12}$/;

/* ------------------------------------------------------------------ */
/* Crypto: AES-256-GCM, key = HMAC(masterKey, scrypt(PIN, salt))       */
/* ------------------------------------------------------------------ */
const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
const masterKey = crypto.scryptSync(MASTER_SECRET, 'discord-wallet-bot/master/v1', 32, SCRYPT);

async function deriveKey(pin, salt) {
  const pinKey = await scrypt(pin, salt, 32, SCRYPT);
  return crypto.createHmac('sha256', masterKey).update(pinKey).digest();
}
const aad = (userId, address) => Buffer.from(`${userId}:${address.toLowerCase()}`);

async function encryptKey(userId, address, privateKey, pin) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(pin, salt);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad(userId, address));
  const pt = Buffer.from(privateKey.slice(2), 'hex');
  const ct = Buffer.concat([c.update(pt), c.final()]);
  pt.fill(0); key.fill(0);
  return { salt, iv, tag: c.getAuthTag(), ct };
}

async function decryptKey(row, pin) {
  try {
    const key = await deriveKey(pin, Buffer.from(row.salt));
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(row.iv));
    d.setAAD(aad(row.discord_id, row.address));
    d.setAuthTag(Buffer.from(row.tag));
    const pt = Buffer.concat([d.update(Buffer.from(row.ct)), d.final()]);
    const hex = '0x' + pt.toString('hex');
    pt.fill(0); key.fill(0);
    return hex;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Database                                                            */
/* ------------------------------------------------------------------ */
const db = new DatabaseSync(DB_PATH);
try { fs.chmodSync(DB_PATH, 0o600); } catch { /* non-fatal */ }
db.exec('PRAGMA journal_mode = WAL;');
db.exec(`
  CREATE TABLE IF NOT EXISTS wallets (
    discord_id      TEXT PRIMARY KEY,
    address         TEXT NOT NULL UNIQUE,
    salt            BLOB NOT NULL,
    iv              BLOB NOT NULL,
    tag             BLOB NOT NULL,
    ct              BLOB NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    lock_count      INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    since_block     INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS deposits (
    tx_hash    TEXT NOT NULL,
    discord_id TEXT NOT NULL,
    amount     TEXT NOT NULL,
    block      INTEGER NOT NULL,
    PRIMARY KEY (tx_hash, discord_id)
  );
`);
const st = {
  get: db.prepare('SELECT * FROM wallets WHERE discord_id = ?'),
  all: db.prepare('SELECT discord_id, address, since_block FROM wallets'),
  insert: db.prepare(`INSERT INTO wallets (discord_id, address, salt, iv, tag, ct, since_block, created_at)
                      VALUES (@discord_id, @address, @salt, @iv, @tag, @ct, @since_block, @created_at)`),
  reencrypt: db.prepare('UPDATE wallets SET salt=@salt, iv=@iv, tag=@tag, ct=@ct WHERE discord_id=@discord_id'),
  del: db.prepare('DELETE FROM wallets WHERE discord_id = ?'),
  attempt: db.prepare('UPDATE wallets SET failed_attempts=?, lock_count=?, locked_until=? WHERE discord_id=?'),
  reset: db.prepare('UPDATE wallets SET failed_attempts=0, lock_count=0, locked_until=0 WHERE discord_id=?'),
  getMeta: db.prepare('SELECT value FROM meta WHERE key = ?'),
  setMeta: db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
  deposit: db.prepare('INSERT OR IGNORE INTO deposits (tx_hash, discord_id, amount, block) VALUES (?, ?, ?, ?)'),
};
const watch = new Map(); // lowercase address -> { id, since }
for (const r of st.all.all()) watch.set(r.address.toLowerCase(), { id: r.discord_id, since: r.since_block });

/* ------------------------------------------------------------------ */
/* PIN verification with persistent lockout                            */
/* ------------------------------------------------------------------ */
async function unlock(userId, pin) {
  const row = st.get.get(userId);
  if (!row) return { status: 'none' };
  const now = Date.now();
  if (row.locked_until > now) return { status: 'locked', until: row.locked_until };

  // Count the attempt synchronously BEFORE the slow check so parallel guesses can't bypass the limit.
  const attempts = row.failed_attempts + 1;
  let lockCount = row.lock_count;
  let lockedUntil = 0;
  const lockNow = attempts >= MAX_ATTEMPTS;
  if (lockNow) {
    lockCount += 1;
    lockedUntil = now + Math.min(BASE_LOCK_MS * 2 ** (lockCount - 1), MAX_LOCK_MS);
  }
  st.attempt.run(lockNow ? 0 : attempts, lockCount, lockedUntil, userId);

  const privateKey = await decryptKey(row, pin);
  if (privateKey) {
    st.reset.run(userId);
    return { status: 'ok', row, privateKey };
  }
  return lockNow
    ? { status: 'locked', until: lockedUntil }
    : { status: 'bad', left: MAX_ATTEMPTS - attempts };
}

/* ------------------------------------------------------------------ */
/* Presentation helpers                                                */
/* ------------------------------------------------------------------ */
const C = { brand: 0x5865f2, ok: 0x57f287, warn: 0xfee75c, err: 0xed4245 };
let NETWORK_LABEL = env.NETWORK_NAME || 'EVM';
let provider;
let lastScanned = 0;

class UserError extends Error {}

const base = (color) => new EmbedBuilder().setColor(color).setFooter({ text: `${NETWORK_LABEL} • ${SYMBOL}` });
const ok = (title, desc) => ({ embeds: [base(C.ok).setTitle(`✅ ${title}`).setDescription(desc || null)], components: [] });
const warn = (title, desc) => ({ embeds: [base(C.warn).setTitle(`⚠️ ${title}`).setDescription(desc || null)], components: [] });
const fail = (desc) => ({ embeds: [base(C.err).setTitle('❌ Something to fix').setDescription(desc)], components: [] });

function unlockFail(r) {
  if (r.status === 'none') return fail("You don't have a wallet yet. Use `/wallet panel` to set one up.");
  if (r.status === 'locked') {
    return { embeds: [base(C.err).setTitle('🔒 Wallet locked')
      .setDescription(`Too many wrong PINs. Try again <t:${Math.ceil(r.until / 1000)}:R>.`)], components: [] };
  }
  return fail(`Wrong PIN. **${r.left}** attempt${r.left === 1 ? '' : 's'} left before a lockout.`);
}

const fmt = (v, dp = 8) => {
  if (v === 0n) return '0';
  const [a, b = ''] = ethers.formatEther(v).split('.');
  const t = b.slice(0, dp).replace(/0+$/, '');
  if (!t && a === '0') return `<0.${'0'.repeat(dp - 1)}1`;
  return t ? `${a}.${t}` : a;
};
const gwei = (v) => Number(ethers.formatUnits(v, 'gwei')).toFixed(2);
const short = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
const txLink = (h) => (EXPLORER_TX ? `[${h.slice(0, 10)}…${h.slice(-6)}](${EXPLORER_TX}${h})` : `\`${h}\``);
const addrLink = (a) => (EXPLORER_TX.endsWith('/tx/') ? ` • [Explorer](${EXPLORER_TX.replace(/\/tx\/$/, '/address/')}${a})` : '');
// ethers often wraps the node's real error; dig it out so users see e.g. "nonce too low"
const rpcReason = (e) => e?.info?.error?.message || e?.error?.message || e?.shortMessage || e?.message || 'RPC error';
const botAvatar = () => client.user?.displayAvatarURL({ extension: 'png', size: 256 });

/* ------------------------------------------------------------------ */
/* QR code with logo                                                   */
/* ------------------------------------------------------------------ */
let logoBuf; // undefined = not loaded yet, null = none available
const qrCache = new Map();

async function loadLogo() {
  if (logoBuf !== undefined) return logoBuf;
  logoBuf = null;
  try {
    if (LOGO_PATH) logoBuf = fs.readFileSync(LOGO_PATH);
    else {
      const url = client.user.displayAvatarURL({ extension: 'png', size: 256, forceStatic: true });
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (res.ok) logoBuf = Buffer.from(await res.arrayBuffer());
    }
  } catch (e) { console.warn('Logo load failed, using built-in glyph:', e.message); }
  return logoBuf;
}

async function qrAttachment(address) {
  try {
    let png = qrCache.get(address);
    if (!png) {
      png = await renderQr(address, await loadLogo());
      if (qrCache.size > 200) qrCache.delete(qrCache.keys().next().value);
      qrCache.set(address, png);
    }
    return new AttachmentBuilder(png, { name: 'deposit.png' });
  } catch (e) {
    console.warn('QR render failed:', e.message);
    return null;
  }
}

async function depositPayload(address, headline = '📥 Deposit') {
  const file = await qrAttachment(address);
  const e = base(C.brand).setTitle(headline)
    .setDescription(`Send **${SYMBOL}** on **${NETWORK_LABEL}** to your address:\n\`\`\`${address}\`\`\`${addrLink(address).replace(' • ', '')}`)
    .addFields({ name: 'Heads up', value: `Only ${SYMBOL} is supported. Tokens sent here can't be viewed or sent by this bot. You'll get a DM when a deposit lands.` });
  if (file) e.setImage('attachment://deposit.png');
  return { embeds: [e], components: [], files: file ? [file] : [] };
}

/* ------------------------------------------------------------------ */
/* Chain connection                                                    */
/* ------------------------------------------------------------------ */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function probeChainId(url) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_chainId', params: [] }),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const j = await res.json();
  if (!j.result) throw new Error(j.error?.message || 'unexpected response');
  return BigInt(j.result);
}

async function connect() {
  for (let attempt = 1; ; attempt++) {
    const healthy = [];
    let chainId;
    for (const url of RPC_URLS) {
      try {
        const id = await probeChainId(url);
        if (chainId === undefined) chainId = id;
        if (id === chainId) healthy.push(url);
        else console.warn(`Skipping ${url}: different chain id`);
      } catch (e) {
        console.warn(`RPC unreachable (${url.replace(/\/[^/]{12,}$/, '/…')}): ${e.message}`);
      }
    }
    if (healthy.length) {
      const network = ethers.Network.from(chainId);
      if (!env.NETWORK_NAME) NETWORK_LABEL = network.name && network.name !== 'unknown' ? network.name : `Chain ${chainId}`;
      // batchMaxCount: 1 avoids "batch request not allowed" errors on many free RPC tiers
      const opts = { staticNetwork: network, batchMaxCount: 1 };
      const list = healthy.map((u) => new ethers.JsonRpcProvider(u, network, opts));
      console.log(`Connected: chain ${chainId} via ${healthy.length} RPC(s)`);
      return list.length === 1 ? list[0] : new ethers.FallbackProvider(list, network, { quorum: 1 });
    }
    console.warn(`No RPC reachable (attempt ${attempt}). Retrying in 10s…`);
    await sleep(10_000);
  }
}

async function storeWallet(userId, privateKey, address, pin) {
  const enc = await encryptKey(userId, address, privateKey, pin);
  let since = lastScanned;
  try { since = await provider.getBlockNumber(); } catch { /* keep lastScanned */ }
  st.insert.run({ discord_id: userId, address, ...enc, since_block: since, created_at: Date.now() });
  watch.set(address.toLowerCase(), { id: userId, since });
}

/* ------------------------------------------------------------------ */
/* Modals                                                              */
/* ------------------------------------------------------------------ */
const EPH = { flags: MessageFlags.Ephemeral };

const field = (id, label, o = {}) => {
  const input = new TextInputBuilder()
    .setCustomId(id).setLabel(label)
    .setStyle(o.long ? TextInputStyle.Paragraph : TextInputStyle.Short)
    .setRequired(true).setMinLength(o.min ?? 1).setMaxLength(o.max ?? 64);
  if (o.ph) input.setPlaceholder(o.ph);
  return new ActionRowBuilder().addComponents(input);
};
const pinField = (id = 'pin', label = 'PIN (6–12 digits)') => field(id, label, { min: 6, max: 12, ph: 'digits only' });
const modal = (id, title, ...rows) => new ModalBuilder().setCustomId(id).setTitle(title).addComponents(...rows);

const modals = {
  create: () => modal('wallet:create', 'Create wallet', pinField(), pinField('pin2', 'Confirm PIN')),
  import: () => modal('wallet:import', 'Import wallet',
    field('secret', 'Private key or recovery phrase', { long: true, max: 300 }), pinField(), pinField('pin2', 'Confirm PIN')),
  export: () => modal('wallet:export', 'Export private key', pinField()),
  changepin: () => modal('wallet:changepin', 'Change PIN', pinField('old', 'Current PIN'), pinField('pin', 'New PIN (6–12 digits)'), pinField('pin2', 'Confirm new PIN')),
  delete: () => modal('wallet:delete', 'Delete wallet', field('confirm', 'Type DELETE to confirm', { max: 6 }), pinField()),
  send: () => modal('send:form', `Send ${SYMBOL}`,
    field('to', 'Recipient address', { min: 42, max: 42, ph: '0x…' }),
    field('amount', `Amount in ${SYMBOL} (or "max")`, { max: 30, ph: '0.05' })),
};

/* ------------------------------------------------------------------ */
/* Dashboard                                                           */
/* ------------------------------------------------------------------ */
const btn = (id, label, style = ButtonStyle.Secondary) => new ButtonBuilder().setCustomId(id).setLabel(label).setStyle(style);

async function panelPayload(uid) {
  const row = st.get.get(uid);
  if (!row) {
    const e = base(C.brand).setTitle('👛 Set up your wallet')
      .setDescription([
        'Hold, receive and send crypto without leaving Discord.',
        '',
        '**Create** a brand-new wallet, or **Import** one you already own.',
        'Your key is encrypted with a PIN only you know.',
      ].join('\n'))
      .setThumbnail(botAvatar() || null);
    return { embeds: [e], components: [new ActionRowBuilder().addComponents(
      btn('ui:create', '✨ Create wallet', ButtonStyle.Success), btn('ui:import', '📥 Import wallet'),
    )] };
  }

  let bal = 'unavailable';
  try { bal = `${fmt(await provider.getBalance(row.address))} ${SYMBOL}`; } catch { /* RPC hiccup */ }
  const locked = row.locked_until > Date.now()
    ? `\n🔒 PIN locked <t:${Math.ceil(row.locked_until / 1000)}:R>` : '';
  const e = base(C.brand).setTitle('👛 Your wallet')
    .setDescription(`### ${bal}${locked}`)
    .addFields(
      { name: 'Address', value: `\`${row.address}\`${addrLink(row.address)}` },
      { name: 'Network', value: NETWORK_LABEL, inline: true },
    )
    .setThumbnail(botAvatar() || null)
    .setTimestamp();
  return { embeds: [e], components: [
    new ActionRowBuilder().addComponents(
      btn('ui:deposit', '📥 Deposit', ButtonStyle.Success), btn('ui:send', '📤 Send', ButtonStyle.Primary), btn('ui:refresh', '🔄 Refresh'),
    ),
    new ActionRowBuilder().addComponents(
      btn('ui:export', '🔑 Export key'), btn('ui:changepin', '🔐 Change PIN'), btn('ui:delete', '🗑️ Delete', ButtonStyle.Danger),
    ),
  ] };
}

/* ------------------------------------------------------------------ */
/* Send flow                                                           */
/* ------------------------------------------------------------------ */
const pending = new Map();
const sending = new Set();
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expires < now) pending.delete(k);
}, 60_000).unref();

async function buildQuote(row, toRaw, amountRaw) {
  const toIn = toRaw.trim();
  if (!ethers.isAddress(toIn)) throw new UserError('That is not a valid 0x address.');
  const to = ethers.getAddress(toIn.toLowerCase());
  if (to === ethers.ZeroAddress) throw new UserError('Refusing to send to the zero address.');

  const amt = amountRaw.trim();
  const isMax = amt.toLowerCase() === 'max';
  let value = 0n;
  if (!isMax) {
    if (!/^\d*\.?\d+$/.test(amt)) throw new UserError('Amount must be a positive number like `0.05`, or `max`.');
    try { value = ethers.parseEther(amt); } catch { throw new UserError('Invalid amount (max 18 decimals).'); }
    if (value <= 0n) throw new UserError('Amount must be greater than zero.');
  }

  const [balance, fd, code] = await Promise.all([
    provider.getBalance(row.address), provider.getFeeData(), provider.getCode(to),
  ]);
  if (!isMax && value > balance) throw new UserError(`Insufficient balance: you have **${fmt(balance)} ${SYMBOL}**.`);

  const eip1559 = fd.maxFeePerGas != null && fd.maxPriorityFeePerGas != null;
  const feePerGas = eip1559 ? fd.maxFeePerGas : fd.gasPrice;
  if (feePerGas == null) throw new UserError('Could not read gas prices from the RPC node.');

  let est;
  try {
    est = await provider.estimateGas({ from: row.address, to, value });
  } catch {
    throw new UserError('Gas estimation failed. The transaction would likely revert, or you lack funds for gas.');
  }
  const gasLimit = est === 21000n ? est : (est * 120n) / 100n;
  const fee = gasLimit * feePerGas;

  if (isMax) {
    value = balance - fee;
    if (value <= 0n) throw new UserError(`Your balance (${fmt(balance)} ${SYMBOL}) doesn't cover the network fee (~${fmt(fee)}).`);
  } else if (value + fee > balance) {
    throw new UserError(`Insufficient funds: need **${fmt(value + fee)} ${SYMBOL}** (amount + max fee), you have ${fmt(balance)}.`);
  }
  return { from: row.address, to, value, gasLimit, fee, balance, eip1559, feePerGas, tip: fd.maxPriorityFeePerGas, isContract: code !== '0x' };
}

function quotePayload(q, quoteId) {
  const e = base(C.brand).setTitle('📤 Review & confirm')
    .setDescription(`### ${ethers.formatEther(q.value)} ${SYMBOL}\n**${short(q.from)}** ➜ **${short(q.to)}**`)
    .addFields(
      { name: 'Recipient', value: `\`${q.to}\`` },
      { name: 'Max network fee', value: `${fmt(q.fee)} ${SYMBOL}`, inline: true },
      { name: 'Gas', value: `${q.gasLimit} @ ≤ ${gwei(q.feePerGas)} gwei`, inline: true },
      { name: 'Max total', value: `${fmt(q.value + q.fee)} ${SYMBOL}`, inline: true },
      { name: 'Balance after (worst case)', value: `${fmt(q.balance - q.value - q.fee)} ${SYMBOL}`, inline: true },
    );
  if (q.isContract) e.addFields({ name: '⚠️ Contract recipient', value: 'This address is a smart contract. Make sure it accepts plain transfers.' });
  e.addFields({ name: '\u200b', value: '⏱ Quote valid for 2 minutes. The real fee is usually lower than the max.' });
  return { embeds: [e], components: [new ActionRowBuilder().addComponents(
    btn(`send:ok:${quoteId}`, '✅ Confirm with PIN', ButtonStyle.Success), btn(`send:no:${quoteId}`, '✖ Cancel'),
  )] };
}

async function presentQuote(i, to, amount) {
  const row = st.get.get(i.user.id);
  if (!row) return i.editReply(fail("You don't have a wallet yet. Use `/wallet panel`."));
  const q = await buildQuote(row, to, amount);
  const quoteId = crypto.randomBytes(8).toString('hex');
  pending.set(quoteId, { ...q, userId: i.user.id, expires: Date.now() + SEND_TTL_MS });
  return i.editReply(quotePayload(q, quoteId));
}

async function handleSendSubmit(i, quoteId) {
  const pin = i.fields.getTextInputValue('pin').trim();
  const q = pending.get(quoteId);
  if (!q || q.userId !== i.user.id || q.expires < Date.now()) {
    return i.editReply(warn('Quote expired', 'This quote expired or was already used. Run `/send` again.'));
  }
  if (!PIN_RE.test(pin)) return i.editReply(fail('PIN must be 6–12 digits.'));
  if (sending.has(i.user.id)) return i.editReply(warn('Please wait', 'You already have a transaction being sent.'));

  const fd = await provider.getFeeData();
  const nowFee = q.eip1559 ? fd.maxFeePerGas : fd.gasPrice;
  if (nowFee != null && nowFee > (q.feePerGas * 125n) / 100n) {
    pending.delete(quoteId);
    return i.editReply(warn('Gas prices rose', 'Fees went up since your quote. Run `/send` again for a fresh estimate.'));
  }

  sending.add(i.user.id);
  try {
    const r = await unlock(i.user.id, pin);
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    if (!pending.delete(quoteId)) return i.editReply(warn('Already used', 'This quote was already used.'));

    const wallet = new ethers.Wallet(r.privateKey, provider);
    const req = { to: q.to, value: q.value, gasLimit: q.gasLimit };
    if (q.eip1559) Object.assign(req, { type: 2, maxFeePerGas: q.feePerGas, maxPriorityFeePerGas: q.tip });
    else Object.assign(req, { type: 0, gasPrice: q.feePerGas });

    let tx;
    try {
      tx = await wallet.sendTransaction(req);
    } catch (e) {
      console.error('send failed:', rpcReason(e));
      pending.set(quoteId, q); // PIN was correct; let them retry the same quote
      return i.editReply(fail(`Broadcast failed: ${rpcReason(e).slice(0, 200)}\nNothing was sent. You can press **Confirm** again.`));
    }

    const line = `**${ethers.formatEther(q.value)} ${SYMBOL}** ➜ \`${short(q.to)}\``;
    await i.editReply({ embeds: [base(C.warn).setTitle('⏳ Transaction sent')
      .setDescription(`${line}\nTx: ${txLink(tx.hash)}\nWaiting for confirmation…`)], components: [] });

    tx.wait(1, 180_000).then(
      (rc) => i.editReply({ embeds: [base(C.ok).setTitle('✅ Confirmed')
        .setDescription(`${line}\nBlock **${rc.blockNumber}** • Tx: ${txLink(tx.hash)}`)] }).catch(() => {}),
      (err) => {
        // ethers v6 REJECTS wait() on revert (CALL_EXCEPTION) and on timeout, so inspect the code
        let embed;
        if (err.code === 'CALL_EXCEPTION') {
          embed = base(C.err).setTitle('❌ Transaction reverted').setDescription(`${line}\nTx: ${txLink(tx.hash)}\nFunds were not transferred (gas was still spent).`);
        } else if (err.code === 'TRANSACTION_REPLACED') {
          embed = base(C.warn).setTitle('♻️ Transaction replaced').setDescription(`Tx: ${txLink(tx.hash)}`);
        } else {
          embed = base(C.warn).setTitle('⏳ Still pending').setDescription(`Not confirmed after 3 minutes. Track it: ${txLink(tx.hash)}`);
        }
        return i.editReply({ embeds: [embed] }).catch(() => {});
      },
    );
  } finally {
    sending.delete(i.user.id);
  }
}

/* ------------------------------------------------------------------ */
/* Modal submit handling                                               */
/* ------------------------------------------------------------------ */
function parseSecret(input) {
  const s = input.trim();
  try {
    if (/\s/.test(s)) {
      const w = ethers.Wallet.fromPhrase(s.toLowerCase().replace(/\s+/g, ' '));
      return { privateKey: w.privateKey, address: w.address };
    }
    const w = new ethers.Wallet(s.startsWith('0x') ? s : '0x' + s);
    return { privateKey: w.privateKey, address: w.address };
  } catch { return null; }
}

function checkPins(pin, pin2) {
  if (!PIN_RE.test(pin)) return 'PIN must be 6–12 digits.';
  if (pin !== pin2) return 'The PINs did not match.';
  if (/^(\d)\1+$/.test(pin) || '0123456789012'.includes(pin) || '9876543210987'.includes(pin)) {
    return 'That PIN is too easy to guess. Pick something less predictable (10+ digits is best).';
  }
  return null;
}

async function handleModal(i) {
  const id = i.customId;
  const uid = i.user.id;
  await i.deferReply(EPH);

  if (id === 'send:form') {
    return presentQuote(i, i.fields.getTextInputValue('to'), i.fields.getTextInputValue('amount'));
  }

  if (id === 'wallet:create' || id === 'wallet:import') {
    const pin = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(pin, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(fail(err));
    if (st.get.get(uid)) return i.editReply(warn('Wallet exists', 'You already have a wallet.'));

    let w;
    const creating = id === 'wallet:create';
    if (creating) {
      const r = ethers.Wallet.createRandom();
      w = { privateKey: r.privateKey, address: r.address };
    } else {
      w = parseSecret(i.fields.getTextInputValue('secret'));
      if (!w) return i.editReply(fail('Could not read that as a private key or recovery phrase.'));
    }
    try {
      await storeWallet(uid, w.privateKey, w.address, pin);
    } catch (e) {
      if (/constraint/i.test(String(e.message))) return i.editReply(fail('That wallet is already registered with this bot.'));
      throw e;
    }
    const p = await depositPayload(w.address, creating ? '🎉 Wallet created' : '🎉 Wallet imported');
    p.embeds[0].addFields({
      name: 'Important',
      value: 'Back up your key with **Export key** in `/wallet panel`. If you forget your PIN, your funds are unrecoverable.',
    });
    return i.editReply(p);
  }

  if (id === 'wallet:export') {
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim());
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    return i.editReply({ embeds: [base(C.warn).setTitle('🔑 Your private key')
      .setDescription(`Never share this. Anyone with it controls your funds.\n||\`${r.privateKey}\`||`)] });
  }

  if (id === 'wallet:changepin') {
    const nu = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(nu, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(fail(err));
    const r = await unlock(uid, i.fields.getTextInputValue('old').trim());
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    const enc = await encryptKey(uid, r.row.address, r.privateKey, nu);
    st.reencrypt.run({ discord_id: uid, ...enc });
    return i.editReply(ok('PIN changed', 'Use your new PIN from now on.'));
  }

  if (id === 'wallet:delete') {
    if (i.fields.getTextInputValue('confirm').trim() !== 'DELETE') return i.editReply(warn('Cancelled', 'You must type `DELETE` exactly.'));
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim());
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    st.del.run(uid);
    watch.delete(r.row.address.toLowerCase());
    return i.editReply(ok('Wallet deleted', 'Removed from this bot. Funds on the address are only recoverable if you exported the key.'));
  }

  if (id.startsWith('send:pin:')) return handleSendSubmit(i, id.slice('send:pin:'.length));
}

/* ------------------------------------------------------------------ */
/* Commands, buttons                                                   */
/* ------------------------------------------------------------------ */
const commands = [
  new SlashCommandBuilder().setName('wallet').setDescription('Your crypto wallet')
    .addSubcommand((s) => s.setName('panel').setDescription('Open your wallet dashboard'))
    .addSubcommand((s) => s.setName('create').setDescription('Create a new wallet'))
    .addSubcommand((s) => s.setName('import').setDescription('Import a private key or recovery phrase'))
    .addSubcommand((s) => s.setName('deposit').setDescription('Show your address and QR code'))
    .addSubcommand((s) => s.setName('balance').setDescription('Show your balance'))
    .addSubcommand((s) => s.setName('export').setDescription('Reveal your private key (PIN required)'))
    .addSubcommand((s) => s.setName('changepin').setDescription('Change your PIN'))
    .addSubcommand((s) => s.setName('delete').setDescription('Delete your wallet from this bot')),
  new SlashCommandBuilder().setName('send').setDescription(`Send ${SYMBOL} from your wallet`)
    .addStringOption((o) => o.setName('to').setDescription('Recipient 0x address').setRequired(true))
    .addStringOption((o) => o.setName('amount').setDescription(`Amount in ${SYMBOL}, or "max"`).setRequired(true)),
].map((c) => c.toJSON());

const client = new Client({ intents: [GatewayIntentBits.Guilds] });
const noWallet = () => ({ ...fail("You don't have a wallet yet. Use `/wallet panel` to set one up."), ...EPH });

async function handleCommand(i) {
  const uid = i.user.id;

  if (i.commandName === 'send') {
    await i.deferReply(EPH);
    return presentQuote(i, i.options.getString('to', true), i.options.getString('amount', true));
  }

  const sub = i.options.getSubcommand();
  const row = st.get.get(uid);

  if (sub === 'panel') {
    await i.deferReply(EPH);
    return i.editReply(await panelPayload(uid));
  }
  if (sub === 'create' || sub === 'import') {
    if (row) return i.reply({ ...warn('Wallet exists', 'You already have a wallet. Delete it first to start over.'), ...EPH });
    return i.showModal(modals[sub]());
  }
  if (!row) return i.reply(noWallet());

  if (sub === 'deposit') { await i.deferReply(EPH); return i.editReply(await depositPayload(row.address)); }
  if (sub === 'balance') {
    await i.deferReply(EPH);
    return i.editReply({ embeds: [base(C.brand).setTitle('💰 Balance')
      .setDescription(`### ${fmt(await provider.getBalance(row.address))} ${SYMBOL}\n\`${row.address}\``)] });
  }
  return i.showModal(modals[sub]()); // export | changepin | delete
}

async function handleButton(i) {
  const [ns, action, arg] = i.customId.split(':');

  if (ns === 'send') {
    const q = pending.get(arg);
    if (!q || q.userId !== i.user.id || q.expires < Date.now()) {
      pending.delete(arg);
      return i.update(warn('Quote expired', 'Run `/send` again for a fresh estimate.'));
    }
    if (action === 'no') {
      pending.delete(arg);
      return i.update({ embeds: [base(C.warn).setTitle('Cancelled').setDescription('Nothing was sent.')], components: [] });
    }
    return i.showModal(modal(`send:pin:${arg}`, 'Confirm transaction', pinField()));
  }

  if (ns === 'ui') {
    const row = st.get.get(i.user.id);
    if (action === 'create' || action === 'import') {
      if (row) return i.reply({ ...warn('Wallet exists', 'You already have a wallet.'), ...EPH });
      return i.showModal(modals[action]());
    }
    if (!row) return i.reply(noWallet());
    if (action === 'refresh') { await i.deferUpdate(); return i.editReply(await panelPayload(i.user.id)); }
    if (action === 'deposit') { await i.deferReply(EPH); return i.editReply(await depositPayload(row.address)); }
    return i.showModal(modals[action]()); // send | export | changepin | delete
  }
}

client.on(Events.InteractionCreate, async (i) => {
  try {
    if (i.isChatInputCommand()) await handleCommand(i);
    else if (i.isButton()) await handleButton(i);
    else if (i.isModalSubmit()) await handleModal(i);
  } catch (e) {
    if (!(e instanceof UserError)) console.error(e);
    const payload = fail(e instanceof UserError ? e.message : 'Something went wrong. Please try again.');
    try {
      if (i.deferred || i.replied) await i.editReply(payload);
      else await i.reply({ ...payload, ...EPH });
    } catch { /* interaction expired */ }
  }
});

/* ------------------------------------------------------------------ */
/* Deposit watcher                                                     */
/* ------------------------------------------------------------------ */
async function notifyDeposit(userId, address, tx, block) {
  const e = base(C.ok).setTitle('💸 Deposit received')
    .setDescription(`### +${ethers.formatEther(tx.value)} ${SYMBOL}`)
    .addFields(
      { name: 'From', value: `\`${short(tx.from)}\``, inline: true },
      { name: 'Block', value: String(block), inline: true },
      { name: 'Tx', value: txLink(tx.hash) },
    ).setThumbnail(botAvatar() || null).setTimestamp();
  try {
    const bal = await provider.getBalance(address);
    e.addFields({ name: 'New balance', value: `${fmt(bal)} ${SYMBOL}` });
  } catch { /* optional */ }
  try {
    const user = await client.users.fetch(userId);
    await user.send({ embeds: [e] });
  } catch (err) {
    console.warn(`Could not DM ${userId} (DMs closed?): ${err.message}`);
  }
}

async function pollDeposits() {
  try {
    const target = (await provider.getBlockNumber()) - CONFIRMATIONS;
    let done = 0;
    for (let n = lastScanned + 1; n <= target && done < MAX_BLOCKS_PER_TICK; n++, done++) {
      const block = await provider.getBlock(n, true);
      if (!block) break;
      for (const tx of block.prefetchedTransactions) {
        if (!tx.to || tx.value === 0n) continue;
        const w = watch.get(tx.to.toLowerCase());
        if (!w || n <= w.since || tx.from.toLowerCase() === tx.to.toLowerCase()) continue;
        if (st.deposit.run(tx.hash, w.id, tx.value.toString(), n).changes) notifyDeposit(w.id, tx.to, tx, n);
      }
      lastScanned = n;
      st.setMeta.run('last_scanned', String(n));
    }
  } catch (e) {
    console.error('watcher:', e.shortMessage || e.message);
  } finally {
    setTimeout(pollDeposits, POLL_MS);
  }
}

/* ------------------------------------------------------------------ */
/* Boot                                                                */
/* ------------------------------------------------------------------ */
(async () => {
  provider = await connect();
  const saved = st.getMeta.get('last_scanned');
  lastScanned = saved ? Number(saved.value) : (await provider.getBlockNumber()) - CONFIRMATIONS;

  const rest = new REST({ version: '10' }).setToken(TOKEN);
  await rest.put(
    GUILD_ID ? Routes.applicationGuildCommands(CLIENT_ID, GUILD_ID) : Routes.applicationCommands(CLIENT_ID),
    { body: commands },
  );

  client.once(Events.ClientReady, (c) => {
    console.log(`Logged in as ${c.user.tag}`);
    pollDeposits();
  });
  await client.login(TOKEN);
})().catch((e) => { console.error(e); process.exit(1); });

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { db.close(); } catch { /* ignore */ } process.exit(0); });
}

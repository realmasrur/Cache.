'use strict';
require('dotenv').config();

const fs = require('node:fs');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { ethers } = require('ethers');
const {
  Client, GatewayIntentBits, REST, Routes, Events, MessageFlags,
  SlashCommandBuilder, ModalBuilder, TextInputBuilder, TextInputStyle,
  ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder, AttachmentBuilder,
  StringSelectMenuBuilder, Options,
} = require('discord.js');
const { openDb } = require('./db');
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
const RPC_URLS = need('RPC_URL').split(',').map((s) => s.trim()).filter(Boolean);
const MASTER_SECRET = need('MASTER_SECRET');
if (MASTER_SECRET.length < 32) {
  console.error('MASTER_SECRET must be at least 32 characters (try: openssl rand -hex 32)');
  process.exit(1);
}
const GUILD_ID = env.GUILD_ID || null;
const DB_PATH = env.DB_PATH || './wallets.db';
const SYMBOL = env.NATIVE_SYMBOL || 'ETH';
const EXPLORER_TX = env.EXPLORER_TX_URL || '';
const LOGO_PATH = env.LOGO_PATH || '';                    // optional PNG for the QR centre; default = bot avatar
const CONFIRMATIONS = Number(env.CONFIRMATIONS ?? 2);
const POLL_MS = Number(env.POLL_MS || 12000);
const MAX_WALLETS = Math.min(Math.max(Number(env.MAX_WALLETS || 5), 1), 10);

const MAX_ATTEMPTS = 5;
const BASE_LOCK_MS = 15 * 60 * 1000;
const MAX_LOCK_MS = 24 * 60 * 60 * 1000;
const SEND_TTL_MS = 2 * 60 * 1000;
const MAX_BLOCKS_PER_TICK = 5;
const MAX_CATCHUP_BLOCKS = Number(env.MAX_CATCHUP_BLOCKS || 600); // after downtime, skip older blocks instead of replaying them
// scrypt memory = 128 * 2^N * 8 bytes: 15 -> 32 MB (default), 14 -> 16 MB, 13 -> 8 MB. Lower it on small hosts.
const SCRYPT_LOG_N = Math.min(Math.max(Number(env.SCRYPT_LOG_N || 15), 12), 17);
const PIN_RE = /^\d{6,12}$/;

const mem = () => {
  const m = process.memoryUsage();
  const mb = (x) => Math.round(x / 1048576);
  return `rss ${mb(m.rss)} MB (heap ${mb(m.heapUsed)}, native ${mb(m.external + m.arrayBuffers)})`;
};

/* ------------------------------------------------------------------ */
/* Crypto: AES-256-GCM, key = HMAC(masterKey, scrypt(PIN, salt))       */
/* ------------------------------------------------------------------ */
const scrypt = promisify(crypto.scrypt);
const scryptOpts = (logN) => ({ N: 2 ** logN, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
// Fixed forever: changing it would make every existing wallet undecryptable.
let masterKeyP;
const getMasterKey = () => (masterKeyP ||= scrypt(MASTER_SECRET, 'discord-wallet-bot/master/v1', 32, scryptOpts(15)));

// scrypt is memory-hungry: run them one at a time so concurrent users can't spike RAM.
let scryptQueue = Promise.resolve();
function deriveKey(pin, salt, logN) {
  const run = scryptQueue.then(async () => {
    const master = await getMasterKey();
    const pinKey = await scrypt(pin, salt, 32, scryptOpts(logN));
    return crypto.createHmac('sha256', master).update(pinKey).digest();
  });
  scryptQueue = run.catch(() => {});
  return run;
}
const aad = (userId, address) => Buffer.from(`${userId}:${address.toLowerCase()}`);

async function encryptKey(userId, address, privateKey, pin) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(pin, salt, SCRYPT_LOG_N);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad(userId, address));
  const pt = Buffer.from(privateKey.slice(2), 'hex');
  const ct = Buffer.concat([c.update(pt), c.final()]);
  pt.fill(0); key.fill(0);
  return { salt, iv, tag: c.getAuthTag(), ct, kdf_n: SCRYPT_LOG_N };
}

async function decryptKey(row, pin) {
  try {
    const key = await deriveKey(pin, Buffer.from(row.salt), row.kdf_n || 15);
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
/* Database + account helpers                                          */
/* ------------------------------------------------------------------ */
const { db, st } = openDb(DB_PATH);
const watch = new Map(); // lowercase address -> { acct, since }
for (const r of st.watchAll.all()) watch.set(r.address.toLowerCase(), { acct: r.id, since: r.since_block });

function activeAccount(uid) {
  const u = st.user.get(uid);
  if (!u) return null;
  let a = u.active_id ? st.account.get(u.active_id, uid) : null;
  if (!a) {
    a = st.accounts.all(uid)[0] || null;
    if (a) st.setActive.run(a.id, uid);
  }
  return a;
}

const cleanLabel = (s, fallback) => (String(s || '').replace(/\s+/g, ' ').trim().slice(0, 24) || fallback);

/* ------------------------------------------------------------------ */
/* PIN verification with persistent per-user lockout                   */
/* ------------------------------------------------------------------ */
async function unlock(userId, pin, accountId) {
  const u = st.user.get(userId);
  const row = accountId ? st.account.get(accountId, userId) : null;
  if (!u || !row) return { status: 'none' };
  const now = Date.now();
  if (u.locked_until > now) return { status: 'locked', until: u.locked_until };

  // Count the attempt synchronously BEFORE the slow check so parallel guesses can't bypass the limit.
  const attempts = u.failed_attempts + 1;
  let lockCount = u.lock_count;
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
  if (r.status === 'none') return fail("That wallet wasn't found. Use `/wallet panel` to set one up.");
  if (r.status === 'locked') {
    return { embeds: [base(C.err).setTitle('🔒 Wallets locked')
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
const addrLink = (a) => (EXPLORER_TX.endsWith('/tx/') ? `[Explorer](${EXPLORER_TX.replace(/\/tx\/$/, '/address/')}${a})` : '');
// ethers often wraps the node's real error; dig it out so users see e.g. "nonce too low"
const rpcReason = (e) => e?.info?.error?.message || e?.error?.message || e?.shortMessage || e?.message || 'RPC error';
const botAvatar = () => client.user?.displayAvatarURL({ extension: 'png', size: 256 });

/* ------------------------------------------------------------------ */
/* QR code with logo                                                   */
/* ------------------------------------------------------------------ */
let logoBuf; // undefined = not loaded yet, null = none
const qrCache = new Map();

async function loadLogo() {
  if (logoBuf !== undefined) return logoBuf;
  logoBuf = null;
  try {
    if (LOGO_PATH) logoBuf = fs.readFileSync(LOGO_PATH);
    else {
      const url = client.user.displayAvatarURL({ extension: 'png', size: 128, forceStatic: true });
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
      if (qrCache.size > 50) qrCache.delete(qrCache.keys().next().value);
      qrCache.set(address, png);
    }
    return new AttachmentBuilder(png, { name: 'deposit.png' });
  } catch (e) {
    console.warn('QR render failed:', e.message);
    return null;
  }
}

async function depositPayload(row, headline) {
  const file = await qrAttachment(row.address);
  const link = addrLink(row.address);
  const e = base(C.brand).setTitle(headline || `📥 Deposit • ${row.label}`)
    .setDescription(`Send **${SYMBOL}** on **${NETWORK_LABEL}** to this address:\n\`\`\`${row.address}\`\`\`\n${link}`)
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
      const opts = { staticNetwork: network, batchMaxCount: 1 }; // many free RPCs reject batched requests
      const list = healthy.map((u) => new ethers.JsonRpcProvider(u, network, opts));
      console.log(`Connected: chain ${chainId} via ${healthy.length} RPC(s)`);
      return list.length === 1 ? list[0] : new ethers.FallbackProvider(list, network, { quorum: 1 });
    }
    console.warn(`No RPC reachable (attempt ${attempt}). Retrying in 10s…`);
    await sleep(10_000);
  }
}

async function storeWallet(userId, label, privateKey, address, pin) {
  const enc = await encryptKey(userId, address, privateKey, pin);
  let since = lastScanned;
  try { since = await provider.getBlockNumber(); } catch { /* keep lastScanned */ }
  st.ensureUser.run(userId);
  const res = st.insert.run({ discord_id: userId, label, address, ...enc, since_block: since, created_at: Date.now() });
  const id = Number(res.lastInsertRowid);
  st.setActive.run(id, userId); // newly created/imported wallet becomes the active one
  watch.set(address.toLowerCase(), { acct: id, since });
  return id;
}

/* ------------------------------------------------------------------ */
/* Modals                                                              */
/* ------------------------------------------------------------------ */
const EPH = { flags: MessageFlags.Ephemeral };

const field = (id, label, o = {}) => {
  const input = new TextInputBuilder()
    .setCustomId(id).setLabel(label)
    .setStyle(o.long ? TextInputStyle.Paragraph : TextInputStyle.Short)
    .setRequired(!o.optional).setMinLength(o.optional ? 0 : (o.min ?? 1)).setMaxLength(o.max ?? 64);
  if (o.ph) input.setPlaceholder(o.ph);
  if (o.value) input.setValue(o.value);
  return new ActionRowBuilder().addComponents(input);
};
const pinField = (id = 'pin', label = 'PIN (6–12 digits)') => field(id, label, { min: 6, max: 12, ph: 'digits only' });
const labelField = () => field('label', 'Wallet name (optional)', { optional: true, max: 24, ph: 'e.g. Savings' });
const modal = (id, title, ...rows) => new ModalBuilder().setCustomId(id).setTitle(title.slice(0, 45)).addComponents(...rows);

const modals = {
  create: () => modal('wallet:create', 'Create wallet', labelField(), pinField(), pinField('pin2', 'Confirm PIN')),
  import: () => modal('wallet:import', 'Import wallet',
    field('secret', 'Private key or recovery phrase', { long: true, max: 300 }), labelField(), pinField(), pinField('pin2', 'Confirm PIN')),
  export: (a) => modal(`wallet:export:${a.id}`, `Export key: ${a.label}`, pinField()),
  changepin: (a) => modal(`wallet:changepin:${a.id}`, `Change PIN: ${a.label}`,
    pinField('old', 'Current PIN'), pinField('pin', 'New PIN (6–12 digits)'), pinField('pin2', 'Confirm new PIN')),
  delete: (a) => modal(`wallet:delete:${a.id}`, `Delete: ${a.label}`,
    field('confirm', 'Type DELETE to confirm', { max: 6 }), pinField()),
  rename: (a) => modal(`wallet:rename:${a.id}`, 'Rename wallet', field('label', 'New name', { max: 24, value: a.label })),
  send: () => modal('send:form', `Send ${SYMBOL}`,
    field('to', 'Recipient address', { min: 42, max: 42, ph: '0x…' }),
    field('amount', `Amount in ${SYMBOL} (or "max")`, { max: 30, ph: '0.05' })),
};

/* ------------------------------------------------------------------ */
/* Dashboard                                                           */
/* ------------------------------------------------------------------ */
const btn = (id, label, style = ButtonStyle.Secondary) => new ButtonBuilder().setCustomId(id).setLabel(label).setStyle(style);

async function panelPayload(uid) {
  const all = st.accounts.all(uid);
  const active = all.length ? activeAccount(uid) : null;
  if (!active) {
    const e = base(C.brand).setTitle('👛 Set up your wallet')
      .setDescription([
        'Hold, receive and send crypto without leaving Discord.',
        '',
        '**Create** a brand-new wallet, or **Import** one you already own.',
        'Each wallet is encrypted with a PIN only you know.',
      ].join('\n'))
      .setThumbnail(botAvatar() || null);
    return { embeds: [e], components: [new ActionRowBuilder().addComponents(
      btn('ui:create', '✨ Create wallet', ButtonStyle.Success), btn('ui:import', '📥 Import wallet'),
    )] };
  }

  const u = st.user.get(uid);
  let bal = 'unavailable';
  try { bal = `${fmt(await provider.getBalance(active.address))} ${SYMBOL}`; } catch { /* RPC hiccup */ }
  const locked = u.locked_until > Date.now() ? `\n🔒 PIN locked <t:${Math.ceil(u.locked_until / 1000)}:R>` : '';
  const link = addrLink(active.address);
  const e = base(C.brand).setTitle(`👛 ${active.label}`)
    .setDescription(`### ${bal}${locked}`)
    .addFields({ name: 'Address', value: `\`${active.address}\`${link ? `\n${link}` : ''}` })
    .setThumbnail(botAvatar() || null)
    .setTimestamp();
  if (all.length > 1) {
    e.addFields({
      name: `Your wallets (${all.length}/${MAX_WALLETS})`,
      value: all.map((a) => `${a.id === active.id ? '▶️' : '▫️'} **${a.label}** · \`${short(a.address)}\``).join('\n'),
    });
  }

  const rows = [];
  if (all.length > 1) {
    rows.push(new ActionRowBuilder().addComponents(
      new StringSelectMenuBuilder().setCustomId('ui:switch').setPlaceholder('Switch wallet…').addOptions(
        all.slice(0, 25).map((a) => ({ label: a.label, description: short(a.address), value: String(a.id), default: a.id === active.id })),
      ),
    ));
  }
  rows.push(
    new ActionRowBuilder().addComponents(
      btn('ui:deposit', '📥 Deposit', ButtonStyle.Success), btn('ui:send', '📤 Send', ButtonStyle.Primary), btn('ui:refresh', '🔄 Refresh'),
    ),
    new ActionRowBuilder().addComponents(
      btn('ui:create', '✨ New wallet'), btn('ui:import', '📥 Import'), btn('ui:rename', '✏️ Rename'),
    ),
    new ActionRowBuilder().addComponents(
      btn('ui:export', '🔑 Export key'), btn('ui:changepin', '🔐 Change PIN'), btn('ui:delete', '🗑️ Delete', ButtonStyle.Danger),
    ),
  );
  return { embeds: [e], components: rows };
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
  if (!isMax && value > balance) throw new UserError(`Insufficient balance in **${row.label}**: you have **${fmt(balance)} ${SYMBOL}**.`);

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
    throw new UserError(`Insufficient funds: need **${fmt(value + fee)} ${SYMBOL}** (amount + max fee), **${row.label}** has ${fmt(balance)}.`);
  }
  return {
    acct: row.id, label: row.label, from: row.address, to, value, gasLimit, fee, balance,
    eip1559, feePerGas, tip: fd.maxPriorityFeePerGas, isContract: code !== '0x',
  };
}

function quotePayload(q, quoteId) {
  const e = base(C.brand).setTitle('📤 Review & confirm')
    .setDescription(`### ${ethers.formatEther(q.value)} ${SYMBOL}\n**${q.label}** (${short(q.from)}) ➜ **${short(q.to)}**`)
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
  const row = activeAccount(i.user.id);
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
    const r = await unlock(i.user.id, pin, q.acct); // always the wallet the quote was made for
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

    const line = `**${ethers.formatEther(q.value)} ${SYMBOL}** from **${q.label}** ➜ \`${short(q.to)}\``;
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
  const [ns, kind, arg] = i.customId.split(':');
  const uid = i.user.id;
  await i.deferReply(EPH);

  if (ns === 'send') {
    if (kind === 'form') return presentQuote(i, i.fields.getTextInputValue('to'), i.fields.getTextInputValue('amount'));
    if (kind === 'pin') return handleSendSubmit(i, arg);
    return undefined;
  }

  if (kind === 'create' || kind === 'import') {
    const pin = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(pin, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(fail(err));
    const count = st.count.get(uid).n;
    if (count >= MAX_WALLETS) return i.editReply(warn('Wallet limit reached', `You can hold up to ${MAX_WALLETS} wallets. Delete one first.`));

    const creating = kind === 'create';
    let w;
    if (creating) {
      const r = ethers.Wallet.createRandom();
      w = { privateKey: r.privateKey, address: r.address };
    } else {
      w = parseSecret(i.fields.getTextInputValue('secret'));
      if (!w) return i.editReply(fail('Could not read that as a private key or recovery phrase.'));
    }
    const label = cleanLabel(i.fields.getTextInputValue('label'), `Wallet ${count + 1}`);
    let id;
    try {
      id = await storeWallet(uid, label, w.privateKey, w.address, pin);
    } catch (e) {
      if (/constraint/i.test(String(e.message))) return i.editReply(fail('That wallet is already registered with this bot.'));
      throw e;
    }
    const p = await depositPayload(st.account.get(id, uid), creating ? `🎉 Wallet created • ${label}` : `🎉 Wallet imported • ${label}`);
    p.embeds[0].addFields({
      name: 'Important',
      value: `It's now your **active** wallet. Back up its key with **Export key** in \`/wallet panel\`. If you forget this wallet's PIN, its funds are unrecoverable.`,
    });
    return i.editReply(p);
  }

  const row = st.account.get(Number(arg), uid);
  if (!row) return i.editReply(fail('That wallet no longer exists.'));

  if (kind === 'export') {
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim(), row.id);
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    return i.editReply({ embeds: [base(C.warn).setTitle(`🔑 Private key • ${row.label}`)
      .setDescription(`Never share this. Anyone with it controls your funds.\n||\`${r.privateKey}\`||`)] });
  }

  if (kind === 'rename') {
    const label = cleanLabel(i.fields.getTextInputValue('label'), row.label);
    st.rename.run(label, row.id, uid);
    return i.editReply(ok('Renamed', `**${row.label}** is now **${label}**.`));
  }

  if (kind === 'changepin') {
    const nu = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(nu, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(fail(err));
    const r = await unlock(uid, i.fields.getTextInputValue('old').trim(), row.id);
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    const enc = await encryptKey(uid, row.address, r.privateKey, nu);
    st.reencrypt.run({ id: row.id, ...enc });
    return i.editReply(ok('PIN changed', `Use the new PIN for **${row.label}** from now on.`));
  }

  if (kind === 'delete') {
    if (i.fields.getTextInputValue('confirm').trim() !== 'DELETE') return i.editReply(warn('Cancelled', 'You must type `DELETE` exactly.'));
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim(), row.id);
    if (r.status !== 'ok') return i.editReply(unlockFail(r));
    st.del.run(row.id, uid);
    watch.delete(row.address.toLowerCase());
    activeAccount(uid); // re-points the active wallet if needed
    return i.editReply(ok('Wallet deleted', `**${row.label}** was removed from this bot. Funds on \`${short(row.address)}\` are only recoverable if you exported the key.`));
  }
  return undefined;
}

/* ------------------------------------------------------------------ */
/* Commands, buttons, menus                                            */
/* ------------------------------------------------------------------ */
const commands = [
  new SlashCommandBuilder().setName('wallet').setDescription('Your crypto wallets')
    .addSubcommand((s) => s.setName('panel').setDescription('Open your wallet dashboard'))
    .addSubcommand((s) => s.setName('create').setDescription('Create a new wallet'))
    .addSubcommand((s) => s.setName('import').setDescription('Import a private key or recovery phrase'))
    .addSubcommand((s) => s.setName('switch').setDescription('Switch your active wallet')
      .addStringOption((o) => o.setName('wallet').setDescription('Which wallet').setRequired(true).setAutocomplete(true)))
    .addSubcommand((s) => s.setName('rename').setDescription('Rename your active wallet'))
    .addSubcommand((s) => s.setName('deposit').setDescription('Show your active address and QR code'))
    .addSubcommand((s) => s.setName('balance').setDescription('Show your active wallet balance'))
    .addSubcommand((s) => s.setName('export').setDescription('Reveal the active wallet private key (PIN required)'))
    .addSubcommand((s) => s.setName('changepin').setDescription('Change the active wallet PIN'))
    .addSubcommand((s) => s.setName('delete').setDescription('Delete the active wallet from this bot')),
  new SlashCommandBuilder().setName('send').setDescription(`Send ${SYMBOL} from your active wallet`)
    .addStringOption((o) => o.setName('to').setDescription('Recipient 0x address').setRequired(true))
    .addStringOption((o) => o.setName('amount').setDescription(`Amount in ${SYMBOL}, or "max"`).setRequired(true)),
].map((c) => c.toJSON());

// Keep discord.js caches tiny: this bot only needs interactions + DMs.
const client = new Client({
  intents: [GatewayIntentBits.Guilds],
  makeCache: Options.cacheWithLimits({
    ...Options.DefaultMakeCacheSettings,
    MessageManager: 0, PresenceManager: 0, ReactionManager: 0, GuildMemberManager: 0, GuildBanManager: 0,
    GuildInviteManager: 0, GuildScheduledEventManager: 0, GuildStickerManager: 0, GuildEmojiManager: 0,
    StageInstanceManager: 0, VoiceStateManager: 0, ThreadMemberManager: 0, UserManager: 25,
  }),
});
const noWallet = () => ({ ...fail("You don't have a wallet yet. Use `/wallet panel` to set one up."), ...EPH });
const atLimit = () => ({ ...warn('Wallet limit reached', `You can hold up to ${MAX_WALLETS} wallets. Delete one first.`), ...EPH });

async function handleCommand(i) {
  const uid = i.user.id;

  if (i.commandName === 'send') {
    await i.deferReply(EPH);
    return presentQuote(i, i.options.getString('to', true), i.options.getString('amount', true));
  }

  const sub = i.options.getSubcommand();

  if (sub === 'panel') { await i.deferReply(EPH); return i.editReply(await panelPayload(uid)); }
  if (sub === 'create' || sub === 'import') {
    if (st.count.get(uid).n >= MAX_WALLETS) return i.reply(atLimit());
    return i.showModal(modals[sub]());
  }

  const row = activeAccount(uid);
  if (!row) return i.reply(noWallet());

  if (sub === 'switch') {
    const target = st.account.get(Number(i.options.getString('wallet', true)), uid);
    if (!target) return i.reply({ ...fail('Pick a wallet from the list.'), ...EPH });
    st.setActive.run(target.id, uid);
    await i.deferReply(EPH);
    return i.editReply(await panelPayload(uid));
  }
  if (sub === 'deposit') { await i.deferReply(EPH); return i.editReply(await depositPayload(row)); }
  if (sub === 'balance') {
    await i.deferReply(EPH);
    return i.editReply({ embeds: [base(C.brand).setTitle(`💰 ${row.label}`)
      .setDescription(`### ${fmt(await provider.getBalance(row.address))} ${SYMBOL}\n\`${row.address}\``)] });
  }
  return i.showModal(modals[sub](row)); // rename | export | changepin | delete
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
    return i.showModal(modal(`send:pin:${arg}`, `Confirm from ${q.label}`, pinField()));
  }

  if (ns === 'ui') {
    const uid = i.user.id;
    if (action === 'create' || action === 'import') {
      if (st.count.get(uid).n >= MAX_WALLETS) return i.reply(atLimit());
      return i.showModal(modals[action]());
    }
    const row = activeAccount(uid);
    if (!row) return i.reply(noWallet());
    if (action === 'refresh') { await i.deferUpdate(); return i.editReply(await panelPayload(uid)); }
    if (action === 'deposit') { await i.deferReply(EPH); return i.editReply(await depositPayload(row)); }
    return i.showModal(modals[action](row)); // send | rename | export | changepin | delete
  }
  return undefined;
}

async function handleSelect(i) {
  if (i.customId !== 'ui:switch') return;
  const target = st.account.get(Number(i.values[0]), i.user.id);
  if (!target) return i.reply({ ...fail('That wallet no longer exists.'), ...EPH });
  st.setActive.run(target.id, i.user.id);
  await i.deferUpdate();
  await i.editReply(await panelPayload(i.user.id));
}

async function handleAutocomplete(i) {
  const q = i.options.getFocused().toLowerCase();
  const list = st.accounts.all(i.user.id)
    .filter((a) => a.label.toLowerCase().includes(q) || a.address.toLowerCase().includes(q))
    .slice(0, 25)
    .map((a) => ({ name: `${a.label} (${short(a.address)})`.slice(0, 100), value: String(a.id) }));
  await i.respond(list);
}

client.on(Events.InteractionCreate, async (i) => {
  try {
    if (i.isAutocomplete()) await handleAutocomplete(i);
    else if (i.isChatInputCommand()) await handleCommand(i);
    else if (i.isButton()) await handleButton(i);
    else if (i.isStringSelectMenu()) await handleSelect(i);
    else if (i.isModalSubmit()) await handleModal(i);
  } catch (e) {
    if (!(e instanceof UserError)) console.error(e);
    if (i.isAutocomplete()) return;
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
async function notifyDeposit(acctId, tx, block) {
  const a = st.byId.get(acctId);
  if (!a) return;
  const e = base(C.ok).setTitle('💸 Deposit received')
    .setDescription(`### +${ethers.formatEther(tx.value)} ${SYMBOL}`)
    .addFields(
      { name: 'Wallet', value: `**${a.label}** · \`${short(a.address)}\``, inline: true },
      { name: 'From', value: `\`${short(tx.from)}\``, inline: true },
      { name: 'Block', value: String(block), inline: true },
      { name: 'Tx', value: txLink(tx.hash) },
    ).setThumbnail(botAvatar() || null).setTimestamp();
  try {
    e.addFields({ name: 'New balance', value: `${fmt(await provider.getBalance(a.address))} ${SYMBOL}` });
  } catch { /* optional */ }
  try {
    const user = await client.users.fetch(a.discord_id);
    await user.send({ embeds: [e] });
  } catch (err) {
    console.warn(`Could not DM ${a.discord_id} (they must share a server with the bot, and allow DMs): ${err.message}`);
  }
}

async function pollDeposits() {
  try {
    const target = (await provider.getBlockNumber()) - CONFIRMATIONS;
    if (watch.size === 0) {
      // nobody to watch for: skip ahead instead of downloading blocks
      if (target > lastScanned) { lastScanned = target; st.setMeta.run('last_scanned', String(target)); }
      return;
    }
    if (target - lastScanned > MAX_CATCHUP_BLOCKS) {
      console.warn(`Watcher was ${target - lastScanned} blocks behind; skipping to the last ${MAX_CATCHUP_BLOCKS} (older deposits won't trigger DMs).`);
      lastScanned = target - MAX_CATCHUP_BLOCKS;
      st.setMeta.run('last_scanned', String(lastScanned));
    }
    let done = 0;
    for (let n = lastScanned + 1; n <= target && done < MAX_BLOCKS_PER_TICK; n++, done++) {
      const block = await provider.getBlock(n, true);
      if (!block) break;
      for (const tx of block.prefetchedTransactions) {
        if (!tx.to || tx.value === 0n) continue;
        const w = watch.get(tx.to.toLowerCase());
        if (!w || n <= w.since || tx.from.toLowerCase() === tx.to.toLowerCase()) continue;
        const a = st.byId.get(w.acct);
        if (a && st.deposit.run(tx.hash, a.discord_id, tx.value.toString(), n).changes) notifyDeposit(w.acct, tx, n);
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
console.log(`Starting… ${mem()}`);
setInterval(() => console.log(`[mem] ${mem()}`), 10 * 60 * 1000).unref();

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
    console.log(`Logged in as ${c.user.tag} • ${mem()}`);
    pollDeposits();
  });
  await client.login(TOKEN);
})().catch((e) => { console.error(e); process.exit(1); });

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { db.close(); } catch { /* ignore */ } process.exit(0); });
}

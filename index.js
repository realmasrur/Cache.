'use strict';
require('dotenv').config();

const fs = require('node:fs');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const Database = require('better-sqlite3');
const { ethers } = require('ethers');
const {
  Client, GatewayIntentBits, REST, Routes, Events, MessageFlags,
  SlashCommandBuilder, ModalBuilder, TextInputBuilder, TextInputStyle,
  ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder,
} = require('discord.js');

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
const RPC_URL = need('RPC_URL');
const MASTER_SECRET = need('MASTER_SECRET');
if (MASTER_SECRET.length < 32) {
  console.error('MASTER_SECRET must be at least 32 characters (try: openssl rand -hex 32)');
  process.exit(1);
}
const GUILD_ID = env.GUILD_ID || null;           // set for instant command registration while developing
const DB_PATH = env.DB_PATH || './wallets.db';
const SYMBOL = env.NATIVE_SYMBOL || 'ETH';
const EXPLORER_TX = env.EXPLORER_TX_URL || '';   // e.g. https://etherscan.io/tx/
const CONFIRMATIONS = Number(env.CONFIRMATIONS ?? 2);
const POLL_MS = Number(env.POLL_MS || 12000);

const MAX_ATTEMPTS = 5;                  // wrong PINs before lockout
const BASE_LOCK_MS = 15 * 60 * 1000;     // first lockout; doubles each time
const MAX_LOCK_MS = 24 * 60 * 60 * 1000;
const SEND_TTL_MS = 2 * 60 * 1000;       // quote validity
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

// AAD binds the ciphertext to its owner + address so rows can't be swapped between users.
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
    const key = await deriveKey(pin, row.salt);
    const d = crypto.createDecipheriv('aes-256-gcm', key, row.iv);
    d.setAAD(aad(row.discord_id, row.address));
    d.setAuthTag(row.tag);
    const pt = Buffer.concat([d.update(row.ct), d.final()]);
    const hex = '0x' + pt.toString('hex');
    pt.fill(0); key.fill(0);
    return hex;
  } catch {
    return null; // GCM auth failure = wrong PIN (or wrong master secret / tampered row)
  }
}

/* ------------------------------------------------------------------ */
/* Database                                                            */
/* ------------------------------------------------------------------ */
const db = new Database(DB_PATH);
try { fs.chmodSync(DB_PATH, 0o600); } catch { /* non-fatal (e.g. Windows) */ }
db.pragma('journal_mode = WAL');
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

// lowercase address -> { id, since }
const watch = new Map();
for (const r of st.all.all()) watch.set(r.address.toLowerCase(), { id: r.discord_id, since: r.since_block });

/* ------------------------------------------------------------------ */
/* PIN verification with persistent lockout                            */
/* ------------------------------------------------------------------ */
// The attempt is "reserved" (counted) synchronously BEFORE the slow scrypt check, so
// parallel guesses can't sneak past the counter. A correct PIN resets everything.
async function unlock(userId, pin) {
  const row = st.get.get(userId);
  if (!row) return { status: 'none' };
  const now = Date.now();
  if (row.locked_until > now) return { status: 'locked', until: row.locked_until };

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

function unlockError(r) {
  if (r.status === 'none') return "You don't have a wallet yet. Use `/wallet create`.";
  if (r.status === 'locked') return `🔒 Too many wrong PINs. Locked until <t:${Math.ceil(r.until / 1000)}:R>.`;
  return `❌ Wrong PIN. ${r.left} attempt${r.left === 1 ? '' : 's'} left before a lockout.`;
}

/* ------------------------------------------------------------------ */
/* Chain helpers                                                       */
/* ------------------------------------------------------------------ */
let provider;
let lastScanned = 0;

class UserError extends Error {}

const fmt = (v, dp = 8) => {
  const [a, b = ''] = ethers.formatEther(v).split('.');
  const t = b.slice(0, dp).replace(/0+$/, '');
  return t ? `${a}.${t}` : a;
};
const gwei = (v) => Number(ethers.formatUnits(v, 'gwei')).toFixed(2);
const txLink = (h) => (EXPLORER_TX ? `[${h.slice(0, 10)}…${h.slice(-6)}](${EXPLORER_TX}${h})` : `\`${h}\``);

async function storeWallet(userId, privateKey, address, pin) {
  const enc = await encryptKey(userId, address, privateKey, pin);
  let since = lastScanned;
  try { since = await provider.getBlockNumber(); } catch { /* fall back to lastScanned */ }
  st.insert.run({
    discord_id: userId, address, ...enc, since_block: since, created_at: Date.now(),
  });
  watch.set(address.toLowerCase(), { id: userId, since });
}

/* ------------------------------------------------------------------ */
/* Discord UI helpers                                                  */
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

const pending = new Map(); // quoteId -> quote
const sending = new Set(); // userIds with an in-flight broadcast
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pending) if (v.expires < now) pending.delete(k);
}, 60_000).unref();

/* ------------------------------------------------------------------ */
/* Slash commands                                                      */
/* ------------------------------------------------------------------ */
const commands = [
  new SlashCommandBuilder().setName('wallet').setDescription('Manage your wallet')
    .addSubcommand((s) => s.setName('create').setDescription('Create a new wallet'))
    .addSubcommand((s) => s.setName('import').setDescription('Import a private key or recovery phrase'))
    .addSubcommand((s) => s.setName('address').setDescription('Show your deposit address'))
    .addSubcommand((s) => s.setName('balance').setDescription('Show your balance'))
    .addSubcommand((s) => s.setName('export').setDescription('Reveal your private key (PIN required)'))
    .addSubcommand((s) => s.setName('changepin').setDescription('Change your PIN'))
    .addSubcommand((s) => s.setName('delete').setDescription('Permanently delete your wallet from this bot')),
  new SlashCommandBuilder().setName('send').setDescription(`Send ${SYMBOL} from your wallet`)
    .addStringOption((o) => o.setName('to').setDescription('Recipient 0x address').setRequired(true))
    .addStringOption((o) => o.setName('amount').setDescription(`Amount in ${SYMBOL}, or "max"`).setRequired(true)),
].map((c) => c.toJSON());

/* ------------------------------------------------------------------ */
/* Send flow                                                           */
/* ------------------------------------------------------------------ */
async function buildQuote(row, toRaw, amountRaw) {
  if (!ethers.isAddress(toRaw)) throw new UserError('That is not a valid 0x address.');
  const to = ethers.getAddress(toRaw.toLowerCase());
  if (to === ethers.ZeroAddress) throw new UserError('Refusing to send to the zero address.');

  const isMax = amountRaw.trim().toLowerCase() === 'max';
  let value = 0n;
  if (!isMax) {
    if (!/^\d*\.?\d+$/.test(amountRaw.trim())) throw new UserError('Amount must be a positive number like `0.05`, or `max`.');
    try { value = ethers.parseEther(amountRaw.trim()); } catch { throw new UserError('Invalid amount (max 18 decimals).'); }
    if (value <= 0n) throw new UserError('Amount must be greater than zero.');
  }

  const [balance, fd, code] = await Promise.all([
    provider.getBalance(row.address), provider.getFeeData(), provider.getCode(to),
  ]);
  if (!isMax && value > balance) throw new UserError(`Insufficient balance: you have ${fmt(balance)} ${SYMBOL}.`);

  const eip1559 = fd.maxFeePerGas != null && fd.maxPriorityFeePerGas != null;
  const feePerGas = eip1559 ? fd.maxFeePerGas : fd.gasPrice;
  if (feePerGas == null) throw new UserError('Could not read gas prices from the RPC node.');

  let est;
  try {
    est = await provider.estimateGas({ from: row.address, to, value });
  } catch {
    throw new UserError('Gas estimation failed. The transaction would likely revert or you lack funds for gas.');
  }
  const gasLimit = est === 21000n ? est : (est * 120n) / 100n; // 20% headroom only for contract recipients
  const fee = gasLimit * feePerGas; // worst case

  if (isMax) {
    value = balance - fee;
    if (value <= 0n) throw new UserError(`Balance (${fmt(balance)} ${SYMBOL}) doesn't cover the network fee (~${fmt(fee)}).`);
  } else if (value + fee > balance) {
    throw new UserError(`Insufficient funds: need ${fmt(value + fee)} ${SYMBOL} (amount + max fee), you have ${fmt(balance)}.`);
  }

  return {
    to, value, gasLimit, fee, balance, eip1559, feePerGas,
    tip: fd.maxPriorityFeePerGas, isContract: code !== '0x',
  };
}

function quoteEmbed(q) {
  const e = new EmbedBuilder().setTitle('Confirm transaction').setColor(0x5865f2).addFields(
    { name: 'To', value: `\`${q.to}\``, inline: false },
    { name: 'Amount', value: `${ethers.formatEther(q.value)} ${SYMBOL}`, inline: true },
    { name: 'Max network fee', value: `${fmt(q.fee)} ${SYMBOL}`, inline: true },
    { name: 'Gas', value: `${q.gasLimit} units @ ≤ ${gwei(q.feePerGas)} gwei`, inline: true },
    { name: 'Max total', value: `${fmt(q.value + q.fee)} ${SYMBOL}`, inline: true },
    { name: 'Balance after (worst case)', value: `${fmt(q.balance - q.value - q.fee)} ${SYMBOL}`, inline: true },
  ).setFooter({ text: 'Quote expires in 2 minutes. Actual fee is usually lower than the max.' });
  if (q.isContract) e.setDescription('⚠️ The recipient is a **contract**, not a regular wallet. Make sure it accepts plain transfers.');
  return e;
}

async function handleSendSubmit(i, quoteId) {
  const pin = i.fields.getTextInputValue('pin').trim();
  const q = pending.get(quoteId);
  if (!q || q.userId !== i.user.id || q.expires < Date.now()) {
    return i.editReply('⌛ This quote expired or was already used. Run `/send` again.');
  }
  if (!PIN_RE.test(pin)) return i.editReply('PIN must be 6–12 digits.');
  if (sending.has(i.user.id)) return i.editReply('You already have a transaction being sent. Please wait.');

  // If the network got >25% more expensive than quoted, make them re-quote.
  const fd = await provider.getFeeData();
  const now = q.eip1559 ? fd.maxFeePerGas : fd.gasPrice;
  if (now != null && now > (q.feePerGas * 125n) / 100n) {
    pending.delete(quoteId);
    return i.editReply('⛽ Gas prices rose since your quote. Run `/send` again for a fresh estimate.');
  }

  sending.add(i.user.id);
  try {
    const r = await unlock(i.user.id, pin);
    if (r.status !== 'ok') return i.editReply(unlockError(r));
    if (!pending.delete(quoteId)) return i.editReply('This quote was already used.'); // atomic anti-double-submit

    const wallet = new ethers.Wallet(r.privateKey, provider);
    const req = { to: q.to, value: q.value, gasLimit: q.gasLimit };
    if (q.eip1559) Object.assign(req, { type: 2, maxFeePerGas: q.feePerGas, maxPriorityFeePerGas: q.tip });
    else Object.assign(req, { type: 0, gasPrice: q.feePerGas });

    let tx;
    try {
      tx = await wallet.sendTransaction(req);
    } catch (e) {
      console.error('send failed:', e.shortMessage || e.message);
      return i.editReply(`❌ Broadcast failed: ${e.shortMessage || 'RPC error'}. Nothing was sent.`);
    }
    await i.editReply(`📤 Sent **${ethers.formatEther(q.value)} ${SYMBOL}** to \`${q.to}\`\nTx: ${txLink(tx.hash)}\nWaiting for confirmation…`);

    tx.wait(1, 180_000).then(
      (rc) => i.editReply(`${rc.status === 1 ? '✅ Confirmed' : '❌ Reverted'} in block ${rc.blockNumber}\nTx: ${txLink(tx.hash)}`).catch(() => {}),
      () => i.editReply(`⏳ Still pending after 3 minutes. Track it: ${txLink(tx.hash)}`).catch(() => {}),
    );
  } finally {
    sending.delete(i.user.id);
  }
}

/* ------------------------------------------------------------------ */
/* Modal handlers                                                      */
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
  if (/^(\d)\1+$/.test(pin) || '0123456789012'.includes(pin) || '9876543210987'.includes(pin)) return 'That PIN is too easy to guess. Pick something less predictable.';
  return null;
}

async function handleModal(i) {
  const id = i.customId;
  const uid = i.user.id;
  await i.deferReply(EPH);

  if (id === 'wallet:create' || id === 'wallet:import') {
    const pin = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(pin, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(`❌ ${err}`);
    if (st.get.get(uid)) return i.editReply('You already have a wallet.');

    let w;
    if (id === 'wallet:create') {
      const r = ethers.Wallet.createRandom();
      w = { privateKey: r.privateKey, address: r.address };
    } else {
      w = parseSecret(i.fields.getTextInputValue('secret'));
      if (!w) return i.editReply('❌ Could not parse that as a private key or recovery phrase.');
    }
    try {
      await storeWallet(uid, w.privateKey, w.address, pin);
    } catch (e) {
      if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return i.editReply('❌ That wallet is already registered with this bot.');
      throw e;
    }
    return i.editReply(
      `✅ Wallet ${id === 'wallet:create' ? 'created' : 'imported'}.\n**Address:** \`${w.address}\`\n\n`
      + 'Your key is encrypted with your PIN. **Back it up** with `/wallet export`; if you forget your PIN the funds are unrecoverable.',
    );
  }

  if (id === 'wallet:export') {
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim());
    if (r.status !== 'ok') return i.editReply(unlockError(r));
    return i.editReply(`🔑 **Private key** (never share it):\n||\`${r.privateKey}\`||`);
  }

  if (id === 'wallet:changepin') {
    const oldPin = i.fields.getTextInputValue('old').trim();
    const nu = i.fields.getTextInputValue('pin').trim();
    const err = checkPins(nu, i.fields.getTextInputValue('pin2').trim());
    if (err) return i.editReply(`❌ ${err}`);
    const r = await unlock(uid, oldPin);
    if (r.status !== 'ok') return i.editReply(unlockError(r));
    const enc = await encryptKey(uid, r.row.address, r.privateKey, nu);
    st.reencrypt.run({ discord_id: uid, ...enc });
    return i.editReply('✅ PIN changed.');
  }

  if (id === 'wallet:delete') {
    if (i.fields.getTextInputValue('confirm').trim() !== 'DELETE') return i.editReply('Cancelled: you must type DELETE exactly.');
    const r = await unlock(uid, i.fields.getTextInputValue('pin').trim());
    if (r.status !== 'ok') return i.editReply(unlockError(r));
    st.del.run(uid);
    watch.delete(r.row.address.toLowerCase());
    return i.editReply('🗑️ Wallet deleted from this bot. Any funds still on the address are only recoverable if you exported the key.');
  }

  if (id.startsWith('send:pin:')) return handleSendSubmit(i, id.slice('send:pin:'.length));
}

/* ------------------------------------------------------------------ */
/* Client                                                              */
/* ------------------------------------------------------------------ */
const client = new Client({ intents: [GatewayIntentBits.Guilds] });

async function handleCommand(i) {
  const uid = i.user.id;

  if (i.commandName === 'send') {
    await i.deferReply(EPH);
    const row = st.get.get(uid);
    if (!row) return i.editReply("You don't have a wallet yet. Use `/wallet create`.");
    const q = await buildQuote(row, i.options.getString('to', true), i.options.getString('amount', true));
    const quoteId = crypto.randomBytes(8).toString('hex');
    pending.set(quoteId, { ...q, userId: uid, expires: Date.now() + SEND_TTL_MS });
    return i.editReply({
      embeds: [quoteEmbed(q)],
      components: [new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`send:ok:${quoteId}`).setLabel('Confirm with PIN').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId(`send:no:${quoteId}`).setLabel('Cancel').setStyle(ButtonStyle.Secondary),
      )],
    });
  }

  // /wallet <sub>
  const sub = i.options.getSubcommand();
  const row = st.get.get(uid);

  if (sub === 'create' || sub === 'import') {
    if (row) return i.reply({ content: 'You already have a wallet. Delete it first to start over.', ...EPH });
    const rows = sub === 'create'
      ? [pinField(), pinField('pin2', 'Confirm PIN')]
      : [field('secret', 'Private key or recovery phrase', { long: true, max: 300 }), pinField(), pinField('pin2', 'Confirm PIN')];
    return i.showModal(modal(`wallet:${sub}`, sub === 'create' ? 'Create wallet' : 'Import wallet', ...rows));
  }

  if (!row) return i.reply({ content: "You don't have a wallet yet. Use `/wallet create`.", ...EPH });

  if (sub === 'address') return i.reply({ content: `Your deposit address:\n\`${row.address}\``, ...EPH });

  if (sub === 'balance') {
    await i.deferReply(EPH);
    return i.editReply(`💰 **${fmt(await provider.getBalance(row.address))} ${SYMBOL}**\n\`${row.address}\``);
  }
  if (sub === 'export') return i.showModal(modal('wallet:export', 'Export private key', pinField()));
  if (sub === 'changepin') {
    return i.showModal(modal('wallet:changepin', 'Change PIN', pinField('old', 'Current PIN'), pinField('pin', 'New PIN (6–12 digits)'), pinField('pin2', 'Confirm new PIN')));
  }
  if (sub === 'delete') {
    return i.showModal(modal('wallet:delete', 'Delete wallet', field('confirm', 'Type DELETE to confirm', { max: 6 }), pinField()));
  }
}

async function handleButton(i) {
  const [, action, quoteId] = i.customId.split(':');
  const q = pending.get(quoteId);
  if (!q || q.userId !== i.user.id || q.expires < Date.now()) {
    pending.delete(quoteId);
    return i.update({ content: '⌛ This quote expired. Run `/send` again.', embeds: [], components: [] });
  }
  if (action === 'no') {
    pending.delete(quoteId);
    return i.update({ content: 'Cancelled.', embeds: [], components: [] });
  }
  return i.showModal(modal(`send:pin:${quoteId}`, 'Confirm transaction', pinField()));
}

client.on(Events.InteractionCreate, async (i) => {
  try {
    if (i.isChatInputCommand()) await handleCommand(i);
    else if (i.isButton() && i.customId.startsWith('send:')) await handleButton(i);
    else if (i.isModalSubmit()) await handleModal(i);
  } catch (e) {
    const msg = e instanceof UserError ? `❌ ${e.message}` : '⚠️ Something went wrong. Please try again.';
    if (!(e instanceof UserError)) console.error(e);
    try {
      if (i.deferred || i.replied) await i.editReply({ content: msg, embeds: [], components: [] });
      else await i.reply({ content: msg, ...EPH });
    } catch { /* interaction expired */ }
  }
});

/* ------------------------------------------------------------------ */
/* Deposit watcher (native-coin transfers via plain JSON-RPC)          */
/* ------------------------------------------------------------------ */
async function notifyDeposit(userId, tx, block) {
  const embed = new EmbedBuilder().setTitle('💸 Deposit received').setColor(0x57f287).addFields(
    { name: 'Amount', value: `${ethers.formatEther(tx.value)} ${SYMBOL}`, inline: true },
    { name: 'Block', value: String(block), inline: true },
    { name: 'From', value: `\`${tx.from}\`` },
    { name: 'Tx', value: txLink(tx.hash) },
  ).setTimestamp();
  try {
    const user = await client.users.fetch(userId);
    await user.send({ embeds: [embed] });
  } catch (e) {
    console.warn(`Could not DM ${userId} (DMs closed?): ${e.message}`);
  }
}

async function pollDeposits() {
  try {
    const target = (await provider.getBlockNumber()) - CONFIRMATIONS;
    let done = 0;
    for (let n = lastScanned + 1; n <= target && done < MAX_BLOCKS_PER_TICK; n++, done++) {
      const block = await provider.getBlock(n, true);
      if (!block) break; // node hasn't indexed it yet; retry next tick
      for (const tx of block.prefetchedTransactions) {
        if (!tx.to || tx.value === 0n) continue;
        const w = watch.get(tx.to.toLowerCase());
        if (!w || n <= w.since || tx.from.toLowerCase() === tx.to.toLowerCase()) continue;
        if (st.deposit.run(tx.hash, w.id, tx.value.toString(), n).changes) notifyDeposit(w.id, tx, n);
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
  const probe = new ethers.JsonRpcProvider(RPC_URL);
  const network = await probe.getNetwork();
  probe.destroy();
  provider = new ethers.JsonRpcProvider(RPC_URL, network, { staticNetwork: network });
  console.log(`Connected to chain ${network.chainId} (${network.name})`);

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

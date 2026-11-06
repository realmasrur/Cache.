'use strict';
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite'); // built into Node >= 22.13

function migrateLegacy(db) {
  // v1 had one wallet per user in table `wallets`. Move those rows into the multi-wallet schema.
  const legacy = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='wallets'").get();
  if (!legacy) return;
  db.exec('BEGIN');
  try {
    const insUser = db.prepare('INSERT OR IGNORE INTO users (discord_id, failed_attempts, lock_count, locked_until) VALUES (?, ?, ?, ?)');
    const insAcct = db.prepare(`INSERT OR IGNORE INTO accounts (discord_id, label, address, salt, iv, tag, ct, since_block, created_at)
                                VALUES (?, 'Wallet 1', ?, ?, ?, ?, ?, ?, ?)`);
    const setActive = db.prepare(`UPDATE users SET active_id = (SELECT id FROM accounts WHERE discord_id = ? ORDER BY id LIMIT 1)
                                  WHERE discord_id = ? AND active_id IS NULL`);
    for (const r of db.prepare('SELECT * FROM wallets').all()) {
      insUser.run(r.discord_id, r.failed_attempts, r.lock_count, r.locked_until);
      insAcct.run(r.discord_id, r.address, r.salt, r.iv, r.tag, r.ct, r.since_block, r.created_at);
      setActive.run(r.discord_id, r.discord_id);
    }
    db.exec('ALTER TABLE wallets RENAME TO wallets_legacy');
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    throw e;
  }
}

function openDb(path) {
  const db = new DatabaseSync(path);
  try { fs.chmodSync(path, 0o600); } catch { /* non-fatal */ }
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      discord_id      TEXT PRIMARY KEY,
      active_id       INTEGER,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      lock_count      INTEGER NOT NULL DEFAULT 0,
      locked_until    INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      discord_id  TEXT NOT NULL,
      label       TEXT NOT NULL,
      address     TEXT NOT NULL UNIQUE,
      salt        BLOB NOT NULL,
      iv          BLOB NOT NULL,
      tag         BLOB NOT NULL,
      ct          BLOB NOT NULL,
      since_block INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS accounts_by_user ON accounts (discord_id);
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS deposits (
      tx_hash    TEXT NOT NULL,
      discord_id TEXT NOT NULL,
      amount     TEXT NOT NULL,
      block      INTEGER NOT NULL,
      PRIMARY KEY (tx_hash, discord_id)
    );
  `);
  // per-wallet scrypt cost (log2 N); older rows used 2^15
  const cols = db.prepare('PRAGMA table_info(accounts)').all().map((c) => c.name);
  if (!cols.includes('kdf_n')) db.exec('ALTER TABLE accounts ADD COLUMN kdf_n INTEGER NOT NULL DEFAULT 15');
  migrateLegacy(db);

  const st = {
    user: db.prepare('SELECT * FROM users WHERE discord_id = ?'),
    ensureUser: db.prepare('INSERT OR IGNORE INTO users (discord_id) VALUES (?)'),
    setActive: db.prepare('UPDATE users SET active_id = ? WHERE discord_id = ?'),
    attempt: db.prepare('UPDATE users SET failed_attempts=?, lock_count=?, locked_until=? WHERE discord_id=?'),
    reset: db.prepare('UPDATE users SET failed_attempts=0, lock_count=0, locked_until=0 WHERE discord_id=?'),
    accounts: db.prepare('SELECT * FROM accounts WHERE discord_id = ? ORDER BY id'),
    account: db.prepare('SELECT * FROM accounts WHERE id = ? AND discord_id = ?'),
    byId: db.prepare('SELECT * FROM accounts WHERE id = ?'),
    count: db.prepare('SELECT COUNT(*) AS n FROM accounts WHERE discord_id = ?'),
    watchAll: db.prepare('SELECT id, discord_id, address, since_block FROM accounts'),
    insert: db.prepare(`INSERT INTO accounts (discord_id, label, address, salt, iv, tag, ct, kdf_n, since_block, created_at)
                        VALUES (@discord_id, @label, @address, @salt, @iv, @tag, @ct, @kdf_n, @since_block, @created_at)`),
    reencrypt: db.prepare('UPDATE accounts SET salt=@salt, iv=@iv, tag=@tag, ct=@ct, kdf_n=@kdf_n WHERE id=@id'),
    rename: db.prepare('UPDATE accounts SET label = ? WHERE id = ? AND discord_id = ?'),
    del: db.prepare('DELETE FROM accounts WHERE id = ? AND discord_id = ?'),
    getMeta: db.prepare('SELECT value FROM meta WHERE key = ?'),
    setMeta: db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
    deposit: db.prepare('INSERT OR IGNORE INTO deposits (tx_hash, discord_id, amount, block) VALUES (?, ?, ?, ?)'),
  };
  return { db, st };
}

module.exports = { openDb };

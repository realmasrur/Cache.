# Discord EVM Wallet Bot

Setup:
1. Create an app + bot at discord.com/developers, copy the token and application ID. Invite with scope `bot applications.commands`.
2. `cp .env.example .env` and fill it in (use a testnet RPC first).
3. `npm install && npm start`

Commands: `/wallet create|import|address|balance|export|changepin|delete`, `/send to amount` (amount may be `max`).

Security model
- Key = HMAC-SHA256(scrypt(MASTER_SECRET), scrypt(PIN, per-wallet salt)); AES-256-GCM with AAD = userId:address.
- 5 wrong PINs => lockout (15 min, doubling, capped at 24h). Counters persist in SQLite; attempts are counted before verification.
- DB leak alone is useless. DB + MASTER_SECRET leak lets an attacker brute-force PINs offline (6 digits is weak), so encourage 10+ digit PINs.
- Back up wallets.db AND MASTER_SECRET separately. Keep the .env and DB out of git (chmod 600).

Limits
- Native coin only; deposit watcher sees direct transfers, not internal contract transfers or ERC-20 (needs getLogs/traces).
- Wallet keys are typed into Discord modals, so treat this as a small-funds / testnet tool.

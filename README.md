# Discord EVM Wallet Bot

Setup
1. Discord dev portal: copy Application ID + bot token. Invite with scopes `bot` and `applications.commands` (no permissions or privileged intents).
2. `cp .env.example .env` and fill it in (testnet first).
3. `npm install && npm start`. Needs Node 22.13+. SQLite is built in (no native build), QR codes are pure JS.

Use `/wallet panel`: Deposit (QR with bot logo), Send, Refresh, New wallet, Import, Rename, Export key, Change PIN, Delete, plus a dropdown to switch wallets.
Slash shortcuts: `/wallet switch|create|import|rename|deposit|balance|export|changepin|delete`, `/send to amount` (amount may be `max`). Actions apply to the active wallet.

Multiple wallets: up to MAX_WALLETS per user, each with its own name and PIN. PIN lockout is per user across all wallets. A v1 database is migrated automatically on first start.

Security model
- Key = HMAC-SHA256(scrypt(MASTER_SECRET), scrypt(PIN, salt)); AES-256-GCM, AAD = userId:address. scrypt runs one at a time to cap RAM.
- 5 wrong PINs => lockout (15 min, doubling, max 24h), persisted; attempts counted before verification.
- DB + MASTER_SECRET leak allows offline PIN brute force: use 10+ digit PINs. Back both up separately; keep .env/DB out of git.

Limits: native coin only; watcher sees direct transfers (no ERC-20/internal). DMs need a shared server and open DMs. Modals can't mask PIN input.
Memory: Node + discord.js + ethers need roughly 120-200 MB. The bot logs `[mem]` (rss/heap/native) at start, after login and every 10 minutes. On small hosts set SCRYPT_LOG_N=14 (or 13) and use 256 MB+ if you can.

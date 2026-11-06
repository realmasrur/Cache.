# Discord EVM Wallet Bot

Setup
1. Discord dev portal: copy Application ID + bot token. Invite with scopes `bot` and `applications.commands` (no permissions or privileged intents needed).
2. `cp .env.example .env`, fill it in (testnet first).
3. `npm install && npm start`

Use `/wallet panel` for the dashboard (Deposit QR, Send, Refresh, Export, Change PIN, Delete). `/send to amount` also works (amount may be `max`).

QR codes: generated locally (qrcode + @napi-rs/canvas, error correction H) with your bot avatar, or LOGO_PATH, in the centre.

Security model
- Key = HMAC-SHA256(scrypt(MASTER_SECRET), scrypt(PIN, salt)); AES-256-GCM, AAD = userId:address.
- 5 wrong PINs => lockout (15 min, doubling, max 24h), persisted in SQLite; attempts counted before verification.
- DB + MASTER_SECRET leak allows offline PIN brute force: encourage 10+ digit PINs. Back both up separately; keep .env/DB out of git.

Limits: native coin only; deposit watcher sees direct transfers (not ERC-20 / internal transfers). Discord modals can't mask PIN input.

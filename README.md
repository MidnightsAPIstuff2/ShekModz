# Shek Modz

Node 22.13+ only, no npm install needed (uses built-in `node:sqlite`).

    ADMIN_PASSWORD='your-password' npm start

- Without `ADMIN_PASSWORD`, a random admin password is generated on first run and printed once.
- Setting `ADMIN_PASSWORD` again later resets it. Only a salted scrypt hash is stored in `shek.db`.
- Set `NODE_ENV=production` behind HTTPS so the session cookie is `Secure`.
- Env: `PORT` (default 3000), `DB_PATH` (default ./shek.db).

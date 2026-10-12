'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'shek.db');
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const SECURE_COOKIE = process.env.NODE_ENV === 'production';

/* ---------- Database ---------- */
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Tested & Working','Not Tested','Not Working')),
    description TEXT NOT NULL,
    file_link TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (date('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
  );
`);

/* ---------- Password hashing (scrypt, salted) ---------- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(pw, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

// First run: set the admin password from ADMIN_PASSWORD, or generate one and print it once.
const getSetting = db.prepare('SELECT value FROM settings WHERE key = ?');
const setSetting = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
if (process.env.ADMIN_PASSWORD) {
  setSetting.run('admin_password', hashPassword(process.env.ADMIN_PASSWORD));
  console.log('[auth] Admin password set from ADMIN_PASSWORD env var.');
} else if (!getSetting.get('admin_password')) {
  const generated = crypto.randomBytes(12).toString('base64url');
  setSetting.run('admin_password', hashPassword(generated));
  console.log('\n==================================================');
  console.log(' First run: generated admin password (shown once):');
  console.log('   ' + generated);
  console.log(' Change it any time by restarting with ADMIN_PASSWORD=...');
  console.log('==================================================\n');
}

// Seed sample posts on an empty DB
if (db.prepare('SELECT COUNT(*) AS n FROM posts').get().n === 0) {
  const ins = db.prepare('INSERT INTO posts (title, author, status, description, file_link, created_at) VALUES (?,?,?,?,?,?)');
  ins.run('Ultra Ray-Tracing Shaders FX', 'GfxGod', 'Tested & Working', 'Unlocks photorealistic global illumination, volumetric fog, and heavy SSR reflections. Tested on DirectX 12 engines.', 'https://example.com/mods/ultraraytracing.zip', '2026-09-24');
  ins.run('Speed Injector Tool v4.1', 'ShekDev', 'Not Tested', 'Memory tweak bypass for physics frame locking. High risk of desync; needs testing on public multiplayer servers.', 'https://example.com/files/speed_injector_v4.rar', '2026-09-25');
  ins.run('Legacy Menu HUD Patch', 'OldSchooler', 'Not Working', 'Restores the classic 2012 monochrome layout. Currently crashes on modern 1.4+ game patches. Needs fix.', 'https://example.com/patch/hud_legacy.7z', '2026-09-26');
}

/* ---------- Sessions ---------- */
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function createSession() {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)').run(sha(token), Date.now() + SESSION_TTL_MS);
  return token;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function isAdmin(req) {
  const token = parseCookies(req).shek_session;
  if (!token) return false;
  const row = db.prepare('SELECT expires_at FROM sessions WHERE token_hash = ?').get(sha(token));
  if (!row) return false;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token));
    return false;
  }
  return true;
}
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()), 1000 * 60 * 30).unref();

/* ---------- Login rate limit (per IP) ---------- */
const attempts = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const rec = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, rec);
  return rec.length >= 8;
}
function recordFailure(ip) { attempts.get(ip).push(Date.now()); }

/* ---------- Helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const STATUSES = ['Tested & Working', 'Not Tested', 'Not Working'];

function send(res, code, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(code, {
    'Content-Type': isObj ? 'application/json' : 'text/plain',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...headers,
  });
  res.end(isObj ? JSON.stringify(body) : body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 100_000) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
function validatePost(b) {
  const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const post = {
    title: clean(b.title, 120),
    author: clean(b.author, 60),
    status: clean(b.status, 30),
    description: clean(b.description, 2000),
    file_link: clean(b.file_link, 500),
  };
  if (!post.title || !post.author || !post.description || !post.file_link) return { error: 'All fields are required.' };
  if (!STATUSES.includes(post.status)) return { error: 'Invalid status.' };
  // Allow http(s) URLs, or a plain filename (no scheme).
  if (/^[a-z][a-z0-9+.-]*:/i.test(post.file_link) && !/^https?:\/\//i.test(post.file_link)) return { error: 'File link must be an http(s) URL or a filename.' };
  return { post };
}
const rowToPost = (r) => ({ id: r.id, title: r.title, author: r.author, status: r.status, desc: r.description, fileLink: r.file_link, date: r.created_at });

/* ---------- Routes ---------- */
async function handleApi(req, res, url) {
  const ip = req.socket.remoteAddress || 'unknown';
  const { pathname } = url;
  const method = req.method;

  if (pathname === '/api/session' && method === 'GET') return send(res, 200, { admin: isAdmin(req) });

  if (pathname === '/api/login' && method === 'POST') {
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const stored = getSetting.get('admin_password').value;
    if (typeof body.password !== 'string' || !verifyPassword(body.password, stored)) {
      recordFailure(ip);
      return send(res, 401, { error: 'Invalid passcode.' });
    }
    const token = createSession();
    const cookie = `shek_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${SECURE_COOKIE ? '; Secure' : ''}`;
    return send(res, 200, { admin: true }, { 'Set-Cookie': cookie });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    const token = parseCookies(req).shek_session;
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token));
    return send(res, 200, { admin: false }, { 'Set-Cookie': 'shek_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (pathname === '/api/posts' && method === 'GET') {
    const rows = db.prepare('SELECT * FROM posts ORDER BY id DESC').all();
    return send(res, 200, rows.map(rowToPost));
  }

  // Everything below requires admin
  const writeRoute = (pathname === '/api/posts' && method === 'POST') || /^\/api\/posts\/\d+$/.test(pathname);
  if (writeRoute) {
    if (!isAdmin(req)) return send(res, 401, { error: 'Admin login required.' });
    // CSRF defence in depth: require same-origin for state-changing requests
    const origin = req.headers.origin;
    if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: 'Bad origin.' });
  }

  if (pathname === '/api/posts' && method === 'POST') {
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const { post, error } = validatePost(body);
    if (error) return send(res, 400, { error });
    const info = db.prepare('INSERT INTO posts (title, author, status, description, file_link) VALUES (?,?,?,?,?)').run(post.title, post.author, post.status, post.description, post.file_link);
    return send(res, 201, rowToPost(db.prepare('SELECT * FROM posts WHERE id = ?').get(info.lastInsertRowid)));
  }

  const m = pathname.match(/^\/api\/posts\/(\d+)$/);
  if (m && method === 'PUT') {
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const { post, error } = validatePost(body);
    if (error) return send(res, 400, { error });
    const info = db.prepare('UPDATE posts SET title=?, author=?, status=?, description=?, file_link=? WHERE id=?').run(post.title, post.author, post.status, post.description, post.file_link, Number(m[1]));
    if (!info.changes) return send(res, 404, { error: 'Not found.' });
    return send(res, 200, rowToPost(db.prepare('SELECT * FROM posts WHERE id = ?').get(Number(m[1]))));
  }
  if (m && method === 'DELETE') {
    const info = db.prepare('DELETE FROM posts WHERE id = ?').run(Number(m[1]));
    return send(res, info.changes ? 200 : 404, { ok: !!info.changes });
  }

  return send(res, 404, { error: 'Not found.' });
}

function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return send(res, 403, 'Forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not found');
    send(res, 200, data, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    serveStatic(req, res, url);
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'Server error.' });
  }
}).listen(PORT, () => console.log(`Shek Modz running on http://localhost:${PORT}`));

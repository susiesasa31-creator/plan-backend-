const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

/* JWT secret: use env var, or generate once and keep it in data/jwt.secret */
function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const f = path.join(DATA_DIR, 'jwt.secret');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(f, 'utf8');
}
const SECRET = loadSecret();

/* ---------- Database ---------- */
const db = new Database(path.join(DATA_DIR, 'studyhub.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS study_plans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject     TEXT NOT NULL,
  topic       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  study_date  TEXT NOT NULL,
  start_time  TEXT NOT NULL,
  end_time    TEXT NOT NULL,
  priority    TEXT NOT NULL DEFAULT 'Medium' CHECK (priority IN ('High','Medium','Low')),
  status      TEXT NOT NULL DEFAULT 'In Progress' CHECK (status IN ('In Progress','Completed')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_plans_user_date ON study_plans(user_id, study_date, start_time);
`);

/* ---------- App ---------- */
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const fail = (res, code, message) => res.status(code).json({ message });
const publicUser = u => ({ id: u.id, name: u.name, email: u.email });
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });

/* Tiny in-memory limiter for login/register: 10 tries / 15 min / IP */
const hits = new Map();
function limiter(req, res, next) {
  const now = Date.now(), win = 15 * 60 * 1000;
  const arr = (hits.get(req.ip) || []).filter(t => now - t < win);
  if (arr.length >= 10) return fail(res, 429, 'Too many attempts. Try again in 15 minutes.');
  arr.push(now); hits.set(req.ip, arr);
  next();
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return fail(res, 401, 'Please log in.');
  try {
    const { id } = jwt.verify(token, SECRET);
    const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(id);
    if (!user) return fail(res, 401, 'Account not found.');
    req.user = user; next();
  } catch { fail(res, 401, 'Session expired. Please log in again.'); }
}

/* ---------- Auth routes ---------- */
app.post('/api/auth/register', limiter, (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, 'Enter a valid email address.');
  if (password.length < 6) return fail(res, 400, 'Password must be at least 6 characters.');
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email))
    return fail(res, 409, 'This email is already registered. Try logging in.');
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)')
    .run(name || email.split('@')[0], email, hash);
  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ token: sign(user), user: publicUser(user) });
});

app.post('/api/auth/login', limiter, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return fail(res, 401, 'Wrong email or password.');
  res.json({ token: sign(user), user: publicUser(user) });
});

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

/* ---------- Study plan routes ---------- */
const FIELDS = ['subject', 'topic', 'description', 'study_date', 'start_time', 'end_time', 'priority', 'status'];

function validate(b, partial) {
  const out = {};
  for (const f of FIELDS) if (b[f] !== undefined) out[f] = String(b[f]).trim();
  if (!partial) for (const f of ['subject', 'topic', 'study_date', 'start_time', 'end_time'])
    if (!out[f]) return { error: `${f.replace('_', ' ')} is required.` };
  if (out.priority && !['High', 'Medium', 'Low'].includes(out.priority)) return { error: 'Invalid priority.' };
  if (out.status && !['In Progress', 'Completed'].includes(out.status)) return { error: 'Invalid status.' };
  if (out.study_date && !/^\d{4}-\d{2}-\d{2}$/.test(out.study_date)) return { error: 'Invalid date.' };
  for (const f of ['start_time', 'end_time'])
    if (out[f] && !/^\d{2}:\d{2}$/.test(out[f])) return { error: 'Invalid time.' };
  if (out.start_time && out.end_time && out.end_time <= out.start_time)
    return { error: 'End time must be after start time.' };
  return { data: out };
}

const getPlan = (id, userId) => db.prepare('SELECT * FROM study_plans WHERE id = ? AND user_id = ?').get(id, userId);

app.get('/api/study-plans', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM study_plans WHERE user_id = ? ORDER BY study_date, start_time').all(req.user.id));
});

app.post('/api/study-plans', auth, (req, res) => {
  const { data, error } = validate(req.body, false);
  if (error) return fail(res, 400, error);
  const p = { description: '', priority: 'Medium', status: 'In Progress', ...data };
  const info = db.prepare(`INSERT INTO study_plans
    (user_id, subject, topic, description, study_date, start_time, end_time, priority, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, p.subject, p.topic, p.description, p.study_date, p.start_time, p.end_time, p.priority, p.status);
  res.status(201).json(getPlan(info.lastInsertRowid, req.user.id));
});

app.put('/api/study-plans/:id', auth, (req, res) => {
  const existing = getPlan(req.params.id, req.user.id);
  if (!existing) return fail(res, 404, 'Plan not found.');
  const { data, error } = validate(req.body, true);
  if (error) return fail(res, 400, error);
  const merged = { ...existing, ...data };
  if (merged.end_time <= merged.start_time) return fail(res, 400, 'End time must be after start time.');
  db.prepare(`UPDATE study_plans SET subject=?, topic=?, description=?, study_date=?, start_time=?,
    end_time=?, priority=?, status=?, updated_at=datetime('now') WHERE id=? AND user_id=?`)
    .run(merged.subject, merged.topic, merged.description, merged.study_date, merged.start_time,
      merged.end_time, merged.priority, merged.status, existing.id, req.user.id);
  res.json(getPlan(existing.id, req.user.id));
});

app.delete('/api/study-plans/:id', auth, (req, res) => {
  const info = db.prepare('DELETE FROM study_plans WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (!info.changes) return fail(res, 404, 'Plan not found.');
  res.json({ message: 'Deleted' });
});

app.use('/api', (req, res) => fail(res, 404, 'Not found.'));
app.use((err, req, res, next) => { console.error(err); fail(res, 500, 'Server error.'); });

app.listen(PORT, () => console.log(`IT Study Hub running at http://localhost:${PORT}`));

require('dotenv').config();
const express = require('express'), cors = require('cors'), mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { PORT = 3000, DB_HOST = 'localhost', DB_PORT = 3306, DB_USER, DB_PASSWORD, DB_NAME = 'studyhub', JWT_SECRET, CORS_ORIGIN = '' } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('Set JWT_SECRET in .env (32+ chars).'); process.exit(1); }

const pool = mysql.createPool({ host: DB_HOST, port: +DB_PORT, user: DB_USER, password: DB_PASSWORD, database: DB_NAME,
  waitForConnections: true, connectionLimit: 10, charset: 'utf8mb4', connectTimeout: 10000 });
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.use(cors({ origin: CORS_ORIGIN.split(',').map(s => s.trim()).filter(Boolean), allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '200kb' }));

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const fail = (res, code, message) => res.status(code).json({ message });
const sign = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role });

const hits = new Map();
function limiter(req, res, next) {
  const now = Date.now(), a = (hits.get(req.ip) || []).filter(t => now - t < 900000);
  if (a.length >= 10) return fail(res, 429, 'Too many attempts. Try again in 15 minutes.');
  a.push(now); hits.set(req.ip, a); next();
}
const auth = wrap(async (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return fail(res, 401, 'Please log in.');
  let id; try { id = jwt.verify(h.slice(7), JWT_SECRET).id; } catch { return fail(res, 401, 'Session expired. Please log in again.'); }
  const [r] = await pool.execute('SELECT id, name, email, role FROM users WHERE id = ?', [id]);
  if (!r[0]) return fail(res, 401, 'Account not found.');
  req.user = r[0]; next();
});
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : fail(res, 403, 'Admins only.');

app.get('/api/health', wrap(async (req, res) => { await pool.query('SELECT 1'); res.json({ ok: true }); }));

/* ---------- Auth ---------- */
app.post('/api/auth/register', limiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  const name = String(req.body.name || '').trim().slice(0, 100) || email.split('@')[0];
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 191) return fail(res, 400, 'Enter a valid email address.');
  if (password.length < 6) return fail(res, 400, 'Password must be at least 6 characters.');
  const [dup] = await pool.execute('SELECT 1 FROM users WHERE email = ?', [email]);
  if (dup.length) return fail(res, 409, 'This email is already registered. Try logging in.');
  const [[c]] = await pool.query('SELECT COUNT(*) AS n FROM users');
  const role = c.n === 0 ? 'admin' : 'user';           // the very first account is the admin
  const [r] = await pool.execute('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)', [name, email, bcrypt.hashSync(password, 10), role]);
  const u = { id: r.insertId, name, email, role };
  res.status(201).json({ token: sign(u), user: pub(u) });
}));
app.post('/api/auth/login', limiter, wrap(async (req, res) => {
  const [r] = await pool.execute('SELECT * FROM users WHERE email = ?', [String(req.body.email || '').trim().toLowerCase()]);
  const u = r[0];
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash)) return fail(res, 401, 'Wrong email or password.');
  res.json({ token: sign(u), user: pub(u) });
}));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: pub(req.user) }));

/* ---------- Study plans (users: own plans, admin: all plans) ---------- */
const SEL = `SELECT p.id, p.user_id, u.name AS owner, p.subject, p.topic, p.description, p.notes,
  DATE_FORMAT(p.study_date,'%Y-%m-%d') AS study_date, TIME_FORMAT(p.start_time,'%H:%i') AS start_time,
  TIME_FORMAT(p.end_time,'%H:%i') AS end_time, p.priority, p.status FROM study_plans p JOIN users u ON u.id = p.user_id`;
const FIELDS = ['subject', 'topic', 'description', 'notes', 'study_date', 'start_time', 'end_time', 'priority', 'status'];

function validate(b, partial) {
  const o = {};
  for (const f of FIELDS) if (b[f] !== undefined && b[f] !== null) o[f] = String(b[f]).trim();
  if (!partial) for (const f of ['subject', 'topic', 'study_date', 'start_time', 'end_time']) if (!o[f]) return { error: `${f.replace('_', ' ')} is required.` };
  if (o.priority && !['High', 'Medium', 'Low'].includes(o.priority)) return { error: 'Invalid priority.' };
  if (o.status && !['In Progress', 'Completed'].includes(o.status)) return { error: 'Invalid status.' };
  if (o.study_date && !/^\d{4}-\d{2}-\d{2}$/.test(o.study_date)) return { error: 'Invalid date.' };
  for (const f of ['start_time', 'end_time']) if (o[f] && !/^\d{2}:\d{2}$/.test(o[f])) return { error: 'Invalid time.' };
  if ((o.subject || '').length > 150 || (o.topic || '').length > 150) return { error: 'Subject and topic must be under 150 characters.' };
  if ((o.notes || '').length > 10000) return { error: 'Notes are too long.' };
  return { data: o };
}
const getPlan = async (id, u) => {
  const adm = u.role === 'admin';
  const [r] = await pool.execute(SEL + ' WHERE p.id = ?' + (adm ? '' : ' AND p.user_id = ?'), adm ? [id] : [id, u.id]);
  return r[0];
};
async function ownerFor(req, fallback) {      // admins may assign a plan to another user
  if (req.user.role !== 'admin' || !req.body.user_id) return fallback;
  const [r] = await pool.execute('SELECT id FROM users WHERE id = ?', [+req.body.user_id]);
  return r[0] ? r[0].id : null;
}

app.get('/api/study-plans', auth, wrap(async (req, res) => {
  const all = req.user.role === 'admin' && req.query.all === '1';
  const [r] = await pool.execute(SEL + (all ? '' : ' WHERE p.user_id = ?') + ' ORDER BY p.study_date, p.start_time', all ? [] : [req.user.id]);
  res.json(r);
}));
app.post('/api/study-plans', auth, wrap(async (req, res) => {
  const { data, error } = validate(req.body, false); if (error) return fail(res, 400, error);
  const p = { description: '', notes: '', priority: 'Medium', status: 'In Progress', ...data };
  if (p.end_time <= p.start_time) return fail(res, 400, 'End time must be after start time.');
  const owner = await ownerFor(req, req.user.id); if (!owner) return fail(res, 400, 'Unknown user.');
  const [r] = await pool.execute(`INSERT INTO study_plans (user_id, subject, topic, description, notes, study_date, start_time, end_time, priority, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, [owner, p.subject, p.topic, p.description, p.notes, p.study_date, p.start_time, p.end_time, p.priority, p.status]);
  res.status(201).json(await getPlan(r.insertId, req.user));
}));
app.put('/api/study-plans/:id', auth, wrap(async (req, res) => {
  const cur = await getPlan(req.params.id, req.user); if (!cur) return fail(res, 404, 'Plan not found.');
  const { data, error } = validate(req.body, true); if (error) return fail(res, 400, error);
  const m = { ...cur, ...data };
  if (m.end_time <= m.start_time) return fail(res, 400, 'End time must be after start time.');
  const owner = await ownerFor(req, cur.user_id); if (!owner) return fail(res, 400, 'Unknown user.');
  await pool.execute(`UPDATE study_plans SET user_id=?, subject=?, topic=?, description=?, notes=?, study_date=?, start_time=?, end_time=?, priority=?, status=? WHERE id=?`,
    [owner, m.subject, m.topic, m.description, m.notes || '', m.study_date, m.start_time, m.end_time, m.priority, m.status, cur.id]);
  res.json(await getPlan(cur.id, req.user));
}));
app.delete('/api/study-plans/:id', auth, wrap(async (req, res) => {
  const cur = await getPlan(req.params.id, req.user); if (!cur) return fail(res, 404, 'Plan not found.');
  await pool.execute('DELETE FROM study_plans WHERE id = ?', [cur.id]); res.json({ message: 'Deleted' });
}));

/* ---------- Admin: manage users ---------- */
app.get('/api/admin/users', auth, adminOnly, wrap(async (req, res) => {
  const [r] = await pool.query(`SELECT u.id, u.name, u.email, u.role, DATE_FORMAT(u.created_at,'%Y-%m-%d') AS created_at,
    (SELECT COUNT(*) FROM study_plans WHERE user_id = u.id) AS plans FROM users u ORDER BY u.id`);
  res.json(r);
}));
app.put('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  const role = req.body.role;
  if (!['admin', 'user'].includes(role)) return fail(res, 400, 'Invalid role.');
  if (+req.params.id === req.user.id && role !== 'admin') return fail(res, 400, 'You cannot remove your own admin role.');
  const [r] = await pool.execute('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  if (!r.affectedRows) return fail(res, 404, 'User not found.'); res.json({ message: 'Updated' });
}));
app.delete('/api/admin/users/:id', auth, adminOnly, wrap(async (req, res) => {
  if (+req.params.id === req.user.id) return fail(res, 400, 'You cannot delete your own account.');
  const [r] = await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
  if (!r.affectedRows) return fail(res, 404, 'User not found.'); res.json({ message: 'Deleted' });
}));

app.use('/api', (req, res) => fail(res, 404, 'Not found.'));
app.use((err, req, res, next) => { console.error(err); fail(res, 500, 'Server error.'); });
pool.query('SELECT 1').then(() => app.listen(PORT, () => console.log(`API running on port ${PORT}, database ${DB_HOST}:${DB_PORT}/${DB_NAME}`)))
  .catch(e => { console.error('Cannot connect to the database:', e.code || e.message); process.exit(1); });

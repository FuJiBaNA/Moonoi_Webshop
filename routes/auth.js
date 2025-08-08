// routes/auth.js - Clean implementation
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

const router = express.Router();

// Import helpers from server
let getDbPool, requireAuth, logActivity, config, generateToken;
try {
  const serverModule = require('../server');
  getDbPool = serverModule.dbPool;
  requireAuth = serverModule.requireAuth;
  logActivity = serverModule.logActivity;
  config = serverModule.config;
  generateToken = serverModule.generateToken;
  if (typeof generateToken !== 'function') {
  const secret = (config && config.jwt_secret) || process.env.JWT_SECRET || 'jwt-key-default-change-this';
  generateToken = (user) => jwt.sign(
    { id: user.id, username: user.username, email: user.email, role: user.role },
    secret,
    { expiresIn: '24h' }
  );
}
} catch (e) {
  console.error('Auth routes: cannot import server helpers', e);
  getDbPool = () => null;
  requireAuth = (req,res,next)=>next();
  logActivity = async()=>{};
  config = { jwt_secret: process.env.JWT_SECRET || 'jwt-key-default-change-this' };
  generateToken = (user) => jwt.sign({ id:user.id, username:user.username, email:user.email, role:user.role }, config.jwt_secret, { expiresIn: '24h' });
}

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100 });

// Mailer
function getMailer() {
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  return require('nodemailer').createTransport({
    host, port, secure: String(process.env.SMTP_SECURE || 'false') === 'true', auth: { user, pass }
  });
}

// Helpers
function sanitizeUser(u) {
  if (!u) return null;
  const { password, password_reset_token, password_reset_expires, ...safe } = u;
  return safe;
}

// POST /api/auth/register
router.post('/register', authLimiter, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ success:false, error:'Missing fields' });
    const [exist] = await db.execute('SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1', [username, email]);
    if (exist.length) return res.status(409).json({ success:false, error:'User already exists' });
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await db.execute('INSERT INTO users (username, email, password) VALUES (?,?,?)', [username, email, hashed]);
    const user = { id: result.insertId, username, email, role: 'user' };
    const token = generateToken(user);
    res.json({ success:true, token, user });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success:false, error:'Failed to register' });
  }
});

// POST /api/auth/login
router.post('/login', authLimiter, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    const { login, password } = req.body || {};
    if (!login || !password) return res.status(400).json({ success:false, error:'Missing fields' });
    const [rows] = await db.execute('SELECT * FROM users WHERE (username = ? OR email = ?) LIMIT 1', [login, login]);
    if (!rows.length) return res.status(401).json({ success:false, error:'Invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password || '');
    if (!ok) return res.status(401).json({ success:false, error:'Invalid credentials' });
    const token = generateToken(user);
    await logActivity(user.id, 'login', 'user', user.id, {}, req);
    res.json({ success:true, token, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success:false, error:'Failed to login' });
  }
});

// GET /api/auth/me
router.get('/me', requireAuth, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ success:false, error:'User not found' });
    res.json({ success:true, user: sanitizeUser(rows[0]) });
  } catch (e) {
    res.status(500).json({ success:false, error:'Failed to fetch user' });
  }
});

// POST /api/auth/change-password
router.post('/change-password', requireAuth, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) return res.status(400).json({ success:false, error:'Missing fields' });
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ success:false, error:'User not found' });
    const ok = await bcrypt.compare(oldPassword, rows[0].password || '');
    if (!ok) return res.status(401).json({ success:false, error:'Invalid current password' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await db.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id]);
    res.json({ success:true, message:'Password updated.' });
  } catch (e) {
    res.status(500).json({ success:false, error:'Failed to change password' });
  }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  try { req.logout?.(); req.session?.destroy?.(()=>{}); } catch(e) {}
  res.json({ success:true, message:'Logged out' });
});

// Password reset flow
router.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ error: 'Database not available' });
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required' });
    const [users] = await db.execute('SELECT id, username, email FROM users WHERE email = ? LIMIT 1', [email]);
    const generic = { message: 'If the email exists, a password reset link has been sent' };
    if (!users.length) return res.json(generic);
    const user = users[0];
    const token = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    const mins = parseInt(process.env.PASSWORD_RESET_EXPIRES_MIN || '60', 10);
    await db.execute(
      'UPDATE users SET password_reset_token = ?, password_reset_expires = DATE_ADD(NOW(), INTERVAL ? MINUTE) WHERE id = ?',
      [hashed, mins, user.id]
    );
    const base = process.env.APP_BASE_URL || `${req.protocol}://${req.get('host')}`;
    const url = `${base}/reset-password.html?token=${token}`;
    const mailer = getMailer();
    if (mailer) {
      try {
        await mailer.sendMail({
          from: process.env.SMTP_FROM || `no-reply@${req.hostname || 'example.com'}`,
          to: user.email,
          subject: 'Reset your password',
          html: `<p>Hi ${user.username || ''},</p>
                 <p>Click to reset your password (expires in ${mins} minutes): <a href="${url}">${url}</a></p>`
        });
      } catch (e) { console.error('Mailer send error:', e); }
    } else {
      console.log('Password reset link:', url);
    }
    res.json(generic);
  } catch (e) {
    console.error('forgot-password error:', e);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

router.get('/verify-reset-token', async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ error: 'Database not available' });
    const { token } = req.query || {};
    if (!token) return res.status(400).json({ error: 'Token is required' });
    const hashed = crypto.createHash('sha256').update(String(token)).digest('hex');
    const [rows] = await db.execute('SELECT id FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW() LIMIT 1', [hashed]);
    res.json({ valid: rows.length > 0 });
  } catch (e) {
    res.status(500).json({ error: 'Failed to verify token' });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ error: 'Database not available' });
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
    if (String(newPassword).length < 6) return res.status(400).json({ error: 'Password too short' });
    const hashed = crypto.createHash('sha256').update(String(token)).digest('hex');
    const [rows] = await db.execute('SELECT id FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW() LIMIT 1', [hashed]);
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired token' });
    const userId = rows[0].id;
    const hashedPw = await bcrypt.hash(newPassword, 10);
    await db.execute('UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?', [hashedPw, userId]);
    await logActivity(userId, 'password_reset_success', 'user', userId, {}, req);
    res.json({ message: 'Password has been reset successfully.' });
  } catch (e) {
    console.error('reset-password error:', e);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

module.exports = router;

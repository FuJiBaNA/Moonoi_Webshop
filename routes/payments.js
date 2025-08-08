// routes/payments.js - Pending + Auto-Verification (BYShop slip + TrueMoney pluggable)
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const axios = require('axios');

let Jimp = null;
let jsQR = null;

const router = express.Router();

let getDbPool, requireAuth, logActivity;
try {
  const serverModule = require('../server');
  getDbPool = serverModule.dbPool;
  requireAuth = serverModule.requireAuth;
  logActivity = serverModule.logActivity;
} catch (e) {
  console.error('Payments routes: cannot import server helpers', e);
  getDbPool = () => null;
  requireAuth = (req,res,next)=>next();
  logActivity = async()=>{};
}

async function ensureTables(db) {
  await db.execute(`CREATE TABLE IF NOT EXISTS payment_transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    method ENUM('bank_slip','truewallet','promptpay','other') DEFAULT 'bank_slip',
    status ENUM('pending','approved','rejected') DEFAULT 'pending',
    amount_expected DECIMAL(10,2) NULL,
    amount_confirmed DECIMAL(10,2) NULL,
    slip_filename VARCHAR(255) NULL,
    reference VARCHAR(255) NULL,
    admin_note TEXT NULL,
    metadata JSON NULL,
    verified_by INT NULL,
    verified_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
}

function safeFilename(originalname) {
  const base = path.basename(originalname || '').replace(/[^a-zA-Z0-9._-]/g, '_');
  return base || 'file.bin';
}
function randomName(prefix, ext) {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}${ext}`;
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(process.cwd(), 'uploads', 'slips');
    fs.mkdir(uploadPath, { recursive: true }, (err) => cb(err, uploadPath));
  },
  filename: (req, file, cb) => {
    const ext = (path.extname(safeFilename(file.originalname)) || '').toLowerCase();
    cb(null, randomName('slip', ext || '.jpg'));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg','image/png','image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Invalid file type'), ok);
  }
});

async function initializeLibraries() {
  if (!Jimp) {
    try {
      Jimp = (await import('jimp')).default || (await import('jimp')).Jimp || (await import('jimp'));
    } catch(e) {
      console.warn('Jimp not available:', e.message);
    }
  }
  if (!jsQR) {
    try {
      jsQR = (await import('jsqr')).default || (await import('jsqr'));
    } catch(e) {
      console.warn('jsQR not available:', e.message);
    }
  }
}

async function extractQRCodeFromImage(imagePath) {
  await initializeLibraries();
  if (!Jimp || !jsQR) return null;
  try {
    const image = await Jimp.read(imagePath);
    image.greyscale();
    const { width, height, data } = image.bitmap;
    const u8 = new Uint8ClampedArray(data);
    const result = jsQR(u8, width, height);
    return result ? result.data : null;
  } catch (e) {
    console.warn('QR extract failed:', e.message);
    return null;
  }
}

// Settings accessors
async function getSetting(db, key) {
  const [rows] = await db.execute('SELECT setting_value, setting_type FROM site_settings WHERE setting_key = ? LIMIT 1', [key]);
  if (!rows.length) return null;
  const row = rows[0];
  if (row.setting_type === 'json') {
    try { return JSON.parse(row.setting_value); } catch { return null; }
  }
  if (row.setting_type === 'number') return Number(row.setting_value);
  if (row.setting_type === 'boolean') return row.setting_value === '1' || row.setting_value === 'true';
  return row.setting_value;
}

async function getVerificationMode(db) {
  return await getSetting(db, 'payments.verify_mode') || 'manual'; // 'manual' | 'auto_api'
}

async function verifySlipByAPI(db, qrcodeText) {
  const endpoint = (await getSetting(db, 'payments.byslip.endpoint')) || 'https://byshop.me/api/check_slip';
  const keyapi = await getSetting(db, 'payments.byslip.keyapi');
  if (!endpoint || !keyapi || !qrcodeText) {
    return { ok:false, reason:'missing_config_or_qr' };
  }
  try {
    const resp = await axios.post(endpoint, { keyapi, qrcode_text: qrcodeText }, { timeout: 15000 });
    const data = resp.data || {};
    // Expect data.status true/false; may include amount
    const ok = data.status === true || data.status === 1 || String(data.status).toLowerCase() === 'true' || data.code === 200;
    const amount = Number(data.amount || data.total_amount || data.price || 0) || null;
    return { ok, amount, raw: data };
  } catch (e) {
    console.error('verifySlipByAPI error:', e.message);
    return { ok:false, error:e.message };
  }
}

async function verifyTrueMoneyByAPI(db, payload) {
  const endpoint = await getSetting(db, 'payments.truemoney.endpoint'); // e.g. https://...
  const apikey = await getSetting(db, 'payments.truemoney.apikey');    // key header or field
  if (!endpoint || !apikey) return { ok:false, reason:'missing_truemoney_config' };
  try {
    // Try common patterns: send as JSON with { api_key, gift_link } or { keyapi, gift_link }
    const body = { api_key: apikey, gift_link: payload.gift_link, phone: payload.phone || undefined };
    const resp = await axios.post(endpoint, body, { timeout: 15000 });
    const data = resp.data || {};
    const ok = data.status === true || data.status === 1 || String(data.status).toLowerCase() === 'true' || data.code === 200;
    const amount = Number(data.amount || data.value || 0) || null;
    return { ok, amount, raw: data };
  } catch (e) {
    console.error('verifyTrueMoneyByAPI error:', e.message);
    return { ok:false, error:e.message };
  }
}

// --- Routes ---

// Upload slip -> create PENDING; if mode=auto_api then try verify and auto-approve
router.post('/slip-upload', requireAuth, upload.single('slip_image'), async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    await ensureTables(db);
    const expected = parseFloat(req.body?.expected_amount || '0');
    const [result] = await db.execute(
      `INSERT INTO payment_transactions (user_id, method, status, amount_expected, slip_filename, metadata)
       VALUES (?,?,?,?,?,?)`,
      [req.user.id, 'bank_slip', 'pending', !isNaN(expected) && expected > 0 ? expected : null, req.file?.filename || null, JSON.stringify({ ip: req.ip })]
    );
    const txId = result.insertId;
    await logActivity(req.user.id, 'payment_slip_pending', 'payment', txId, { filename: req.file?.filename }, req);

    // Respond immediately; start verification if auto mode
    res.json({ success:true, transaction_id: txId, status:'pending' });

    // Fire-and-forget auto verification
    (async () => {
      try {
        if (await getVerificationMode(db) !== 'auto_api') return;
        const filepath = path.join(process.cwd(), 'uploads', 'slips', req.file?.filename || '');
        const qr = await extractQRCodeFromImage(filepath);
        if (!qr) return;
        const v = await verifySlipByAPI(db, qr);
        if (!v.ok) return;
        const credit = v.amount || (!isNaN(expected) && expected>0 ? expected : null);
        if (!credit || credit <= 0) return;
        await db.beginTransaction();
        const [rows] = await db.execute('SELECT * FROM payment_transactions WHERE id = ? FOR UPDATE', [txId]);
        if (!rows.length || rows[0].status !== 'pending') { await db.rollback(); return; }
        await db.execute('UPDATE payment_transactions SET status = ?, amount_confirmed = ?, verified_by = NULL, verified_at = NOW(), metadata = ? WHERE id = ?', 
          ['approved', credit, JSON.stringify({ ...(rows[0].metadata? JSON.parse(rows[0].metadata):{}), auto:'slip_api', raw:v.raw||null }), txId]);
        await db.execute('UPDATE users SET credits = credits + ? WHERE id = ?', [credit, rows[0].user_id]);
        await db.commit();
        await logActivity(rows[0].user_id, 'payment_approved_auto', 'payment', txId, { amount: credit, source: 'slip_api' }, null);
      } catch (e) {
        try { const db = getDbPool(); await db.rollback(); } catch(_){}
        console.error('auto slip verify error:', e.message);
      }
    })();

  } catch (e) {
    console.error('slip-upload error:', e);
    res.status(500).json({ success:false, error: 'Failed to create transaction' });
  }
});

// TrueMoney -> create PENDING; auto verify if configured
router.post('/truewallet', requireAuth, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    await ensureTables(db);
    const { amount, gift_link, phone, ref } = req.body || {};
    const amt = parseFloat(amount || '0');
    const [result] = await db.execute(
      `INSERT INTO payment_transactions (user_id, method, status, amount_expected, reference, metadata)
       VALUES (?,?,?,?,?,?)`,
      [req.user.id, 'truewallet', 'pending', (!isNaN(amt) && amt>0) ? amt : null, ref || null, JSON.stringify({ gift_link: gift_link ? '***masked***' : null, phone })]
    );
    const txId = result.insertId;
    await logActivity(req.user.id, 'payment_truewallet_pending', 'payment', txId, {}, req);
    res.json({ success:true, transaction_id: txId, status:'pending' });

    (async () => {
      try {
        if (await getVerificationMode(db) !== 'auto_api') return;
        const v = await verifyTrueMoneyByAPI(db, { gift_link, phone });
        if (!v.ok) return;
        const credit = v.amount || (!isNaN(amt) && amt>0 ? amt : null);
        if (!credit || credit <= 0) return;
        await db.beginTransaction();
        const [rows] = await db.execute('SELECT * FROM payment_transactions WHERE id = ? FOR UPDATE', [txId]);
        if (!rows.length || rows[0].status !== 'pending') { await db.rollback(); return; }
        await db.execute('UPDATE payment_transactions SET status = ?, amount_confirmed = ?, verified_by = NULL, verified_at = NOW(), metadata = ? WHERE id = ?', 
          ['approved', credit, JSON.stringify({ ...(rows[0].metadata? JSON.parse(rows[0].metadata):{}), auto:'truemoney_api', raw:v.raw||null }), txId]);
        await db.execute('UPDATE users SET credits = credits + ? WHERE id = ?', [credit, rows[0].user_id]);
        await db.commit();
        await logActivity(rows[0].user_id, 'payment_approved_auto', 'payment', txId, { amount: credit, source: 'truemoney_api' }, null);
      } catch (e) {
        try { const db = getDbPool(); await db.rollback(); } catch(_){}
        console.error('auto truemoney verify error:', e.message);
      }
    })();

  } catch (e) {
    console.error('truewallet pending error:', e);
    res.status(500).json({ success:false, error:'Failed to create transaction' });
  }
});

router.get('/transactions', requireAuth, async (req, res) => {
  try {
    const db = getDbPool();
    if (!db) return res.status(500).json({ success:false, error:'Database not available' });
    await ensureTables(db);
    const [rows] = await db.execute(
      'SELECT id, method, status, amount_expected, amount_confirmed, slip_filename, reference, created_at, verified_at FROM payment_transactions WHERE user_id = ? ORDER BY id DESC LIMIT 50',
      [req.user.id]
    );
    res.json({ success:true, transactions: rows });
  } catch (e) {
    res.status(500).json({ success:false, error:'Failed to fetch transactions' });
  }
});

module.exports = router;

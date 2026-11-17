'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// ---------------------------------------------------------------------------
// Konfigurasi
// ---------------------------------------------------------------------------
const app = express();
const PORT = process.env.PORT || 3000;
// Folder data (users/events/purchases). Di hosting, arahkan ke disk permanen: DATA_DIR=/var/data
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
const IS_PROD = process.env.NODE_ENV === 'production';
// Mode demo: token reset password dikembalikan di response (hanya untuk lokal: npm run dev)
const DEMO = process.argv.includes('--demo') || process.env.DEMO_RESET === '1';

const SESSION_DAYS = 7;
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 72; // batas bcrypt

try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (_) {}
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');
const PURCHASES_FILE = path.join(DATA_DIR, 'purchases.json');
const SECRET_FILE = path.join(DATA_DIR, '.session-secret');

// Di belakang Nginx/Cloudflare/Railway dll: set TRUST_PROXY=1 agar IP & HTTPS terbaca benar
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
app.disable('x-powered-by');

// ---------------------------------------------------------------------------
// Penyimpanan file JSON (tahan file terkunci + backup otomatis)
// ---------------------------------------------------------------------------
function sleepSync(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function writeFileSafe(file, content, retries = 6) {
    const tmp = file + '.tmp';
    let lastErr;
    // simpan salinan terakhir yang masih bagus
    try {
        if (fs.existsSync(file) && fs.statSync(file).size > 2) fs.copyFileSync(file, file + '.bak');
    } catch (_) {}
    for (let i = 0; i < retries; i++) {
        try {
            // tulis ke file sementara lalu ganti nama: file asli tidak pernah setengah tertulis
            fs.writeFileSync(tmp, content, 'utf8');
            fs.renameSync(tmp, file);
            return;
        } catch (e) {
            lastErr = e;
            try { fs.unlinkSync(tmp); } catch (_) {}
            // fallback: tulis langsung lewat file descriptor
            try {
                const fd = fs.openSync(file, 'w');
                try { fs.writeSync(fd, content, 0, 'utf8'); } finally { fs.closeSync(fd); }
                return;
            } catch (e2) {
                lastErr = e2;
            }
            sleepSync(100 * (i + 1));
        }
    }
    throw lastErr;
}

function parseJsonText(file) {
    const raw = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').trim();
    return raw ? JSON.parse(raw) : null;
}

function readJsonFile(file) {
    if (!fs.existsSync(file)) return [];
    try {
        const data = parseJsonText(file);
        if (data !== null) return data;
        console.warn('[WARN]', path.basename(file), 'kosong, mencoba .bak');
    } catch (e) {
        console.warn('[WARN]', path.basename(file), 'rusak:', e.message, '- mencoba .bak');
    }
    if (fs.existsSync(file + '.bak')) {
        const data = parseJsonText(file + '.bak');
        if (data !== null) return data;
    }
    return [];
}

const readUsers = () => readJsonFile(USERS_FILE);
const writeUsers = (v) => writeFileSafe(USERS_FILE, JSON.stringify(v, null, 2));
const readEvents = () => readJsonFile(EVENTS_FILE);
const writeEvents = (v) => writeFileSafe(EVENTS_FILE, JSON.stringify(v, null, 2));
const readPurchases = () => readJsonFile(PURCHASES_FILE);
const writePurchases = (v) => writeFileSafe(PURCHASES_FILE, JSON.stringify(v, null, 2));

// ---------------------------------------------------------------------------
// Validasi input
// ---------------------------------------------------------------------------
// Email harus lengkap (nama@domain.tld). Gmail wajib persis @gmail.com
function validateEmail(email) {
    const e = String(email || '').trim();
    if (e.length > 254 || /[<>"'`\\]/.test(e) || !/^[^\s@]+@[^\s@]+\.[^\s@.]{2,}$/.test(e)) {
        return 'Format email tidak valid. Gunakan format lengkap, contoh: example@gmail.com';
    }
    const domain = e.split('@')[1].toLowerCase();
    if (domain.startsWith('gmail') && domain !== 'gmail.com') {
        return 'Email Gmail harus lengkap dan diakhiri @gmail.com, contoh: example@gmail.com';
    }
    return null;
}

function validateUsername(username) {
    if (!/^[A-Za-z0-9_.-]{3,30}$/.test(username)) {
        return 'Username 3-30 karakter dan hanya boleh huruf, angka, titik, garis bawah atau strip.';
    }
    return null;
}

function validatePassword(password) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD) {
        return 'Password minimal ' + MIN_PASSWORD + ' karakter.';
    }
    if (password.length > MAX_PASSWORD) {
        return 'Password maksimal ' + MAX_PASSWORD + ' karakter.';
    }
    return null;
}

function validateFullname(fullname) {
    if (!fullname || fullname.length > 100) return 'Nama lengkap wajib diisi (maksimal 100 karakter).';
    if (/[<>]/.test(fullname)) return 'Nama lengkap tidak boleh mengandung tanda < atau >.';
    return null;
}

const str = (v) => (typeof v === 'string' ? v : (v === undefined || v === null ? '' : String(v)));

// ---------------------------------------------------------------------------
// Pembatas percobaan (anti tebak password / spam)
// ---------------------------------------------------------------------------
const hits = new Map();
function limited(key, max, windowMs) {
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.resetAt <= now) {
        h = { count: 0, resetAt: now + windowMs };
        hits.set(key, h);
    }
    h.count++;
    return h.count > max;
}
function resetLimit(key) { hits.delete(key); }
setInterval(() => {
    const now = Date.now();
    for (const [k, h] of hits) if (h.resetAt <= now) hits.delete(k);
}, 10 * 60 * 1000).unref();

const MIN15 = 15 * 60 * 1000;

// ---------------------------------------------------------------------------
// Sesi login (cookie bertanda tangan HMAC, httpOnly)
// ---------------------------------------------------------------------------
function loadSecret() {
    if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
    try {
        const s = fs.readFileSync(SECRET_FILE, 'utf8').trim();
        if (s.length >= 32) return s;
    } catch (_) {}
    const s = crypto.randomBytes(48).toString('hex');
    try { fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 }); }
    catch (e) { console.warn('[WARN] tidak bisa menyimpan .session-secret; sesi akan hilang saat server restart.'); }
    return s;
}
const SECRET = loadSecret();
const COOKIE_NAME = 'libro_sid';
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const sign = (payload) => crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
const pwFingerprint = (user) => crypto.createHash('sha256').update(String(user.password || '')).digest('hex').slice(0, 16);

function makeToken(user) {
    const payload = b64url(JSON.stringify({
        u: user.username,
        ph: pwFingerprint(user),
        exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
    }));
    return payload + '.' + sign(payload);
}

function parseCookies(req) {
    const out = {};
    const header = req.headers.cookie;
    if (!header) return out;
    header.split(';').forEach(part => {
        const i = part.indexOf('=');
        if (i < 0) return;
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    });
    return out;
}

function setSession(req, res, user) {
    res.cookie(COOKIE_NAME, makeToken(user), {
        httpOnly: true,
        sameSite: 'lax',
        secure: !!req.secure,
        maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
        path: '/'
    });
}

function clearSession(req, res) {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, sameSite: 'lax', secure: !!req.secure, path: '/' });
}

// Mengembalikan user dari cookie sesi (atau null). Hasil disimpan per request.
function currentUser(req) {
    if (req._user !== undefined) return req._user;
    req._user = null;
    try {
        const token = parseCookies(req)[COOKIE_NAME];
        if (!token) return null;
        const [payload, sig] = token.split('.');
        if (!payload || !sig) return null;
        const expected = sign(payload);
        const a = Buffer.from(sig), b = Buffer.from(expected);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
        const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
        if (!data || !data.u || !data.exp || data.exp < Date.now()) return null;
        const user = readUsers().find(u => u && u.username === data.u);
        if (!user || pwFingerprint(user) !== data.ph) return null; // user dihapus / password sudah diganti
        req._user = user;
    } catch (_) {
        req._user = null;
    }
    return req._user;
}

function requireAuth(req, res, next) {
    if (!currentUser(req)) return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
    next();
}

function requireAdmin(req, res, next) {
    const u = currentUser(req);
    if (!u) return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
    if (String(u.role || '').toLowerCase() !== 'admin') return res.status(403).json({ error: 'Hanya admin yang boleh melakukan ini.' });
    next();
}

const isAdminUser = (u) => !!u && String(u.role || '').toLowerCase() === 'admin';
const publicUser = (u) => ({ id: u.id, fullname: u.fullname, username: u.username, email: u.email, role: u.role || 'user' });
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// ---------------------------------------------------------------------------
// Middleware umum + file statis (HANYA index.html dan folder assets)
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
    next();
});

app.use('/assets', express.static(path.join(__dirname, 'assets'), { dotfiles: 'deny' }));
const sendIndex = (req, res) => res.sendFile(path.join(__dirname, 'index.html'));
app.get('/', sendIndex);
app.get('/index.html', sendIndex);
app.get('/favicon.ico', (req, res) => res.status(204).end());

app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '100kb' }));

app.use((req, res, next) => {
    if (!IS_PROD) console.log('[REQ]', req.method, req.url);
    res.setHeader('Cache-Control', 'no-store');
    next();
});

// ---------------------------------------------------------------------------
// Akun: register, login, logout, sesi
// ---------------------------------------------------------------------------
app.post('/register', async (req, res) => {
    try {
        if (limited('register:' + req.ip, 20, 60 * 60 * 1000)) {
            return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
        }
        const body = req.body || {};
        const fullname = str(body.fullname).trim();
        const username = str(body.username).trim();
        const email = str(body.email).trim();
        const password = str(body.password);
        // CATATAN: field "role" dari client sengaja diabaikan. Semua akun baru = user biasa.

        if (!fullname || !username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }
        const err = validateFullname(fullname) || validateUsername(username) || validateEmail(email) || validatePassword(password);
        if (err) return res.status(400).json({ error: err });

        const hashedPassword = await bcrypt.hash(password, 10);

        // baca -> cek -> tulis tanpa await di tengah, supaya dua pendaftaran bersamaan tidak saling menimpa
        const users = readUsers();
        if (users.find(u => u && str(u.username).toLowerCase() === username.toLowerCase())) {
            return res.status(409).json({ error: 'Username already exists.' });
        }
        if (users.find(u => u && str(u.email).toLowerCase() === email.toLowerCase())) {
            return res.status(409).json({ error: 'Email already registered.' });
        }
        let maxId = 0;
        users.forEach(u => { if (u && typeof u.id === 'number' && u.id > maxId) maxId = u.id; });
        users.push({ id: maxId + 1, fullname, username, email, password: hashedPassword, role: 'user' });
        writeUsers(users);
        res.json({ success: true });
    } catch (err) {
        console.error('[REGISTER ERROR]', err);
        res.status(500).json({ error: 'Gagal menyimpan akun', ...(IS_PROD ? {} : { detail: err.message }) });
    }
});

app.post('/login', async (req, res) => {
    try {
        const body = req.body || {};
        const ident = str(body.username).trim().toLowerCase();
        const password = str(body.password);
        if (!ident || !password) {
            return res.status(400).json({ error: 'Username and password required.' });
        }
        // kalau yang diketik berisi @, harus email lengkap (Gmail wajib @gmail.com)
        if (ident.includes('@')) {
            const emailError = validateEmail(ident);
            if (emailError) return res.status(400).json({ error: emailError });
        }
        const key = 'login:' + req.ip + ':' + ident;
        if (limited(key, 10, MIN15)) {
            return res.status(429).json({ error: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' });
        }
        const users = readUsers();
        const user = users.find(u => u && (
            str(u.username).trim().toLowerCase() === ident ||
            str(u.email).trim().toLowerCase() === ident
        ));
        // selalu jalankan bcrypt supaya waktu respons tidak membocorkan apakah user ada
        const match = await bcrypt.compare(password, user ? str(user.password) : DUMMY_HASH);
        if (!user || !match) {
            if (!IS_PROD) console.log('[LOGIN] gagal untuk:', ident, user ? '(password salah)' : '(user tidak ditemukan)');
            return res.status(401).json({ error: 'Invalid username or password.' });
        }
        resetLimit(key);
        setSession(req, res, user);
        res.json({ success: true, username: user.username, fullname: user.fullname, email: user.email, role: user.role || 'user' });
    } catch (err) {
        console.error('[LOGIN ERROR]', err);
        res.status(500).json({ error: 'Login gagal', ...(IS_PROD ? {} : { detail: err.message }) });
    }
});

app.get('/me', (req, res) => {
    const u = currentUser(req);
    if (!u) return res.json({ authenticated: false });
    res.json({ authenticated: true, success: true, username: u.username, fullname: u.fullname, email: u.email, role: u.role || 'user' });
});

app.post('/logout', (req, res) => {
    clearSession(req, res);
    res.json({ success: true });
});

// ---------------------------------------------------------------------------
// Events (baca: publik, ubah: admin)
// ---------------------------------------------------------------------------
app.get('/events', (req, res) => {
    try {
        res.json(readEvents());
    } catch (e) {
        res.status(500).json({ error: 'Failed to parse events data.' });
    }
});

app.post('/events/add', requireAdmin, (req, res) => {
    try {
        const { name, price, amount } = req.body || {};
        if (!str(name).trim() || price === undefined || amount === undefined) {
            return res.status(400).json({ error: 'Name, price and amount are required.' });
        }
        const priceNum = Number(price);
        const amountNum = Number(amount);
        if (!Number.isFinite(priceNum) || !Number.isFinite(amountNum)) {
            return res.status(400).json({ error: 'Price and amount must be numbers.' });
        }
        if (priceNum < 0 || amountNum < 0) {
            return res.status(400).json({ error: 'Price and amount cannot be negative.' });
        }
        const cleanName = str(name).trim().slice(0, 200);
        const uid = currentUser(req).id || 0;

        const events = readEvents();
        const event = events.find(e => e && e.name && String(e.name).toLowerCase() === cleanName.toLowerCase());
        if (event) {
            event.prices = event.prices || [];
            const priceObj = event.prices.find(p => Number(p.price) === priceNum);
            if (priceObj) {
                priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + amountNum;
            } else {
                event.prices.push({ price: priceNum, stock: amountNum, userId: uid });
            }
            event.prices.sort((a, b) => a.price - b.price);
        } else {
            const maxId = events.reduce((max, e) => (e && e.id && e.id > max) ? e.id : max, 0);
            events.push({ id: maxId + 1, name: cleanName, prices: [{ price: priceNum, stock: amountNum, userId: uid }] });
        }
        writeEvents(events);
        res.json({ success: true, message: 'Successfully added event' });
    } catch (err) {
        console.error('[EVENTS.ADD] ERROR:', err);
        res.status(500).json({ error: 'Failed to add event', ...(IS_PROD ? {} : { detail: err.message }) });
    }
});

app.post('/events/update', requireAdmin, (req, res) => {
    try {
        const { id, name, price, amount } = req.body || {};
        if (!id) return res.status(400).json({ error: 'Event id required' });
        const events = readEvents();
        const ev = events.find(e => String(e.id) === String(id));
        if (!ev) return res.status(404).json({ error: 'Event not found' });
        if (name && String(name).trim()) ev.name = String(name).trim().slice(0, 200);
        ev.prices = ev.prices || [];
        if (Array.isArray(req.body.prices)) {
            const cleaned = req.body.prices.map(p => ({ price: Number(p && p.price), stock: Number(p && p.stock) }));
            ev.prices = cleaned.map(p => ({
                price: Number.isFinite(p.price) && p.price >= 0 ? p.price : 0,
                stock: Number.isFinite(p.stock) && p.stock >= 0 ? p.stock : 0
            }));
            ev.prices.sort((a, b) => a.price - b.price);
        } else if (price && amount) {
            const priceVal = Number(price);
            const amountVal = Number(amount);
            if (!Number.isFinite(priceVal) || !Number.isFinite(amountVal) || priceVal < 0 || amountVal < 0) {
                return res.status(400).json({ error: 'Price and amount must be non-negative numbers.' });
            }
            const priceObj = ev.prices.find(p => Number(p.price) === priceVal);
            if (priceObj) {
                priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + amountVal;
            } else {
                ev.prices.push({ price: priceVal, stock: amountVal });
            }
            ev.prices.sort((a, b) => a.price - b.price);
        }
        writeEvents(events);
        res.json({ success: true, message: 'Event updated' });
    } catch (err) {
        console.error('[EVENTS.UPDATE] ERROR:', err);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

app.post('/events/delete', requireAdmin, (req, res) => {
    try {
        const { id } = req.body || {};
        if (!id) return res.status(400).json({ error: 'Event id required' });
        const events = readEvents();
        const idx = events.findIndex(e => String(e.id) === String(id));
        if (idx === -1) return res.status(404).json({ error: 'Event not found' });
        events.splice(idx, 1);
        writeEvents(events);
        res.json({ success: true, message: 'Event deleted' });
    } catch (err) {
        console.error('[EVENTS.DELETE] ERROR:', err);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

// ---------------------------------------------------------------------------
// Pembelian tiket (harus login) & riwayat (user: milik sendiri, admin: semua)
// ---------------------------------------------------------------------------
app.post('/tickets/purchase', requireAuth, (req, res) => {
    try {
        const { eventId, quantity } = req.body || {};
        const qty = Number(quantity);
        if (!eventId || !Number.isInteger(qty) || qty < 1 || qty > 1000) {
            return res.status(400).json({ error: 'eventId and positive quantity required' });
        }
        const events = readEvents();
        let ev = events.find(e => String(e.id) === String(eventId));
        if (!ev) ev = events.find(e => e.name && String(e.name).trim().toLowerCase() === String(eventId).trim().toLowerCase());
        if (!ev) return res.status(404).json({ error: 'Event not found' });

        const prices = (ev.prices || []).slice().sort((a, b) => a.price - b.price);
        let qtyLeft = qty;
        const breakdown = [];
        for (const p of prices) {
            if (qtyLeft <= 0) break;
            const available = Number.isFinite(p.stock) ? p.stock : 0;
            const take = Math.min(available, qtyLeft);
            if (take > 0) {
                breakdown.push({ price: p.price, count: take });
                qtyLeft -= take;
            }
        }
        if (qtyLeft > 0) {
            const totalStock = (ev.prices || []).reduce((s, p) => s + (Number.isFinite(p.stock) ? p.stock : 0), 0);
            return res.status(400).json({ error: 'Not enough stock', available: totalStock });
        }

        let remaining = qty;
        for (let i = 0; i < ev.prices.length; i++) {
            if (remaining <= 0) break;
            const p = ev.prices[i];
            const avail = Number.isFinite(p.stock) ? p.stock : 0;
            const take = Math.min(avail, remaining);
            if (take > 0) {
                p.stock = avail - take;
                remaining -= take;
            }
        }
        writeEvents(events);

        try {
            const purchases = readPurchases();
            const maxId = purchases.reduce((m, it) => (typeof it.id === 'number' && it.id > m ? it.id : m), 0);
            const total = breakdown.reduce((s, b) => s + (b.price * b.count), 0);
            purchases.push({
                id: maxId + 1,
                timestamp: Date.now(),
                username: currentUser(req).username,
                eventId: ev.id != null ? ev.id : ev.name,
                eventName: ev.name,
                quantity: qty,
                breakdown,
                total
            });
            writePurchases(purchases);
        } catch (e) {
            console.error('Failed to record purchase', e);
        }
        res.json({ success: true, breakdown });
    } catch (err) {
        console.error('[PURCHASE] ERROR:', err);
        res.status(500).json({ error: 'Failed to purchase tickets' });
    }
});

function filteredPurchases(req) {
    const me = currentUser(req);
    let purchases = readPurchases();
    if (!isAdminUser(me)) purchases = purchases.filter(p => p && p.username === me.username);
    const q = req.query.q ? String(req.query.q).trim().toLowerCase() : '';
    const eventFilter = req.query.event ? String(req.query.event).trim().toLowerCase() : '';
    const from = req.query.from ? Number(req.query.from) : 0;
    const to = req.query.to ? Number(req.query.to) : 0;
    if (q) purchases = purchases.filter(p => (p.eventName && String(p.eventName).toLowerCase().includes(q)) || String(p.id || '').toLowerCase().includes(q));
    if (eventFilter) purchases = purchases.filter(p => p.eventName && p.eventName.toLowerCase() === eventFilter);
    if (from) purchases = purchases.filter(p => (p.timestamp || 0) >= from);
    if (to) purchases = purchases.filter(p => (p.timestamp || 0) <= to);
    purchases.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    return purchases;
}

app.get('/purchases', requireAuth, (req, res) => {
    try {
        res.json(filteredPurchases(req));
    } catch (e) {
        res.status(500).json({ error: 'Failed to read purchases' });
    }
});

function exportPurchasesHandler(req, res) {
    try {
        const purchases = filteredPurchases(req);
        // cegah CSV/formula injection di Excel
        const esc = (val) => {
            if (val === null || val === undefined) return '""';
            let s = String(val);
            if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
            return '"' + s.replace(/"/g, '""') + '"';
        };
        const headers = ['id', 'timestamp', 'date', 'username', 'eventId', 'eventName', 'quantity', 'total', 'breakdown', 'cancelled'];
        const rows = purchases.map(p => {
            const date = new Date(p.timestamp || 0).toISOString();
            const breakdown = (p.breakdown || []).map(b => `${b.count}x${b.price}`).join(';');
            return [esc(p.id), esc(p.timestamp), esc(date), esc(p.username || ''), esc(p.eventId), esc(p.eventName), esc(p.quantity), esc(p.total || 0), esc(breakdown), esc(p.cancelled ? 'yes' : 'no')].join(',');
        });
        const csv = '\uFEFF' + headers.map(h => '"' + h + '"').join(',') + '\n' + rows.join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="purchases.csv"');
        res.send(csv);
    } catch (e) {
        console.error('[EXPORT] error', e);
        res.status(500).json({ error: 'Failed to export purchases' });
    }
}
app.get('/purchases/export', requireAuth, exportPurchasesHandler);
app.get('/purchases/export.csv', requireAuth, exportPurchasesHandler);
app.get('/export-purchases', requireAuth, exportPurchasesHandler);

app.post('/purchases/cancel', requireAuth, (req, res) => {
    const pid = Number((req.body || {}).id);
    if (!pid) return res.status(400).json({ error: 'purchase id required' });
    try {
        const me = currentUser(req);
        const purchases = readPurchases();
        const idx = purchases.findIndex(p => Number(p.id) === pid);
        if (idx === -1) return res.status(404).json({ error: 'Purchase not found' });
        const purchase = purchases[idx];
        if (!isAdminUser(me) && purchase.username !== me.username) {
            return res.status(403).json({ error: 'Anda tidak boleh membatalkan pembelian ini.' });
        }
        if (purchase.cancelled) return res.status(400).json({ error: 'Purchase already cancelled' });

        const events = readEvents();
        const ev = events.find(e => String(e.id) === String(purchase.eventId)) ||
            events.find(e => e.name && String(e.name).trim().toLowerCase() === String(purchase.eventName || purchase.eventId).trim().toLowerCase());
        if (ev && Array.isArray(purchase.breakdown)) {
            ev.prices = ev.prices || [];
            for (const b of purchase.breakdown) {
                const priceVal = Number(b.price);
                const priceObj = ev.prices.find(p => Number(p.price) === priceVal);
                if (priceObj) {
                    priceObj.stock = (Number.isFinite(priceObj.stock) ? priceObj.stock : 0) + Number(b.count || 0);
                } else {
                    ev.prices.push({ price: priceVal, stock: Number(b.count || 0) });
                }
            }
            ev.prices.sort((a, b) => a.price - b.price);
            writeEvents(events);
        }
        purchase.cancelled = true;
        purchase.cancelledAt = Date.now();
        writePurchases(purchases);
        res.json({ success: true });
    } catch (e) {
        console.error('Failed to cancel purchase', e);
        res.status(500).json({ error: 'Failed to cancel purchase' });
    }
});

// ---------------------------------------------------------------------------
// Manajemen user (admin)
// ---------------------------------------------------------------------------
app.get('/users', requireAdmin, (req, res) => {
    res.json(readUsers().filter(Boolean).map(publicUser));
});

app.post('/users/make-admin', requireAdmin, (req, res) => {
    try {
        const username = str((req.body || {}).username).trim();
        if (!username) return res.status(400).json({ error: 'Username required' });
        const users = readUsers();
        const user = users.find(u => u && str(u.username).toLowerCase() === username.toLowerCase());
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.role = 'admin';
        writeUsers(users);
        res.json({ success: true });
    } catch (err) {
        console.error('[MAKE-ADMIN] ERROR:', err);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.post('/users/delete', requireAdmin, (req, res) => {
    try {
        const username = str((req.body || {}).username).trim();
        if (!username) return res.status(400).json({ error: 'Username required' });
        let users = readUsers();
        const user = users.find(u => u && str(u.username).toLowerCase() === username.toLowerCase());
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.role && String(user.role).toLowerCase() === 'admin') {
            return res.status(403).json({ error: 'Admin users cannot be deleted.' });
        }
        users = users.filter(u => u && str(u.username).toLowerCase() !== username.toLowerCase());
        writeUsers(users);
        res.json({ success: true });
    } catch (err) {
        console.error('[DELETE-USER] ERROR:', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// ---------------------------------------------------------------------------
// Password: lupa, reset, ganti
// ---------------------------------------------------------------------------
// Belum ada layanan email, jadi token TIDAK dikirim ke penelepon (kecuali mode demo lokal).
// Token dicetak di log server supaya pemilik server bisa meneruskannya ke user yang bersangkutan.
app.post('/forgot', (req, res) => {
    try {
        if (limited('forgot:' + req.ip, 5, MIN15)) {
            return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
        }
        const email = str((req.body || {}).email).trim();
        if (!email) return res.status(400).json({ error: 'Email required' });
        const emailLower = email.toLowerCase();
        const users = readUsers();
        const user = users.find(u => u && u.email && str(u.email).trim().toLowerCase() === emailLower);
        const generic = { success: true, message: 'Jika email terdaftar, instruksi reset password telah dibuat.' };
        if (!user) return res.json(generic);

        const token = crypto.randomBytes(20).toString('hex');
        user.resetTokenHash = sha256(token);
        user.resetExpires = Date.now() + 60 * 60 * 1000;
        delete user.resetToken;
        writeUsers(users);
        console.log('[RESET] token untuk', user.email, ':', token, '(berlaku 1 jam)');
        res.json(DEMO ? { ...generic, token } : generic);
    } catch (err) {
        console.error('[FORGOT] ERROR:', err);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

app.post('/reset-password', async (req, res) => {
    try {
        if (limited('reset:' + req.ip, 10, MIN15)) {
            return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
        }
        const { email, token, newPassword } = req.body || {};
        if (!email || !token || !newPassword) return res.status(400).json({ error: 'Email, token and newPassword required' });
        const pwErr = validatePassword(str(newPassword));
        if (pwErr) return res.status(400).json({ error: pwErr });

        const hashed = await bcrypt.hash(str(newPassword), 10);
        const users = readUsers();
        const user = users.find(u => u && u.email && str(u.email).toLowerCase() === str(email).trim().toLowerCase());
        const stored = user && (user.resetTokenHash || (user.resetToken ? sha256(user.resetToken) : null));
        const given = sha256(str(token));
        const ok = !!stored && !!user.resetExpires && Date.now() <= user.resetExpires &&
            stored.length === given.length && crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(given));
        if (!ok) return res.status(400).json({ error: 'Invalid or expired token' });

        user.password = hashed;
        delete user.resetTokenHash;
        delete user.resetToken;
        delete user.resetExpires;
        writeUsers(users);
        res.json({ success: true, message: 'Password updated' });
    } catch (err) {
        console.error('[RESET-PASSWORD] ERROR:', err);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

app.post('/users/change-password', requireAuth, async (req, res) => {
    try {
        const me = currentUser(req);
        const { currentPassword, newPassword } = req.body || {};
        if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });
        const pwErr = validatePassword(str(newPassword));
        if (pwErr) return res.status(400).json({ error: pwErr });

        const key = 'chpw:' + me.username;
        if (limited(key, 10, MIN15)) {
            return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
        }
        const match = await bcrypt.compare(str(currentPassword), str(me.password));
        if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
        resetLimit(key);

        const hashed = await bcrypt.hash(str(newPassword), 10);
        const users = readUsers();
        const user = users.find(u => u && u.username === me.username);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.password = hashed;
        writeUsers(users);
        setSession(req, res, user); // sesi lama otomatis tidak berlaku; beri sesi baru untuk perangkat ini
        res.json({ success: true, message: 'Password changed' });
    } catch (e) {
        console.error('Change password error', e);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ---------------------------------------------------------------------------
// 404 & penanganan error
// ---------------------------------------------------------------------------
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
    if (err && (err.type === 'entity.parse.failed' || err.status === 400)) {
        return res.status(400).json({ error: 'Request tidak valid.' });
    }
    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ error: 'Request terlalu besar.' });
    }
    console.error('[ERROR]', err && err.stack ? err.stack : err);
    res.status(500).json({ error: 'Internal Server Error', ...(IS_PROD ? {} : { detail: err && err.message }) });
});

process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught Exception:', err);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    console.error('[FATAL] Unhandled Rejection:', reason);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}` + (DEMO ? '  [mode demo]' : ''));
});

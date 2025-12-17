// server.js – FULL BACKEND SKELETON v0.3 (z SMTP zamiast SendGrid + debug + próg z e-mailem)
// Dodatkowo: mechanizm SSE (/events) i wypychanie zdarzeń przy /uplink

const express    = require('express');
const bodyParser = require('body-parser');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const axios      = require('axios');
const chirpUpdate = require('./ChirpUpdate');   //  update chirpstacka o nazwe itd
const registerAdsRoute = require('./reklama');
const nodemailer = require('nodemailer');
const moment     = require('moment-timezone');
const { Pool }   = require('pg');
const crypto     = require('crypto'); // do losowania nowego hasła
const { geocodeAddress } = require('./geocode'); 
const { logDeviceSummary } = require('./handlers/logi');  // ← logger „karty”
const fs = require('fs');


const handlers = {
  septic: require('./handlers/septic'),
  leak: require('./handlers/leak'),
 co:     require('./handlers/co'),   // ← DODAJ
  // dodaj inne typy, jeśli będą
};

// Publiczny bazowy adres do linków w mailach (potwierdzenie konta)
const PUBLIC_BASE_URL    = (process.env.PUBLIC_BASE_URL    || 'https://szambo.onrender.com').trim();
const ADMIN_NOTIFY_EMAIL = (process.env.ADMIN_NOTIFY_EMAIL || 'biuro@techiot.pl').trim();

// ── Sekret do /uplink ───────────────────────────────────────────────
const UPLINK_BEARER = (process.env.UPLINK_BEARER || '').trim();

const BEARER_FILE = (process.env.BEARER_FILE || '').trim();
let bearerConfig = null;

function loadBearerConfig() {
  if (!BEARER_FILE) return null;
  try {
    const txt = fs.readFileSync(BEARER_FILE, 'utf8');
    const json = JSON.parse(txt);
    if (!json || typeof json !== 'object') throw new Error('bad json');
    return json;
  } catch (e) {
    console.warn('⚠️ Nie mogę wczytać BEARER_FILE:', e.message);
    return null;
  }
}
bearerConfig = loadBearerConfig();

function hostFromReq(req) {
  const h = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().toLowerCase();
  return h.replace(/:\d+$/, ''); // bez portu
}

function isTokenAllowed(host, token) {
  if (!token) return false;
  // 1) wsteczna kompatybilność – stary pojedynczy bearer
  if (UPLINK_BEARER && token === UPLINK_BEARER) return true;

  // 2) nowa ścieżka – plik JSON z listą
  const cfg = bearerConfig && bearerConfig.hosts;
  if (!cfg) return false;

  const list = Array.isArray(cfg[host]) ? cfg[host]
              : Array.isArray(cfg['*']) ? cfg['*']
              : [];
  return list.includes(token);
}


require('dotenv').config();
const helmet = require('helmet');

// ═══════════ ZGODY – aktualna wersja dokumentów ═══════════
const CURRENT_TERMS_VERSION   = 5;   // zmienisz na 2 przy nowym PDF
const CURRENT_PRIVACY_VERSION = 5;


// ═══════════   ***  Do  nowej apki techiot_admin  rejestracja device  ***   ═══════════════════════════
// Hasło do panelu admin – ustaw w Render.com → Environment
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();
if (!ADMIN_PASSWORD) {
  console.warn('⚠️  Brak zmiennej ADMIN_PASSWORD – /admin/login będzie zawsze odrzucał');
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,      // 15 min
  max: 5,
  standardHeaders: true,         // „RateLimit-*” w odpowiedzi
  legacyHeaders: false,
  message: 'Zbyt wiele prób logowania – spróbuj ponownie później.',
    // ⚠️ NAJWAŻNIEJSZE: kluczem jest e-mail z body,
  // a gdy go nie ma – fallback na req.ip
  keyGenerator: (req /*, res */) =>
    (req.body?.email || req.ip || '').toString().toLowerCase().trim()
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,      // 1 h
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Zbyt wiele resetów hasła – spróbuj ponownie za godzinę.',
    // liczymy per-email; gdy brak – per IP
  keyGenerator: req =>
    (req.body?.email || req.ip || '').toLowerCase().trim()
});


const app  = express();
app.use(helmet());

// Gdy aplikacja stoi za proxy (Render, Heroku, Nginx, Cloudflare…)
// zaufaj 1. wpisowi z X-Forwarded-For, żeby req.ip pokazywało prawdziwy adres
app.set('trust proxy', 1);




const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';

app.use(cors());
app.use(bodyParser.json());



// Nominatim – kontakt do nagłówka i parametru email (wymagane przez OSM)
const NOMINATIM_CONTACT = (process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl').trim();
/**
 * Buduje rozsądne warianty zapytań do geokodera z „brudnego” pola street.
 * Obsługuje m.in.:
 *  - "Bydgoszcz ul. Elbląska 1"  → "Elbląska 1, Bydgoszcz, Polska" itd.
 *  - "ul. Elbląska 1 Bydgoszcz"  → "Elbląska 1, Bydgoszcz, Polska" itd.
 *  - przypadki z/bez przecinka
 */
function buildGeocodeVariants(raw) {
  const s0 = String(raw || '').trim();
  if (!s0) return [];

  // ujednolicenie "ul." → "ul. " (jedno "ul.")
  const fixUl = (t) => t.replace(/\bul\.?\s*/gi, 'ul. ');
  // spacje po przecinkach
  const s = fixUl(s0).replace(/\s*,\s*/g, ', ');

  const variants = new Set();
  const parts = s.split(',').map(v => v.trim());
  const hasDigits = str => /\d/.test(str);

  if (parts.length === 2) {
    // klasycznie: "Ulica 1, Miasto" albo "Miasto, Ulica 1"
    const [a, b] = parts;
    if (!hasDigits(a) && hasDigits(b)) variants.add(`${fixUl(b)}, ${a}, Polska`); // "Miasto, Ulica" → "Ulica, Miasto"
    if (hasDigits(a) && !hasDigits(b)) variants.add(`${fixUl(a)}, ${b}, Polska`); // "Ulica, Miasto" (OK)
  } else {
    // brak przecinka — spróbuj wykryć wzorce
    const r1 = /^(.+?)\s+ul\.?\s*(.+)$/i;               // "Miasto ul. Elbląska 1"
    const r2 = /^ul\.?\s*(.+?)\s+([A-ZŻŹĆĄŚĘŁÓŃ].+)$/i; // "ul. Elbląska 1 Bydgoszcz"
    if (r1.test(s)) {
      const [, city, streetPart] = s.match(r1);
      variants.add(`${fixUl(streetPart)}, ${city}, Polska`);
      variants.add(`${city}, ${fixUl(streetPart)}, Polska`);
    } else if (r2.test(s)) {
      const [, streetPart, city] = s.match(r2);
      variants.add(`${fixUl(streetPart)}, ${city}, Polska`);
      variants.add(`${city}, ${fixUl(streetPart)}, Polska`);
    }
  }

  // zawsze: literal + "Polska", i wersja z prefiksem "ul." (jeśli brak)
  variants.add(`${s}, Polska`);
  if (!/^ul\./i.test(s)) variants.add(`ul. ${s}, Polska`);

  return Array.from(variants);
}

async function geocodeAndUpdateDeviceBySerial(serial, { force = false } = {}) {
  try {
    const { rows } = await db.query(
      `SELECT street, lat, lon FROM devices WHERE serial_number=$1 LIMIT 1`,
      [serial]
    );
    if (!rows.length) {
      console.warn(`geo: device not found serial=${serial}`);
      return { ok: false, reason: 'not_found' };
    }
    const { street, lat, lon } = rows[0];
    console.log(`geo: start serial=${serial} street="${street}" lat=${lat} lon=${lon}`);
    if (!street) return { ok: false, reason: 'no_street' };
    if (!force && lat != null && lon != null) return { ok: true, reason: 'already' };

    // przygotuj warianty zapytań
    const variants = new Set(buildGeocodeVariants(street));

    let coords = null;
    for (const q of variants) {
      console.log(`geo: try "${q}" via OpenCage→Nominatim`);
      coords = await geocodeAddress(q); // <— to jest import z ./geocode (OpenCage fallback Nominatim)
      if (coords) break;
    }
    if (!coords) {
      console.warn(`geo: miss serial=${serial} after ${variants.size} variants`);
      return { ok: false, reason: 'geocoder_miss' };
    }
 await db.query(
   `UPDATE devices
       SET lat=$1,
           lon=$2,
           city   = COALESCE($3, city),
           region = COALESCE($4, region)
     WHERE serial_number=$5`,
   [coords.lat, coords.lon, coords.city || null, coords.region || null, serial]
 );
    console.log(`📍 geocoded ${serial} → ${coords.lat},${coords.lon}`);
    return { ok: true, lat: coords.lat, lon: coords.lon };
  } catch (e) {
    console.warn('⚠️ geocode failed for', serial, e.message);
	  return { ok: false, error: e.message };
  }
}

async function geocodeUserStreetAndUpdateSepticDevices(userId, streetRaw) {
  try {
    const s0 = String(streetRaw || '').trim();
    if (!s0) return { ok: false, reason: 'no_street' };
	  
    // warianty jak w device-geocode (wspólny helper)
    const variants = new Set(buildGeocodeVariants(s0));

    let coords = null;
    for (const q of variants) {
      console.log(`geo(profile): try "${q}"`);
      coords = await geocodeAddress(q);
      if (coords) break;
    }
    if (!coords) return { ok: false, reason: 'geocoder_miss' };

    // 1) zapisz do users.lat/lon
    await db.query('UPDATE users SET lat=$1, lon=$2 WHERE id=$3', [coords.lat, coords.lon, userId]);
    // 2) zapisz do wszystkich septic tego usera, ale tylko tam, gdzie brak adresu lub brak współrzędnych
    await db.query(
      `UPDATE devices
          SET lat=$1, lon=$2
        WHERE user_id=$3
          AND LOWER(COALESCE(device_type,''))='septic'
          AND (street IS NULL OR street='' OR lat IS NULL OR lon IS NULL)`,
      [coords.lat, coords.lon, userId]
    );
    console.log(`📍 geocode(profile) user=${userId} → ${coords.lat},${coords.lon}`);
    return { ok: true, ...coords };
  } catch (e) {
    console.warn('⚠️ geocode(profile) failed:', e.message);
    return { ok: false, error: e.message };
  }
}




// ─────────────────────────────────────────────────────────────
//         adminowe  do nowej apki   gdzie dodajemy czujnik i tyle
//  POST /admin/login   { password }
//  Zwraca JWT z rolą 'admin', gdy hasło = ADMIN_PASSWORD
// ─────────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password || typeof password !== 'string') {
    return res.status(400).send('password required');
  }
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).send('wrong password');
  }

  // token ważny 12 h – możesz zmienić, jeśli chcesz krócej/dłużej
  const token = jwt.sign(
    { id: 'admin', email: 'admin@techiot.local', role: 'admin' },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
  return res.json({ token });
});




// ─────────────────────────────────────────────────────────────────────────────
// DATABASE (pool) + migracje w osobnym pliku
// ─────────────────────────────────────────────────────────────────────────────
const { runMigration } = require('./migration');




const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,                 // trochę mniejszy limit połączeń
  idleTimeoutMillis: 30_000
});

// ► Migracja odpalana **tylko**, gdy RUN_MIGRATION=true
if (process.env.RUN_MIGRATION === 'true') {
  runMigration(db).catch((e) => {
    console.error('❌ Migration failed:', e);
    process.exit(1); // zachowujemy dotychczasową semantykę
  });
}
// ───────────────  REKLAMY (/ads)  ───────────────
// <— dopiero teraz, gdy `db` już istnieje:
registerAdsRoute(app, db);


// ─────────────────────────────────────────────────────────────────────────────
// SMTP KONFIGURACJA (nodemailer)
// ─────────────────────────────────────────────────────────────────────────────
const smtpHost   = process.env.SMTP_HOST;
const smtpPort   = parseInt(process.env.SMTP_PORT || '465', 10);
const smtpSecure = (process.env.SMTP_SECURE === 'true');
const smtpUser   = process.env.SMTP_USER;
const smtpPass   = process.env.SMTP_PASS;
const smtpFrom   = process.env.SMTP_FROM;   // np. 'TechioT <noreply@techiot.pl>'

if (!smtpHost || !smtpPort || !smtpUser || !smtpPass || !smtpFrom) {
  console.warn('⚠️ Brakuje zmiennych SMTP_* w środowisku. E-mail nie będzie działać.');
}

const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: smtpSecure, // true jeśli port 465
  auth: {
    user: smtpUser,
    pass: smtpPass
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Sprawdź połączenie z serwerem SMTP przy starcie
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ SMTP transporter verification failed:', error);
  } else {
    console.log('✅ SMTP transporter is ready to send messages');
  }
});

async function sendEmail(to, subj, html) {
  if (!transporter) {
    throw new Error('SMTP transporter nie jest skonfigurowany');
  }
  const recipients = Array.isArray(to) ? to.join(', ') : to;
  const mailOptions = {
    from: smtpFrom,
    to: recipients,
    subject: subj,
    html: html
  };
  console.log(`✉️ Próbuję wysłać e-maila do: ${recipients} (temat: "${subj}")`);
  const info = await transporter.sendMail(mailOptions);
  console.log('✅ Wysłano e-mail przez SMTP:', info.messageId);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function removePolishLetters(str = "") {
  const pl = {
    'ą':'a','ć':'c','ę':'e','ł':'l','ń':'n','ó':'o','ś':'s','ź':'z','ż':'z',
    'Ą':'A','Ć':'C','Ę':'E','Ł':'L','Ń':'N','Ó':'O','Ś':'S','Ź':'Z','Ż':'Z'
  };
  return str.replace(/[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/g, m => pl[m]);
}

function normalisePhone(p) {
  if (!p || p.length < 9) return null;
  return p.startsWith('+48') ? p : '+48' + p;
}

// konsumuje z puli użytkownika atomowo; zwraca nową wartość, albo null gdy brak środków
async function consumeSms(db, userId, count = 1) {
  const q = `
    UPDATE users
       SET sms_limit = sms_limit - $2
     WHERE id = $1::uuid
       AND sms_limit >= $2
     RETURNING sms_limit`;
  const r = await db.query(q, [userId, count]);
  return r.rowCount ? r.rows[0].sms_limit : null;
}

// próbuje wysłać SMS **i** pobrać 1 z puli; gdy brak środków → nic nie wysyła i zwraca false
async function sendSmsWithQuota(db, userId, phone, msg, tag='') {
  const left = await consumeSms(db, userId, 1);
  if (left === null) {
    console.log(`⛔ Brak SMS w puli user=${userId}, nie wysyłam (${tag})`);
    return false;
  }
  try {
    await sendSMS(phone, msg, tag);
    return true;
  } catch (e) {
    // zwrotka: oddaj kredyt z powrotem (best effort)
    await db.query('UPDATE users SET sms_limit = sms_limit + 1 WHERE id = $1::uuid', [userId]).catch(()=>{});
    throw e;
  }
}



async function sendSMS(phone, msg, tag = '') {
  const { SMSAPIKEY: key, SMSAPIPASSWORD: pwd } = process.env;
  if (!key || !pwd) throw new Error('SMS keys missing');
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${pwd}&from=techiot.pl&to=${encodeURIComponent(phone)}&msg=${encodeURIComponent(msg)}`;
 const r = await axios.post(url, null, { headers: { Accept: 'application/json' } });
  if (r.status !== 200) {
    throw new Error('SMSplanet HTTP ' + r.status);
  }
  const data = r.data;
  console.log(`📨 SMSPlanet (${tag || 'no-tag'}) resp →`, JSON.stringify(data));
  // Zależnie od API SMSPlanet – dopasuj warunek do realnego pola „sukcesu”
  const logicalOk =
    (typeof data === 'object' && (
      data.status === 'OK' ||
      data.result === 'OK' ||
      data.success === true ||
      data.error === undefined
    )) || (typeof data === 'string' && data.toLowerCase().includes('ok'));
  if (!logicalOk) {
    throw new Error('SMSplanet logic error: ' + JSON.stringify(data));
  }
  return data;
}

function randomHex(bytes = 16) {
  try { return crypto.randomBytes(bytes).toString('hex'); }
  catch { return Math.random().toString(16).slice(2).padEnd(bytes*2, '0'); }
}


// ─────────────────────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE (+kontrola „user nadal istnieje?”)
// ─────────────────────────────────────────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Missing token');
  try {
    const payload = jwt.verify(token, JWT_SECRET);

    // token admina generujemy lokalnie – pomijamy sprawdzanie w DB
    if (payload.id !== 'admin') {
      const { rows } = await db.query(
        'SELECT 1 FROM users WHERE id = $1',
        [payload.id]
      );
      // user usunięty?  → przerwij sesję
      if (!rows.length) return res.status(401).send('USER_DELETED');
    }

    req.user = payload;
    return next();
  } catch {
    return res.status(401).send('Invalid token');
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// DODANA TRASA: GET /admin/users-with-devices (auth + adminOnly)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/admin/users-with-devices', auth, adminOnly, async (req, res) => {
  const q = `
 SELECT u.id, u.email, u.name, u.sms_limit, u.abonament_expiry,
        u.customer_type AS customer_type,
        u.is_active,
        u.confirmed,
           COALESCE(
             json_agg(d.*) FILTER (WHERE d.id IS NOT NULL),
             '[]'::json
           ) AS devices
      FROM users u
      LEFT JOIN devices d ON d.user_id = u.id
     GROUP BY u.id`;
  const { rows } = await db.query(q);
  res.json(rows);
});

async function firmOnly(req, res, next) {
  try {
    const { rows } = await db.query('SELECT customer_type FROM users WHERE id = $1', [req.user.id]);
    if (!rows.length || (rows[0].customer_type || 'client') !== 'firmowy') {
      return res.status(403).send('FORBIDDEN_NOT_FIRM');
    }
    next();
  } catch (e) {
    console.error('firmOnly err', e);
    res.status(500).send('server error');
  }
}

// pomocniczo – normalizacja numeru (bardzo prosta)
function normalizePhone(p) {
  if (!p) return '';
  let s = String(p).trim();
  // usuń spacje, myślniki, nawiasy
  s = s.replace(/[()\s-]+/g, '');
  // jeżeli polski 9-cyfrowy bez prefiksu, dołóż +48
  if (/^\d{9}$/.test(s)) s = '+48' + s;
  return s;
}

app.post('/firm/clients/attach', auth, consentGuard, firmOnly, async (req, res) => {
  try {
    const emailRaw = (req.body?.email || '').toString().trim().toLowerCase();
    const phoneRaw = (req.body?.phone || '').toString().trim();
    const label    = (req.body?.label || '').toString().trim() || null;

    const hasEmail = !!emailRaw;
    const hasPhone = !!phoneRaw;

    if (!hasEmail && !hasPhone) {
      return res.status(400).json({ message: 'Provide email or phone' });
    }

    let client; // { id, email }

    if (hasEmail) {
      const { rows } = await db.query(
        'SELECT id, email FROM users WHERE LOWER(email)=LOWER($1)',
        [emailRaw]
      );
      if (!rows.length) return res.status(404).json({ message: 'CLIENT_NOT_FOUND' });
      client = rows[0];
    } else {
      const phone = normalizePhone(phoneRaw);
      if (!phone) return res.status(400).json({ message: 'INVALID_PHONE' });

      // znajdź unikalnego właściciela urządzenia septic z tym numerem
      const q = `
        SELECT DISTINCT u.id, u.email
        FROM devices d
        JOIN users u ON u.id = d.user_id
        WHERE (d.phone = $1 OR d.phone2 = $1)
          AND LOWER(COALESCE(d.device_type,'')) = 'septic'
      `;
      const { rows } = await db.query(q, [phone]);

      if (rows.length === 0) {
        return res.status(404).json({ message: 'PHONE_NOT_FOUND', phone });
      }
      if (rows.length > 1) {
        return res.status(409).json({
          message: 'PHONE_AMBIGUOUS',
          phone,
          matches: rows.map(r => r.email)
        });
      }
      client = rows[0];
    }

// ... mamy już: let client = { id, email } wyłuskany po emailu/telefonie

// ⬇️ NOWE: sprawdź zgodę użytkownika
{
  const { rows: ccons } = await db.query(
    'SELECT allow_company_attach FROM users WHERE id = $1',
    [client.id]
  );
  const allow = ccons[0]?.allow_company_attach === true;
  if (!allow) {
    return res.status(403).json({ message: 'CLIENT_NO_CONSENT' });
  }
}



	  
    // UPSERT powiązania + label
    await db.query(
      `INSERT INTO firm_clients (firm_user_id, client_user_id, label)
       VALUES ($1,$2,$3)
       ON CONFLICT (firm_user_id, client_user_id)
       DO UPDATE SET label = EXCLUDED.label`,
      [req.user.id, client.id, label]
    );

    return res.status(200).json({
      ok: true,
      client_email: client.email,
      using: hasEmail ? 'email' : 'phone',
    });
  } catch (e) {
    console.error('attach error', e);
    return res.status(500).json({ message: 'server error' });
  }
});


// PATCH /firm/clients/:client_email/label  { label }
app.patch('/firm/clients/:client_email/label', auth, consentGuard, firmOnly, async (req, res) => {
  const clientEmail = String(req.params.client_email || '').toLowerCase().trim();
  const label = (req.body && 'label' in req.body) ? String(req.body.label || '').trim() : null;

  try {
    const { rows:c } = await db.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [clientEmail]);
    if (!c.length) return res.status(404).send('client not found');

    const r = await db.query(
      `UPDATE firm_clients SET label = $1
         WHERE firm_user_id = $2 AND client_user_id = $3`,
      [label || null, req.user.id, c[0].id]
    );
    if (!r.rowCount) return res.status(404).send('relation not found');

    return res.sendStatus(200);
  } catch (e) {
    console.error('PATCH /firm/clients/:email/label', e);
    return res.status(500).send('server error');
  }
});
// DELETE /firm/clients/:client_email
app.delete('/firm/clients/:client_email', auth, consentGuard, firmOnly, async (req, res) => {
  const clientEmail = String(req.params.client_email || '').toLowerCase().trim();
  try {
    const { rows:c } = await db.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [clientEmail]);
    if (!c.length) return res.status(404).send('client not found');

    const r = await db.query(
      'DELETE FROM firm_clients WHERE firm_user_id=$1 AND client_user_id=$2',
      [req.user.id, c[0].id]
    );
    if (!r.rowCount) return res.status(404).send('relation not found');

    return res.sendStatus(200);
  } catch (e) {
    console.error('DELETE /firm/clients/:email', e);
    return res.status(500).send('server error');
  }
});


/** Middleware: wpuszcza tylko, gdy user ma aktualne zgody */
function consentGuard(req, res, next) {
  const sql = `
    SELECT COUNT(*) AS cnt
      FROM user_consents
     WHERE user_id = $1
       AND (
             (doc_type = 'terms'   AND version = $2)
          OR (doc_type = 'privacy' AND version = $3)
           )`;

  db.query(sql, [req.user.id, CURRENT_TERMS_VERSION, CURRENT_PRIVACY_VERSION])
    .then(({ rows: [row] }) => {
      const ok = Number(row.cnt) === 2;   // muszą być DWA wiersze
      if (ok) return next();
      console.log('⛔ consentGuard – brak zgód u', req.user.email);
      res.status(403).send('CONSENT_REQUIRED');
    })
    .catch(err => {
      console.error('❌ consentGuard DB err', err);
      res.status(500).send('server error');
    });
}

// GET /me/companies → firmy, które przypięły zalogowanego klienta
// Zwraca: [{ firm_email, company, street, label }]
app.get('/me/companies', auth, consentGuard, async (req, res) => {
  try {
    // (opcjonalny guard — zgodny z frontem, który i tak nie pobiera listy, gdy zgoda=FALSE)
    const { rows: cons } = await db.query(
      'SELECT allow_company_attach FROM users WHERE id = $1',
      [req.user.id]
    );
    if (cons[0]?.allow_company_attach !== true) {
      return res.json([]); // brak zgody → pusta lista
    }

    const q = `
      SELECT
        f.email   AS firm_email,
        f.company AS company,   -- tylko users.company (bez fallbacków)
        f.street  AS street,    -- tylko users.street
        fc.label  AS label
      FROM firm_clients fc
      JOIN users f
        ON f.id = fc.firm_user_id
      WHERE fc.client_user_id = $1
      ORDER BY lower(coalesce(f.company, '')), lower(f.email)
    `;
    const { rows } = await db.query(q, [req.user.id]);

    // Front oczekuje płaskich pól "company" i "street"
    res.json(rows.map(r => ({
      firm_email: r.firm_email,
      company:    r.company || '',
      street:     r.street  || '',
      label:      r.label ?? null
    })));
  } catch (e) {
    console.error('GET /me/companies error:', e);
    res.status(500).send('server error');
  }
});



// GET /me/firm-consent — stan zgody ---->> zgoda  czy  moze dodac 
app.get('/me/firm-consent', auth, consentGuard, async (req, res) => {
  const { rows } = await db.query(
    'SELECT allow_company_attach FROM users WHERE id = $1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).send('user not found');
  res.json({ allow: rows[0].allow_company_attach === true });
});

// PATCH /me/firm-consent { allow: boolean }
//  • gdy allow=false → kasujemy wszystkie powiązania firmowe dla tego usera
app.patch('/me/firm-consent', auth, consentGuard, async (req, res) => {
  const allow = req.body?.allow === true;
  const client = await db.connect();
  try {
    await client.query('BEGIN');

    // TYLKO flaga, bez *_ts
    await client.query(
      `UPDATE users
          SET allow_company_attach = $1
        WHERE id = $2`,
      [allow, req.user.id]
    );

    if (!allow) {
      await client.query(
        'DELETE FROM firm_clients WHERE client_user_id = $1',
        [req.user.id]
      );
    }

    await client.query('COMMIT');
    return res.status(200).json({ ok: true, allow });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('PATCH /me/firm-consent', e);
    return res.status(500).send('server error');
  } finally {
    client.release();
  }
});




//-------------------------------------------------------------
//pingujemy server  hobby zeby nie padł 
//------------------------------------------------------------

app.get("/health", (req, res) => {
  const time = new Date().toISOString();
  console.log(`[PING] ${time} – /health ok oracle `);
  res.status(200).send("OK");
});




//
// ─────────────────────────────────────────────────────────────────────────────
// Poniżej dodajemy prosty broker SSE:
// 
// * KLIENCI → trzymamy array odpowiedzi `res`
// * Wysyłamy event: uplink, data: {...} do wszystkich podłączonych
// 
// ─────────────────────────────────────────────────────────────────────────────

let clients = [];

/**
 * Usuwa zamknięte odpowiedzi i wypisuje do logów ilość aktywnych klientów
 */
function pruneClients() {
  clients = clients.filter(r => !r.writableEnded && !r.finished);
 // console.log(`ℹ️ Aktywnych klientów SSE: ${clients.length}`);
}

/**
 * Wysyła zdarzenie SSE do wszystkich podłączonych klientów.
 * `payload` to dowolny JS‐owy obiekt, np. { serial, distance, voltage, ts }.
 */
function sendEvent(payload) {
  pruneClients();

  if (clients.length === 0) {
 //   console.log('ℹ️ Brak podłączonych klientów SSE – pomijam wysyłkę');
    return;
  }

  const dataAsJson = JSON.stringify(payload);
const msg = ['event: uplink', `data: ${dataAsJson}`, '', ''].join('\n');

  clients.forEach(res => {
    try {
      res.write(msg);
    } catch (err) {
      console.warn('⚠️ Błąd podczas pisania do klienta SSE – usuwam go:', err.message);
    }
  });
  console.log(`▶️ Wyemitowano SSE uplink → ${dataAsJson}`);
}

/**
 * Route SSE: GET /events
 * Utrzymuje otwarte połączenie HTTP jako text/event-stream. Każdy nowy /uplink wypchnie event.
 */
app.get('/events', (req, res) => {
  // 1) Ustawiamy nagłówki wymagane przez SSE
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive'
  });
  res.flushHeaders();

  // 2) Wyślij od razu „komentarz” (heartbeat), żeby połączenie się uaktywniło w przeglądarce
  //    i żeby proxy/go-between nie ściąło tego połączenia jako „nieużywane”.
  res.write(': ping\n\n');

  // 3) Dodajemy to `res` do listy aktywnych klientów
  clients.push(res);
//  console.log('➕ Nowy klient SSE podłączony, wszystkich:', clients.length);

  // 4) Jeśli klient zamknie połączenie – usuwamy `res` z listy
  req.on('close', () => {
    clients = clients.filter(r => r !== res);
    console.log('➖ Klient SSE rozłączony, pozostało:', clients.length);
  });
});



// ─────────────────────────────────────────────────────────────────────────────
// GET /device/:serial/params – pola konfiguracyjne w „Ustawieniach”
// ─────────────────────────────────────────────────────────────────────────────
app.get('/device/:serial/params', auth, consentGuard, async (req,res)=> {
  const { serial } = req.params;
      
    const q = `
    SELECT
      d.name,
      d.phone, d.phone2, d.tel_do_szambiarza, d.capacity, d.alert_email,
      d.red_cm,
      u.sms_limit                AS sms_limit,          -- globalny limit użytkownika
      d.do_not_disturb,
      d.empty_cm, d.empty_ts,
      u.abonament_expiry         AS abonament_expiry,   -- globalna data
      d.street, d.sms_after_empty,
      -- pola CO:
      d.co_phone1, d.co_phone2, d.leak_phone1, d.leak_phone2, d.co_threshold_ppm,
      -- statusy informacyjne:
      d.co_status, d.co_ppm
    FROM devices d
    JOIN users   u ON u.id = d.user_id
    WHERE d.serial_number = $1
    LIMIT 1`;
  const { rows } = await db.query(q, [serial]);
  if (!rows.length) return res.status(404).send('Not found');
  res.json(rows[0]);
});


// GET /device/:serial/measurements – ostatnie ≤10 rekordów
app.get('/device/:serial/measurements', auth, consentGuard, async (req, res) => {
  const { serial } = req.params;
  const q = `
    SELECT distance_cm, ts
      FROM measurements
     WHERE device_serial = $1
     ORDER BY ts DESC
     LIMIT 240`;            // -------------> tu dajemy ile ostanich  pomiarów ma   byc
  const { rows } = await db.query(q, [serial]);
  res.json(rows);
});


//////////////////////to zeby sprawdzic w htmlu historie pomiarów  ....
// ADMIN: historia pomiarów (do 240)
app.get('/admin/device/:serial/measurements', auth, adminOnly, async (req, res) => {
  const { serial } = req.params;
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 240);

  const { rows } = await db.query(
    `SELECT ts, distance_cm, snr
       FROM measurements
      WHERE device_serial = $1
      ORDER BY ts DESC
      LIMIT $2`,
    [serial, limit]
  );

  res.json(rows);
});


///////////////////////////////////////////////tu koniec tego ? /////////////////


// GET /admin/firm/tree — drzewko: firmy → klienci → urządzenia
app.get('/admin/firm/tree', auth, adminOnly, async (req, res) => {
  try {
    const { rows: firms } = await db.query(
      `SELECT id, email, name, company, street
         FROM users
        WHERE customer_type = 'firmowy'`
    );
    const out = [];
    for (const f of firms) {
      // klienci tej firmy
      const { rows: clients } = await db.query(
        `SELECT c.id, c.email, c.name
           FROM firm_clients fc
           JOIN users c ON c.id = fc.client_user_id
          WHERE fc.firm_user_id = $1`,
        [f.id]
      );
      const clientsOut = [];
      for (const c of clients) {
        // urządzenia klienta (distance z kolumny albo z params)
        const { rows: devs } = await db.query(
          `SELECT serial_number, name, street, lat, lon,
                  COALESCE(distance_cm, NULLIF((params->>'distance')::int, 0)) AS distance_cm
             FROM devices
            WHERE user_id = $1`,
          [c.id]
        );
        clientsOut.push({
          email: c.email,
          name:  c.name,
          devices: devs.map(d => ({
            serial_number: d.serial_number,
            name: d.name,
            street: d.street,
            lat: d.lat,
            lon: d.lon,
            distance_cm: d.distance_cm
          }))
        });
      }
      out.push({
        firm: { email: f.email, name: f.name, company: f.company, street: f.street },
        clients: clientsOut
      });
    }
    res.json(out);
  } catch (e) {
    console.error('GET /admin/firm/tree error:', e);
    res.status(500).send('server error');
  }
});



// ─────────────────────────────────────────────────────────────────────────────
// PATCH /admin/device/:serial/params – zapis parametrów (ADMIN)
//  • pola globalne "u.*" idą do tabeli users (po user_id z devices)
//  • pozostałe pola aktualizują devices
// ─────────────────────────────────────────────────────────────────────────────
app.patch('/admin/device/:serial/params', auth, adminOnly, async (req, res) => {
  const { serial } = req.params;
  const body = req.body || {};

  // 1) Znajdź device i user_id
  const { rows:devRows } = await db.query(
    'SELECT id, user_id FROM devices WHERE serial_number = $1 LIMIT 1',
    [serial]
  );
  if (!devRows.length) return res.status(404).send('Device not found');
  const { id: deviceId, user_id: userId } = devRows[0];

  const { rows: typeRow } = await db.query(
    'SELECT device_type FROM devices WHERE id = $1',
    [deviceId]
  );
  const currentType = (typeRow[0]?.device_type || '').toLowerCase();
  const isSeptic = currentType === 'septic';
  const isLeak   = currentType === 'leak';
  const isCO     = currentType === 'co';

  const septicOnly = new Set([
    'phone','phone2','tel_do_szambiarza','red_cm','capacity','sms_after_empty'
  ]);
  const leakOnly = new Set(['leak_phone1','leak_phone2']);
  const coOnly   = new Set(['co_phone1','co_phone2','co_threshold_ppm']);

  // 2) Zestawy pól
  const allowedDevice = new Set([
    'phone','phone2','tel_do_szambiarza','street',
    'red_cm','serial_number','serie_number','capacity',
    'alert_email','trigger_dist','sms_after_empty','device_type',
    'co_phone1','co_phone2','leak_phone1','leak_phone2','co_threshold_ppm','lat','lon'
  ]);
  const allowedUser = new Set(['u.sms_limit','u.abonament_expiry']);

  const devCols = [];
  const devVals = [];
  const userCols = [];
  const userVals = [];
  let iDev = 1, iUser = 1;

  // mały helper
  const pushDev = (col, val) => { devCols.push(`${col} = $${iDev++}`); devVals.push(val); };
  const pushUser = (col, val) => { userCols.push(`${col} = $${iUser++}`); userVals.push(val); };

  // 3) Walidacja i rozdzielenie pól
  for (const [rawK, v] of Object.entries(body)) {
    const k = rawK.trim();

    // ---- pola USER (globalne) ----
    if (allowedUser.has(k)) {
      if (k === 'u.sms_limit') {
        const num = Number(v);
        if (!Number.isFinite(num) || num < 0) return res.status(400).send('u.sms_limit must be >= 0');
        pushUser('sms_limit', num);
        continue;
      }
      if (k === 'u.abonament_expiry') {
        // dopuszczamy null/"" → NULL
        if (v == null || String(v).trim() === '') { pushUser('abonament_expiry', null); continue; }
        const s = String(v).trim();
        // prosta walidacja YYYY-MM-DD
        if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return res.status(400).send('u.abonament_expiry must be YYYY-MM-DD');
        pushUser('abonament_expiry', s);
        continue;
      }
    }

    // ---- pola DEVICE ----
    if (!allowedDevice.has(k)) {
      return res.status(400).send(`Niedozwolone pole: ${k}`);
    }
    // zablokuj edycję pól niepasujących do bieżącego typu (anty-cross update)
    if (septicOnly.has(k) && !isSeptic) continue;
    if (leakOnly.has(k)   && !isLeak)   continue;
    if (coOnly.has(k)     && !isCO)     continue;
	  
    // alias: serie_number → serial_number
    if (k === 'serie_number') {
      if (!/^[0-9A-Fa-f]{16}$/.test(String(v||'').trim())) {
        return res.status(400).send('serial_number must be 16 hex chars');
      }
      pushDev('serial_number', String(v).trim().toUpperCase());
      continue;
    }

    if (k === 'serial_number') {
      if (!/^[0-9A-Fa-f]{16}$/.test(String(v||'').trim())) {
        return res.status(400).send('serial_number must be 16 hex chars');
      }
      pushDev('serial_number', String(v).trim().toUpperCase());
      continue;
    }

    // telefony: pozwól wyczyścić → NULL
    if (['phone','phone2','tel_do_szambiarza','co_phone1','co_phone2','leak_phone1','leak_phone2'].includes(k)) {
      if (v == null || String(v).trim() === '') { pushDev(k, null); continue; }
      if (typeof v !== 'string') return res.status(400).send(`Niepoprawny format dla pola: ${k}`);
      const nv = normalisePhone(v.replace(/\s+/g,''));
      if (!nv) return res.status(400).send(`Niepoprawny numer telefonu: ${k}`);
      pushDev(k, nv);
      continue;
    }

    if (k === 'alert_email') {
      if (v == null || String(v).trim() === '') { pushDev(k, null); continue; }
      if (typeof v !== 'string' || !v.includes('@')) return res.status(400).send('Niepoprawny email');
      pushDev(k, String(v).trim());
      continue;
    }

    if (k === 'trigger_dist' || k === 'sms_after_empty') {
      if (typeof v !== 'boolean') return res.status(400).send(`${k} must be boolean`);
      pushDev(k, v);
      continue;
    }

    if (k === 'red_cm') {
      const num = Number(v);
      if (!Number.isFinite(num) || num < 0) return res.status(400).send('red_cm must be >= 0');
      pushDev(k, num);
      continue;
    }

    if (k === 'capacity') {
      const num = Number(v);
      if (!Number.isInteger(num) || num <= 0) return res.status(400).send('capacity must be positive integer');
      pushDev(k, num);
      continue;
    }

    if (k === 'co_threshold_ppm') {
      const num = Number(v);
      if (!Number.isInteger(num) || num <= 0) return res.status(400).send('co_threshold_ppm must be positive integer');
      pushDev(k, num);
      continue;
    }
    if (k === 'lat' || k === 'lon') {
      if (v == null || String(v).trim() === '') { pushDev(k, null); continue; }
      const num = Number(v);
      if (!Number.isFinite(num)) return res.status(400).send(`${k} must be number`);
      if (k === 'lat' && (num < -90 || num > 90))   return res.status(400).send('lat out of range');
      if (k === 'lon' && (num < -180 || num > 180)) return res.status(400).send('lon out of range');
      pushDev(k, num);
      continue;
    }




	  
    if (k === 'street' || k === 'device_type') {
      const s = String(v ?? '').trim();
      pushDev(k, s || null);
      continue;
    }

    // bezpieczny fallback:
    pushDev(k, v);
  }

  if (!devCols.length && !userCols.length) {
    return res.status(400).send('Brak danych do aktualizacji');
  }

  // 4) Transakcja – najpierw devices, potem users
  const client = await db.connect();
  try {
    await client.query('BEGIN');

    if (devCols.length) {
		      try {
        console.log(
          '[PATCH /admin/device/%s/params] type=%s devFields=%j userFields=%j',
          serial,
          currentType,
          devCols.map(c => c.split('=')[0].trim()),
          userCols.map(c => c.split('=')[0].trim())
        );
      } catch {}
      // UWAGA: szukamy po starym serialu z :param
      const q = `UPDATE devices SET ${devCols.join(', ')} WHERE serial_number = $${iDev}`;
      await client.query(q, [...devVals, serial]);
    }

    if (userCols.length) {
      const qU = `UPDATE users SET ${userCols.join(', ')} WHERE id = $${iUser}`;
      await client.query(qU, [...userVals, userId]);
    }

    await client.query('COMMIT');
  

    // ⬇️ jeżeli admin zmienił adres urządzenia → przelicz geolokację „od ręki”
    try {
      if (Object.prototype.hasOwnProperty.call(body, 'street')) {
        geocodeAndUpdateDeviceBySerial(serial, { force: true }).catch(()=>{});
      }
    } catch (e) {
      console.warn('[admin geo trigger] err:', e.message);
    }
    return res.sendStatus(200);


	  
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(`[PATCH /admin/device/${serial}/params] DB error:`, err);
    return res.status(500).send('Błąd serwera');
  } finally {
    client.release();
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// POST /login — logowanie
// ─────────────────────────────────────────────────────────────────────────────
app.post('/login', authLimiter, async (req, res) => { 
  const { email, password } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    console.log(`❌ [POST /login] Niepoprawny email: ${email}`);
    return res.status(400).send('Niepoprawny email');
  }
  if (!password || typeof password !== 'string' || password.length < 6) {
    console.log(`❌ [POST /login] Za krótkie hasło dla: ${email}`);
    return res.status(400).send('Hasło musi mieć minimum 6 znaków');
  }
  console.log(`🔑 [POST /login] próba logowania użytkownika: ${email}`);
  let rows;
  try {
    ({ rows } = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]));
  } catch (err) {
    console.error(`❌ [POST /login] Błąd bazy przy pobieraniu usera:`, err);
    return res.status(500).send('Błąd serwera');
  }
  const u = rows[0];
  if (!u) {
    console.log(`❌ [POST /login] Brak usera: ${email}`);
    return res.status(401).send('Niepoprawne dane logowania');
  }
  let passwordMatches;
  try {
    passwordMatches = await bcrypt.compare(password, u.password_hash);
  } catch (err) {
    console.error(`❌ [POST /login] Błąd bcrypt dla: ${email}`, err);
    return res.status(500).send('Błąd serwera');
  }
  if (!passwordMatches) {
    console.log(`❌ [POST /login] Złe hasło dla usera: ${email}`);
    return res.status(401).send('Niepoprawne dane logowania');
  }
  let token;
  try {
    token = jwt.sign(
      { id: u.id, email: u.email, role: u.role },
      JWT_SECRET
    );
  } catch (err) {
    console.error(`❌ [POST /login] Błąd przy generowaniu tokenu dla: ${email}`, err);
    return res.status(500).send('Błąd serwera');
  }
  // konto nieaktywne?
  if (!u.is_active) {
    console.log(`⛔ login: konto zablokowane ${email}`);
    return res.status(403).send('ACCOUNT_INACTIVE');
  }

	  // e-mail/konto niepotwierdzone przez admina?
  if (u.confirmed === false) {
    console.log(`⛔ login: email not confirmed ${email}`);
    return res.status(403).send('EMAIL_NOT_CONFIRMED');
  }

  // sprawdź, czy są aktualne zgody
  const { rows:[row] } = await db.query(
    `SELECT COUNT(*) AS cnt
       FROM user_consents
      WHERE user_id = $1
        AND (
              (doc_type='terms'   AND version=$2)
           OR (doc_type='privacy' AND version=$3)
            )`,
    [u.id, CURRENT_TERMS_VERSION, CURRENT_PRIVACY_VERSION]
  );
 const consentOk = Number(row.cnt) === 2;


  console.log(`✅ [POST /login] ${email} consentOK=${consentOk}`);
  return res.json({ token, consentOk });
});


//////////////tu dodaje zmien hasło/////////////////////////

// POST /change-password — zmiana hasła przez zalogowanego usera
app.post('/change-password', auth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (
    !oldPassword || typeof oldPassword !== 'string' ||
    !newPassword || typeof newPassword !== 'string' ||
    newPassword.length < 6
  ) {
    return res.status(400).send('Niepoprawne dane');
  }
  try {
    // 1) pobierz hasło użytkownika
    const { rows } = await db.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!rows.length) return res.status(404).send('Nie znaleziono użytkownika');

    // 2) porównaj stare hasło
    const ok = await bcrypt.compare(oldPassword, rows[0].password_hash);
    if (!ok) return res.status(401).send('Niepoprawne stare hasło');

    // 3) zahashuj nowe i zapisz
    const newHash = await bcrypt.hash(newPassword, 10);
    await db.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [ newHash, req.user.id ]
    );

    console.log(`✅ [POST /change-password] User ${req.user.email} changed password`);
    return res.sendStatus(200);
  } catch (err) {
    console.error('❌ Error in /change-password:', err);
    return res.status(500).send('Błąd serwera');
  }
});
///////////////////////////////////////////////////////////////////////////////////////////koniec  zmien hasłao////////////////////////


// ─────────────────────────────────────────────────────────────────────────────
// POST /forgot-password — generuje nowe hasło, zapisuje w bazie i wysyła e-mail
// ─────────────────────────────────────────────────────────────────────────────
app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string' || !email.includes('@')) {
      console.log('❌ [POST /forgot-password] Niepoprawny email:', email);
      return res.status(400).send('Niepoprawny email');
    }
    console.log(`🔄 [POST /forgot-password] Prośba o reset hasła dla: ${email}`);
    const { rows } = await db.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (!rows.length) {
      console.log(`⚠️ [POST /forgot-password] Nie znaleziono usera o e-mailu: ${email}`);
      return res
        .status(200)
        .send('Jeśli konto o podanym adresie istnieje, otrzymasz nowe hasło mailem.');
    }
    const newPassword = crypto.randomBytes(4).toString('hex');
    console.log(`🔑 [POST /forgot-password] Wygenerowane hasło dla ${email}: ${newPassword}`);
    const newHash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE email = $2', [newHash, email.toLowerCase()]);
    console.log(`✅ [POST /forgot-password] Zaktualizowano hasło w bazie dla ${email}`);
    const htmlContent = `
    <!-- 1. Reset hasła (/forgot-password) -->
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Twoje nowe hasło – TechioT</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
  <table role="presentation" style="width:100%; border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:20px 0;">
        <table role="presentation" style="width:600px; border-collapse:collapse; background-color:#ffffff; box-shadow:0 0 10px rgba(0,0,0,0.1);">
          <tr>
            <td align="center" style="padding:20px;">
              <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg"
                   alt="TechioT Logo" style="max-width:150px; height:auto;">
            </td>
          </tr>
          <tr>
            <td style="padding:0 20px; border-bottom:1px solid #eeeeee;">
              <h2 style="color:#333333; font-size:22px; margin:0;">
                Wygenerowaliśmy nowe hasło
              </h2>
            </td>
          </tr>
          <tr>
            <td style="padding:20px;">
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Cześć,<br>
                na Twoją prośbę wygenerowaliśmy nowe hasło do aplikacji Szambo Control.
              </p>
              <p style="background-color:#f0f0f0; padding:15px; border-radius:5px; display:inline-block;">
                <strong>Twoje nowe hasło:</strong><br>
                <code style="font-size:18px; letter-spacing:1px;">${newPassword}</code>
              </p>
              <p style="color:#999999; font-size:12px; line-height:1.4; margin-top:30px;">
                Ten e-mail został wygenerowany automatycznie, prosimy na niego nie odpowiadać.
              </p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:10px 20px; background-color:#fafafa;">
              <p style="color:#777777; font-size:14px; margin:0;">
                Pozdrawiamy,<br>
                <strong>TechioT</strong>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>

    `;
    console.log(`✉️ [POST /forgot-password] Wysyłam maila do ${email}`);
    await sendEmail(email.toLowerCase(), 'Twoje nowe hasło – TechioT', htmlContent);
    console.log(`✅ [POST /forgot-password] Mail z nowym hasłem wysłany do ${email}`);
    return res
      .status(200)
      .send('Jeśli konto o podanym adresie istnieje, otrzymasz nowe hasło mailem.');
  } catch (err) {
    console.error('❌ Error in /forgot-password:', err);
    return res.status(500).send('Internal server error');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC REGISTER: POST /public/register
// body: { email, name?, phone? }
//  • tworzy usera z confirmed=false (is_active=true)
//  • generuje token i wysyła do biura link do potwierdzenia
// ─────────────────────────────────────────────────────────────────────────────
app.post('/public/register', async (req, res) => {
  try {
    const { email, name, phone } = req.body || {};
    const em = String(email || '').trim().toLowerCase();
    if (!em || !em.includes('@')) return res.status(400).send('invalid email');

    // opcjonalny telefon
    let phoneNorm = null;
    if (phone != null && String(phone).trim() !== '') {
      const p = String(phone).replace(/\s+/g, '').trim();
      phoneNorm = normalisePhone(p);
      if (!phoneNorm) return res.status(400).send('invalid phone');
    }

    // czy e-mail już istnieje?
    const { rowCount: exists } = await db.query(
      'SELECT 1 FROM users WHERE LOWER(email)=LOWER($1)',
      [em]
    );
    if (exists) return res.status(409).send('email exists');

    // robocze hasło (potem zostanie nadpisane przy potwierdzeniu)
    const tmpPwd = randomHex(4);
    const hash   = await bcrypt.hash(tmpPwd, 10);

    const { rows: created } = await db.query(
      `INSERT INTO users (email, password_hash, name, phone, confirmed, is_active)
       VALUES ($1,$2,$3,$4,false,true)
       RETURNING id, email, name`,
      [em, hash, (name ?? '').toString().trim() || null, phoneNorm]
    );
    const userId = created[0].id;

    // token (ważny 14 dni) + e-mail do biura
    const token = randomHex(16);
    await db.query(
      `INSERT INTO email_verification_tokens(user_id, token, expires_at)
       VALUES($1,$2, now() + interval '14 days')`,
      [userId, token]
    );

    const url = `${PUBLIC_BASE_URL}/admin/confirm-account?token=${encodeURIComponent(token)}`;
    const htmlAdmin = `
      <div style="font-family:Arial,sans-serif;font-size:15px;color:#333">
        <p><b>Nowa rejestracja użytkownika</b></p>
        <ul>
          <li><b>Email:</b> ${em}</li>
          ${name ? `<li><b>Imię i nazwisko:</b> ${String(name).trim()}</li>` : ''}
          ${phoneNorm ? `<li><b>Telefon:</b> ${phoneNorm}</li>` : ''}
        </ul>
        <p>Potwierdź konto: <a href="${url}">${url}</a> (ważny 14 dni)</p>
      </div>`;

    await sendEmail(ADMIN_NOTIFY_EMAIL, '🆕 Nowa rejestracja – TechioT', htmlAdmin);
    return res.sendStatus(200);
  } catch (e) {
    console.error('❌ /public/register error:', e);
    return res.status(500).send('server error');
  }
});



// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/create-user — tworzenie użytkownika (wymaga auth+adminOnly)
//  • bez crashy na duplikacie (ON CONFLICT DO NOTHING)
//  • zwraca 409 USER_EXISTS gdy e-mail już jest
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-user', auth, adminOnly, async (req, res) => {
  try {
    let { email, password, role = 'client', name = '', company = '' } = req.body || {};
    const em = String(email || '').trim().toLowerCase();
    if (!em || !em.includes('@')) return res.status(400).send('invalid email');
    if (!password || String(password).length < 8) {
      // brak/krótkie hasło → wygeneruj 8 heksów (opcjonalnie pokażesz w UI)
      password = randomHex(4);
    }
    if (!['client','firmowy','admin'].includes(role)) role = 'client';

    const hash = await bcrypt.hash(String(password), 10);
    const q = `
      INSERT INTO users (email, password_hash, role, name, company, confirmed)
      VALUES ($1, $2, $3, $4, $5, TRUE)
      ON CONFLICT (email) DO NOTHING
      RETURNING id`;
    const r = await db.query(q, [em, hash, role, name || null, company || null]);

    if (r.rowCount === 0) {
      console.log(`⚠️ [POST /admin/create-user] Użytkownik już istnieje: ${em}`);
      return res.status(409).json({ message: 'USER_EXISTS' });
    }
    console.log(`✅ [POST /admin/create-user] Utworzono: ${em} (id=${r.rows[0].id})`);
    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error('❌ [POST /admin/create-user] DB error:', e);
    return res.status(500).send('server error');
  }
});

// PATCH /admin/user/:email/params — admin zmienia parametry użytkownika

app.patch('/admin/user/:email/params', auth, adminOnly, async (req, res) => {
  const email = String(req.params.email || '').toLowerCase().trim();
  if (!email || !email.includes('@')) return res.status(400).send('invalid email param');

  const allowed = new Set(['name','company','street','phone','is_active','customer_type','confirmed','password']);
  const cols = [];
  const vals = [];
  let i = 1;
	let pendingPassword = null; // hasło przetworzymy po pętli

  for (const [k, raw] of Object.entries(req.body || {})) {
    if (!allowed.has(k)) return res.status(400).send(`field ${k} not allowed`);


    // password → walidacja i odłożenie, NIE wrzucamy surowego do SQL
    if (k === 'password') {
      const pwd = String(raw || '').trim();
      if (!pwd) continue; // puste pole ignorujemy
      if (pwd.length < 8) return res.status(400).send('password too short (min 8)');
      pendingPassword = pwd;
      continue;
    }

    if (k === 'is_active') {
      if (typeof raw !== 'boolean') return res.status(400).send('is_active must be boolean');
      cols.push(`is_active = $${i++}`); vals.push(raw);
      continue;
    }

	   if (k === 'confirmed') {
   if (typeof raw !== 'boolean') return res.status(400).send('confirmed must be boolean');
   cols.push(`confirmed = $${i++}`); vals.push(raw);
   continue;
 }
    if (k === 'customer_type') {
      const v = String(raw || '').trim().toLowerCase();
      if (!['client','firmowy'].includes(v)) return res.status(400).send('customer_type must be client|firmowy');
      cols.push(`customer_type = $${i++}`); vals.push(v);
      continue;
    }
    if (k === 'phone') {
      if (raw == null || String(raw).trim() === '') {
        cols.push(`phone = $${i++}`); vals.push(null); continue;
      }
      if (typeof raw !== 'string') return res.status(400).send('invalid phone');
      const nv = normalisePhone(raw.replace(/\s+/g,''));
      if (!nv) return res.status(400).send('invalid phone');
      cols.push(`phone = $${i++}`); vals.push(nv);
      continue;
    }
    // name/company/street → string lub null
    if (raw == null || String(raw).trim() === '') {
      cols.push(`${k} = $${i++}`); vals.push(null);
    } else {
      cols.push(`${k} = $${i++}`); vals.push(String(raw).trim());
    }
  }

    // jeżeli przyszło hasło → hashujemy i dopinamy do tego samego UPDATE
  if (pendingPassword) {
    const hash = await bcrypt.hash(pendingPassword, 10);
    // ZMIEŃ 'password_hash' jeśli masz inną nazwę kolumny na hash:
    cols.push(`password_hash = $${i++}`);
    vals.push(hash);
  }


  vals.push(email);

  try {
    const q = `UPDATE users SET ${cols.join(', ')} WHERE LOWER(email)=LOWER($${i++}) RETURNING id`;
    const r = await db.query(q, vals);
    if (!r.rowCount) return res.status(404).send('user not found');
    return res.sendStatus(200);
  } catch (e) {
    console.error('❌ [PATCH /admin/user/:email/params]', e);
    return res.status(500).send('server error');
  }
});





// ─────────────────────────────────────────────────────────────────────────────
//  USER PROFILE  (wykorzystywane przez UserDataScreen)
// ─────────────────────────────────────────────────────────────────────────────

/** GET /me/profile – zwraca podstawowe dane użytkownika                                */
app.get(['/me/profile','/me/profile/'], auth, consentGuard, async (req, res) => {
  const { rows } = await db.query(
    'SELECT email, name, street FROM users WHERE id = $1',
    [req.user.id]
  );
  if (!rows.length) return res.status(404).send('user not found');
  res.json(rows[0]);
});

/** PATCH /me/profile – aktualizuje name/street (walidacja pól)                         */
app.patch(['/me/profile','/me/profile/'], auth, consentGuard, async (req, res) => {
  const allowed = new Set(['name', 'street']);
  const cols = [];
  const vals = [];
  let i = 1;

  const newStreet =
    (typeof req.body?.street === 'string' && req.body.street.trim().length > 0)
      ? req.body.street.trim()
      : null;

	
  for (const [k, v] of Object.entries(req.body || {})) {
    if (!allowed.has(k)) {
      return res.status(400).send(`field ${k} not allowed`);
    }
    if (typeof v !== 'string') {
      return res.status(400).send(`invalid value for ${k}`);
    }
    const s = v.trim();
    // Pusty string ⇒ pomiń (nie aktualizuj tego pola, ale nie rób błędu)
    if (s.length === 0) continue;
    cols.push(`${k} = $${i++}`);
    vals.push(s);
  }

  if (!cols.length) {
    return res.status(400).send('nothing to update');
  }

  vals.push(req.user.id);

  try {
    await db.query(
      `UPDATE users SET ${cols.join(', ')} WHERE id = $${i}`,
      vals
    );
    console.log(`✅ [PATCH /me/profile] updated ${cols.join(', ')} for`, req.user.email);
       // geokoduj w tle, jeśli zaktualizowano ulicę
    if (newStreet) {
      geocodeUserStreetAndUpdateSepticDevices(req.user.id, newStreet).catch(()=>{});
    }
       // ⬇️ GEO po zmianie ulicy (opcjonalnie – robi się „od ręki”)
    if (Object.prototype.hasOwnProperty.call(req.body, 'street')) {
      const s = String(req.body.street || '').trim();
      if (s.length >= 3) {
        try {
          const coords = await geocodeAddress(`${s}, Polska`);
          if (coords) {
            // users: zawsze aktualizuj lat/lon; city/region gdy znamy
            await db.query(
              `UPDATE users
                  SET lat=$1, lon=$2, city=$3, region=$4
                WHERE id=$5`,
              [coords.lat, coords.lon, coords.city || null, coords.region || null, req.user.id]
            );
            // devices: uzupełnij tylko tam, gdzie brak lat/lon
            await db.query(
              `UPDATE devices
                  SET lat=$1, lon=$2,
                      city   = COALESCE($3, city),
                      region = COALESCE($4, region)
                WHERE user_id=$5 AND (lat IS NULL OR lon IS NULL)`,
              [coords.lat, coords.lon, coords.city || null, coords.region || null, req.user.id]
            );
            console.log('📍 profile geocoded →', coords);
          }
        } catch (e) {
          console.warn('⚠️ geocode(profile) failed:', e.message);
        }
      }
    }
    res.sendStatus(200)

  } catch (err) {
    console.error('❌ error in PATCH /me/profile:', err);
    res.status(500).send('server error');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /me/devices — zwraca urządzenia zalogowanego usera (wymaga auth)
// ─────────────────────────────────────────────────────────────────────────────
app.get(['/me/devices','/me/devices/'], auth, consentGuard, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM devices WHERE user_id=$1', [req.user.id]);
  const iso = v => (v ? new Date(v).toISOString() : null);
  const mapped = rows.map(d => ({
    ...d,
    leak_last_change_ts: iso(d.leak_last_change_ts),
    leak_last_uplink_ts: iso(d.leak_last_uplink_ts),
    co_last_change_ts:   iso(d.co_last_change_ts),
    co_last_uplink_ts:   iso(d.co_last_uplink_ts),
    empty_ts:            iso(d.empty_ts),
    created_at:          iso(d.created_at),
  }));
  res.json(mapped);
});

// GET /me/devices/:id/support-contact
// - znajduje urządzenie usera
// - czyta description z któregoś ChirpStacka (TARGETS w ChirpUpdate.js)
// - jeśli description niepuste -> traktujemy jako numer telefonu
// - jeśli puste / błąd -> fallback na kontakt@techiot.pl
app.get('/me/devices/:id/support-contact', auth, consentGuard, async (req, res) => {
  try {
        const raw = String(req.params.id || '').trim();
    const serial = raw.replace(/[^0-9a-f]/gi, '').toUpperCase();
    const isSerial = /^[0-9A-F]{16}$/.test(serial);
    const isUuid =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(raw);

    let rows = [];
    if (isSerial) {
      console.log(`[support-contact] by SERIAL serial=${serial} user=${req.user.email}`);
      ({ rows } = await db.query(
        'SELECT eui FROM devices WHERE serial_number=$1 AND user_id=$2 LIMIT 1',
        [serial, req.user.id]
      ));
    } else if (isUuid) {
      console.log(`[support-contact] by UUID id=${raw} user=${req.user.email}`);
      ({ rows } = await db.query(
        'SELECT eui FROM devices WHERE id=$1::uuid AND user_id=$2 LIMIT 1',
        [raw, req.user.id]
      ));
    } else {
      console.log(`[support-contact] BAD_DEVICE_ID raw="${raw}" user=${req.user.email}`);
      return res.status(400).send('BAD_DEVICE_ID');
    }
    if (!rows.length) {
      return res.status(404).send('DEVICE_NOT_FOUND');
    }

    const eui = String(rows[0].eui || serial || '').toUpperCase();
    const info = await chirpUpdate.getDeviceDescription(eui);

	      const eui = String(rows[0].eui || serial || '').toUpperCase();
    console.log(`[support-contact] fetch desc eui=${eui} (raw="${raw}")`);

    const t0 = Date.now();
    const info = await chirpUpdate.getDeviceDescription(eui);
    const ms = Date.now() - t0;
    const desc = (info && info.description != null) ? String(info.description) : '';
    console.log(
      `[support-contact] desc result ok=${!!info?.ok} target=${info?.target} status=${info?.status} ms=${ms} descLen=${desc.trim().length} desc="${desc.trim().slice(0, 40)}"`
    );

    if (info.ok && info.description && info.description.trim() !== '') {
      return res.json({ type: 'phone', value: info.description.trim() });
    }

    return res.json({ type: 'email', value: 'kontakt@techiot.pl' });
  } catch (err) {
    console.error('GET /me/devices/:id/support-contact error:', err);
    return res.json({ type: 'email', value: 'kontakt@techiot.pl' });
  }
});




// GET /firm/clients — lista klientów i ich urządzeń dla zalogowanego "firmowy"
app.get('/firm/clients', auth, consentGuard, async (req, res) => {
  try {
    const { rows: who } = await db.query('SELECT customer_type FROM users WHERE id=$1', [req.user.id]);
    if (!who.length || (who[0].customer_type || 'client') !== 'firmowy') {
      return res.status(403).send('FORBIDDEN_NOT_FIRM');
    }
    const q = `
      SELECT
        c.id          AS client_id,
        c.email       AS client_email,
		COALESCE(fc.label, c.name) AS client_name,  -- << TU JEST TWEAK
        
        c.street      AS client_street,
		fc.label      AS client_label,                  -- ⬅️ NOWE
        d.serial_number,
        d.name        AS device_name,
        d.street      AS device_street,
        (d.lat)::double precision AS lat,
        (d.lon)::double precision AS lon,
        COALESCE(d.distance_cm, NULLIF((d.params->>'distance')::int, 0)) AS distance_cm,
        d.red_cm,
        d.trigger_dist,
        d.device_type,
		d.phone AS phone                    -- ⬅️ TU
      FROM firm_clients fc
      JOIN users   c ON c.id = fc.client_user_id
      LEFT JOIN devices d ON d.user_id = c.id
      WHERE fc.firm_user_id = $1
      ORDER BY c.email, d.serial_number`;
    const { rows } = await db.query(q, [req.user.id]);
    return res.json(rows);
  } catch (e) {
    console.error('❌ GET /firm/clients', e);
    return res.status(500).send('server error');
  }
});



// ─────────────────────────────────────────────────────────────────────────────
// POST /me/devices/claim — użytkownik dopina istniejące urządzenie do konta
//  body: { serial, device_type, device_name?, street? }
//  • walidacja 16-znakowego EUI (HEX, wielkie litery)
//  • weryfikacja w LNS (chirpUpdate), jak w adminowej ścieżce
//  • odrzucenie, jeśli serial już przypięty do innego usera
// ─────────────────────────────────────────────────────────────────────────────
app.post('/me/devices/claim', auth, consentGuard, async (req, res) => {
  try {
    const { serial, device_type, device_name = '', street = null } = req.body || {};

    const serialNorm = String(serial || '').trim().toUpperCase();
    if (!/^[0-9A-F]{16}$/.test(serialNorm)) {
      return res.status(400).send('serial must be 16 hex chars');
    }
    const type = String(device_type || '').trim().toLowerCase();
    if (!['septic','leak','co'].includes(type)) {
      return res.status(400).send('device_type must be "septic", "leak" or "co"');
    }

    // 1) Czy urządzenie już istnieje?
    const { rows: exists } = await db.query(
      'SELECT user_id FROM devices WHERE serial_number = $1 LIMIT 1',
      [serialNorm]
    );

    if (exists.length) {
      // Jeśli już jest przypięte do TEGO usera → idempotentnie OK
      if (exists[0].user_id === req.user.id) {
        return res.status(200).json({ ok: true, alreadyOwned: true });
      }
      // Przypięte do innego konta
      return res.status(409).send('Device already registered');
    }

    // 2) Sprawdzenie w LNS (jak w /admin/create-device-with-user)
    const label = device_name || req.user.email || serialNorm;
        // NIE nadpisujemy description w LNS (tam jest numer telefonu)
    const lnsResults = await chirpUpdate(serialNorm, label, null);
    const anyOk = Array.isArray(lnsResults) && lnsResults.some(r => r && r.ok);
    if (!anyOk) {
      return res
        .status(400)
        .json({ message: 'Urządzenie nie znaleziono w żadnym LNS, rejestracja przerwana', lns: lnsResults });
    }

    // 3) Wstaw urządzenie do devices przypisane do zalogowanego usera
    await db.query(
      `INSERT INTO devices (
         user_id, name, serial_number, eui,
         street, device_type
       )
       VALUES ($1,$2,$3,$3,$4,$5)`,
      [req.user.id, device_name || null, serialNorm, street ? String(street).trim() : null, type]
    );

    console.log(`✅ [/me/devices/claim] user=${req.user.email} dodał ${serialNorm} (type=${type})`);
    geocodeAndUpdateDeviceBySerial(serialNorm).catch(()=>{});
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Error in /me/devices/claim:', e);
    return res.status(500).send('server error');
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// PUT /device/:id/phone — zmiana numeru telefonu (wymaga auth)
// ─────────────────────────────────────────────────────────────────────────────
app.put('/device/:id/phone', auth, consentGuard, async (req, res) => {
  const phone = normalisePhone(String(req.body.phone || '').replace(/\s+/g, ''));
  if (!phone) return res.status(400).send('Invalid phone');
  await db.query('UPDATE devices SET phone=$1 WHERE id=$2 AND user_id=$3', [
    phone,
    req.params.id,
    req.user.id
  ]);
  res.send('Updated');
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /admin/user/:email — usuwa użytkownika wraz z urządzeniami (ON DELETE CASCADE)
// ─────────────────────────────────────────────────────────────────────────────
app.delete('/admin/user/:email', auth, adminOnly, async (req, res) => {
  const email = req.params.email.toLowerCase();
  console.log(`🗑️ [DELETE /admin/user/${email}] Próba usunięcia usera`);
  try {
    const result = await db.query(
      'DELETE FROM users WHERE email = $1 RETURNING id',
      [email]
    );
    if (result.rowCount === 0) {
      console.log(`⚠️ [DELETE /admin/user/${email}] Użytkownik nie istniał`);
      return res.status(404).send(`User ${email} not found`);
    }
    console.log(`✅ [DELETE /admin/user/${email}] Usunięto użytkownika i urządzenia`);
    return res.send(`Deleted user ${email} and their devices`);
  } catch (err) {
    console.error(`❌ Error in DELETE /admin/user/${email}:`, err);
    return res.status(500).send(err.message);
  }
});

// DELETE /admin/device/:serial — usuwa pojedyncze urządzenie po serialu
app.delete('/admin/device/:serial', auth, adminOnly, async (req, res) => {
  const serial = req.params.serial;
  try {
    const r = await db.query('DELETE FROM devices WHERE serial_number = $1 RETURNING id', [serial]);
    if (r.rowCount === 0) return res.status(404).send(`Device ${serial} not found`);
    return res.send(`Deleted device ${serial}`);
  } catch (err) {
    console.error(`❌ Error in DELETE /admin/device/${serial}:`, err);
    return res.status(500).send('server error');
  }
});

// helper: tylko cyfry
function digitsOnly(s) {
  return String(s || '').replace(/\D+/g, '');
}

// POST /admin/firm/:firmEmail/clients
// Body: { client_email?: string, client_phone?: string, label?: string }
app.post('/admin/firm/:firmEmail/clients', auth, adminOnly, async (req, res) => {
  const firmEmail = String(req.params.firmEmail || '').trim().toLowerCase();
  const clientEmail = (req.body.client_email || '').trim().toLowerCase();
  const clientPhoneRaw = req.body.client_phone || '';
  const label = (req.body.label || '').toString();

  if (!firmEmail) {
    return res.status(400).send('firm_email required in URL');
  }
  if (!clientEmail && !clientPhoneRaw) {
    return res.status(400).send('provide client_email or client_phone');
  }

  try {
    // 1) firma
    const firmQ = await db.query(
      'SELECT id, email FROM users WHERE lower(email) = lower($1) LIMIT 1',
      [firmEmail]
    );
    if (firmQ.rowCount === 0) {
      return res.status(404).send('firm not found');
    }
    const firmId = firmQ.rows[0].id;

    // 2) klient -> po e-mailu albo po telefonie z devices(septic)
    let clientId = null;
    let resolvedClientEmail = null;

    if (clientEmail) {
      const cQ = await db.query(
        'SELECT id, email FROM users WHERE lower(email) = lower($1) LIMIT 1',
        [clientEmail]
      );
      if (cQ.rowCount === 0) return res.status(404).send('client (email) not found');
      clientId = cQ.rows[0].id;
      resolvedClientEmail = cQ.rows[0].email;
    } else {
      const digits = digitsOnly(clientPhoneRaw);
      if (!digits) return res.status(400).send('invalid phone');

      // przygotuj warianty: np. 515... i 48 515...
      const with48 = digits.startsWith('48') ? digits : '48' + digits;

      // Szukamy właściciela septic-a po numerze z devices.phone
      const dQ = await db.query(
        `
        SELECT DISTINCT d.user_id AS id
        FROM devices d
        WHERE lower(d.device_type) = 'septic'
          AND d.user_id IS NOT NULL
          AND regexp_replace(coalesce(d.phone,''), '\\D', '', 'g') IN ($1, $2)
        LIMIT 1
        `,
        [digits, with48]
      );
      if (dQ.rowCount === 0) {
        return res.status(404).send('client (by device phone) not found');
      }
      clientId = dQ.rows[0].id;

      // dociągnij e-mail klienta (do odpowiedzi)
      const ce = await db.query('SELECT email FROM users WHERE id = $1', [clientId]);
      resolvedClientEmail = ce.rows[0]?.email || null;
    }

    // 3) INSERT/UPSERT do firm_clients
    const up = await db.query(
      `
      INSERT INTO firm_clients (firm_user_id, client_user_id, label)
      VALUES ($1, $2, $3)
      ON CONFLICT (firm_user_id, client_user_id)
      DO UPDATE SET label = COALESCE(EXCLUDED.label, firm_clients.label)
      RETURNING firm_user_id, client_user_id, label
      `,
      [firmId, clientId, label || null]
    );

    return res.json({
      ok: true,
      firm_email: firmEmail,
      client_email: resolvedClientEmail,
      label: up.rows[0].label,
    });
  } catch (e) {
    console.error('[admin attach]', e);
    return res.status(500).send('internal error');
  }
});


// DELETE /admin/firm/:firm_email/clients/:client_email — usuwa powiązanie
app.delete('/admin/firm/:firm_email/clients/:client_email', auth, adminOnly, async (req, res) => {
  const firmEmail   = String(req.params.firm_email || '').toLowerCase().trim();
  const clientEmail = String(req.params.client_email || '').toLowerCase().trim();
  if (!firmEmail || !clientEmail) return res.status(400).send('firm_email & client_email required');
  try {
    const { rows: f } = await db.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [firmEmail]);
    const { rows: c } = await db.query('SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [clientEmail]);
    if (!f.length || !c.length) return res.status(404).send('firm or client not found');
    const r = await db.query('DELETE FROM firm_clients WHERE firm_user_id=$1 AND client_user_id=$2', [f[0].id, c[0].id]);
    if (!r.rowCount) return res.status(404).send('link not found');
    return res.sendStatus(200);
  } catch (e) {
    console.error('❌ DELETE /admin/firm/.../clients/...', e);
    return res.status(500).send('server error');
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/create-device-with-user — tworzenie (lub dopięcie) urządzenia
//  • gdy użytkownik istnieje → NIE wysyłamy maila/SMS, tylko dopinamy device
//  • gdy użytkownik nie istnieje → tworzymy konto + mail powitalny (+ SMS)
//  • sprawdzamy duplikat seriala i wynik chirpUpdate()
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-device-with-user', auth, adminOnly, async (req, res) => {
  // ZMIANA: deklaracje na górze funkcji
  let userId = null;
  let userCreated = false;
  let basePwd = null;
  try {
    const {
      serie_number,                     // ⬅︎ zachowujemy tę nazwę z formularza
      email,
      client_name,                      // imię/nazwisko (dla konta)
      device_name,                      // nazwa urządzenia
      name,                             // (legacy – fallback)
      phone = '0',
      phone2 = null,
      tel_do_szambiarza = '',
      street = 'N/A',
      company = '',
      device_type                       // 'septic' | 'leak'
    } = req.body || {};
const originalStreet = (street ?? '').toString().trim().replace(/\s*,\s*/g, ', ');
    // ── walidacja wejścia ─────────────────────────────────────────
    const em = String(email || '').trim().toLowerCase();
    const serial = String(serie_number || '').replace(/\s+/g,'').trim().toUpperCase();
    const typeRaw = String(device_type || '').trim().toLowerCase();
    if (!em || !serial) {
      return res.status(400).send('serie_number & email required');
    }
    if (!['septic', 'leak', 'co'].includes(typeRaw)) {
      return res.status(400).send('device_type must be "septic", "leak" or "co"');
    }
    // jeśli EUI to 16-znakowy hex – odkomentuj walidację jeśli potrzebna
    // if (!/^[0-9a-f]{16}$/i.test(serial)) {
    //   return res.status(400).send('serial_number must be 16 hex chars');
    // }

    const userName = (client_name ?? name ?? '').toString().trim();
    const devName  = (device_name ?? '').toString().trim();
    const typeOk   = typeRaw;

    console.log(`➕ [/admin/create-device-with-user] ${serial} → ${em} (type=${typeOk})`);

    const client = await db.connect();
    try {
      await client.query('BEGIN');

		  // 📍 Jednorazowe geokodowanie profilu — tylko dla NOWEGO usera z adresem
  if (userCreated && originalStreet && originalStreet.length >= 3) {
    try {
      await db.query('UPDATE users SET street = $1 WHERE id = $2', [originalStreet, userId]);
      const geo = await geocodeAddress(originalStreet);
      if (geo) {
        await db.query('UPDATE users SET lat = $1, lon = $2 WHERE id = $3', [geo.lat, geo.lon, userId]);
        console.log(`📍 geocode OK user=${em} lat=${geo.lat} lon=${geo.lon}`);
      } else {
        console.log(`📍 geocode MISS user=${em} addr="${originalStreet}"`);
      }
    } catch (e) {
      console.warn('⚠️ geocode/store failed:', e.message);
    }
  }

      // 1) sprawdź, czy user istnieje
      const u1 = await client.query(
        'SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1',
        [em]
      );

     

      if (u1.rowCount > 0) {
        // użytkownik istnieje → nie wysyłamy maila/SMS
        userId = u1.rows[0].id;
        userCreated = false;
        console.log(`ℹ️  user exists: ${em} (id=${userId}) — attach device only`);
          } else {
        // 2) tworzymy konto z losowym hasłem (z fallbackiem na duplikat)
        basePwd = randomHex(4); // 8 znaków
        const hash = await bcrypt.hash(basePwd, 10);
        try {
          const insU = await client.query(
            'INSERT INTO users(email, password_hash, name, company, confirmed) VALUES ($1,$2,$3,$4,FALSE) RETURNING id',
            [em, hash, userName, company]
          );
          userId = insU.rows[0].id;
          userCreated = true;
          console.log(`✅  created user ${em} (id=${userId})`);
        } catch (e) {
          if (e && e.code === '23505') {
            // ktoś utworzył tego usera "obok" – przełącz się na tryb attach
            const u2 = await client.query(
              'SELECT id FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1',
              [em]
            );
            if (!u2.rowCount) throw e; // bardzo rzadkie – przerywamy normalnie
            userId = u2.rows[0].id;
            userCreated = false;
            console.log(`ℹ️  user already existed during txn: ${em} (id=${userId})`);
          } else {
            throw e;
          }
        }

    // nadaj globalny abonament na 365 dni (gdyby default nie zadziałał)
    await client.query(
      `UPDATE users
          SET abonament_expiry = COALESCE(abonament_expiry, CURRENT_DATE) + INTERVAL '365 days',
              sms_limit = COALESCE(sms_limit, 30)
        WHERE id = $1`,
      [userId]
    );

		  
      }

      // 3) wstaw urządzenie (serial unik.)
      const insD = await client.query(
        `INSERT INTO devices (
           user_id, name, serial_number, eui,
           phone, phone2, tel_do_szambiarza,
           street, abonament_expiry, device_type
         )
         VALUES ($1,$2,$3,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (serial_number) DO NOTHING
         RETURNING *`,
        [
          userId,
          devName,                                             // nazwa urządzenia
          serial,                                              // serial = eui
          normalisePhone(phone),
          phone2 ? normalisePhone(phone2) : null,
          tel_do_szambiarza ? normalisePhone(tel_do_szambiarza) : '',
          originalStreet,
          moment().add(366, 'days').format('YYYY-MM-DD'),
          typeOk
        ]
      );

      if (insD.rowCount === 0) {
        // duplikat seriala
        await client.query('ROLLBACK');
        return res.status(409).send(`Device ${serial} already exists`);
      }

      // 4) zaktualizuj opisy w LNS (ChirpStack itp.)
            // NIE nadpisujemy description w LNS (tam jest numer telefonu)
      const lnsResults = await chirpUpdate(serial, devName || userName || serial, null);
      console.log('✅ LNS results:', JSON.stringify(lnsResults));
      const anyOk = Array.isArray(lnsResults) && lnsResults.some(r => r && r.ok);
      if (!anyOk) {
        await client.query('ROLLBACK');
        return res
          .status(400)
          .json({ message: 'Urządzenie nie znaleziono w żadnym LNS, rejestracja przerwana', lns: lnsResults });
      }

      await client.query('COMMIT');
		      // geokoduj urządzenie w tle (jeśli ma adres)
      geocodeAndUpdateDeviceBySerial(serial).catch(()=>{});

      // 5) komunikacja zewnętrzna TYLKO gdy user NOWY
      if (userCreated) {
        // e-mail powitalny
        const htmlContent = `
<!DOCTYPE html>
 <html lang="pl">
 <head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width,initial-scale=1">
   <meta http-equiv="X-UA-Compatible" content="IE=edge">

  <title>Rejestracja przyjęta – TechioT</title>
   <!-- Preheader (ukryty podgląd w skrzynce) -->
   <style>
     .preheader { display:none !important; visibility:hidden; opacity:0; color:transparent; height:0; width:0; overflow:hidden; mso-hide:all; }
     @media screen and (max-width: 620px) {
       .container { width:100% !important; }
       .p-20 { padding:16px !important; }
       .btn { width:100% !important; display:block !important; }
     }
   </style>
 </head>
 <body style="margin:0; padding:0; background:#f4f4f4; font-family:Arial,Helvetica,sans-serif;">
   <div class="preheader">

    Rejestracja przyjęta – czekaj na potwierdzenie. Hasło wyślemy w kolejnym mailu.
   </div>
 
   <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse;">
     <tr>
       <td align="center" style="padding:24px 12px;">
         <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" class="container" style="width:600px; max-width:600px; background:#ffffff; border-radius:8px; box-shadow:0 0 10px rgba(0,0,0,0.06);">
           <!-- Logo -->
           <tr>
             <td align="center" style="padding:24px;">
               <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg" width="150" height="auto" alt="TechioT" style="display:block; border:0; outline:none; text-decoration:none; max-width:150px;">
             </td>
           </tr>
 
           <!-- Nagłówek -->
           <tr>
             <td style="padding:0 24px 16px 24px; border-bottom:1px solid #eeeeee;">

              <h1 style="margin:0; font-size:22px; line-height:1.3; color:#222;">Dziękujemy za rejestrację</h1>
             </td>
           </tr>
 
           <!-- Treść -->
           <tr>
             <td class="p-20" style="padding:24px;">

              <p style="margin:0 0 12px 0; font-size:16px; color:#444; line-height:1.6;">
                Twoje konto zostało utworzone i <strong>czeka na potwierdzenie przez TechioT</strong>.
                Wkrótce otrzymasz kolejny e-mail z <strong>hasłem do logowania</strong>.
              </p>
 

               

       </td>
     </tr>
   </table>
 </body>
 </html>
`;
        console.log(`✉️  [/admin/create-device-with-user] pending confirmation mail → ${em}`);
        await sendEmail(em, '🕒 Rejestracja przyjęta – TechioT', htmlContent);

        // SMS (opcjonalnie)
        const nrm = normalisePhone(phone);
        if (nrm) {
          console.log(`📱 [/admin/create-device-with-user] welcome SMS → ${nrm}`);
          await sendSMS(nrm, 'Gratulacje! Pakiet 30 SMS aktywowany.');
        }
		          // ➕ WYŚLIJ LINK DO POTWIERDZENIA NA BIURO
        try {
          const token = randomHex(16);
          await db.query(
            `INSERT INTO email_verification_tokens(user_id, token, expires_at)
             VALUES($1,$2, now() + interval '14 days')`,
            [userId, token]
          );
          const url = `${PUBLIC_BASE_URL}/admin/confirm-account?token=${encodeURIComponent(token)}`;
          const htmlAdmin = `
            <div style="font-family:Arial,sans-serif;font-size:15px;color:#333">
              <p>Nowe konto dodane przez panel:</p>
              <p><strong>${em}</strong></p>
              <p>Potwierdź aktywację: <a href="${url}">${url}</a></p>
              <p>(Link wygaśnie za 14 dni)</p>
            </div>`;
          await sendEmail(ADMIN_NOTIFY_EMAIL, '🔗 Potwierdź konto użytkownika – TechioT', htmlAdmin);
          console.log(`✉️  wysłano link potwierdzający do ${ADMIN_NOTIFY_EMAIL}`);
        } catch (ee) { console.warn('⚠️ confirm-mail error:', ee.message); }
      } else {
        console.log('ℹ️  existing user — skipped welcome mail/SMS');
      }

      return res.status(200).json({
        ok: true,
        userCreated,
        message: userCreated
          ? 'Założono nowe konto i dodano urządzenie'
          : 'Dodano urządzenie do istniejącego konta'
      });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('❌ Error in /admin/create-device-with-user:', e);
    return res.status(500).send(e.message || 'server error');
  }
});


// ── /uplink: wymagaj sekretny token w nagłówku Authorization ───────
// Akceptujemy DWIE formy:
//   1) "Authorization: Bearer <TOKEN>"
//   2) "Authorization: <TOKEN>"        ← to możesz wpisać w ChirpStacku
function ensureUplinkBearer(req, res, next) {
  if (!UPLINK_BEARER && !bearerConfig) {
    console.warn('⚠️ Brak UPLINK_BEARER i BEARER_FILE – /uplink zablokowane');
    return res.status(500).send('uplink bearer not configured');
  }

  const ip   = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  const hdr  = (req.headers.authorization || '').trim();
  if (!hdr) {
    console.warn(`[UPLINK] missing Authorization header from ${ip}`);
    return res.status(401).send('Unauthorized');
  }

  let token = hdr;
  if (/^Bearer\s+/i.test(hdr)) token = hdr.replace(/^Bearer\s+/i, '').trim();

  const host = hostFromReq(req);
  if (!isTokenAllowed(host, token)) {
    console.warn(`[UPLINK] bad token from ${ip} host=${host || '-'} `);
    return res.status(401).send('Unauthorized');
  }
  return next();
}


// ── /uplink (z Bearer + normalizacja EUI do UPPERCASE) ─────────────
app.post('/uplink', ensureUplinkBearer, async (req, res) => {
  try {
    // Złap wszystkie popularne warianty z ChirpStacka
const rawDevEui =
  req.body?.deviceInfo?.devEui ??
  req.body?.devEui ??
  req.body?.dev_eui ??
  req.body?.devEUI ?? null;
if (!rawDevEui) return res.status(400).send('dev_eui missing');

// 🔧 Sanitizacja: usuń wszystko poza [0-9a-f] i dopiero potem UPPER
const devEui = String(rawDevEui).replace(/[^0-9a-f]/gi, '').toUpperCase();

//console.log(`[UPLINK] RX EUI raw="${rawDevEui}" → norm="${devEui}"`);
    // 1) pobieramy urządzenie
    const { rows } = await db.query('SELECT * FROM devices WHERE serial_number=$1', [devEui]);
    if (!rows.length) return res.status(404).send('unknown device');

    const dev     = rows[0];
    const type    = (dev.device_type || 'septic').toLowerCase();   // default
    const handler = handlers[type] || handlers.septic;             // fallback

	      // 🔎 zwięzły log kontekstu urządzenia (tylko niepuste pola)
    try { await logDeviceSummary(db, dev); }
    catch (e) { console.warn('[UPLINK][DEV] summary error:', e.message); }

    // 2) delegujemy całą logikę do modułu w handlers/
    await handler.handleUplink(
      { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment,sendSmsWithQuota, consumeSms  },
      dev,
      req.body
    );

    return res.send('OK');
  } catch (e) {
    console.error('uplink error', e);
    return res.status(500).send('uplink error');
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// GET /device/:serial_number/vars – zwraca distance, voltage, ts, empty_cm, empty_ts i procent
// ─────────────────────────────────────────────────────────────────────────────
app.get('/device/:serial_number/vars', auth, consentGuard, async (req, res) => {
  const { serial_number } = req.params;
  const q = `
    SELECT
      (params ->> 'distance')::int      AS distance,
      (params ->> 'voltage')::numeric   AS voltage,
      (params ->> 'snr')::numeric       AS snr,
      params ->> 'ts'                   AS ts,
	  params ->> 'ts_seen'              AS ts_seen,
	  (params ->> 'issue')              AS issue,   -- ← po to aby pokazac   znak zapytania kiedy para
   (params ->> 'issue_ts')           AS issue_ts,
      empty_cm,
      empty_ts,
      CASE
        WHEN empty_cm IS NOT NULL
          THEN ROUND( ( (params->>'distance')::int - empty_cm )::numeric
                      / (0-empty_cm) * 100 )
      END                               AS procent
    FROM devices
    WHERE serial_number = $1
    LIMIT 1`;
  const { rows } = await db.query(q, [serial_number]);
  if (!rows.length) {
    console.log(`⚠️ [GET /device/${serial_number}/vars] Nie znaleziono urządzenia`);
    return res.status(404).send('Device not found');
  }
  res.json(rows[0]);
});

// ─────────────────────────────────────────────────────────────────────────────
// PATCH /device/:serial/params – zapis nowych parametrów (walidacja kluczy)
// ─────────────────────────────────────────────────────────────────────────────
// PATCH /device/:serial/params – zapis nowych parametrów (user)
app.patch('/device/:serial/params', auth, consentGuard, async (req, res) => {
  const { serial } = req.params;
  const body = req.body || {};

  // Ostrzeżenie, jeśli serial wygląda podejrzanie krótko
  if (!serial || String(serial).trim().length < 12) {
    console.warn(`⚠️  [PATCH /device/${serial}/params] Krótki lub pusty serial (user=${req.user.email})`);
  }

  // Dozwolone pola do edycji przez użytkownika
  const allowedFields = new Set([
    'phone',
    'phone2',
    'tel_do_szambiarza',
    'alert_email',
    'red_cm',
    'capacity',
    'street',
    'name',
    'do_not_disturb',
    'sms_limit',
    'sms_after_empty',
    // —— CO only:
    'co_phone1',
    'co_phone2',
	'leak_phone1',
    'leak_phone2',
    'co_threshold_ppm'
  ]);

  // 0) wstępna walidacja kluczy
  const unknown = Object.keys(body).filter(k => !allowedFields.has(k));
  if (unknown.length) {
    console.log(`❌ [PATCH /device/${serial}/params] Niedozwolone pola: ${unknown.join(', ')} (user=${req.user.email})`);
    return res.status(400).send(`Niedozwolone pola: ${unknown.join(', ')}`);
  }

  try {
    // 1) Pobierz stan "przed" (i jednocześnie weryfikuj własność)
    const { rows: beforeRows } = await db.query(
      `SELECT id, user_id, serial_number, device_type, name,
              phone, phone2, tel_do_szambiarza, alert_email,
              red_cm, capacity, street, do_not_disturb, sms_limit, sms_after_empty,
              co_phone1, co_phone2,leak_phone1,leak_phone2, co_threshold_ppm
         FROM devices
        WHERE serial_number = $1 AND user_id = $2
        LIMIT 1`,
      [serial, req.user.id]
    );
    if (!beforeRows.length) {
      console.log(`⚠️  [PATCH /device/${serial}/params] Device not found or not owned by user (${req.user.email})`);
      return res.status(404).send('Device not found or not owned by user');
    }
    const before = beforeRows[0];

    const isSeptic = (before.device_type || '').toLowerCase() === 'septic';
    const isLeak   = (before.device_type || '').toLowerCase() === 'leak';
    const isCO     = (before.device_type || '').toLowerCase() === 'co';

    // pola specyficzne dla typów
    const septicOnly = new Set([
      'phone','phone2','tel_do_szambiarza','red_cm','capacity','sms_after_empty'
    ]);
    const leakOnly = new Set(['leak_phone1','leak_phone2']);
    const coOnly   = new Set(['co_phone1','co_phone2','co_threshold_ppm'])

    // 2) Zbuduj UPDATE z walidacją wartości
    const cols = [];
    const vals = [];
    let i = 1;

    const pushCol = (k, v) => { cols.push(`${k} = $${i++}`); vals.push(v); };

    for (const [k, vRaw] of Object.entries(body)) {
		      // Odrzuć pola niepasujące do typu urządzenia
      if (septicOnly.has(k) && !isSeptic) continue;
      if (leakOnly.has(k)   && !isLeak)   continue;
      if (coOnly.has(k)     && !isCO)     continue;
      // TELEFONY – pozwól wyczyścić: "" lub null → NULL
      if (['phone', 'phone2', 'tel_do_szambiarza', 'co_phone1', 'co_phone2','leak_phone1', 'leak_phone2'].includes(k)) {
        if (vRaw == null || String(vRaw).trim() === '') {
          pushCol(k, null);
          continue;
        }
        if (typeof vRaw !== 'string') {
          return res.status(400).send(`Niepoprawny format dla pola: ${k}`);
        }
        const nv = normalisePhone(vRaw.replace(/\s+/g, ''));
        if (!nv) return res.status(400).send(`Niepoprawny numer telefonu: ${k}`);
        pushCol(k, nv);
        continue;
      }

      // BOOLEANY
      if (k === 'sms_after_empty' || k === 'do_not_disturb') {
        if (typeof vRaw !== 'boolean') return res.status(400).send(`${k} must be boolean`);
        pushCol(k, vRaw);
        continue;
      }

      // LICZBY
      if (k === 'red_cm' || k === 'sms_limit') {
        const num = Number(vRaw);
        if (!Number.isFinite(num) || num < 0) {
          return res.status(400).send(`Niepoprawna wartość dla pola: ${k}`);
        }
        pushCol(k, num);
        continue;
      }

      if (k === 'capacity') {
        const num = Number(vRaw);
        if (!Number.isInteger(num) || num <= 0) {
          return res.status(400).send('capacity must be a positive integer');
        }
        pushCol(k, num);
        continue;
      }

      if (k === 'co_threshold_ppm') {
        const num = Number(vRaw);
        if (!Number.isInteger(num) || num <= 0) {
          return res.status(400).send('co_threshold_ppm must be a positive integer');
        }
        pushCol(k, num);
        continue;
      }

      // E-MAIL – pozwól wyczyścić
      if (k === 'alert_email') {
        if (vRaw == null || String(vRaw).trim() === '') {
          pushCol(k, null);
          continue;
        }
        if (typeof vRaw !== 'string' || !vRaw.includes('@')) {
          return res.status(400).send('Niepoprawny email');
        }
        pushCol(k, vRaw.trim());
        continue;
      }

      // STRINGI (name, street)
      if (k === 'name' || k === 'street') {
        if (vRaw == null) { pushCol(k, null); continue; }
        if (typeof vRaw !== 'string' || vRaw.trim().length === 0) {
          return res.status(400).send(`invalid value for ${k}`);
        }
        pushCol(k, vRaw.trim());
        continue;
      }

      // Bezpieczny fallback – jeżeli coś pominęliśmy w if-ach powyżej:
      pushCol(k, vRaw);
    }

    if (!cols.length) {
      console.log(`❌ [PATCH /device/${serial}/params] Brak danych do aktualizacji (user=${req.user.email})`);
      return res.status(400).send('Brak danych do aktualizacji');
    }

      // 3) Log i UPDATE
    try {
      console.log(
        '[PATCH /device/%s/params] (user=%s) type=%s fields=%j',
        serial,
        req.user.email,
        before.device_type,
        cols.map(c => c.split('=')[0].trim())
      );
    } catch {}
    vals.push(serial, req.user.id);
    const q = `
      UPDATE devices
         SET ${cols.join(', ')}
       WHERE serial_number = $${i++} AND user_id = $${i++}
       RETURNING id, serial_number, device_type, name`;
    const { rows: afterRows } = await db.query(q, vals);

    if (!afterRows.length) {
      console.log(`⚠️  [PATCH /device/${serial}/params] Nic nie zaktualizowano (user=${req.user.email})`);
      return res.status(404).send('Device not found or not owned by user');
    }
    const after = afterRows[0];

    // 4) Logi – czytelne i jednoznaczne
    const changedFields = Object.keys(body).join(', ');
    if ('name' in body) {
      console.log(
        `🛠️  rename ${before.device_type} serial=${before.serial_number} (user=${req.user.email}) ` +
        `"${before.name || ''}" → "${after.name || ''}"; fields=[${changedFields}]`
      );
    } else {
      console.log(
        `✅ [PATCH /device/${serial}/params] user=${req.user.email} ` +
        `type=${before.device_type} serial=${before.serial_number} fields=[${changedFields}]`
      );
    }

        // 5) Jeśli zmieniono adres urządzenia → przelicz geolokację (force)
    if (Object.prototype.hasOwnProperty.call(body, 'street')) {
      geocodeAndUpdateDeviceBySerial(serial, { force: true }).catch(()=>{});
    }
    // Zwróć mały JSON, żeby front mógł odświeżyć nazwę bez dodatkowego GET
    return res.status(200).json({
      id: after.id,
      serial_number: after.serial_number,
      name: after.name
    });
  } catch (err) {
    console.error(`❌ [PATCH /device/${serial}/params] Błąd serwera:`, err);
    return res.status(500).send('Błąd serwera');
  }
});


// ─────────────────────────────────────────────────────────────────────────────
// DOKLEJAMY SMS PAYMENTS → po utworzeniu express() i auth middleware
// ─────────────────────────────────────────────────────────────────────────────
const smsPayments = require('./payments/sms');
smsPayments(app, db, auth);  // rejestruje /sms/orders i /sms/verify


// ─────────────────────────────────────────────────────────────────────────────

// na samym dole, przed app.listen:
app.get('/device/:serial/empties', auth, consentGuard, async (req, res) => {
  const { serial } = req.params;
  // najpierw znajdź device.id
  const { rows: dev } = await db.query(
    'SELECT id FROM devices WHERE serial_number = $1',
    [serial]
  );
  if (!dev.length) return res.status(404).send('Device not found');
  const deviceId = dev[0].id;
  // potem zwróć historię opróżnień
  const { rows } = await db.query(
    `SELECT from_ts, removed_m3
       FROM empties
      WHERE device_id = $1
      ORDER BY from_ts DESC`,
    [deviceId]
  );
  res.json(rows);
});

// ──────────────────────────────────────────────────────────
// POST /consent/accept – zapisuje kliknięcie
// ──────────────────────────────────────────────────────────
app.post('/consent/accept', auth, async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0];
  const ua = req.headers['user-agent'] || '';
  console.log(`[CONSENT] accept ${req.user.email} IP=${ip}`);
  await db.query(
    `INSERT INTO user_consents (user_id, doc_type, version, ip, user_agent)
       VALUES
         ($1,'terms',   $4, $2, $3),
         ($1,'privacy', $5, $2, $3)
     ON CONFLICT DO NOTHING`,
    [
      req.user.id,         // $1
      ip,                  // $2
      ua,                  // $3
      CURRENT_TERMS_VERSION,      // $4
      CURRENT_PRIVACY_VERSION     // $5
    ]
  );
  res.sendStatus(200);
});

// ──────────────────────────────────────────────────────────
// POST /consent/decline – użytkownik odmawia → blokujemy konto
// ──────────────────────────────────────────────────────────
app.post('/consent/decline', auth, async (req, res) => {
  console.log(`[CONSENT] DECLINE ${req.user.email}`);
  await db.query('UPDATE users SET is_active = FALSE WHERE id=$1', [req.user.id]);
  res.sendStatus(200);      // front wyloguje i pokaże info
});


// POST /admin/geocode-device?serial=...
app.post('/admin/geocode-device', auth, adminOnly, async (req, res) => {
  const serial = String(req.query.serial || req.body.serial || '').trim().toUpperCase();
  if (!/^[0-9A-F]{16}$/.test(serial)) return res.status(400).send('serial (16 hex) required');
  const result = await geocodeAndUpdateDeviceBySerial(serial);
  return res.json(result);
});

// POST /admin/geocode-missing — do 50 brakujących na strzał (1 req/s, żeby nie wkurzać OSM)
app.post('/admin/geocode-missing', auth, adminOnly, async (req, res) => {
  const { rows } = await db.query(`
    SELECT serial_number, street
      FROM devices
     WHERE (lat IS NULL OR lon IS NULL)
       AND street IS NOT NULL AND street <> ''
     LIMIT 50`);
  const out = [];
  for (const r of rows) {
    /* eslint-disable no-await-in-loop */
    const one = await geocodeAndUpdateDeviceBySerial(r.serial_number);
    out.push({ serial: r.serial_number, street: r.street, ...one });
    await new Promise(s => setTimeout(s, 1000)); // 1 r/s
  }
  return res.json({ count: out.length, results: out });
});



// ──────────────────────────────────────────────────────────
// GET /admin/confirm-account?token=...  (publiczny link z maila)
// Ustawia users.confirmed=TRUE i wysyła do klienta powiadomienie e-mail.
// ──────────────────────────────────────────────────────────
app.get('/admin/confirm-account', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    if (!token) return res.status(400).send('Token required');

    const { rows } = await db.query(
      `UPDATE users u
          SET confirmed = TRUE
         FROM email_verification_tokens t
        WHERE t.token = $1
          AND t.user_id = u.id
          AND t.used_at IS NULL
          AND t.expires_at > now()
        RETURNING u.id, u.email`, [token]);

    if (!rows.length) return res.status(400).send('Token nieprawidłowy lub wygasł');

    await db.query('UPDATE email_verification_tokens SET used_at = now() WHERE token = $1', [token]).catch(()=>{});

    // ustaw finalne hasło i wyślij do użytkownika
    const userId = rows[0].id;
    const to     = rows[0].email;
    const newPwd  = randomHex(4); // 8 znaków
    const newHash = await bcrypt.hash(newPwd, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, userId]);

      // Pełny HTML z danymi logowania (jak w sekcji 5., ale już z hasłem)
    const htmlU = `
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Konto potwierdzone – TechioT</title>
  <style>
    .preheader { display:none!important; visibility:hidden; opacity:0; color:transparent; height:0; width:0; overflow:hidden; mso-hide:all; }
    @media screen and (max-width:620px){
      .container{width:100%!important}
      .p-24{padding:20px!important}
      .btn-fixed{width:100%!important}
    }
  </style>
</head>
<body style="margin:0; padding:0; background:#f4f4f4; font-family:Arial,Helvetica,sans-serif;">
  <div class="preheader">Konto potwierdzone – w środku Twoje dane do logowania.</div>

  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" class="container" style="width:600px; max-width:600px; background:#ffffff; border-radius:8px; box-shadow:0 0 10px rgba(0,0,0,0.06);">
          <!-- Logo -->
          <tr>
            <td align="center" style="padding:24px;">
              <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg" width="150" alt="TechioT" style="display:block; border:0; outline:none; text-decoration:none; max-width:150px; height:auto;">
            </td>
          </tr>

          <!-- Heading -->
          <tr>
            <td style="padding:0 24px 16px 24px; border-bottom:1px solid #eeeeee;">
              <h1 style="margin:0; font-size:22px; line-height:1.3; color:#222;">Twoje konto zostało potwierdzone</h1>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td class="p-24" style="padding:24px;">
              <p style="margin:0 0 12px 0; font-size:16px; color:#444; line-height:1.6;">
                Poniżej znajdziesz dane do logowania. Zaloguj się w aplikacji TechioT.
              </p>

              <!-- Login box -->
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:16px 0 8px 0; border-collapse:separate; border-spacing:0; background:#f7f7f8; border:1px solid #eee; border-radius:6px;">
                <tr>
                  <td style="padding:12px 14px; font-size:15px; color:#333;">
                    <strong>Login:</strong> ${to}<br>
                    <strong>Hasło:</strong> ${newPwd}
                  </td>
                </tr>
              </table>

              <!-- Oficjalne przyciski pobierania -->
              <div style="text-align:center; margin:28px 0 12px 0;">
                <a href="https://play.google.com/store/apps/details?id=pl.techiot.szambocontrol&utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding" target="_blank" style="display:inline-block; margin:6px;">
                  <img src="https://tracktrace.azureedge.net/google-play.jpg" alt="Pobierz w Google Play" width="160" style="display:block; border:0; max-width:160px; height:auto;">
                </a>
                <a href="https://apple-szambo-control.techiot.pl/?utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding" target="_blank" style="display:inline-block; margin:6px;">
                  <img src="https://tracktrace.azureedge.net/app-store.jpg" alt="Pobierz w App Store" width="160" style="display:block; border:0; max-width:160px; height:auto;">
                </a>
              </div>

              <!-- Prawne zastrzeżenia znaków towarowych -->
              <p style="margin:14px 0 0 0; font-size:11px; color:#888; line-height:1.5; text-align:center;">
                Google Play i logo Google Play są znakami towarowymi Google LLC.<br>
                Apple oraz logo Apple są znakami towarowymi Apple Inc., zarejestrowanymi w USA i innych krajach.<br>
                App Store jest znakiem usługowym Apple Inc.
              </p>

              <!-- Fallback links -->
              <p style="margin:14px 0 0 0; font-size:13px; color:#777; line-height:1.6;">
                Jeśli przyciski nie działają, skopiuj i wklej w przeglądarce:
                <br>
                Android: <span style="word-break:break-all;">https://play.google.com/store/apps/details?id=pl.techiot.szambocontrol</span><br>
                iPhone/iPad: <span style="word-break:break-all;">https://apple-szambo-control.techiot.pl/</span>
              </p>

              <!-- Note -->
              <p style="margin:28px 0 0 0; color:#9a9a9a; font-size:12px; line-height:1.5;">
                Ten e-mail został wygenerowany automatycznie. Prosimy na niego nie odpowiadać.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td align="center" style="padding:16px 24px; background:#fafafa; border-top:1px solid #eeeeee;">
              <p style="margin:0; font-size:14px; color:#666;">Zespół <strong>TechioT</strong></p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`;
    try { await sendEmail(to, '✅ Konto potwierdzone – TechioT', htmlU); } catch {}
    return res.status(200).send('Konto potwierdzone. Użytkownik otrzymał e-mail z hasłem.');
  } catch (e) { console.error('confirm-account error', e); return res.status(500).send('server error'); }
});

app.listen(PORT, () => console.log(`Elegancko, dziala.  ${PORT}`));

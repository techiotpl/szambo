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

// ───────────────  REKLAMY (/ads)  ───────────────
registerAdsRoute(app);


const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';

app.use(cors());
app.use(bodyParser.json());

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
// DATABASE (migration i inicjalizacja poola)
// ─────────────────────────────────────────────────────────────────────────────


const MIGRATION = String.raw`
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

--────────────────────────  USERS  ────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'client',
  name TEXT,
  company TEXT,
  street TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
-- gdy skrypt był już odpalony wcześniej i kolumny nie ma:
ALTER TABLE users ADD COLUMN IF NOT EXISTS street TEXT;

--────────────────────────  DEVICES  ──────────────────────
CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  name TEXT,
  serial_number TEXT UNIQUE NOT NULL,
  eui TEXT,
  phone TEXT,
  phone2 TEXT,
  tel_do_szambiarza TEXT,
  street TEXT,
  _limit INT  DEFAULT 30,
  red_cm   INT  DEFAULT 30,
  empty_cm INT  DEFAULT 150,
  capacity INT  DEFAULT 8,
  empty_ts TIMESTAMPTZ,
  distance_cm INT,
  trigger_dist BOOLEAN DEFAULT false,
  params JSONB  DEFAULT '{}' ,
  abonament_expiry DATE,
  alert_email TEXT,
  last_removed_m3 NUMERIC(6,2),        -- ← nowa kolumna
  created_at TIMESTAMPTZ DEFAULT now()
);

--────────────────────────  _ORDERS  ───────────────────
CREATE TABLE IF NOT EXISTS _orders (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id     UUID REFERENCES devices(id) ON DELETE CASCADE,
  serial_number TEXT NOT NULL,
  amount        NUMERIC(10,2) NOT NULL DEFAULT 50.00,
  status        TEXT NOT NULL DEFAULT 'new',
  redirect_url  TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  paid_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx__orders_serial
  ON _orders(serial_number);

--────────────────────────  EMPTIES  ──────────────────────
CREATE TABLE IF NOT EXISTS empties (
  id            BIGSERIAL PRIMARY KEY,
  device_id     UUID REFERENCES devices(id) ON DELETE CASCADE,
  prev_cm       INT      NOT NULL,
  empty_cm      INT      NOT NULL,
  removed_m3    NUMERIC(6,2) NOT NULL,
  from_ts       TIMESTAMPTZ,
  to_ts         TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS last_removed_m3 NUMERIC(6,2);

  -- zabezpieczenie triggerem zamiast CHECK z subquery
  CREATE OR REPLACE FUNCTION check_removed_le_capacity()
  RETURNS TRIGGER AS $$
  DECLARE cap INT;
  BEGIN
    SELECT capacity INTO cap FROM devices WHERE id = NEW.device_id LIMIT 1;
    IF NEW.removed_m3 > cap THEN
      RAISE EXCEPTION 'removed_m3 (%) exceeds capacity (%)', NEW.removed_m3, cap;
    END IF;
    RETURN NEW;
  END;
  $$ LANGUAGE plpgsql;

  DROP TRIGGER IF EXISTS trg_check_removed_capacity ON empties;
  CREATE TRIGGER trg_check_removed_capacity
    BEFORE INSERT OR UPDATE ON empties
    FOR EACH ROW
    EXECUTE FUNCTION check_removed_le_capacity();


--────────────────────────  TRIGGER _ORDER  ────────────
CREATE OR REPLACE FUNCTION _order_after_paid() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'paid' AND OLD.status <> 'paid' THEN
    UPDATE devices
      SET _limit        = 30,
          abonament_expiry = COALESCE( abonament_expiry, CURRENT_DATE )
                             + INTERVAL '365 days'
    WHERE id = NEW.device_id;
    NEW.paid_at := now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg__order_after_paid ON _orders;
CREATE TRIGGER trg__order_after_paid
  AFTER UPDATE ON _orders
  FOR EACH ROW
  EXECUTE FUNCTION _order_after_paid();
`; 


const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,                 // trochę mniejszy limit połączeń
  idleTimeoutMillis: 30_000
});

// ► Migracja odpalana **tylko**, gdy RUN_MIGRATION=true
if (process.env.RUN_MIGRATION === 'true') {
  (async () => {
    const client = await db.connect();
    try {
      // unikamy wyścigu o DDL: jedna instancja dostaje lock - reszta czeka
      const { rows: [{ ok }] } =
        await client.query('SELECT pg_try_advisory_lock(42) AS ok');
      if (!ok) {
        console.log('⏩ Inna instancja trzyma lock – pomijam migrację');
        return;
      }

      await client.query('BEGIN');
      await client.query(MIGRATION);
      await client.query('COMMIT');
      console.log('✅ Migration executed.');
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('❌ Migration error:', e);
      process.exit(1);      // nie startuj web-serwera, jeśli DDL się wywalił
    } finally {
      client.release();
    }
  })();
}



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
    SELECT u.id, u.email, u.name,
           json_agg(d.*) AS devices
      FROM users u
      LEFT JOIN devices d ON d.user_id = u.id
     GROUP BY u.id`;
  const { rows } = await db.query(q);
  res.json(rows);
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
  console.log(`ℹ️ Aktywnych klientów SSE: ${clients.length}`);
}

/**
 * Wysyła zdarzenie SSE do wszystkich podłączonych klientów.
 * `payload` to dowolny JS‐owy obiekt, np. { serial, distance, voltage, ts }.
 */
function sendEvent(payload) {
  pruneClients();

  if (clients.length === 0) {
    console.log('ℹ️ Brak podłączonych klientów SSE – pomijam wysyłkę');
    return;
  }

  const dataAsJson = JSON.stringify(payload);
  const msg = [
    'event: uplink',
    `data: ${dataAsJson}`,
    '',
    ''
  ].join('\n');

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
  console.log('➕ Nowy klient SSE podłączony, wszystkich:', clients.length);

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
    SELECT phone, phone2, tel_do_szambiarza, capacity ,alert_email,
           red_cm, sms_limit,do_not_disturb,
           empty_cm, empty_ts, abonament_expiry,street,sms_after_empty
      FROM devices
     WHERE serial_number = $1`;
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

// ─────────────────────────────────────────────────────────────────────────────
// PATCH /admin/device/:serial/params – zapis nowych parametrów (walidacja kluczy)
// Ten endpoint dostępny tylko dla admina (adminOnly).
// ─────────────────────────────────────────────────────────────────────────────
app.patch('/admin/device/:serial/params', auth, adminOnly, async (req, res) => {
  const { serial } = req.params;
  const body = req.body;
  const allowedFields = new Set([
    'phone',
    'phone2',
    'tel_do_szambiarza',
    'street',
    'red_cm',
    'serial_number',
    'capacity',
    'abonament_expiry',
    'sms_limit',
    'alert_email',
    'trigger_dist',
    'sms_after_empty'
  ]);
  const cols = [];
  const vals = [];
  let i = 1;
  for (const [k, v] of Object.entries(body)) {
    if (!allowedFields.has(k)) {
      console.log(`❌ [PATCH /admin/device/${serial}/params] Niedozwolone pole: ${k}`);
      return res.status(400).send(`Niedozwolone pole: ${k}`);
    }
    if ((k === 'phone' || k === 'phone2' || k === 'tel_do_szambiarza') && typeof v !== 'string') {
      return res.status(400).send(`Niepoprawny format dla pola: ${k}`);
    }
    if (k === 'red_cm' || k === 'sms_limit') {
      const num = Number(v);
      if (Number.isNaN(num) || num < 0) {
        return res.status(400).send(`Niepoprawna wartość dla pola: ${k}`);
      }
      
    }
    if (k === 'alert_email' && (typeof v !== 'string' || !v.includes('@'))) {
      return res.status(400).send('Niepoprawny email');
    }
    if (k === 'trigger_dist') {
      if (typeof v !== 'boolean') {
        return res.status(400).send(`Niepoprawna wartość dla pola: trigger_dist`);
      
      }
          }
    if (k === 'sms_after_empty') {
      if (typeof v !== 'boolean') {
        return res.status(400).send('sms_after_empty must be boolean');
      }
    }
    cols.push(`${k} = $${i++}`);
    vals.push(v);
  }
  if (!cols.length) {
    console.log(`❌ [PATCH /admin/device/${serial}/params] Brak danych do zaktualizowania`);
    return res.status(400).send('Brak danych do aktualizacji');
  }
  vals.push(serial);
  const q = `UPDATE devices SET ${cols.join(', ')} WHERE serial_number = $${i}`;
  try {
    await db.query(q, vals);
    console.log(`✅ [PATCH /admin/device/${serial}/params] Zaktualizowano: ${JSON.stringify(body)}`);
    return res.sendStatus(200);
  } catch (err) {
    console.error(`❌ [PATCH /admin/device/${serial}/params] Błąd bazy:`, err);
    return res.status(500).send('Błąd serwera');
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
// POST /admin/create-user — tworzenie użytkownika (wymaga auth+adminOnly)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-user', auth, adminOnly, async (req, res) => {
  const { email, password, role='client', name='', company='' } = req.body;
  console.log(`➕ [POST /admin/create-user] Tworzę usera: ${email}`);
  const hash = await bcrypt.hash(password, 10);
  await db.query(
    'INSERT INTO users(email,password_hash,role,name,company) VALUES($1,$2,$3,$4,$5)',
    [email.toLowerCase(), hash, role, name, company]
  );
  console.log(`✅ [POST /admin/create-user] Użytkownik ${email} utworzony.`);
  res.send('User created');
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

  for (const [k, v] of Object.entries(req.body || {})) {
    if (!allowed.has(k)) {
      return res.status(400).send(`field ${k} not allowed`);
    }
    if (typeof v !== 'string' || v.trim().length === 0) {
      return res.status(400).send(`invalid value for ${k}`);
    }
    cols.push(`${k} = $${i++}`);
    vals.push(v.trim());
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
    res.sendStatus(200);
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
  res.json(rows);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /device/:id/phone — zmiana numeru telefonu (wymaga auth)
// ─────────────────────────────────────────────────────────────────────────────
app.put('/device/:id/phone', auth, consentGuard, async (req, res) => {
  const phone = normalisePhone(req.body.phone);
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

// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/create-device-with-user — tworzenie użytkownika + urządzenia
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-device-with-user', auth, adminOnly, async (req, res) => {
  try {
    const { serie_number, email, name='', phone='0', street='N/A', company='' } = req.body;
    console.log(`➕ [POST /admin/create-device-with-user] Dodaję device ${serie_number} dla ${email}`);
    if (!serie_number || !email) return res.status(400).send('serie_number & email required');

    // create/find user
    const basePwd = email.split('@')[0] + Math.floor(Math.random() * 90 + 10) + '!';
    const { rows: uRows } = await db.query(
      'INSERT INTO users(email,password_hash,name,company) VALUES ($1,$2,$3,$4) ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email RETURNING id',
      [email.toLowerCase(), await bcrypt.hash(basePwd, 10), name, company]
    );
    const userId = uRows[0].id;

    // otwieramy transakcję
    const client = await db.connect();
    let dRows;
    try {
      await client.query('BEGIN');

      // create device
      const { rows } = await client.query(
      `INSERT INTO devices (user_id,name,serial_number,eui,phone,street,abonament_expiry)
       VALUES ($1,$2,$3,$3,$4,$5,$6)
       ON CONFLICT (serial_number) DO NOTHING
       RETURNING *`,
      [
        userId,
        name.trim(),                    // ← zapisujemy dokładnie to, co podasz, lub '' jeśli puste
        serie_number,
        normalisePhone(phone),
        removePolishLetters(street),
        moment().add(366, 'days').format('YYYY-MM-DD')
      ]
    );
      dRows = rows;

      // ► aktualizacja na wszystkich zdefiniowanych LNS-ach
      const lnsResults = await chirpUpdate(serie_number, name, street);
      const ok = lnsResults.some(r => r.ok);
      console.log('✅ LNS results:', JSON.stringify(lnsResults));

      // jeżeli w żadnym LNS-ie nie znaleziono urządzenia → rollback i abort
      if (!ok) {
        await client.query('ROLLBACK');
        return res
          .status(400)
          .json({ message: 'Urządzenie nie znaleziono w żadnym LNS, rejestracja przerwana', lns: lnsResults });
      }

      // commitujemy dopiero gdy LNS OK
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      client.release();
      throw err;
    }
    client.release();

// 1) Przygotuj pełny szablon HTML
const htmlContent = `
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Twoje konto TechioT</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
  <table role="presentation" style="width:100%; border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:20px 0;">
        <table role="presentation" style="width:600px; border-collapse:collapse;
              background-color:#ffffff; box-shadow:0 0 10px rgba(0,0,0,0.1);">
          <tr>
            <td align="center" style="padding:20px;">
              <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg"
                   alt="TechioT Logo" style="max-width:150px; height:auto;">
            </td>
          </tr>
          <tr>
            <td style="padding:0 20px; border-bottom:1px solid #eeeeee;">
              <h2 style="color:#333333; font-size:24px; margin:0;">
                Witamy w TechioT
              </h2>
            </td>
          </tr>
          <tr>
            <td style="padding:20px;">
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Twoje konto zostało pomyślnie utworzone, a urządzenie dodane do systemu.
              </p>
              <table role="presentation" style="width:100%; margin:20px 0; border-collapse:collapse;">
                <tr>
                  <td style="padding:10px; background-color:#f0f0f0; border-radius:5px;">
                    <strong>Login:</strong> ${email}<br>
                    <strong>Hasło:</strong> ${basePwd}
                  </td>
                </tr>
              </table>
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                <strong>Pobierz lub otwórz aplikację TechioT:</strong><br>
                <a href="intent://openApp#Intent;scheme=techiot;package=pl.techiot.szambocontrol;S.browser_fallback_url=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dpl.techiot.szambocontrol;end"
                   style="color:#1a73e8; text-decoration:none; font-size:16px;">
                  Uruchom aplikację Szambo Control
                </a>
              </p>
              <p style="color:#999999; font-size:12px; line-height:1.4; margin-top:30px;">
                Ten e-mail został wygenerowany automatycznie, prosimy na niego nie odpowiadać.
              </p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:10px 20px; background-color:#fafafa;">
              <p style="color:#777777; font-size:14px; margin:0;">
                Zespół <strong>TechioT</strong>
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

// 2) Wyślij e-mail z użyciem nowego szablonu


    console.log(`✉️ [POST /admin/create-device-with-user] Wysyłam maila z danymi do ${email}`);
    await sendEmail(
      email.toLowerCase(),
      '✅ Konto TechioT',
      htmlContent
    );

    if (normalisePhone(phone)) {
      console.log(`📱 [POST /admin/create-device-with-user] Wysyłam SMS do ${phone}`);
      await sendSMS(normalisePhone(phone), 'Gratulacje! Pakiet 30 SMS aktywowany.');
    }

    // wszystko ok → zwracamy 200
    return res.status(200).json({ user_id: userId, device: dRows[0] });
  } catch (e) {
    console.error('❌ Error in /admin/create-device-with-user:', e);
    res.status(500).send(e.message);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// /uplink: odbiór pomiaru z ChirpStack → zapis do bazy + e-mail/SMS + SSE
// ─────────────────────────────────────────────────────────────────────────────
app.post('/uplink', async (req, res) => {
  try {
    /* 1) devEUI ---------------------------------------------------------- */
    const devEui = req.body.dev_eui
                 || req.body.devEUI
                 || req.body.deviceInfo?.devEui;
    if (!devEui) {
      console.log('🚫 [POST /uplink] Brak dev_eui w body');
      return res.status(400).send('dev_eui missing');
    }

/* 2) urządzenie w bazie --------------------------------------------- */
const dev = await db.query(
  `SELECT 
     id,
     distance_cm,        -- poprzedni pomiar [cm]
     empty_cm,           -- poziom „pustego” z params
     capacity,           -- objętość zbiornika [m³]
     phone, 
     phone2, 
     tel_do_szambiarza, 
     street,
     red_cm, 
     trigger_dist AS old_flag, 
     do_not_disturb,
     sms_limit,
     sms_after_empty,
     alert_email
   FROM devices
  WHERE serial_number = $1`,
  [devEui]
);

    if (!dev.rowCount) {
      console.log(`⚠️ [POST /uplink] Nieznane urządzenie: ${devEui}`);
      return res.status(404).send('Unknown device');
    }



    const d = dev.rows[0];
    /* 3) payload --------------------------------------------------------- */
    
    const obj      = req.body.object || {};

    /*────────────────  ISSUE‑ONLY payload  ──────────────────
      Uplink:
        "object": { "issue": 1 }
      → log, SMS (jeśli jest numer i sms_limit > 0) + decrement,
        inaczej fallback na e‑mail. Emitujemy też SSE.
    */
    if (Object.keys(obj).length === 1 && (obj.issue === 1 || obj.issue === '1')) {
      const iso = new Date().toISOString();
      const msg = ' czujnik zabrudzony, twoj kolejny pomiar moze byc falszywy – sprawdz czujnik';
      const limit = Number(d.sms_limit) || 0;

      console.warn(
        `🚨 ISSUE(1) flag received from ${devEui} (${iso}) phone=${d.phone || '-'} sms_limit=${limit}`
      );

      let smsSent = false;
      if (d.phone && limit > 0) {
        const num = normalisePhone(d.phone);
        if (num) {
          try {
            await sendSMS(num, msg, 'issue');
            smsSent = true;
            const { rows: [lim] } = await db.query(
              'UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1 RETURNING sms_limit',
              [d.id]
            );
            console.log(`📤 issue:1 → SMS sent to ${num}, new sms_limit=${lim.sms_limit}`);
          } catch (e) {
            console.error('❌ issue:1 SMS send error:', e);
          }
        } else {
          console.warn('⚠️ issue:1 → phone present but could not normalize');
        }
      } else {
        console.log(`ℹ️ issue:1 → SMS skipped (no phone or sms_limit=${limit})`);
      }

      if (!smsSent) {
        if (d.alert_email) {
          try {
            await sendEmail(
              d.alert_email,
              '🚨 Czujnik zabrudzony',
              `<p>${msg}</p>`
            );
            console.log(`✉️ issue:1 → email sent to ${d.alert_email}`);
          } catch (e) {
            console.error('❌ issue:1 e-mail send error:', e);
          }
        } else {
          console.warn('⚠️ issue:1 → no SMS and no alert_email – nothing sent');
        }
      }
      // dodatkowo: powiadomienie wewnętrzne
      try {
        await sendEmail(
          'biuro@techiot.pl',
          `ISSUE(1) – możliwy problem z czujnikiem ${devEui}`,
          `<p>Możliwy problem z czujnikiem o numerze seryjnym <b>${devEui}</b> (issue=1).<br/>Czas: ${iso}</p>`
        );
        console.log('✉️ issue:1 → email sent to biuro@techiot.pl');
      } catch (e) {
        console.error('❌ issue:1 internal email error:', e);
      }
      sendEvent({ serial: devEui, issue: 1, ts: iso });
      return res.send('OK (issue=1)');
    }

    const distance = obj.distance ?? null;  // cm
    const voltage  = obj.voltage  ?? null;  // V
    /* 3a) radio parameters ---------------------------------------------- */
const snr = req.body.rxInfo?.[0]?.snr ?? null;   // Helium-ChirpStack v4
      /* 3b) DND – blokujemy wysyłkę 23:00-6:00 */
    const hour = moment().tz('Europe/Warsaw').hour();     // lokalna godzina
    const dnd  = d.do_not_disturb === true || d.do_not_disturb === 't';
    if (dnd && (hour >= 23 || hour < 6)) {               // 6 = godzina testowa
      console.log(`🔕 [POST /uplink] DND active, skipping alerts for ${devEui}`);
    
  if (distance !== null) {                      // ✔︎ zapisuj tylko gdy jest pomiar
    await db.query(
      'INSERT INTO measurements (device_serial, distance_cm, snr) VALUES ($1,$2,$3)',
      [devEui, distance, snr]
   );
  }
      sendEvent({ serial: devEui, distance, voltage, snr, ts: new Date().toISOString() });
      return res.send('OK (DND)');
    }
    if (distance === null) {
      console.log(`ℹ️ [POST /uplink] Brak distance dla ${devEui}, pomijam`);
      return res.send('noop (no distance)');
    }
/* >>> TU DODAJ NOWĄ LINIKĘ – zapisujemy odczyt do measurements <<< */
await db.query(
  'INSERT INTO measurements (device_serial, distance_cm, snr) VALUES ($1,$2,$3)',
  [devEui, distance, snr]
);

    // dodajemy znacznik czasu ISO-8601
    const varsToSave = {
      distance,
      snr,
      voltage,
      ts: new Date().toISOString()
    };

    /* 4) zapis + obliczenie nowej flagi ---------------------------------- */
    const q = `
      UPDATE devices
         SET params       = coalesce(params,'{}'::jsonb) || $3::jsonb,
             distance_cm  = $2::int,
             last_measurement_ts   = now(),
             trigger_measurement   = FALSE,
             trigger_dist = CASE
                              WHEN $2::int <= red_cm THEN TRUE
                              WHEN $2::int >= red_cm THEN FALSE
                              ELSE trigger_dist
                            END
       WHERE id = $1
       RETURNING 
         trigger_dist AS new_flag, 
         red_cm, 
         sms_limit,
         phone, 
         phone2, 
         tel_do_szambiarza, 
         do_not_disturb,
         street,
         stale_alert_sent,
         alert_email`;
    const { rows: [row] } = await db.query(q, [d.id, distance, JSON.stringify(varsToSave)]);

    // --- jeśli czujnik znowu wysłał pomiar – kasujemy znacznik „72 h alert wysłany”
    if (row.stale_alert_sent) {
      await db.query(
        'UPDATE devices SET stale_alert_sent = FALSE WHERE id = $1',
        [d.id]
      );
      console.log(`🔄  Flaga stale_alert_sent wyzerowana dla ${devEui}`);
    }

/* 4a) zapis empty_* przy opróżnieniu + log do empties + update last_removed_m3 */
if (d.old_flag && !row.new_flag) {
  console.log(`⚡ [POST /uplink] Detekcja opróżnienia dla ${devEui}`);

  // 1) zaktualizuj devices.empty_cm oraz empty_ts
  await db.query(
    'UPDATE devices SET empty_cm = $1, empty_ts = now() WHERE id = $2',
    [distance, d.id]
  );

  // 2) oblicz ile m³ zostało opróżnione:
  //    removed_m3 = capacity * (1 - (prev_cm / empty_cm))
  const prevCm = d.distance_cm;
  const emptyCm = distance;         // <-- TU bierzesz nowy odczyt
  const cap     = d.capacity;
  const removed = emptyCm > 0
    ? +(cap * (1 - (prevCm / emptyCm))).toFixed(2)
    : 0;

  // 3) wstaw wpis do tabeli empties
  await db.query(
    `INSERT INTO empties 
       (device_id, prev_cm, empty_cm, removed_m3, from_ts) 
     VALUES ($1,$2,$3,$4, now())`,
    [d.id, prevCm, distance, removed]
  );

  // 4) zapisz ostatnie opróżnienie w devices.last_removed_m3
  await db.query(
    'UPDATE devices SET last_removed_m3 = $1 WHERE id = $2',
    [removed, d.id]
  );
    /* 5) jednorazowy SMS „opróżniono” ---------------------------------- */
  if (d.sms_after_empty && d.sms_limit > 0 && d.phone) {
    const num = normalisePhone(d.phone);
    if (num) {
     try {
        await sendSMS(num, '✅ Zbiornik opróżniony,  nie dłuzej niż 4h temu.', 'after_empty');
        await db.query(
          'UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1',
          [d.id]
        );
        console.log(`📤 SMS po opróżnieniu wysłany do ${num}`);
      } catch (e) {
        console.error('❌ SMS po opróżnieniu – błąd:', e);
      }
    }
  }


  console.log(`   → empties log: prev=${prevCm}cm, now=${distance}cm, removed=${removed}m³`);
}


    /* 4b) logowanie wartości ------------------------------------------------ */
    const ref = row.red_cm;  // próg alarmu
    const pct = Math.round(((distance - ref) / -ref) * 100);
    console.log(
      `🚀 Saved uplink ${devEui}: ${distance} cm (≈${pct}%); red=${ref}; flag ${d.old_flag}→${row.new_flag}`
    );

    /* 5) ALARM SMS + ALARM E-MAIL (po przekroczeniu progu) ---------------- */
    if (!d.old_flag && row.new_flag) {
      console.log(`📲 [POST /uplink] Próg przekroczony dla ${devEui} → wysyłam alerty`);

      // 5a) SMS na phone i phone2 (jeśli istnieją i jeśli sms_limit > 0)
      const toNumbers = [];
      if (row.phone) {
        const p = normalisePhone(row.phone);
        if (p) toNumbers.push(p);
      }
      if (row.phone2) {
        const p2 = normalisePhone(row.phone2);
        if (p2) toNumbers.push(p2);
      }
      // Czy w tym samym uplinku mamy także issue:1?
      const issueInPayload = (obj.issue === 1 || obj.issue === '1');
      if (toNumbers.length && row.sms_limit > 0) {
        // Treść SMS zależna od obecności issue:1 oraz tego, czy mamy tel_do_szambiarza
        let msg;
        if (issueInPayload) {
          if (!row.tel_do_szambiarza) {
            msg = `Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm - TEN POMIAR PRAWDOPODOBNIE JEST NIE WŁASCIWY - SPRAWDZ CZUJNIK`;
          } else {
            msg = `Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm - TEN POMIAR PRAWDOPODOBNIE JEST NIE WŁASCIWY,SMS DO FIRMY ASENIZACYJNEJ NIE ZOSTAŁ WYSŁANY`;
          }
        } else {
          msg = `⚠️ Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm`;
        }
        console.log(`📲 [POST /uplink] Wysyłam SMS na: ${toNumbers.join(', ')}`);
        let usedSms = 0;
        for (const num of toNumbers) {
          if (row.sms_limit - usedSms <= 0) break; // nie ma już limitu
          try {
            await sendSMS(num, msg, 'threshold');
            usedSms++;
          } catch (smsErr) {
            console.error(`❌ Błąd przy wysyłaniu SMS do ${num}:`, smsErr);
          }
        }
        row.sms_limit -= usedSms;
      } else {
        console.log(`⚠️ [POST /uplink] sms_limit=0 lub brak numerów, pomijam SMS`);
      }

      // 5b) SMS dla szambiarza (jeśli istnieje i jeśli sms_limit > 0)
      //     Gdy issue:1 jest w tym samym uplinku → NIE wysyłamy do szambiarza.
      if (issueInPayload && row.tel_do_szambiarza) {
        console.log(`⏭️ [POST /uplink] Pomijam SMS do szambiarza (issue:1 w tym samym uplinku).`);
      } else if (row.tel_do_szambiarza && row.sms_limit > 0) {
        const szam = normalisePhone(row.tel_do_szambiarza);
        if (szam) {
          const msg2 = `${row.street || '(brak adresu)'} – zbiornik pełny. Prosze o oproznienie. Tel: ${toNumbers[0] || 'brak'}`;
          try {
            console.log(`📲 [POST /uplink] Wysyłam SMS do szambiarza: ${szam}`);
            await sendSMS(szam, msg2, 'szambiarz');
            row.sms_limit--;
          } catch (smsErr) {
            console.error(`❌ Błąd przy wysyłaniu SMS do szambiarza (${szam}):`, smsErr);
          }
        }
      }

      // 5c) Zaktualizuj pozostały sms_limit
      await db.query('UPDATE devices SET sms_limit=$1 WHERE id=$2', [row.sms_limit, d.id]);
      console.log(`📉 [POST /uplink] Zaktualizowano sms_limit → ${row.sms_limit}`);

      // 5d) WYŚLIJ e-mail, jeśli alert_email jest ustawione
      if (row.alert_email) {
        const mailTo = row.alert_email;
        const subj   = `⚠️ Poziom ${distance} cm przekroczył próg na ${devEui}`;
        const html   = `
      <!-- 3. Alert wysokiego poziomu cieczy (/uplink) -->
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Alert: Wysoki poziom cieczy</title>
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
              <h2 style="color:#c62828; font-size:24px; margin:0;">
                ⚠️ Poziom cieczy przekroczył próg!
              </h2>
            </td>
          </tr>
          <tr>
            <td style="padding:20px;">
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Poziom cieczy <strong>${distance} cm</strong>,
                przekraczył ustawiony próg alarmowy <strong>${row.red_cm} cm</strong>.
              </p>
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Prosimy o pilne opróżnienie zbiornika.
              </p>
              <p style="color:#999999; font-size:12px; line-height:1.4; margin-top:30px;">
                Ta wiadomość została wysłana automatycznie, prosimy na nią nie odpowiadać.
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
        console.log(`✉️ [POST /uplink] Wysyłam e-mail na: ${mailTo}`);
        try {
          await sendEmail(mailTo, subj, html);
        } catch (emailErr) {
          console.error(`❌ Błąd przy wysyłaniu e-maila do ${mailTo}:`, emailErr);
        }
      } else {
        console.log(`⚠️ [POST /uplink] alert_email nie jest ustawione, pomijam e-mail`);
      }
    }

    /** ◾️ TU wypychamy SSE do wszystkich podłączonych: */
    sendEvent({
      serial: devEui,
      distance,
      voltage,
      snr,
      ts: varsToSave.ts
    });

    return res.send('OK');
  } catch (err) {
    console.error('❌ Error in /uplink:', err);
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
app.patch('/device/:serial/params', auth, consentGuard, async (req, res) => {
  const { serial } = req.params;
  const body = req.body; // np. { phone: "...", red_cm: 40, alert_email: "...", ... }
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
    'sms_after_empty'
  ]);
  const cols = [];
  const vals = [];
  let i = 1;
  for (const [k, v] of Object.entries(body)) {
    if (!allowedFields.has(k)) {
      console.log(`❌ [PATCH /device/${serial}/params] Niedozwolone pole: ${k}`);
      return res.status(400).send(`Niedozwolone pole: ${k}`);
    }
    if ((k === 'phone' || k === 'phone2' || k === 'tel_do_szambiarza') && typeof v !== 'string') {
      return res.status(400).send(`Niepoprawny format dla pola: ${k}`);
    }
        if (k === 'sms_after_empty' && typeof v !== 'boolean') {
      return res.status(400).send('sms_after_empty must be boolean');
    }
    if (k === 'red_cm' || k === 'sms_limit') {
      const num = Number(v);
      if (Number.isNaN(num) || num < 0) {
        return res.status(400).send(`Niepoprawna wartość dla pola: ${k}`);
      }
    }
    cols.push(`${k} = $${i++}`);
    vals.push(v);
  }
  if (!cols.length) {
    console.log(`❌ [PATCH /device/${serial}/params] Brak danych do zaktualizowania`);
    return res.status(400).send('Brak danych do aktualizacji');
  }
  vals.push(serial);
  const q = `UPDATE devices SET ${cols.join(', ')} WHERE serial_number = $${i}`;
  try {
    await db.query(q, vals);
    console.log(`✅ [PATCH /device/${serial}/params] Zaktualizowano: ${JSON.stringify(body)}`);
    return res.sendStatus(200);
  } catch (err) {
    console.error(`❌ [PATCH /device/${serial}/params] Błąd bazy:`, err);
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

app.listen(PORT, () => console.log(`TechioT backend listening on ${PORT}`));

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
-- pole potwierdzenia konta (e-maila)
ALTER TABLE users ADD COLUMN IF NOT EXISTS confirmed BOOLEAN;
-- istniejących nie blokujemy: jeśli NULL → TRUE
UPDATE users SET confirmed = TRUE WHERE confirmed IS NULL;
-- domyślnie FALSE dla nowych rekordów (po powyższym uzupełnieniu)
ALTER TABLE users ALTER COLUMN confirmed SET DEFAULT FALSE;

-- tokeny do potwierdzania konta (klikane z maila admina)
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  token      TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evt_token ON email_verification_tokens(token);


-- watchdog / stale alerts  --- zeby nie spamowało  po 48h
ALTER TABLE devices ADD COLUMN IF NOT EXISTS stale_alert_sent BOOLEAN DEFAULT FALSE;



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
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS confirmed BOOLEAN DEFAULT FALSE;

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
  
  --────────────────────────  UZUPEŁNIENIA SCHEMATU  ──────────────────────

-- 1) devices – brakujące kolumny używane przez serwer
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type       TEXT        DEFAULT 'septic';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS sms_limit         INT         DEFAULT 30;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS do_not_disturb    BOOLEAN     DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS sms_after_empty   BOOLEAN     DEFAULT FALSE;

-- LEAK (czujnik zalania)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_phone1            TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_phone2            TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_status            BOOLEAN     DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_last_change_ts    TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_last_alert_ts     TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS leak_last_uplink_ts    TIMESTAMPTZ;




-- CO (czujnik czadu)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_phone1         TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_phone2         TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_threshold_ppm  INT         DEFAULT 50;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_status         BOOLEAN     DEFAULT FALSE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_ppm            INT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_last_change_ts TIMESTAMPTZ;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_last_alert_ts  TIMESTAMPTZ;
-- CO (dopisz brakujący timestamp ostatniego uplinku)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS co_last_uplink_ts      TIMESTAMPTZ;

-- bateryjka (wspólna)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS battery_v         NUMERIC(5,2);

-- 2) users – pola używane w kodzie
ALTER TABLE users   ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- 3) measurements – jeśli brak
CREATE TABLE IF NOT EXISTS measurements (
  device_serial TEXT NOT NULL,
  distance_cm   INT  NOT NULL,
  ts            TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (device_serial, ts)
);

-- 4) user_consents – wymagane przez consentGuard
CREATE TABLE IF NOT EXISTS user_consents (
  id         BIGSERIAL PRIMARY KEY,
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  doc_type   TEXT NOT NULL CHECK (doc_type IN ('terms','privacy')),
  version    INT  NOT NULL,
  ip         TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE (user_id, doc_type, version)
);

-- 5) indeksy pomocnicze
CREATE INDEX IF NOT EXISTS idx_devices_devicetype ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_meas_device_ts     ON measurements(device_serial, ts DESC);

-- 6) migracja _limit -> sms_limit (gdyby istniało stare pole)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_name='devices' AND column_name='_limit'
  )
  THEN
    UPDATE devices SET sms_limit = COALESCE(sms_limit, _limit, 30);
  END IF;
END$$;


-- ───────── GLOBALNY LIMIT SMS NA UŻYTKOWNIKA ─────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS sms_limit INT DEFAULT 30,
  ADD COLUMN IF NOT EXISTS abonament_expiry DATE;

-- Domyślka: nowi userzy dostają 365 dni od dziś
ALTER TABLE users
  ALTER COLUMN abonament_expiry
  SET DEFAULT (CURRENT_DATE + INTERVAL '365 days')::date;


-- Jednorazowe wypełnienie z devices (max z urządzeń, żeby nic nie „uciąć”):
UPDATE users u
SET sms_limit        = COALESCE(u.sms_limit, x.sms_limit),
    abonament_expiry = COALESCE(u.abonament_expiry, x.abonament_expiry)
FROM (
  SELECT user_id,
         COALESCE(MAX(sms_limit), 30) AS sms_limit,
         MAX(abonament_expiry)        AS abonament_expiry
  FROM devices
  GROUP BY user_id
) x
WHERE u.id = x.user_id
  AND (u.sms_limit IS NULL OR u.abonament_expiry IS NULL);


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
    'co_phone1','co_phone2','leak_phone1','leak_phone2','co_threshold_ppm'
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
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-user', auth, adminOnly, async (req, res) => {
  const { email, password, role='client', name='', company='' } = req.body;
  console.log(`➕ [POST /admin/create-user] Tworzę usera: ${email}`);
  const hash = await bcrypt.hash(password, 10);
  await db.query(
    'INSERT INTO users(email,password_hash,role,name,company,confirmed) VALUES($1,$2,$3,$4,$5,TRUE)',
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
    const lnsResults = await chirpUpdate(serialNorm, label, street);
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



// ─────────────────────────────────────────────────────────────────────────────
// POST /admin/create-device-with-user — tworzenie (lub dopięcie) urządzenia
//  • gdy użytkownik istnieje → NIE wysyłamy maila/SMS, tylko dopinamy device
//  • gdy użytkownik nie istnieje → tworzymy konto + mail powitalny (+ SMS)
//  • sprawdzamy duplikat seriala i wynik chirpUpdate()
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-device-with-user', auth, adminOnly, async (req, res) => {
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
const originalStreet = (street ?? '').toString().trim();
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

      let userId, userCreated = false, basePwd = null;

      if (u1.rowCount > 0) {
        // użytkownik istnieje → nie wysyłamy maila/SMS
        userId = u1.rows[0].id;
        userCreated = false;
        console.log(`ℹ️  user exists: ${em} (id=${userId}) — attach device only`);
      } else {
        // 2) tworzymy konto z losowym hasłem
       basePwd = randomHex(4); // 8 znaków
        const hash = await bcrypt.hash(basePwd, 10);
        const insU = await client.query(
          'INSERT INTO users(email, password_hash, name, company, confirmed) VALUES ($1,$2,$3,$4,FALSE) RETURNING id',
          [em, hash, userName, company]
        );
        userId = insU.rows[0].id;
        userCreated = true;
        console.log(`✅  created user ${em} (id=${userId})`);

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
          removePolishLetters(street),
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
      const lnsResults = await chirpUpdate(serial, devName || userName || serial, street);
      console.log('✅ LNS results:', JSON.stringify(lnsResults));
      const anyOk = Array.isArray(lnsResults) && lnsResults.some(r => r && r.ok);
      if (!anyOk) {
        await client.query('ROLLBACK');
        return res
          .status(400)
          .json({ message: 'Urządzenie nie znaleziono w żadnym LNS, rejestracja przerwana', lns: lnsResults });
      }

      await client.query('COMMIT');

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
  if (!UPLINK_BEARER) {
    console.warn('⚠️ UPLINK_BEARER nie ustawiony – blokuję /uplink');
    return res.status(500).send('uplink bearer not configured');
  }
  const ip   = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
  const hdr  = (req.headers.authorization || '').trim();
  if (!hdr) {
    console.warn(`[UPLINK] missing Authorization header from ${ip}`);
    return res.status(401).send('Unauthorized');
  }
  // wyjmij token (z prefiksem Bearer lub bez)
  let token = hdr;
  if (/^Bearer\s+/i.test(hdr)) {
    token = hdr.replace(/^Bearer\s+/i, '').trim();
  }
  if (token !== UPLINK_BEARER) {
    console.warn(`[UPLINK] bad token from ${ip}`);
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
      req.body?.devEUI ??
      null;
    if (!rawDevEui) return res.status(400).send('dev_eui missing');
    // 🔑 NORMALIZACJA: zapis i porównywanie zawsze WIELKIMI
    const devEui = String(rawDevEui).trim().toUpperCase();

    // 1) pobieramy urządzenie
    const { rows } = await db.query('SELECT * FROM devices WHERE serial_number=$1', [devEui]);
    if (!rows.length) return res.status(404).send('unknown device');

    const dev     = rows[0];
    const type    = (dev.device_type || 'septic').toLowerCase();   // default
    const handler = handlers[type] || handlers.septic;             // fallback

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

    // 5) Zwróć mały JSON, żeby front mógł odświeżyć nazwę bez dodatkowego GET
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

              <!-- Android label -->
              <p style="margin:20px 0 10px 0; font-size:16px; color:#222; font-weight:bold;">Pobierz aplikację na Androida:</p>

              <!-- ANDROID BUTTON (table-based, fixed width) -->
              <table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" class="btn-fixed" width="360" style="width:360px; margin:0 auto;">
                <tr>
                  <td align="center" style="padding:0;">
                    <!--[if mso]>
                    <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="https://play.google.com/store/apps/details?id=pl.techiot.szambocontrol&utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding"
                      style="height:48px;v-text-anchor:middle;width:360px;" arcsize="8%" stroke="f" fillcolor="#1a73e8">
                      <w:anchorlock/>
                      <center style="color:#ffffff;font-family:Arial,sans-serif;font-size:16px;">Pobierz z Google Play</center>
                    </v:roundrect>
                    <![endif]-->
                    <!--[if !mso]><!-- -->
                    <a href="https://play.google.com/store/apps/details?id=pl.techiot.szambocontrol&utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding"
                       style="background:#1a73e8; color:#ffffff; display:block; text-align:center; text-decoration:none; font-size:16px; line-height:16px; padding:16px 22px; border-radius:6px;">
                       Pobierz z Google Play
                    </a>
                    <!--<![endif]-->
                  </td>
                </tr>
              </table>

              <!-- Spacer -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr><td height="16" style="line-height:16px;font-size:16px;">&nbsp;</td></tr>
              </table>

              <!-- Apple label -->
              <p style="margin:0 0 10px 0; font-size:16px; color:#222; font-weight:bold;">iPhone / iPad:</p>

              <!-- APPLE BUTTON (table-based, same fixed width) -->
              <table role="presentation" align="center" cellpadding="0" cellspacing="0" border="0" class="btn-fixed" width="360" style="width:360px; margin:0 auto;">
                <tr>
                  <td align="center" style="padding:0;">
                    <!--[if mso]>
                    <v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="https://apple-szambo-control.techiot.pl/?utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding"
                      style="height:48px;v-text-anchor:middle;width:360px;" arcsize="8%" stroke="f" fillcolor="#111111">
                      <w:anchorlock/>
                      <center style="color:#ffffff;font-family:Arial,sans-serif;font-size:16px;">Jeśli używasz Apple () – kliknij tu</center>
                    </v:roundrect>
                    <![endif]-->
                    <!--[if !mso]><!-- -->
                    <a href="https://apple-szambo-control.techiot.pl/?utm_source=confirmation_email&utm_medium=email&utm_campaign=onboarding"
                       style="background:#111111; color:#ffffff; display:block; text-align:center; text-decoration:none; font-size:16px; line-height:16px; padding:16px 22px; border-radius:6px;">
                       Jeśli używasz Apple () – kliknij tu
                    </a>
                    <!--<![endif]-->
                  </td>
                </tr>
              </table>

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

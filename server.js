// server.js – FULL BACKEND SKELETON v0.3 (z SMTP zamiast SendGrid + debug + próg z e-mailem)
// Dodatkowo: mechanizm SSE (/events) i wypychanie zdarzeń przy /uplink

const express    = require('express');
const bodyParser = require('body-parser');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const axios      = require('axios');
const nodemailer = require('nodemailer');
const moment     = require('moment-timezone');
const { Pool }   = require('pg');
const crypto     = require('crypto'); // do losowania nowego hasła
const geoip      = require('geoip-lite');
require('dotenv').config();
const helmet = require('helmet');


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

// ─────────────────────────────────────────────────────────────────────────────
// MAPOWANIE KODÓW REGION → NAZWA WOJEWÓDZTWA (geoip-lite używa kodów ISO 3166-2)
// ─────────────────────────────────────────────────────────────────────────────
const _regionMapPL = {
  '02': 'Dolnośląskie',
  '04': 'Kujawsko-Pomorskie',
  '06': 'Lubelskie',
  '08': 'Lubuskie',
  '10': 'Łódzkie',
  '12': 'Małopolskie',
  '14': 'Mazowieckie',
  '16': 'Opolskie',
  '18': 'Podkarpackie',
  '20': 'Podlaskie',
  '22': 'Pomorskie',
  '24': 'Śląskie',
  '26': 'Świętokrzyskie',
  '28': 'Warmińsko-Mazurskie',
  '30': 'Wielkopolskie',
  '32': 'Zachodniopomorskie',
};

const app  = express();
app.use(helmet());

// Gdy aplikacja stoi za proxy (Render, Heroku, Nginx, Cloudflare…)
// zaufaj 1. wpisowi z X-Forwarded-For, żeby req.ip pokazywało prawdziwy adres
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';

app.use(cors());
app.use(bodyParser.json());

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE (migration i inicjalizacja poola)
// ─────────────────────────────────────────────────────────────────────────────
const db = new Pool({ connectionString: process.env.DATABASE_URL });

const MIGRATION = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

--────────────────────────  USERS  ────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'client',
  name TEXT,
  company TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

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
  sms_limit INT  DEFAULT 30,
  red_cm   INT  DEFAULT 30,
  empty_cm INT  DEFAULT 150,
  capacity    INT  DEFAULT 8, 
  empty_ts TIMESTAMPTZ,
  distance_cm INT,
  trigger_dist BOOLEAN DEFAULT false,
  params JSONB  DEFAULT '{}' ,
  abonament_expiry DATE,
  alert_email TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

--────────────────────────  SMS_ORDERS  ───────────────────
--  Historia zakupów pakietów SMS (30 × SMS / 50 zł brutto)
CREATE TABLE IF NOT EXISTS sms_orders (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id     UUID REFERENCES devices(id) ON DELETE CASCADE,
  serial_number TEXT NOT NULL,
  amount        NUMERIC(10,2) NOT NULL DEFAULT 50.00, -- cena brutto
  status        TEXT NOT NULL DEFAULT 'new',          -- new / paid / error
  redirect_url  TEXT,                                 -- link do Przelewy24
  created_at    TIMESTAMPTZ DEFAULT now(),
  paid_at       TIMESTAMPTZ
);

-- Szybsze wyszukiwanie historii płatności danego urządzenia
CREATE INDEX IF NOT EXISTS idx_sms_orders_serial
  ON sms_orders(serial_number);

--────────────────────────  TRIGGER  ──────────────────────
-- Jeśli status zmieni się na 'paid' →:
--   • sms_limit = 30
--   • abonament_expiry += 365 dni
--   • paid_at = teraz
CREATE OR REPLACE FUNCTION sms_order_after_paid() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'paid' AND OLD.status <> 'paid' THEN
    UPDATE devices
      SET sms_limit        = 30,
          abonament_expiry = COALESCE(abonament_expiry, CURRENT_DATE)
                             + INTERVAL '365 days'
      WHERE id = NEW.device_id;

    NEW.paid_at := now();  -- zapisz datę opłacenia
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sms_order_after_paid ON sms_orders;
CREATE TRIGGER trg_sms_order_after_paid
AFTER UPDATE ON sms_orders
FOR EACH ROW
EXECUTE FUNCTION sms_order_after_paid();
`;

(async () => {
  try {
    await db.query(MIGRATION);
    console.log('✅ Migration executed (tables ensured).');
  } catch (e) {
    console.error('❌ Migration error:', e);
  }
})();

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

async function sendSMS(phone, msg) {
  const { SMSAPIKEY: key, SMSAPIPASSWORD: pwd } = process.env;
  if (!key || !pwd) throw new Error('SMS keys missing');
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${pwd}&from=techiot.pl&to=${encodeURIComponent(phone)}&msg=${encodeURIComponent(msg)}`;
  const r = await axios.post(url, null, { headers: { Accept: 'application/json' } });
  if (r.status !== 200) throw new Error('SMSplanet HTTP ' + r.status);
}

async function updateHelium(serie, name, street) {
  const token = (process.env.HELIUMBEARER || '').trim();
  if (!token) return;
  await axios.put(`https://console.helium-iot.xyz/api/devices/${serie}`, {
    device: {
      applicationId: "b1b1bc39-ce10-49f3-88de-3999b1da5cf4",
      deviceProfileId: "8a862a36-3aba-4c14-9a47-a41a5e33684e",
      name,
      description: street,
      tags:{},
      variables:{}
    }
  }, { headers: { Accept: 'application/json', Authorization: `Bearer ${token}` } });
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).send('Missing token');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
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
// MINI "Baza" banerów  –  rozdzielenie na grupę A (premium) i B (standard)
// ─────────────────────────────────────────────────────────────────────────────
const ADS = {
  // MIASTA ─────────────────────────────────────────────────
  Szczecin: {
       A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png',
        href: 'tel:+515490145' },
       { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg',
        href: 'tel:+515490145' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg',
        href: 'tel:+48911223344' }
    ]
  },
  Bydgoszcz: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png',
        href: 'tel:+51' },
       { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg',
        href: 'tel:+52' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg',
        href: 'tel:+663229464' }
    ]
  },

  // WOJEWÓDZTWA (fallback gdy GeoIP nie zna miasta) ───────
  'Kujawsko-Pomorskie': {
    A: [
            { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png',
        href: 'tel:+515490145' },
       { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg',
        href: 'tel:+515490145' }
      
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg',
        href: '515490145' }
    ]
  },
  'Zachodniopomorskie': {
    A: [

            { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg',
        href: 'tel:+1111' },
       { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg',
        href: 'tel:+222222' }
      
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg',
        href: '997' }
    ]
  },

  // DOMYŚLNY koszyk gdy nic nie pasuje ───────────────────
  OTHER: {
    A: [

            { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png',
        href: 'tel:+515490145' },
       { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg',
        href: 'tel:+515490145' }
      
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg',
        href: 'https://uniwersal-szambiarka.pl' }
    ]
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /ads?group=A|B&city=<opcjonalneMiasto>
// Zwraca listę banerów z żądanej grupy (domyślnie „B”)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/ads', (req, res) => {
  if (process.env.ADS_ENABLED !== 'true') return res.json([]);

  /* 1) Grupa cenowa:  ’A’ – premium,  ’B’ – standard (domyślna) */
  const group = req.query.group === 'A' ? 'A' : 'B';

  /* 2) Ustal miasto / województwo – najpierw query-param, potem GeoIP */
  let city = (req.query.city || '').trim();
  if (!city) {
    const ip = (req.headers['x-forwarded-for'] || req.ip || '')
                 .split(',')[0].trim();
    const geo = geoip.lookup(ip);
    if (geo) {
      city =
        geo.city ||
        (geo.country === 'PL' && _regionMapPL[geo.region]) ||
        '';
    }
  }
  if (city)
    city = city[0].toUpperCase() + city.slice(1).toLowerCase();

  /* 3) Wybierz odpowiedni koszyk; gdy brak w grupie A ⇒ fallback do B */
  const bucket  = ADS[city] || ADS['OTHER'];
  const banners = bucket[group].length ? bucket[group] : bucket['B'];

  return res.json(banners);
});


// ─────────────────────────────────────────────────────────────────────────────
// GET /device/:serial/params – pola konfiguracyjne w „Ustawieniach”
// ─────────────────────────────────────────────────────────────────────────────
app.get('/device/:serial/params', auth, async (req, res) => {
  const { serial } = req.params;
  const q = `
    SELECT phone, phone2, tel_do_szambiarza, capacity ,alert_email,
           red_cm, sms_limit,do_not_disturb,
           empty_cm, empty_ts, abonament_expiry
      FROM devices
     WHERE serial_number = $1`;
  const { rows } = await db.query(q, [serial]);
  if (!rows.length) return res.status(404).send('Not found');
  res.json(rows[0]);
});

// GET /device/:serial/measurements – ostatnie ≤10 rekordów
app.get('/device/:serial/measurements', auth, async (req, res) => {
  const { serial } = req.params;
  const q = `
    SELECT distance_cm, ts
      FROM measurements
     WHERE device_serial = $1
     ORDER BY ts DESC
     LIMIT 10`;
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
    'trigger_dist'
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
  console.log(`✅ [POST /login] Poprawne logowanie: ${email}`);
  return res.json({ token });
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
// GET /me/devices — zwraca urządzenia zalogowanego usera (wymaga auth)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/me/devices', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM devices WHERE user_id=$1', [req.user.id]);
  res.json(rows);
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /device/:id/phone — zmiana numeru telefonu (wymaga auth)
// ─────────────────────────────────────────────────────────────────────────────
app.put('/device/:id/phone', auth, async (req, res) => {
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

    // create device
    const { rows: dRows } = await db.query(
      `INSERT INTO devices (user_id,name,serial_number,eui,phone,street,abonament_expiry)
       VALUES ($1,$2,$3,$3,$4,$5,$6)
       ON CONFLICT (serial_number) DO NOTHING
       RETURNING *`,
      [
        userId,
        '#' + serie_number.slice(-5).toUpperCase() + ' ' + name,
        serie_number,
        normalisePhone(phone),
        removePolishLetters(street),
        moment().add(365, 'days').format('YYYY-MM-DD')
      ]
    );

    // wysyłka e-mail & SMS
    console.log(`✉️ [POST /admin/create-device-with-user] Wysyłam maila z danymi do ${email}`);
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

await sendEmail(
  email.toLowerCase(),
  '✅ Konto TechioT',
  htmlContent
);

    if (normalisePhone(phone)) {
      console.log(`📱 [POST /admin/create-device-with-user] Wysyłam SMS do ${phone}`);
      await sendSMS(normalisePhone(phone), 'Gratulacje! Pakiet 30 SMS aktywowany.');
    }
    await updateHelium(serie_number, name, street);

    console.log(`✅ [POST /admin/create-device-with-user] Użytkownik i urządzenie dodane.`);
    res.json({ user_id: userId, device: dRows[0] });
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
         phone, 
         phone2, 
         tel_do_szambiarza, 
         street,
         red_cm, 
         trigger_dist AS old_flag, 
         do_not_disturb,
         sms_limit,
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
    const distance = obj.distance ?? null;  // cm
    const voltage  = obj.voltage  ?? null;  // V
    /* 3a) radio parameters ---------------------------------------------- */
const snr = req.body.rxInfo?.[0]?.snr ?? null;   // Helium-ChirpStack v4
      /* 3b) DND – blokujemy wysyłkę 23:00-17:00 */
    const hour = moment().tz('Europe/Warsaw').hour();     // lokalna godzina
    const dnd  = d.do_not_disturb === true || d.do_not_disturb === 't';
    if (dnd && (hour >= 23 || hour < 17)) {               // 17 = godzina testowa
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

    /* 4a) zapis empty_* przy opróżnieniu -------------------------------- */
    if (d.old_flag && !row.new_flag) {
      console.log(`⚡ [POST /uplink] Zapisuję empty_cm/empty_ts dla ${devEui}`);
      await db.query(
        'UPDATE devices SET empty_cm = $1, empty_ts = now() WHERE id = $2',
        [distance, d.id]
      );
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
      if (toNumbers.length && row.sms_limit > 0) {
        const msg = `⚠️ Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm`;
        console.log(`📲 [POST /uplink] Wysyłam SMS na: ${toNumbers.join(', ')}`);
        let usedSms = 0;
        for (const num of toNumbers) {
          if (row.sms_limit - usedSms <= 0) break; // nie ma już limitu
          try {
            await sendSMS(num, msg);
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
      if (row.tel_do_szambiarza && row.sms_limit > 0) {
        const szam = normalisePhone(row.tel_do_szambiarza);
        if (szam) {
          const msg2 = `${row.street || '(brak adresu)'} – zbiornik pełny. Prosze o oproznienie. Tel: ${toNumbers[0] || 'brak'}`;
          try {
            console.log(`📲 [POST /uplink] Wysyłam SMS do szambiarza: ${szam}`);
            await sendSMS(szam, msg2);
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
app.get('/device/:serial_number/vars', auth, async (req, res) => {
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
app.patch('/device/:serial/params', auth, async (req, res) => {
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
    'do_not_disturb',
    'sms_limit'
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
app.listen(PORT, () => console.log(`TechioT backend listening on ${PORT}`));

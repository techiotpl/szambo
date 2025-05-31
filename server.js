// iot_backend_nodejs/
// ─────────────────────────────────────────────────────────────────────────────
// server.js – FULL BACKEND SKELETON v0.3 (z SMTP zamiast SendGrid + logi debugujące)
// ─────────────────────────────────────────────────────────────────────────────

const express    = require('express');
const bodyParser = require('body-parser');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcrypt');
const cors       = require('cors');
const axios      = require('axios');
const nodemailer = require('nodemailer');
const moment     = require('moment-timezone');
const { Pool }   = require('pg');
const crypto     = require('crypto'); // do losowania nowego hasła
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';

app.use(cors());
app.use(bodyParser.json());

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────────────────────────────────────────
const db = new Pool({ connectionString: process.env.DATABASE_URL });

const MIGRATION = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'client',
  name TEXT,
  company TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

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
  email_limit INT DEFAULT 30,
  red_cm INT    DEFAULT 30,
  empty_cm INT  DEFAULT 150,
  empty_ts TIMESTAMPTZ,
  distance_cm INT,
  trigger_dist BOOLEAN DEFAULT false,
  params JSONB  DEFAULT '{}',
  abonament_expiry DATE,
  created_at TIMESTAMPTZ DEFAULT now()
);
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
const smtpFrom   = process.env.SMTP_FROM;   // np. 'noreply@techiot.pl'

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

/**
 * Wysyła e-mail przez SMTP (nodemailer).
 * - `to` może być stringiem (pojedynczy email) lub tablicą stringów.
 * - `subj` to temat wiadomości (string).
 * - `html` to zawartość wiadomości w formacie HTML (string).
 */
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

  console.log(`✉️ Próbuję wysłać maila do: ${recipients} (temat: "${subj}")`);
  const info = await transporter.sendMail(mailOptions);
  console.log('✅ Wysłano e-mail przez SMTP:', info.messageId);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function removePolishLetters(str = "") {
  const pl = { 'ą':'a','ć':'c','ę':'e','ł':'l','ń':'n','ó':'o','ś':'s','ź':'z','ż':'z','Ą':'A','Ć':'C','Ę':'E','Ł':'L','Ń':'N','Ó':'O','Ś':'S','Ź':'Z','Ż':'Z' };
  return str.replace(/[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/g, m=>pl[m]);
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
// ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// 1) GET /admin/users-with-devices (auth + adminOnly)
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

/* ------------------------------------------------------------------
 *  GET /device/:serial/params
 *  Zwraca pola konfiguracyjne widoczne w „Ustawieniach”.
 * ----------------------------------------------------------------- */
app.get('/device/:serial/params', auth, async (req, res) => {
  const { serial } = req.params;
  const q = `
    SELECT phone, phone2, tel_do_szambiarza,
           red_cm, sms_limit, email_limit,
           empty_cm, empty_ts, abonament_expiry
      FROM devices
     WHERE serial_number = $1`;
  const { rows } = await db.query(q, [serial]);
  if (!rows.length) return res.status(404).send('Not found');
  res.json(rows[0]);
});

app.patch('/admin/device/:serial/params', auth, adminOnly, async (req, res) => {
  // body = { phone:'...', red_cm:42, ... }  ← dowolny podzbiór
  const updates = [];
  const vals    = [];
  let i = 1;
  for (const [k, v] of Object.entries(req.body)) {
    updates.push(`${k}=$${i++}`);
    vals.push(v);
  }
  vals.push(req.params.serial);
  await db.query(`UPDATE devices SET ${updates.join(',')} WHERE serial_number=$${i}`, vals);
  res.send('updated');
});

// 2) POST /login — logowanie
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log(`🔑 [POST /login] próba logowania użytkownika: ${email}`);
  const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase()]);
  const u = rows[0];
  if (!u) {
    console.log(`❌ [POST /login] Brak usera: ${email}`);
    return res.status(401).send('Bad creds');
  }
  const passwordMatches = await bcrypt.compare(password, u.password_hash);
  if (!passwordMatches) {
    console.log(`❌ [POST /login] Złe hasło dla usera: ${email}`);
    return res.status(401).send('Bad creds');
  }
  const token = jwt.sign({ id: u.id, email: u.email, role: u.role }, JWT_SECRET);
  console.log(`✅ [POST /login] Poprawne logowanie: ${email}`);
  res.json({ token });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /forgot-password – generuje nowe hasło, zapisuje je w bazie i wysyła e-mail
// ─────────────────────────────────────────────────────────────────────────────
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    console.log(`🔄 [POST /forgot-password] Prośba o reset hasła dla: ${email}`);
    if (!email) {
      console.log('❌ [POST /forgot-password] Brak pola "email" w ciele zapytania');
      return res.status(400).send('Email is required');
    }

    // 1) Sprawdź, czy użytkownik o podanym e-mailu istnieje
    const { rows } = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (!rows.length) {
      console.log(`⚠️ [POST /forgot-password] Nie znaleziono usera o e-mailu: ${email}`);
      // Zwracamy 200 nawet jeśli nie ma konta
      return res
        .status(200)
        .send('Jeśli konto o podanym adresie istnieje, otrzymasz nowe hasło mailem.');
    }

    // 2) Wygeneruj losowe, tymczasowe hasło (np. 8-znakowe alfanumeryczne)
    const newPassword = crypto.randomBytes(4).toString('hex');
    console.log(`🔑 [POST /forgot-password] Wygenerowane nowe hasło dla ${email}: ${newPassword}`);

    // 3) Zahaszuj je za pomocą bcrypt
    const newHash = await bcrypt.hash(newPassword, 10);

    // 4) Zapisz nowe zahashowane hasło w bazie
    await db.query(
      'UPDATE users SET password_hash = $1 WHERE email = $2',
      [newHash, email.toLowerCase()]
    );
    console.log(`✅ [POST /forgot-password] Zaktualizowano hasło w bazie dla ${email}`);

    // 5) Wyślij e-mail z nowym hasłem do użytkownika
    const htmlContent = `
      <p>Cześć,</p>
      <p>Na Twoją prośbę wygenerowaliśmy nowe hasło do konta TechioT.</p>
      <p><strong>Twoje nowe hasło:</strong> <code>${newPassword}</code></p>
      <p>Po zalogowaniu możesz je zmienić w ustawieniach profilu.</p>
      <br>
      <p>Pozdrawiamy,<br>TechioT</p>
    `;
    console.log(`✉️ [POST /forgot-password] Próba wysłania maila do ${email}`);
    await sendEmail(
      email.toLowerCase(),
      'Twoje nowe hasło – TechioT',
      htmlContent
    );
    console.log(`✅ [POST /forgot-password] Mail z nowym hasłem wysłany do ${email}`);

    // 6) Zwróć zawsze 200 – nie mówimy, czy e-mail istniał
    return res
      .status(200)
      .send('Jeśli konto o podanym adresie istnieje, otrzymasz nowe hasło mailem.');
  } catch (err) {
    console.error('❌ Error in /forgot-password:', err);
    return res.status(500).send('Internal server error');
  }
});


// 3) POST /admin/create-user — tworzenie użytkownika (wymaga auth+adminOnly)
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

// 4) GET /me/devices — zwraca urządzenia zalogowanego usera (wymaga auth)
app.get('/me/devices', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM devices WHERE user_id=$1', [req.user.id]);
  res.json(rows);
});

// 5) PUT /device/:id/phone — zmiana numeru telefonu (wymaga auth)
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

/**
 * DELETE /admin/user/:email
 * – usuwa użytkownika wraz z urządzeniami (ON DELETE CASCADE)
 */
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

// 6) POST /admin/create-device-with-user — tworzenie użytkownika + urządzenia
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
    await sendEmail(
      email.toLowerCase(),
      '✅ Konto TechioT',
      `Twoje konto jest gotowe.<br>Login: ${email}<br>Hasło: ${basePwd}`
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

// ── FIXED /uplink ENDPOINT (dodano znacznik ts do params) ──────────────────
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
      `SELECT id, phone, phone2, tel_do_szambiarza, street,
              red_cm, trigger_dist AS old_flag, sms_limit
         FROM devices
        WHERE serial_number = $1`,
      [devEui]
    );
    if (!dev.rowCount) {
      console.log(`⚠️ [POST /uplink] Nieznane urządzenie: ${devEui}`);
      return res.status(404).send('Unknown device');
    }
    const d = dev.rows[0];  // stara flaga → d.old_flag

    /* 3) payload --------------------------------------------------------- */
    const obj      = req.body.object || {};
    const distance = obj.distance ?? null;  // cm
    const voltage  = obj.voltage  ?? null;  // V
    if (distance === null) {
      console.log(`ℹ️ [POST /uplink] Brak distance dla ${devEui}, pomijam`);
      return res.send('noop (no distance)');
    }

    // dodajemy znacznik czasu ISO-8601
    const varsToSave = {
      distance,
      voltage,
      ts: new Date().toISOString()
    };

    /* 4) zapis + nowa flaga ---------------------------------------------- */
    const q = `
      UPDATE devices
         SET params       = coalesce(params,'{}'::jsonb) || $3::jsonb,
             distance_cm  = $2::int,
             trigger_dist = CASE
                              WHEN $2::int <= red_cm THEN TRUE
                              WHEN $2::int >= red_cm THEN FALSE
                              ELSE trigger_dist
                            END
       WHERE id = $1
       RETURNING trigger_dist AS new_flag, red_cm, sms_limit,
                 phone, phone2, tel_do_szambiarza, street`;
    const { rows: [row] } = await db.query(q, [d.id, distance, JSON.stringify(varsToSave)]);

    /* 4a) zapis empty_* przy opróżnieniu -------------------------------- */
    if (d.old_flag && !row.new_flag) {
      console.log(`⚡ [POST /uplink] Zapisuję empty_cm/empty_ts dla ${devEui}`);
      await db.query(
        'UPDATE devices SET empty_cm = $1, empty_ts = now() WHERE id = $2',
        [distance, d.id]
      );
    }

    /* 4b) wygodne logowanie --------------------------------------------- */
    const ref = row.red_cm;  // próg alarmu
    const pct = Math.round(((distance - ref) / -ref) * 100);
    console.log(
      `🚀 Saved uplink ${devEui}: ${distance} cm (≈${pct}%); red=${ref}; flag ${d.old_flag}→${row.new_flag}`
    );

    /* 5) SMS alarmowe ---------------------------------------------------- */
    if (!d.old_flag && row.new_flag && row.sms_limit > 0) {
      console.log(`📲 [POST /uplink] Wysyłam alarm SMS dla ${devEui}`);
      const norm = p => p && p.length >= 9
          ? (p.startsWith('+48') ? p : '+48'+p) : null;
      const phones   = [norm(row.phone), norm(row.phone2)].filter(Boolean);
      const szambTel = norm(row.tel_do_szambiarza);

      /* 5a) użytkownik ------------------------------------------------- */
      if (phones.length && row.sms_limit >= phones.length) {
        await sendSMS(
          phones,
          `Poziom ${distance} cm przekroczyl próg ${row.red_cm} cm`
        );
        row.sms_limit -= phones.length;
      }
      /* 5b) szambiarz --------------------------------------------------- */
      if (szambTel && row.sms_limit > 0) {
        await sendSMS(
          [szambTel],
          `${row.street || '(brak adresu)'} – zbiornik pełny. Proszę o opróżnienie. Tel: ${phones[0] || 'brak'}`
        );
        row.sms_limit -= 1;
      }
      /* 5c) aktualizacja limitu ---------------------------------------- */
      await db.query('UPDATE devices SET sms_limit=$1 WHERE id=$2', [row.sms_limit, d.id]);
      console.log(`📉 [POST /uplink] Zaktualizowano sms_limit dla ${devEui} → ${row.sms_limit}`);
    }

    return res.send('OK');
  } catch (err) {
    console.error('❌ Error in /uplink:', err);
    return res.status(500).send('uplink error');
  }
});

/* ─────── GET kolumn urządzenia ─────── */
/* ------------------------------------------------------------------
 *  GET /device/:serial_number/vars
 *  Zwraca distance, voltage, ts, empty_cm / empty_ts i policzony %.
 * ----------------------------------------------------------------- */
app.get('/device/:serial_number/vars', auth, async (req, res) => {
  const { serial_number } = req.params;
  const q = `
    SELECT
      (params ->> 'distance')::int                      AS distance,
      (params ->> 'voltage')::numeric                   AS voltage,
      params ->> 'ts'                                   AS ts,
      empty_cm,
      empty_ts,
      CASE
        WHEN empty_cm IS NOT NULL
          THEN ROUND( ( (params->>'distance')::int - empty_cm )::numeric
                      / (0-empty_cm) * 100 )
      END                                              AS procent
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

/* ─────── PATCH kolumn urządzenia ─────── */
app.patch('/device/:serial/params', async (req, res) => {
  const { serial } = req.params;
  const body = req.body; // { phone: "...", red_cm: 40, ... }

  const cols = [];
  const vals = [];
  let i = 1;
  for (const [k, v] of Object.entries(body)) {
    cols.push(`${k} = $${i++}`);
    vals.push(v);
  }
  if (!cols.length) {
    console.log(`❌ [PATCH /device/${serial}/params] Brak danych do aktualizacji`);
    return res.sendStatus(400);
  }

  vals.push(serial); // ostatni parametr do WHERE
  const q = `UPDATE devices SET ${cols.join(', ')} WHERE serial_number = $${i}`;
  await db.query(q, vals);
  console.log(`✅ [PATCH /device/${serial}/params] Zaktualizowano: ${JSON.stringify(body)}`);
  res.sendStatus(200);
});

// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`TechioT backend listening on ${PORT}`));

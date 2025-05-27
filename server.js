// iot_backend_nodejs/server.js – FULL BACKEND SKELETON v0.2
// -----------------------------------------------------------------------------
// This single file keeps everything in **one place** so it can be deployed
// quickly to Render.com.  When the project grows we can split it into modules
// (services/, routes/, db/, etc.), but for now we stay monolithic for clarity.
// -----------------------------------------------------------------------------

// ─────────────────────────────────────────────────────────────────────────────
// 1. DEPENDENCIES & BASIC APP SET‑UP
// ─────────────────────────────────────────────────────────────────────────────
const express   = require('express');
const bodyParser= require('body-parser');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcrypt');
const cors      = require('cors');
const axios     = require('axios');
const moment    = require('moment-timezone');
const { Pool }  = require('pg');
require('dotenv').config();                // .env support when running locally

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev‑jwt‑secret';

app.use(cors());
app.use(bodyParser.json());

// PostgreSQL pool (compatible with Render Postgres)
const db = new Pool({ connectionString: process.env.DATABASE_URL });

// ─────────────────────────────────────────────────────────────────────────────
// 2. HELPER FUNCTIONS (SMS, E‑MAIL, UTILS)
// ─────────────────────────────────────────────────────────────────────────────

function removePolishLetters(str = "") {
  const pl = { 'ą':'a','ć':'c','ę':'e','ł':'l','ń':'n','ó':'o','ś':'s','ź':'z','ż':'z',
               'Ą':'A','Ć':'C','Ę':'E','Ł':'L','Ń':'N','Ó':'O','Ś':'S','Ź':'Z','Ż':'Z' };
  return str.replace(/[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]/g, m => pl[m]);
}

async function sendSMS(phone, message) {
  const key = process.env.SMSAPIKEY;
  const password = process.env.SMSAPIPASSWORD;
  if (!key || !password) throw new Error('SMS keys not configured');
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${password}&from=techiot.pl&to=${encodeURIComponent(phone)}&msg=${encodeURIComponent(message)}`;
  const r = await axios.post(url, null, { headers:{ Accept:'application/json' } });
  if (r.status !== 200) throw new Error(`SMSplanet HTTP ${r.status}`);
}

async function sendEmail(to, subject, html) {
  const sgKey = process.env.SENDGRIDAPI;
  if (!sgKey) throw new Error('SENDGRID key missing');
  const body = {
    personalizations:[{ to:[{email:to}], subject }],
    from:{ email:'noreply@techiot.pl', name:'TechioT' },
    content:[{ type:'text/html', value:html }]
  };
  await axios.post('https://api.sendgrid.com/v3/mail/send', body, {
    headers:{ Authorization:`Bearer ${sgKey}`, 'Content-Type':'application/json' }
  });
}

async function updateHelium(serieNumber, name, street) {
  const bearer = (process.env.HELIUMBEARER || '').trim();
  if (!bearer) return;    // silently skip in dev if not set
  const url = `https://console.helium-iot.xyz/api/devices/${serieNumber}`;
  const payload = {
    device:{
      applicationId:"b1b1bc39-ce10-49f3-88de-3999b1da5cf4",
      deviceProfileId:"8a862a36-3aba-4c14-9a47-a41a5e33684e",
      name,
      description:street,
      tags:{}, variables:{}
    }
  };
  await axios.put(url, payload, { headers:{ Accept:'application/json', Authorization:`Bearer ${bearer}` } });
}

function normalisePhone(ph) {
  if (!ph || ph.length < 9) return null;
  return ph.startsWith('+48') ? ph : '+48' + ph;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────
function auth(req,res,next){
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return res.status(401).send('No token');
  try{ req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch{ res.status(401).send('Invalid token'); }
}
function adminOnly(req,res,next){ if(req.user.role!== 'admin') return res.status(403).send('Forbidden'); next(); }

// ─────────────────────────────────────────────────────────────────────────────
// 4. SQL MIGRATIONS (RUN ONCE ON STARTUP IF TABLES ARE MISSING)
//    Very light – in prod use proper migrations.
// ─────────────────────────────────────────────────────────────────────────────
const MIGRATION = `
CREATE TABLE IF NOT EXISTS users (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email        TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role         TEXT DEFAULT 'client',
  name         TEXT,
  company      TEXT,
  created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE TABLE IF NOT EXISTS devices (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT,
  serial_number TEXT UNIQUE NOT NULL,
  eui          TEXT,
  phone        TEXT,
  phone2       TEXT,
  street       TEXT,
  sms_limit    INT  DEFAULT 30,
  email_limit  INT  DEFAULT 30,
  red_cm       INT  DEFAULT 30,
  empty_cm     INT  DEFAULT 150,
  abonament_expiry DATE,
  params       JSONB DEFAULT '{}',
  created_at   TIMESTAMPTZ DEFAULT now()
);
`;
(async()=>{ await db.query(MIGRATION); })();

// ─────────────────────────────────────────────────────────────────────────────
// 5. AUTH ROUTES (REGISTER / LOGIN)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-user', auth, adminOnly, async (req,res)=>{
  const { email, password, role='client', name='', company='' } = req.body;
  const hash = await bcrypt.hash(password,10);
  await db.query('INSERT INTO users(email,password_hash,role,name,company) VALUES($1,$2,$3,$4,$5)', [email.toLowerCase(),hash,role,name,company]);
  res.send('User created');
});

app.post('/login', async (req,res)=>{
  const { email, password } = req.body;
  const { rows } = await db.query('SELECT * FROM users WHERE email=$1',[email.toLowerCase()]);
  const user = rows[0];
  if(!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).send('Bad creds');
  const token = jwt.sign({ id:user.id, email:user.email, role:user.role }, JWT_SECRET);
  res.json({ token });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. DEVICE ROUTES (USER SIDE)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/me/devices', auth, async (req,res)=>{
  const { rows } = await db.query('SELECT * FROM devices WHERE user_id=$1',[req.user.id]);
  res.json(rows);
});

app.put('/device/:id/phone', auth, async (req,res)=>{
  const phone = normalisePhone(req.body.phone);
  if(!phone) return res.status(400).send('Invalid phone');
  await db.query('UPDATE devices SET phone=$1 WHERE id=$2 AND user_id=$3',[phone,req.params.id,req.user.id]);
  res.send('Updated');
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. ADMIN ROUTE –  CREATE DEVICE & USER (PORTED FROM TAGO.IO SCRIPT)
//    Expects JSON payload containing *minimum* serie_number & email.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/admin/create-device-with-user', auth, adminOnly, async (req,res)=>{
  try{
    const {
      serie_number,            // required
      name = '',
      email = '',              // required (user login)
      phone = '0',
      phone2 = '-',
      street = 'N/A',
      company = '',
      sms_limit = 30,
      email_limit = 30
    } = req.body;
    if(!serie_number || !email) return res.status(400).send('serie_number & email required');

    const plainPassword = `${email.split('@')[0]}${String(Math.floor(Math.random()*100)).padStart(2,'0')}!`;

    // 1) Create or fetch user
    let { rows:userRows } = await db.query('SELECT id FROM users WHERE email=$1',[email.toLowerCase()]);
    let userId;
    if(userRows.length){ userId = userRows[0].id; }
    else {
      const hash = await bcrypt.hash(plainPassword,10);
      ({ rows:userRows } = await db.query('INSERT INTO users(email,password_hash,name,company) VALUES($1,$2,$3,$4) RETURNING id',
        [email.toLowerCase(),hash,name,company]));
      userId = userRows[0].id;
    }

    // 2) Create device
    const redCm   = 30;
    const emptyCm = 150;
    const abonamentExpiry = moment().add(365,'days').format('YYYY-MM-DD');
    const { rows:devRows } = await db.query(`INSERT INTO devices
      (user_id,name,serial_number,eui,phone,phone2,street,sms_limit,email_limit,red_cm,empty_cm,abonament_expiry)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [userId,`#${serie_number.slice(-5).toUpperCase()} ${name}`,serie_number,serie_number,normalisePhone(phone),normalisePhone(phone2),removePolishLetters(street),sms_limit,email_limit,redCm,emptyCm,abonamentExpiry]);

    const device = devRows[0];

    // 3) Welcome email to user
    const html = `<h3>Witaj ${name || 'Użytkowniku'}!</h3><p>Twoje konto w TechioT jest gotowe.<br/>Login: ${email}<br/>Hasło: ${plainPassword}<br/>Numer klienta: ${serie_number.slice(-5)}</p>`;
    await sendEmail(email,'✅ Utworzenie konta do platformy TechioT',html);

    // 4) Internal email
    await sendEmail('biuro@techiot.pl','Nowy czujnik został dodany.',`<p>Nowy czujnik dodany na ulicy ${street}. User: ${email}</p>`);

    // 5) SMS
    if(normalisePhone(phone)) await sendSMS(normalisePhone(phone),'Gratulacje! Twój pakiet 30 SMS został aktywowany.');

    // 6) Helium update
    await updateHelium(serie_number,name,removePolishLetters(street));

    res.json({ user_id:userId, device });
  }catch(err){ console.error(err); res.status(500).send(err.message); }
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. CHIRPSTACK UPLINK ENDPOINT (ETAP 3 – very thin for now)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/uplink', async (req,res)=>{
  const { dev_eui, object } = req.body;
  if(!dev_eui) return res.status(400).send('dev_eui missing');

  const { rows } = await db.query('SELECT * FROM devices WHERE serial_number=$1',[dev_eui]);
  if(!rows.length) return res.status(404).send('Unknown device');
  // Store data (simplified – ideally insert into measurements table)
  await db.query('UPDATE devices SET params = jsonb_set(coalesce(params,'"{}"')::jsonb,'"{last_distance}"',to_jsonb($2::text)) WHERE id=$1',
    [rows[0].id,String(object?.distance || '')]);
  res.send('OK');
  // TODO: trigger alert logic & SMS/email here (Etap 2)
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. START SERVER
// ─────────────────────────────────────────────────────────────────────────────
app.listen(PORT, ()=> console.log(`TechioT backend listening on ${PORT}`));

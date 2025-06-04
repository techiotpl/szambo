// jobs/check-stale-devices.js

/**
 * Ten skrypt:
 *   - Łączy się do bazy Postgres przez Pool (zmienna środowiskowa DATABASE_URL)
 *   - Szuka urządzeń, które nie wysłały pomiaru od HRS godzin i nie miały jeszcze alertu
 *   - Wysyła SMS i/lub e-mail, oznacza w bazie, że alert poszedł
 */

const { Pool } = require('pg');
const axios    = require('axios');
require('dotenv').config();

const HRS = 1; // próg braku odpowiedzi (w godzinach)

// — pomocnicze funkcje do SMS i e-mail
function normalisePhone(p) {
  if (!p || p.length < 9) return null;
  return p.startsWith('+48') ? p : '+48' + p;
}

async function sendSMS(phone, msg) {
  const { SMSAPIKEY: key, SMSAPIPASSWORD: pwd } = process.env;
  if (!key || !pwd) return;
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${pwd}&from=techiot.pl&to=${encodeURIComponent(
    phone
  )}&msg=${encodeURIComponent(msg)}`;
  await axios.post(url, null, { headers: { Accept: 'application/json' } });
}

const nodemailer = require('nodemailer');
async function sendEmail(to, subj, html) {
  const mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    tls: { rejectUnauthorized: false },
  });
  await mailer.sendMail({ from: process.env.SMTP_FROM, to, subject: subj, html });
}

;(async () => {
  // ---------- DEBUG: Czy na pewno mamy DATABASE_URL? ----------
  console.log('DEBUG → DATABASE_URL =', process.env.DATABASE_URL);

  // Inicjalizujemy połączenie do bazy tak, jak w decrement-abonament.js
  const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Jeśli Twoja baza wymaga SSL – odkomentuj poniższe. 
    // Jeśli nie, zostaw to zakomentowane (bo niektóre bazy na Render akceptują połączenie bez SSL).
    // ssl: { rejectUnauthorized: false }
  });

  try {
    // 1) Pobierz wiersze z urządzeniami, które nie miały pomiaru od > HRS godzin
    const q = `
      SELECT
        id,
        serial_number,
        (params->>'ts')::timestamptz AS ts,
        phone,
        phone2,
        alert_email,
        sms_limit
      FROM devices
      WHERE stale_alert_sent = FALSE
        AND (params->>'ts') IS NOT NULL
        AND (params->>'ts')::timestamptz < now() - interval '${HRS} hours'
    `;
    const { rows } = await db.query(q);

    if (rows.length === 0) {
      console.log('✅ Brak nieodpowiadających urządzeń');
      return;
    }

    console.log(`⚠️  Znaleziono ${rows.length} urządzeń bez pomiaru > ${HRS}h`);
    for (const d of rows) {
      const msgTxt  = `⚠️ Czujnik ${d.serial_number} nie odpowiada od ponad ${HRS}h!`;
      const mailSub = `⚠️ Czujnik ${d.serial_number} nie odpowiada`;
      const mailHtml = `
        <p>Cześć,</p>
        <p>Urządzenie <strong>${d.serial_number}</strong> nie wysłało pomiaru od ponad ${HRS}&nbsp;godzin.</p>
        <p>Prosimy zweryfikować jego działanie.</p><br><p>Pozdrawiamy<br>TechioT</p>
      `;

      // ––– Wysyłka SMS –––
      const nums = [normalisePhone(d.phone), normalisePhone(d.phone2)].filter(Boolean);
      for (const n of nums) {
        if (d.sms_limit > 0) {
          try {
            await sendSMS(n, msgTxt);
            d.sms_limit--;
          } catch (e) {
            console.error('SMS error:', e.message);
          }
        } else {
          console.log(`ℹ️  sms_limit=0 → nie wysyłam SMS do ${n}`);
        }
      }
      if (nums.length) {
        await db.query('UPDATE devices SET sms_limit = $1 WHERE id = $2', [d.sms_limit, d.id]);
      }

      // ––– Wysyłka e-mail –––
      if (d.alert_email) {
        try {
          await sendEmail(d.alert_email, mailSub, mailHtml);
        } catch (e) {
          console.error('E-mail error:', e.message);
        }
      }

      // ––– Oznaczamy, że alert został wysłany –––
      await db.query('UPDATE devices SET stale_alert_sent = TRUE WHERE id = $1', [d.id]);
      console.log(`✅ Alert wysłany dla ${d.serial_number}`);
    }
  } catch (err) {
    console.error('❌ Błąd w check-stale-devices:', err);
  } finally {
    // 2) Zamknij połączenie do bazy
    await db.end();
  }
})();

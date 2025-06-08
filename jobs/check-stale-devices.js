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

const HRS = 72; // próg braku odpowiedzi (w godzinach)

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
  console.log('DEBUG → DATABASE_URL =', process.env.DATABASE_URL);

  const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    // ssl: { rejectUnauthorized: false }
  });

  try {
    // 1) Pobierz wiersze z urządzeniami:
    //    - last_measurement_ts < teraz - HRS
    //    - trigger_measurement = FALSE
    const q = `
      SELECT
        id,
        serial_number,
        last_measurement_ts,
        phone,
        phone2,
        alert_email,
        sms_limit
      FROM devices
      WHERE trigger_measurement = FALSE
        AND last_measurement_ts IS NOT NULL
        AND last_measurement_ts < now() - interval '${HRS} hours'
    `;
    const { rows } = await db.query(q);

    if (rows.length === 0) {
      console.log('✅ Brak nieodpowiadających urządzeń');
      return;
    }

    console.log(`⚠️  Znaleziono ${rows.length} urządzeń bez pomiaru > ${HRS}h`);
    for (const d of rows) {
      const msgTxt  = `⚠️ Czujnik do szamba nie odpowiada od ponad ${HRS}h! sprawdz antene  i czujnik`;
      const mailSub = `⚠️ Czujnik szamba nie odpowiada`;
  const mailHtml = `
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Alert: Brak odpowiedzi z czujnika</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
  <table role="presentation" style="width:100%; border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:20px 0;">
        <table role="presentation" style="width:600px; border-collapse:collapse; background-color:#ffffff; box-shadow:0 0 10px rgba(0,0,0,0.1);">
          <!-- Logo -->
          <tr>
            <td align="center" style="padding:20px;">
              <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg"
                   alt="TechioT Logo"
                   style="max-width:150px; height:auto;">
            </td>
          </tr>
          <!-- Nagłówek -->
          <tr>
            <td style="padding:0 20px; border-bottom:1px solid #eeeeee;">
              <h2 style="color:#333333; font-size:24px; margin:0;">
                ⚠️ Alert: Brak odpowiedzi z czujnika
              </h2>
            </td>
          </tr>
          <!-- Treść -->
          <tr>
            <td style="padding:20px;">
              <p style="color:#555555; font-size:16px; line-height:1.5; margin-bottom:10px;">
                Cześć,
              </p>
              <p style="color:#555555; font-size:16px; line-height:1.5; margin-bottom:10px;">
                Twoje urządzenie <strong>${d.serial_number}</strong> nie wysłało pomiaru od ponad <strong>${HRS}&nbsp;godzin</strong>. Prosimy o:
              </p>
              <ul style="color:#555555; font-size:16px; line-height:1.5; margin:0 0 20px 20px; padding:0;">
                <li style="margin-bottom:8px;">Sprawdzenie anteny</li>
                <li style="margin-bottom:8px;">Weryfikację, czy urządzenie nie zostało uszkodzone przez firmę asenizacyjną</li>
             
              </ul>
              <p style="color:#999999; font-size:12px; line-height:1.4; text-align:center; margin-top:30px;">
                Ta wiadomość została wysłana automatycznie, prosimy na nią nie odpowiadać.
              </p>
            </td>
          </tr>
          <!-- Stopka -->
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


      // — SMS —
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
        await db.query(
          'UPDATE devices SET sms_limit = $1 WHERE id = $2',
          [d.sms_limit, d.id]
        );
      }

      // — E-mail —
      if (d.alert_email) {
        try {
          await sendEmail(d.alert_email, mailSub, mailHtml);
        } catch (e) {
          console.error('E-mail error:', e.message);
        }
      }

      // — Ustawiamy flagę, że już wysłaliśmy alert dla tego urządzenia —
      await db.query(
        'UPDATE devices SET trigger_measurement = TRUE WHERE id = $1',
        [d.id]
      );
      console.log(`✅ Alert wysłany i trigger_measurement=TRUE dla ${d.serial_number}`);
    }
  } catch (err) {
    console.error('❌ Błąd w check-stale-devices:', err);
  } finally {
    await db.end();
  }
})();

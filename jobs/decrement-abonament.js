/**
 * jobs/decrement-abonament.js
 *
 * Co robi:
 *  1) Użytkownikom, którym wygasł abonament (users.abonament_expiry <= dzisiaj)
 *     ustawia users.sms_limit = 0 (tylko, gdy był > 0).
 *  2) Dla każdego takiego usera:
 *     - wysyła 1× SMS na pierwszy numer z urządzeń typu "septic"
 *       (fallback: pierwszy numer z dowolnego urządzenia, jeśli brak septic)
 *     - wysyła e-mail do user.email z kopią do biuro@techiot.pl
 *
 * Wymagane zmienne środowiskowe:
 *   DATABASE_URL
 *   SMSAPIKEY, SMSAPIPASSWORD
 *   SMTP_HOST, SMTP_PORT, SMTP_SECURE ('true'/'false'), SMTP_USER, SMTP_PASS, SMTP_FROM
 */

require('dotenv').config();
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const axios = require('axios');

function normalisePhone(p) {
  if (!p) return null;
  const digits = String(p).replace(/\s+/g, '');
  if (digits.startsWith('+48')) return digits;
  if (/^\d{9}$/.test(digits)) return '+48' + digits;
  if (/^48\d{9}$/.test(digits)) return '+' + digits;
  return null;
}

async function sendSMS(phone, msg, tag = 'abonament_expired') {
  const { SMSAPIKEY: key, SMSAPIPASSWORD: pwd } = process.env;
  if (!key || !pwd) throw new Error('SMS keys missing');
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${pwd}&from=techiot.pl&to=${encodeURIComponent(phone)}&msg=${encodeURIComponent(msg)}`;
  const r = await axios.post(url, null, { headers: { Accept: 'application/json' } });
  if (r.status !== 200) throw new Error('SMSplanet HTTP ' + r.status);
  const data = r.data;
  const logicalOk =
    (typeof data === 'object' && (
      data.status === 'OK' || data.result === 'OK' || data.success === true || data.error === undefined
    )) || (typeof data === 'string' && data.toLowerCase().includes('ok'));
  if (!logicalOk) throw new Error('SMSplanet logic error: ' + JSON.stringify(data));
  console.log(`📨 SMS → ${phone} (${tag}) ok`);
  return true;
}

function createTransporter() {
  const smtpHost   = process.env.SMTP_HOST;
  const smtpPort   = parseInt(process.env.SMTP_PORT || '465', 10);
  const smtpSecure = (process.env.SMTP_SECURE === 'true');
  const smtpUser   = process.env.SMTP_USER;
  const smtpPass   = process.env.SMTP_PASS;
  if (!smtpHost || !smtpPort || !smtpUser || !smtpPass) {
    console.warn('⚠️ Brakuje zmiennych SMTP_* – e-mail nie zadziała.');
    return null;
  }
  return nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: { user: smtpUser, pass: smtpPass },
    tls: { rejectUnauthorized: false }
  });
}

async function sendEmail(transporter, to, subject, html, ccList = []) {
  if (!transporter) throw new Error('SMTP not configured');
  const info = await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    cc: ccList.join(', '),
    subject,
    html
  });
  console.log(`✉️  Mail → ${to} (cc: ${ccList.join(', ')}) ok: ${info.messageId}`);
}

(async () => {
  const db = new Pool({ connectionString: process.env.DATABASE_URL });

  const transporter = createTransporter();
  if (transporter) {
    try { await transporter.verify(); }
    catch (e) { console.warn('⚠️ SMTP verify failed:', e.message); }
  }

  try {
    // 1) Wyzeruj globalny limit u userów, którym wygasł abonament — zwróć listę dotkniętych userów
    const q = `
      WITH affected AS (
        UPDATE users
           SET sms_limit = 0
         WHERE abonament_expiry <= CURRENT_DATE
           AND sms_limit <> 0
         RETURNING id, email
      )
      SELECT a.id       AS user_id,
             a.email    AS user_email,
             COALESCE(septic.phone, anydev.phone) AS sms_phone
        FROM affected a
        -- pierwszy numer z urządzeń typu "septic"
        LEFT JOIN LATERAL (
          SELECT phone
            FROM devices
           WHERE user_id = a.id
             AND device_type = 'septic'
             AND phone IS NOT NULL
           ORDER BY created_at ASC NULLS LAST
           LIMIT 1
        ) AS septic ON TRUE
        -- fallback: pierwszy numer z dowolnego urządzenia
        LEFT JOIN LATERAL (
          SELECT phone
            FROM devices
           WHERE user_id = a.id
             AND phone IS NOT NULL
           ORDER BY created_at ASC NULLS LAST
           LIMIT 1
        ) AS anydev ON TRUE
    `;
    const { rows: affected } = await db.query(q);
    console.log(`✅ Zresetowano sms_limit=0 u ${affected.length} użytkowników`);

    if (affected.length === 0) {
      return; // pool zamknie się w finally
    }

    // (opcjonalnie) dla spójności, wyzeruj sms_limit także w devices powiązanych z tymi userami
    // — nie jest to używane produkcyjnie, ale pomaga uniknąć mylących odczytów w starych miejscach.
    await db.query(`
      UPDATE devices d
         SET sms_limit = 0
        WHERE d.user_id IN (
          SELECT id FROM users WHERE abonament_expiry <= CURRENT_DATE
        )
    `).catch(()=>{});

    // 2) Powiadomienia per user
    const smsMsg = '⛔ Pakiet SMS wygasł. Aby nadal otrzymywać alerty, kup pakiet 30 SMS w aplikacji.';
    for (const u of affected) {
      const phone = normalisePhone(u.sms_phone);
      if (phone) {
        try { await sendSMS(phone, smsMsg, 'abonament_expired'); }
        catch (e) { console.warn(`⚠️ SMS fail for ${u.user_id}/${phone}:`, e.message); }
      } else {
        console.log(`ℹ️  User ${u.user_id} nie ma telefonu – pomijam SMS`);
      }

      // e-mail do usera + kopia do biura
      if (u.user_email && transporter) {
        const html = `
          <div style="font-family:Arial,sans-serif;font-size:15px;color:#333">
            <p>Twoj pakiet SMS wygasł (abonament do: ${new Date().toISOString().slice(0,10)} lub wcześniej).</p>
            <p>Aby nadal otrzymywać powiadomienia SMS, wykup nowy pakiet w aplikacji TechioT (30 SMS / 50 zł).</p>
            <p style="color:#777;font-size:12px">Jeżeli to pomyłka – prosimy o kontakt.</p>
          </div>
        `;
        try { await sendEmail(transporter, u.user_email, '⛔ Pakiet SMS wygasł – TechioT', html, ['biuro@techiot.pl']); }
        catch (e) { console.warn(`⚠️ E-mail fail for ${u.user_email}:`, e.message); }
      }
    }
  } catch (err) {
    console.error('❌ Błąd w jobie decrement-abonament:', err);
  } finally {
    await db.end();
  }
})();

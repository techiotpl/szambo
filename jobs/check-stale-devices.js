// jobs/check-stale-devices.js
/**
 * Watchdog nieaktywności urządzeń:
 *  - obsługuje device_type: septic | leak | co
 *  - używa dedykowanych numerów telefonów:
 *      septic → phone, phone2
 *      leak   → leak_phone1, leak_phone2 (fallback: phone, phone2)
 *      co     → co_phone1, co_phone2     (fallback: phone, phone2)
 *  - korzysta z GLOBALNEGO limitu SMS w users.sms_limit (atomowe zużycie)
 *  - ostatni uplink: GREATEST(ts_seen, *_last_uplink_ts, ostatni pomiar z measurements)
 *  - pętla wysyła 1 alert na „falę nieaktywności”; reset ma zrobić backend przy kolejnym uplinku
 */

const { Pool } = require('pg');
const axios = require('axios');
const nodemailer = require('nodemailer');
require('dotenv').config();

const HRS = parseInt(process.env.STALE_HOURS || '48', 10); // próg braku odpowiedzi

/* ───────── helpers ───────── */

function normalisePhone(p) {
  if (!p) return null;
  const s = String(p).replace(/\s+/g, '');
  if (s.length < 9) return null;
  return s.startsWith('+48') ? s : '+48' + s;
}

async function sendSMS(phone, msg) {
  const { SMSAPIKEY: key, SMSAPIPASSWORD: pwd } = process.env;
  if (!key || !pwd) throw new Error('SMS keys missing');
  const url = `https://api2.smsplanet.pl/sms?key=${key}&password=${pwd}&from=techiot.pl&to=${encodeURIComponent(
    phone
  )}&msg=${encodeURIComponent(msg)}`;
  const r = await axios.post(url, null, { headers: { Accept: 'application/json' } });
  if (r.status !== 200) throw new Error('SMS HTTP ' + r.status);
}

async function sendEmail(to, subject, html) {
  const mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '465', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    tls: { rejectUnauthorized: false },
  });
  await mailer.sendMail({ from: process.env.SMTP_FROM, to, subject, html });
}

// atomowe zużycie 1 SMS z puli użytkownika; zwraca nową wartość lub null przy braku środków
async function consumeSms(db, userId, count = 1) {
  const sql = `
    UPDATE users
       SET sms_limit = sms_limit - $2
     WHERE id = $1::uuid
       AND sms_limit >= $2
     RETURNING sms_limit`;
  const r = await db.query(sql, [userId, count]);
  return r.rowCount ? r.rows[0].sms_limit : null;
}

/* ───────── main ───────── */

(async () => {
  console.log('▶️  check-stale-devices starting… HRS =', HRS);

  const db = new Pool({ connectionString: process.env.DATABASE_URL });

  try {
    // 0) miękka migracja: flaga, że alert wysłany
    await db.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS stale_alert_sent BOOLEAN DEFAULT FALSE`);

    // 1) pobierz urządzenia, których "ostatnio widziane" < HRS
    //    używamy GREATEST(ts_seen, *_last_uplink_ts, ostatni pomiar z measurements)
    const sql = `
      WITH devs AS (
        SELECT
          d.id, d.user_id, d.serial_number, d.device_type,
          d.name,
          d.do_not_disturb,
          d.alert_email,
          d.phone, d.phone2,
          d.co_phone1, d.co_phone2,
          d.leak_phone1, d.leak_phone2,
          d.stale_alert_sent,
          GREATEST(
            COALESCE(NULLIF(d.params->>'ts_seen','')::timestamptz, 'epoch'::timestamptz),
            COALESCE(d.co_last_uplink_ts,  'epoch'::timestamptz),
            COALESCE(d.leak_last_uplink_ts,'epoch'::timestamptz),
            COALESCE(m.last_measurement_ts,'epoch'::timestamptz)
          ) AS last_seen_ts
        FROM devices d
        LEFT JOIN LATERAL (
          SELECT MAX(ts) AS last_measurement_ts
          FROM measurements m
          WHERE m.device_serial = d.serial_number
        ) m ON TRUE
      )
      SELECT *
      FROM devs
      WHERE (
              last_seen_ts = 'epoch'::timestamptz
           OR last_seen_ts < now() - interval '${HRS} hours'
            )
        AND COALESCE(stale_alert_sent, FALSE) = FALSE
    `;
    const { rows } = await db.query(sql);

    if (!rows.length) {
      console.log('✅ Brak nieodpowiadających urządzeń');
      return;
    }

    console.log(`⚠️  Znaleziono ${rows.length} urządzeń bez uplinku > ${HRS}h`);

    for (const d of rows) {
      const type = String(d.device_type || 'septic').toLowerCase();
      const lastSeen = d.last_seen_ts ? new Date(d.last_seen_ts).toISOString() : 'brak danych';
      const titleByType = {
        septic: 'Czujnik szamba nie odpowiada',
        leak:   'Czujnik zalania nie odpowiada',
        co:     'Czujnik CO nie odpowiada',
      };
      const smsTxtByType = {
        septic: `⚠️ ${titleByType.septic} od ponad ${HRS}h (EUI ${d.serial_number}). Sprawdź antenę i zasilanie.`,
        leak:   `⚠️ ${titleByType.leak} od ponad ${HRS}h (EUI ${d.serial_number}). Sprawdź czujnik i zasięg.`,
        co:     `⚠️ ${titleByType.co} od ponad ${HRS}h (EUI ${d.serial_number}). Sprawdź czujnik i zasięg.`,
      };

      const emailSubj = `⚠️ ${titleByType[type] || titleByType.septic}`;
      const emailHtml = `
        <div style="font-family:Arial,sans-serif;font-size:15px;color:#333">
          <h2>${emailSubj}</h2>
          <p>Urządzenie <b>${d.name || '(bez nazwy)'} – ${d.serial_number}</b> nie wysłało żadnego uplinku od ponad <b>${HRS}h</b>.</p>
          <ul>
            <li>Ostatnio widziane: ${lastSeen}</li>
            <li>Typ: ${type.toUpperCase()}</li>
          </ul>
          <p>Zalecenia: sprawdź antenę, zasilanie i miejsce montażu.</p>
          <p style="color:#888;font-size:12px">Wiadomość automatyczna – prosimy nie odpowiadać.</p>
        </div>
      `;

      // dobór numerów wg typu (z fallbackiem do standardowych phone/phone2)
      const typedNumbers =
        type === 'co'
          ? [normalisePhone(d.co_phone1), normalisePhone(d.co_phone2)]
          : type === 'leak'
            ? [normalisePhone(d.leak_phone1), normalisePhone(d.leak_phone2)]
            : [normalisePhone(d.phone), normalisePhone(d.phone2)];

      const fallbackNumbers = [normalisePhone(d.phone), normalisePhone(d.phone2)];
      const numbers = [...new Set([...typedNumbers.filter(Boolean), ...fallbackNumbers.filter(Boolean)])];

      const DND = d.do_not_disturb === true || d.do_not_disturb === 't';
      let anySent = false;

      // SMS — respektuj DND
      if (numbers.length && !DND) {
        for (const n of numbers) {
          // atomowe zużycie puli
          const left = await consumeSms(db, d.user_id, 1);
          if (left === null) {
            console.log(`⛔ Brak środków SMS (user=${d.user_id}) → pomijam wysyłkę do ${n}`);
            break; // brak środków – nie próbujemy kolejnych numerów
          }
          try {
            await sendSMS(n, smsTxtByType[type] || smsTxtByType.septic);
            console.log(`📨 SMS → ${n} (left=${left}) [${d.serial_number}]`);
            anySent = true;
          } catch (e) {
            // oddaj kredyt przy błędzie wysyłki (best effort)
            await db.query('UPDATE users SET sms_limit = sms_limit + 1 WHERE id = $1', [d.user_id]).catch(()=>{});
            console.error(`❌ SMS error to ${n}:`, e.message || e);
          }
        }
      } else if (DND) {
        console.log(`ℹ️ DND=true → nie wysyłam SMS (serial=${d.serial_number})`);
      } else {
        console.log(`ℹ️ Brak numerów telefonu dla ${d.serial_number}`);
      }

      // E-mail — też respektuj DND (jeśli chcesz, usuń warunek !DND)
      if (d.alert_email && !DND) {
        try {
          await sendEmail(d.alert_email, emailSubj, emailHtml);
          console.log(`✉️  E-mail → ${d.alert_email} [${d.serial_number}]`);
          anySent = true;
        } catch (e) {
          console.error('❌ E-mail error:', e.message || e);
        }
      } else if (d.alert_email && DND) {
        console.log(`ℹ️ DND=true → nie wysyłam e-maila (serial=${d.serial_number})`);
      }

      // ustaw flagę tylko jeśli faktycznie coś wysłano
      if (anySent) {
        await db.query('UPDATE devices SET stale_alert_sent = TRUE WHERE id = $1', [d.id]);
        console.log(`✅ stale_alert_sent=TRUE → ${d.serial_number}`);
      } else {
        console.log(`↩️  Nic nie wysłano (DND/brak kontaktu) → flaga NIE ustawiona [${d.serial_number}]`);
      }
    }

    console.log('🏁 Done.');
  } catch (err) {
    console.error('❌ check-stale-devices failed:', err);
  }
})();

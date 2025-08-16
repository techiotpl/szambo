// handlers/leak.js
const axios = require('axios');

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment, sendSmsWithQuota } = utils;
  const obj = body.object || {};
  const now = moment();

  // ---- 1) Parsowanie statusu i baterii ---------------------------------
  let leak = false;
  let src = 'unknown';
  let raw = null;

  if (Object.prototype.hasOwnProperty.call(obj, 'leak')) {
    leak = obj.leak === 1 || obj.leak === '1' || obj.leak === true;
    src = 'leak';
    raw = obj.leak;
  } else if (Object.prototype.hasOwnProperty.call(obj, 'leakage_status')) {
    const s = String(obj.leakage_status).toLowerCase();
    leak = (s === 'leak' || s === 'alarm' || s === 'alert');
    src = 'leakage_status';
    raw = obj.leakage_status;
  }

  const battV = obj.voltage !== undefined && obj.voltage !== null ? Number(obj.voltage) : null;

  console.log(`[LEAK] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  console.log(`[LEAK] PARSED serial=${dev.serial_number} leak=${leak} (src=${src}, val=${raw}) battV=${battV ?? 'n/a'} prev=${dev.leak_status === true}`);

  const prev = dev.leak_status === true;
  const changed = leak !== prev;

  // ---- 2) Helpery do Twilio CALL ---------------------------------------
  const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
  const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
  const TWILIO_FLOW_SID = process.env.TWILIO_FLOW_SID;
  const TWILIO_FROM = process.env.TWILIO_FROM;

  function normalizeE164(num) {
    const digits = String(num || '').replace(/[^\d+]/g, '');
    if (!digits) return null;
    return digits.startsWith('+') ? digits : `+48${digits}`;
  }

  async function sendTwilioCall(toRaw) {
    try {
      if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FLOW_SID || !TWILIO_FROM) {
        console.log('[LEAK] Twilio: brak konfiguracji env – pomijam CALL');
        return false;
      }

      const to = normalizeE164(toRaw);
      if (!to) {
        console.log('[LEAK] Twilio: brak poprawnego numeru – pomijam CALL');
        return false;
      }

      const url = `https://studio.twilio.com/v2/Flows/${TWILIO_FLOW_SID}/Executions`;
      const payload = new URLSearchParams({
        To: to,
        From: TWILIO_FROM
      }).toString();

      const resp = await axios.post(url, payload, {
        auth: {
          username: TWILIO_ACCOUNT_SID,
          password: TWILIO_AUTH_TOKEN
        },
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
      });

      console.log(`[LEAK] Twilio CALL OK → to=${to}, executionSid=${resp.data?.sid || '?'}`);
      return true;
    } catch (e) {
      const msg = e.response?.data ? JSON.stringify(e.response.data) : e.message;
      console.error(`[LEAK] Twilio CALL ERR → ${msg}`);
      return false;
    }
  }

  // ---- 3) Akcja tylko przy zmianie normal → leak ------------------------
  if (changed) {
    console.log(`[LEAK] CHANGE ${dev.serial_number}: ${prev} → ${leak}`);
  }

  if (changed && leak === true) {
    try {
      // a) globalny status abonamentu usera (SMS limit + czy wygasł)
      const { rows: [u] } = await db.query(
        `SELECT sms_limit,
                abonament_expiry,
                (abonament_expiry IS NOT NULL AND abonament_expiry < CURRENT_DATE) AS expired
           FROM users
          WHERE id = $1`,
        [dev.user_id]
      );
      if (!u) { console.log('[LEAK] SKIP – user not found for device', dev.id); return; }
      if (u.expired === true) {
        console.log(\`[LEAK] SKIP – abonament expired for user=\${dev.user_id} (expiry=\${u.abonament_expiry || 'NULL'})\`);
        return;
      }

      // b) 1. zarejestrowany numer z urządzenia typu "septic"
      const { rows: phones } = await db.query(
        `SELECT phone
           FROM devices
          WHERE user_id = $1
            AND device_type = 'septic'
            AND phone IS NOT NULL AND LENGTH(TRIM(phone)) > 0
          ORDER BY created_at ASC
          LIMIT 1`,
        [dev.user_id]
      );
      const phone = phones.length ? normalisePhone(phones[0].phone) : null;
      if (!phone) {
        console.log(\`[LEAK] SKIP – brak zarejestrowanego numeru (septic) u user_id=\${dev.user_id}\`);
        return;
      }

      // c) treść
      const devName = (dev.name && String(dev.name).trim().length) ? String(dev.name).trim() : dev.serial_number;
      const smsMsg  = \`Wykryto zalanie – \${devName}. Sprawdź natychmiast!\`;

      // d) SMS z globalnej puli (users.sms_limit)
      const ok = await sendSmsWithQuota(db, dev.user_id, phone, smsMsg, 'leak');
      if (!ok) { console.log(\`[LEAK] SKIP – brak SMS w globalnej puli user=\${dev.user_id}\`); return; }
      await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
      console.log(\`[LEAK] SMS sent (global quota) → \${phone}\`);

      // e) po SMS – telefon (Twilio) na ten sam numer
      const callOk = await sendTwilioCall(phone);
      if (callOk) {
        await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
      }
    } catch (e) {
      console.error('[LEAK] ALERT block error:', e);
    }
  }

  // ---- 4) Aktualizacja statusu/baterii w DB -----------------------------
  try {
    if (changed) {
      await db.query(
        `UPDATE devices 
         SET leak_status = $1, leak_last_change_ts = now(), battery_v = COALESCE($2, battery_v) 
         WHERE id = $3`,
        [leak, battV, dev.id]
      );
    } else if (battV !== null) {
      await db.query(
        'UPDATE devices SET battery_v = $1 WHERE id = $2',
        [battV, dev.id]
      );
    }
  } catch (e) {
    console.error('[LEAK] DB update error:', e);
  }

  // ---- 5) SSE do frontu -------------------------------------------------
  sendEvent({
    serial: dev.serial_number,
    leak,
    battery_v: battV,
    ts: now.toISOString()
  });
};

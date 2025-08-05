// handlers/leak.js
const axios = require('axios');

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

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

  const battV = obj.voltage !== undefined && obj.voltage !== null
    ? Number(obj.voltage)
    : null;

  console.log(`[LEAK] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  console.log(
    `[LEAK] PARSED serial=${dev.serial_number} leak=${leak} (src=${src}, val=${raw}) battV=${battV ?? 'n/a'} prev=${dev.leak_status === true}`
  );

  const prev = dev.leak_status === true;
  const changed = leak !== prev;

  // ---- 2) Helpery do Twilio CALL ---------------------------------------
  const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
  const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN;
  const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID;
  const TWILIO_FROM        = process.env.TWILIO_FROM;

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
      const payload = new URLSearchParams({ To: to, From: TWILIO_FROM }).toString();

      const resp = await axios.post(url, payload, {
        auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
      // a) Znajdź „dawcę” pakietu SMS (preferuj septic, z dodatnim sms_limit)
      const donorSql = `
        SELECT id, device_type, phone, sms_limit
          FROM devices
         WHERE user_id = $1
           AND sms_limit > 0
         ORDER BY CASE WHEN device_type = 'septic' THEN 0 ELSE 1 END, created_at
         LIMIT 1`;
      const { rows: donors } = await db.query(donorSql, [dev.user_id]);

      if (!donors.length) {
        console.log(`[LEAK] SKIP SMS/CALL – brak urządzeń z dodatnim sms_limit u user_id=${dev.user_id}`);
      } else {
        const donor = donors[0];
        const phone = donor.phone ? normalisePhone(donor.phone) : null;

        if (!phone) {
          console.log(`[LEAK] SKIP SMS/CALL – dawca ${donor.id} nie ma numeru telefonu`);
        } else {
          // b) Tekst i nazwa urządzenia
          const devName = (dev.name && String(dev.name).trim().length)
            ? String(dev.name).trim()
            : dev.serial_number;
          const smsMsg = `Wykryto zalanie – ${devName}. Sprawdź natychmiast!`;

          // c) SMS + dekrement u dawcy
          let smsSent = false;
          try {
            await sendSMS(phone, smsMsg, 'leak');
            await db.query('UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1', [donor.id]);
            await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
            smsSent = true;
            console.log(`[LEAK] SMS sent via donor ${donor.id} (type=${donor.device_type}) → ${phone}`);
          } catch (e) {
            console.error('[LEAK] SMS error:', e);
          }

          // d) CALL (Twilio) – tylko jeśli SMS poszedł OK
          if (smsSent) {
            const callOk = await sendTwilioCall(phone);
            if (callOk) {
              // (opcjonalnie) znacznik ostatniego alertu
              await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
            }
          } else {
            console.log('[LEAK] CALL skipped – SMS nie został wysłany');
          }
        }
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
            SET leak_status = $1,
                leak_last_change_ts = now(),
                battery_v = COALESCE($2, battery_v)
          WHERE id = $3`,
        [leak, battV, dev.id]
      );
    } else if (battV !== null) {
      await db.query(
        `UPDATE devices
            SET battery_v = $1
          WHERE id = $2`,
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

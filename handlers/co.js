// handlers/co.js
const axios = require('axios');

// Twilio (CALL po SMS)
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN  || '';
const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID    || '';
const TWILIO_FROM        = process.env.TWILIO_FROM        || '';

function toBool(v) {
  if (v === true || v === 1 || v === '1') return true;
  if (typeof v === 'string') return ['true','t','yes','y','on'].includes(v.toLowerCase());
  return false;
}

function normalizeE164(num) {
  const digits = String(num || '').replace(/[^\d+]/g, '');
  if (!digits) return null;
  return digits.startsWith('+') ? digits : `+48${digits}`;
}

async function twilioCallOnce(toRaw) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FLOW_SID || !TWILIO_FROM) {
    console.log('[CO] Twilio env not set – skip CALL');
    return false;
  }
  try {
    const to = normalizeE164(toRaw);
    if (!to) return false;

    const url = `https://studio.twilio.com/v2/Flows/${TWILIO_FLOW_SID}/Executions`;
    const payload = new URLSearchParams({ To: to, From: TWILIO_FROM }).toString();
    const resp = await axios.post(url, payload, {
      auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000
    });
    console.log(`[CO] Twilio CALL OK → ${to}, sid=${resp.data?.sid || '?'}`);
    return true;
  } catch (e) {
    console.error('[CO] Twilio CALL ERR', e.response?.data || e.message);
    return false;
  }
}

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendEvent, normalisePhone, moment, sendSmsWithQuota } = utils;

  const obj = body.object || {};
  const now = moment();

  // 1) odczyt alarmu / ppm / batt
  let alarm = false;
  let src = '';
  if ('co_alarm' in obj && toBool(obj.co_alarm)) { alarm = true; src = 'co_alarm'; }
  else if (typeof obj.co_status === 'string') {
    const s = obj.co_status.toLowerCase();
    if (s === 'alarm')  { alarm = true;  src = 'co_status'; }
    if (s === 'normal') { alarm = false; src = 'co_status'; }
  }
  const ppm   = obj.co_ppm != null ? Number(obj.co_ppm) : null;
  const battV = obj.voltage != null ? Number(obj.voltage) : null;

  // jeżeli brak jawnego alarmu, to sprawdź próg z DB
  if (!src && ppm != null) {
    const threshold = Number(dev.co_threshold_ppm || 50);
    alarm = ppm >= threshold;
    src = `ppm>=${threshold}`;
  }

  const prev = !!dev.co_status;
  const changed = alarm !== prev;

  // cooldown (opcjonalnie)
  const cooldownMin = dev.co_alert_cooldown_min || 180;
  const canAlert = !dev.co_last_alert_ts || now.diff(dev.co_last_alert_ts, 'minutes') >= cooldownMin;

  console.log(`[CO] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  console.log(`[CO] PARSED serial=${dev.serial_number} alarm=${alarm} (src=${src}) ppm=${ppm ?? 'n/a'} battV=${battV ?? 'n/a'} prev=${prev} canAlert=${canAlert}`);

  // 2) zmiana stanu → zapis + (ew.) alert
  if (changed) {
    console.log(`[CO] CHANGE ${dev.serial_number}: ${prev} → ${alarm}`);
    try {
      await db.query(
        `UPDATE devices
            SET co_status = $1,
                co_last_change_ts = now(),
                co_ppm = COALESCE($2, co_ppm),
                battery_v = COALESCE($3, battery_v)
          WHERE id = $4`,
        [alarm, ppm, battV, dev.id]
      );
    } catch (e) {
      console.error('[CO] DB update(change) error:', e);
    }

    // ALERT tylko przy przejściu w alarm i po cooldownie
    if (alarm && canAlert) {
      try {
        // a) sprawdź globalny abonament/limit
        const { rows: [u] } = await db.query(
          `SELECT sms_limit,
                  abonament_expiry,
                  (abonament_expiry IS NOT NULL AND abonament_expiry < CURRENT_DATE) AS expired
             FROM users
            WHERE id = $1`,
          [dev.user_id]
        );
        if (!u) {
          console.log('[CO] SKIP – user not found for device', dev.id);
          return;
        }
        if (u.expired === true) {
          console.log(`[CO] SKIP – abonament expired for user=${dev.user_id} (expiry=${u.abonament_expiry || 'NULL'})`);
          return;
        }

        // b) NUMERY: najpierw co_phone1/co_phone2 (oba, jeśli są), fallback: 1. numer z "septic"
        const targets = [dev.co_phone1, dev.co_phone2].map(normalisePhone).filter(Boolean);
        if (targets.length === 0) {
          const { rows: ph } = await db.query(
            `SELECT phone
               FROM devices
              WHERE user_id = $1
                AND device_type = 'septic'
                AND phone IS NOT NULL AND LENGTH(TRIM(phone)) > 0
              ORDER BY created_at ASC
              LIMIT 1`,
            [dev.user_id]
          );
          if (ph.length) targets.push(normalisePhone(ph[0].phone));
        }

        if (targets.length === 0) {
          console.log(`[CO] SKIP – brak docelowych numerów (co_phone1/co_phone2 ani septic) u user_id=${dev.user_id}`);
          return;
        }

        // c) treść
        const name = (dev.name && String(dev.name).trim().length) ? String(dev.name).trim() : dev.serial_number;
        const msg  = `ALARM CO: ${name}${ppm != null ? ` (${ppm} ppm)` : ''}. Natychmiast przewietrz i opuść pomieszczenie!`;

        // d) wyślij do KAŻDEGO numeru z listy; każdy SMS pobiera 1 z globalnej puli
        for (const to of targets) {
          const ok = await sendSmsWithQuota(db, dev.user_id, to, msg, 'co');
          if (!ok) {
            console.log(`[CO] SKIP SMS → brak SMS w globalnej puli (user=${dev.user_id})`);
            break; // skończyła się pula – przerwij
          }
          await db.query('UPDATE devices SET co_last_alert_ts = now() WHERE id = $1', [dev.id]);
          console.log(`[CO] SMS sent (global quota) → ${to}`);

          // CALL po udanym SMS na ten sam numer
          const callOk = await twilioCallOnce(to);
          if (callOk) {
            await db.query('UPDATE devices SET co_last_alert_ts = now() WHERE id = $1', [dev.id]);
          }
        }
      } catch (e) {
        console.error('[CO] ALERT block error:', e);
      }
    }
  } else {
    // bez zmiany – tylko update pól pomocniczych
    if (ppm != null || battV != null) {
      try {
        await db.query(
          'UPDATE devices SET co_ppm=COALESCE($1,co_ppm), battery_v=COALESCE($2,battery_v) WHERE id=$3',
          [ppm, battV, dev.id]
        );
      } catch (e) {
        console.error('[CO] DB update(no-change) error:', e);
      }
    }
  }

  // 3) SSE dla frontu
  sendEvent({
    serial: dev.serial_number,
    co: alarm,
    co_ppm: ppm,
    battery_v: battV,
    ts: now.toISOString()
  });
};

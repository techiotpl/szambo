// handlers/co.js
const axios = require('axios');

// Twilio (CALL po SMS)
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN  || '';
const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID    || '';
const TWILIO_FROM        = process.env.TWILIO_FROM        || '';

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

// Mapowanie poziomu baterii z 'energyStatus' na % (szacunek do UI)
function batteryLevelToPct(level) {
  if (!level) return null;
  const l = String(level).toLowerCase();
  if (l === 'high')     return 80; // >50%
  if (l === 'medium')   return 40; // 20–50%
  if (l === 'low')      return 8;  // 1–10%
  if (l === 'critical') return 1;  // <1%
  return null;
}

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendEvent, normalisePhone, moment, sendSmsWithQuota } = utils;

  const obj = body?.object || body?.data || body || {};
  const now = moment();
  const serial = String(dev.serial_number || dev.eui || dev.serial || '').toUpperCase();

    // === RESET watchdoga po KAŻDYM uplinku ===
  const tsIso =
    (body?.ts && new Date(body.ts).toISOString()) ||
    (body?.time && new Date(body.time).toISOString()) ||
    new Date().toISOString();
  await resetStaleAfterUplink(db, dev.id, tsIso);

  // ppm (priorytet: coConcentration.value)
  let ppm = null;
  if (obj.coConcentration && typeof obj.coConcentration === 'object' && obj.coConcentration.value != null) {
    ppm = Number(obj.coConcentration.value);
  } else if (obj.co_ppm != null) {
    ppm = Number(obj.co_ppm);
  } else if (obj.co != null) {
    ppm = Number(obj.co);
  }

  // battery
  const batteryLevel = obj.energyStatus || null;
  const batteryPct   = batteryLevelToPct(batteryLevel);
  const batteryMonthsLeft = (
    obj.remainingProductLifetime
    && typeof obj.remainingProductLifetime === 'object'
    && obj.remainingProductLifetime.value != null
  ) ? Number(obj.remainingProductLifetime.value) : null;

  const battV = obj.voltage != null ? Number(obj.voltage) : null;

  // stan poprzedni
  const prev = !!dev.co_status;
  let alarm = prev;

  // próg z urządzenia lub domyślny
  const threshold = Number(dev.co_threshold_ppm || 50);

  // logika wejścia w alarm
  if (ppm != null && ppm >= threshold) {
    alarm = true;
  }

  // reset przy ppm <= 5
  if (ppm != null && ppm <= 5 && prev === true) {
    alarm = false;
    await db.query(
      `UPDATE devices
          SET co_status = false,
              co_last_change_ts = now(),
              co_ppm = $1
        WHERE id = $2`,
      [ppm, dev.id]
    );
    console.log(`[CO] RESET alarm (ppm<=5) serial=${serial}`);
  }

  console.log(
    `[CO] RX ${serial} obj=${JSON.stringify(obj)} → alarm=${alarm} ppm=${ppm ?? 'n/a'} prev=${prev}`
  );

  // jeśli zmiana stanu
  if (alarm !== prev) {
    console.log(`[CO] CHANGE ${serial}: ${prev} → ${alarm}`);
    try {
      await db.query(
        `UPDATE devices
            SET co_status = $1,
                co_last_change_ts = now(),
                co_last_uplink_ts = now(),
                co_ppm = COALESCE($2, co_ppm),
                battery_v = COALESCE($3, battery_v)
          WHERE id = $4`,
        [alarm, ppm, battV, dev.id]
      );
    } catch (e) {
      console.error('[CO] DB update(change) error:', e);
    }

    // jeśli wchodzimy w alarm
    if (!prev && alarm) {
      try {
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
          console.log(`[CO] SKIP – abonament expired for user=${dev.user_id}`);
          return;
        }

        // numery do alarmu
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
          console.log(`[CO] SKIP – brak numerów docelowych u user_id=${dev.user_id}`);
          return;
        }

        const name = (dev.name && String(dev.name).trim().length)
          ? String(dev.name).trim()
          : serial;
        const msg  = `ALARM CO: ${name}${ppm != null ? ` (${ppm} ppm)` : ''}. Natychmiast przewietrz i opuść pomieszczenie!`;

        for (const to of targets) {
          const ok = await sendSmsWithQuota(db, dev.user_id, to, msg, 'co');
          if (!ok) {
            console.log(`[CO] SKIP SMS → brak SMS w globalnej puli (user=${dev.user_id})`);
            break;
          }
          await db.query('UPDATE devices SET co_last_alert_ts = now() WHERE id = $1', [dev.id]);
          console.log(`[CO] SMS sent → ${to}`);

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
    // brak zmiany – tylko update pól pomocniczych
    try {
      await db.query(
        `UPDATE devices
            SET co_last_uplink_ts = now(),
                co_ppm = COALESCE($1, co_ppm),
                battery_v = COALESCE($2, battery_v)
          WHERE id = $3`,
        [ppm, battV, dev.id]
      );
    } catch (e) {
      console.error('[CO] DB update(no-change) error:', e);
    }
  }

  // SSE do frontu
  sendEvent({
    serial,
    co: alarm,
    co_ppm: ppm,
    battery_v: battV,
    battery_level: batteryLevel,
    battery_level_pct: batteryPct,
    battery_months_left: batteryMonthsLeft,
    ts: tsIso
  });
};

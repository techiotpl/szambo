// handlers/co.js
const axios = require('axios');

// Twilio (CALL po SMS)
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN  || '';
const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID    || '';
const TWILIO_FROM        = process.env.TWILIO_FROM        || '';

function toBool(v) {
  if (v === true || v === 1 || v === '1') return true;
  if (typeof v === 'string') return ['true','t','yes','y','on','active'].includes(v.toLowerCase());
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

    // ChirpStack v4 codec zwraca zwykle { data, warnings, errors }.


  const obj = body?.object || body?.data || body || {};
  const now = moment();

  // ─────────────────────────────────────────────────────────────────────────────
  // 1) ODCZYT wartości wg Nexelec-decoder (poprawione):
  //    - alarm → z "localAlarm"/"preAlarm"
  //    - ppm   → z "coConcentration.value"
  //    - bateria → z "energyStatus" (string), bez zmiany battery_v w DB
  // ─────────────────────────────────────────────────────────────────────────────

  const typeMsg = (obj.typeOfMessage || '').toString();

  // ppm (priorytet: coConcentration.value)
  let ppm = null;
  if (obj.coConcentration && typeof obj.coConcentration === 'object' && obj.coConcentration.value != null) {
    // bywa, że value przychodzi jako string – Number() zadba o konwersję
    ppm = Number(obj.coConcentration.value);
  } else if (obj.co_ppm != null) {
    ppm = Number(obj.co_ppm);
  } else if (obj.co != null) {
    ppm = Number(obj.co); // legacy
  }

  // alarm – według CO Alarm Status
  let alarm = false;
  let src = '';
  if (typeMsg === 'CO Alarm Status') {
    // "localAlarm" jest kluczowy (właściwy alarm), "preAlarm" to stan wstępny ≥ 40 ppm
    if (typeof obj.localAlarm === 'string' && obj.localAlarm.toLowerCase() === 'active') {
      alarm = true; src = 'localAlarm';
    } else if (typeof obj.preAlarm === 'string' && obj.preAlarm.toLowerCase() === 'active') {
      // jeśli chcesz, aby pre-alarm też wyzwalał alarm → zostaw; jeśli nie, usuń ten blok
      alarm = true; src = 'preAlarm';
    }
  }

  // Jeśli nie wykryto jawnego źródła alarmu, użyj progu ppm (fallback – jak wcześniej)
  if (!src && ppm != null) {
    const threshold = Number(dev.co_threshold_ppm || 50);
    alarm = ppm >= threshold;
    src = `ppm>=${threshold}`;
  }

  // Bateria:
  //  • energyStatus: "High" | "Medium" | "Low" | "Critical"  → mapujemy na % (szacunek do UI)
  //  • remainingProductLifetime: { value: <miesiące>, unit: "month" } → przekażemy w SSE (bez zapisu do DB)
  const batteryLevel = obj.energyStatus || null;            // string lub null
  const batteryPct   = batteryLevelToPct(batteryLevel);     // 80/40/8/1 (% – przybliżenie)
  const batteryMonthsLeft = (
    obj.remainingProductLifetime
    && typeof obj.remainingProductLifetime === 'object'
    && obj.remainingProductLifetime.value != null
  ) ? Number(obj.remainingProductLifetime.value) : null;

  // Napięcie w V: zostawiamy jak było, jeśli przyjdzie "voltage", uaktualnimy battery_v; inaczej nie tykamy.
  const battV = obj.voltage != null ? Number(obj.voltage) : null;

  const prev = !!dev.co_status;
  const changed = alarm !== prev;

  // cooldown (opcjonalnie)
  const cooldownMin = dev.co_alert_cooldown_min || 180;
  const canAlert = !dev.co_last_alert_ts || now.diff(dev.co_last_alert_ts, 'minutes') >= cooldownMin;

  console.log(`[CO] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
    console.log(
    `[CO] PARSED serial=${dev.serial_number} `
     `alarm=${alarm} (src=${src}) `
     `ppm=${ppm ?? 'n/a'} `
     `battV=${battV ?? 'n/a'} `
     `energyStatus=${batteryLevel ?? 'n/a'} `
     `monthsLeft=${batteryMonthsLeft ?? 'n/a'} `
     `prev=${prev} canAlert=${canAlert}`
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // 2) Zmiana stanu → zapis + (ew.) alert
  // ─────────────────────────────────────────────────────────────────────────────
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

        // b) NUMERY: co_phone1/co_phone2 (oba, jeśli są), fallback: 1. numer z 'septic'
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

  // ─────────────────────────────────────────────────────────────────────────────
  // 3) SSE dla frontu — dodajemy battery_level (+ %), zostawiamy battery_v jak było
  // ─────────────────────────────────────────────────────────────────────────────
  sendEvent({
    serial: dev.serial_number,
    co: alarm,
    co_ppm: ppm,
    battery_v: battV,              // napięcie jeśli przyjdzie
    battery_level: batteryLevel,   // High/Medium/Low/Critical
       battery_level_pct: batteryPct, // szacunek dla UI
    battery_months_left: batteryMonthsLeft, // liczba miesięcy z remainingProductLifetime
    ts: now.toISOString()
  });
};

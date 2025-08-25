// handlers/leak.js
const axios = require('axios');

// ─────────────────────────────────────────────────────────────
// Uniwersalny czas uplinku (różne brokery / różne pola czasu)
function extractUplinkIso(body) {
  const c = [
    body?.time,
    body?.receivedAt,
    body?.uplink_received_at,
    body?.rxInfo?.[0]?.time,
    body?.rx_info?.[0]?.time,
    body?.object?.ts,
  ];
  for (const v of c) {
    if (!v) continue;
    const d = new Date(v);
    if (!Number.isNaN(d.getTime())) return d.toISOString();
  }
  return new Date().toISOString();
}

// ─────────────────────────────────────────────────────────────
// Reset 48h-watchdoga na KAŻDYM uplinku (niezależnie od payloadu)
async function resetStaleAfterUplink(db, deviceId, tsIso) {
  await db.query(
    `UPDATE devices
        SET stale_alert_sent = FALSE,
            params = COALESCE(params,'{}'::jsonb) || jsonb_build_object('ts_seen', $2::text)
      WHERE id = $1`,
    [deviceId, tsIso]
  );
}

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendEvent, normalisePhone, moment, sendSmsWithQuota } = utils;

  const obj = body?.object || body?.data || body || {};
  const now = moment();
  const serial = String(dev.serial_number || dev.eui || dev.serial || '').toUpperCase();

  // === RESET watchdoga po KAŻDYM uplinku ===
  const tsIso = extractUplinkIso(body);
  await resetStaleAfterUplink(db, dev.id, tsIso);

  // ── 1) Parsowanie statusu ────────────────────────────────────────────
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

  // ── 2) Bateria ───────────────────────────────────────────────────────
  // ChirpStack payload: { battery: 0..100 } oraz ewentualnie { voltage: "3.52" }
  // battery: % (0–100) lub rzadziej 0–1 → przeskalujmy; zaokrąglamy do int
  let batteryPct = null;
  if (obj.battery != null) {
    const n = Number(obj.battery);
    if (!Number.isNaN(n)) {
      batteryPct = n <= 1 ? Math.round(n * 100) : Math.round(Math.max(0, Math.min(100, n)));
    }
  }
  const battV = (obj.voltage != null && !Number.isNaN(Number(obj.voltage))) ? Number(obj.voltage) : null;

  // leak_status z DB bywa boolean albo 't'/'f' → znormalizuj
  const prev = (dev.leak_status === true || dev.leak_status === 't' || dev.leak_status === 'true');
  const changed = leak !== prev;

  console.log(`[LEAK] RX ${serial} obj=${JSON.stringify(obj)}`);
  console.log(`[LEAK] PARSED serial=${serial} leak=${leak} (src=${src}, val=${raw}) battV=${battV ?? 'n/a'} battery%=${batteryPct ?? 'n/a'} prev=${prev}`);

  // ── 3) Alert: tylko na przejściu normal → leak ───────────────────────
  if (changed && leak === true) {
    try {
      // a) globalny status abonamentu/limit
      const { rows: [u] } = await db.query(
        `SELECT sms_limit,
                abonament_expiry,
                (abonament_expiry IS NOT NULL AND abonament_expiry < CURRENT_DATE) AS expired
           FROM users
          WHERE id = $1`,
        [dev.user_id]
      );
      if (!u) { console.log('[LEAK] SKIP – user not found for device', dev.id); return; }
      if (u.expired === true || u.expired === 't') {
        console.log(`[LEAK] SKIP – abonament expired for user=${dev.user_id} (expiry=${u.abonament_expiry || 'NULL'})`);
        return;
      }

      // b) Preferuj odrębne numery dla leak: leak_phone1/leak_phone2
      let targets = [dev.leak_phone1, dev.leak_phone2].map(normalisePhone).filter(Boolean);



      if (targets.length === 0) {
        console.log(`[LEAK] SKIP – brak numerów docelowych (leak_phone1/2 ani septic) u user_id=${dev.user_id}`);
        return;
      }

      const devName = (dev.name && String(dev.name).trim().length) ? String(dev.name).trim() : serial;
      const smsMsg  = `Wykryto zalanie – ${devName}. Sprawdź natychmiast!`;

      // d) SMS (z globalnej puli) + CALL na każdy numer
      for (const to of targets) {
        const ok = await sendSmsWithQuota(db, dev.user_id, to, smsMsg, 'leak');
        if (!ok) {
          console.log(`[LEAK] SKIP SMS → brak SMS w globalnej puli (user=${dev.user_id})`);
          break; // skończyła się pula – przerywamy, aby nie dzwonić bez SMS
        }
        await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
        console.log(`[LEAK] SMS sent (global quota) → ${to}`);

        // CALL po udanym SMS – jak w CO
        await (async () => {
          try {
            const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
            const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN;
            const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID;
            const TWILIO_FROM        = process.env.TWILIO_FROM;

            const normalizeE164 = (num) => {
              const digits = String(num || '').replace(/[^\d+]/g, '');
              if (!digits) return null;
              return digits.startsWith('+') ? digits : `+48${digits}`;
            };

            if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FLOW_SID || !TWILIO_FROM) {
              console.log('[LEAK] Twilio: brak konfiguracji env – pomijam CALL');
              return;
            }
            const toE164 = normalizeE164(to);
            if (!toE164) return;

            const url = `https://studio.twilio.com/v2/Flows/${TWILIO_FLOW_SID}/Executions`;
            const payload = new URLSearchParams({ To: toE164, From: TWILIO_FROM }).toString();
            const resp = await axios.post(url, payload, {
              auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN },
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              timeout: 15000
            });
            console.log(`[LEAK] Twilio CALL OK → ${toE164}, sid=${resp.data?.sid || '?'}`);
            await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
          } catch (e) {
            console.error('[LEAK] Twilio CALL ERR', e.response?.data || e.message);
          }
        })();
      }
    } catch (e) {
      console.error('[LEAK] ALERT block error:', e);
    }
  }

  // ── 4) Aktualizacja w DB (ostatni uplink + zmiany) ────────────────────
  // Staramy się zapisać leak_last_uplink_ts = tsIso; jeżeli kolumny brak (42703), fallback bez niej.
  try {
    if (changed) {
      try {
        await db.query(
          `UPDATE devices
              SET leak_status = $1,
                  leak_last_change_ts = now(),
                  leak_last_uplink_ts = $2::timestamptz,
                  battery_v = COALESCE($3, battery_v)
            WHERE id = $4`,
          [leak, tsIso, battV, dev.id]
        );
      } catch (e) {
        if (e.code === '42703') {
          await db.query(
            `UPDATE devices
                SET leak_status = $1,
                    leak_last_change_ts = now(),
                    battery_v = COALESCE($2, battery_v)
              WHERE id = $3`,
            [leak, battV, dev.id]
          );
        } else {
          throw e;
        }
      }
    } else {
      try {
        await db.query(
          `UPDATE devices
              SET leak_last_uplink_ts = $1::timestamptz,
                  battery_v = COALESCE($2, battery_v)
            WHERE id = $3`,
          [tsIso, battV, dev.id]
        );
      } catch (e) {
        if (e.code === '42703') {
          await db.query(
            `UPDATE devices
                SET battery_v = COALESCE($1, battery_v)
              WHERE id = $2`,
            [battV, dev.id]
          );
        } else {
          throw e;
        }
      }
    }
  } catch (e) {
    console.error('[LEAK] DB update error:', e);
  }

  // ── 5) SSE do frontu ──────────────────────────────────────────────────
  sendEvent({
    serial,
    leak,
    battery_v: battV,
    battery_pct: batteryPct,   // % baterii z payloadu (jeśli był)
    ts: tsIso                  // „ostatni uplink” dla UI
  });
};

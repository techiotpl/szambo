// handlers/co.js
const axios = require('axios');

const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || '';
const TWILIO_AUTH_TOKEN  = process.env.TWILIO_AUTH_TOKEN  || '';
const TWILIO_FLOW_SID    = process.env.TWILIO_FLOW_SID    || '';
const TWILIO_FROM        = process.env.TWILIO_FROM        || '';

function toBool(v) {
  if (v === true || v === 1 || v === '1') return true;
  if (typeof v === 'string') return ['true','t','yes','y','on'].includes(v.toLowerCase());
  return false;
}

async function twilioCallOnce(toE164) {
  if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_FLOW_SID || !TWILIO_FROM) {
    console.log('[CO] Twilio env not set – skip CALL');
    return false;
  }
  try {
    const params = new URLSearchParams({ To: toE164, From: TWILIO_FROM });
    const url = `https://studio.twilio.com/v2/Flows/${TWILIO_FLOW_SID}/Executions`;
    const resp = await axios.post(url, params.toString(), {
      auth: { username: TWILIO_ACCOUNT_SID, password: TWILIO_AUTH_TOKEN },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000,
    });
    console.log(`[CO] Twilio CALL OK → ${toE164} sid=${resp.data?.sid || '?'}`);
    return true;
  } catch (e) {
    console.error('[CO] Twilio CALL ERR', toE164, e.response?.data || e.message);
    return false;
  }
}

module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

  const obj = body.object || {};
  const now = moment();

  // 1) odczyt co_status / co_alarm / ppm / batt
  let alarm = false, src = '';
  if ('co_alarm' in obj && toBool(obj.co_alarm)) { alarm = true; src = 'co_alarm'; }
  else if (typeof obj.co_status === 'string') {
    const s = obj.co_status.toLowerCase();
    if (s === 'alarm') { alarm = true; src = 'co_status'; }
    else if (s === 'normal') { alarm = false; src = 'co_status'; }
  }
  const ppm   = obj.co_ppm != null ? Number(obj.co_ppm) : null;
  const battV = obj.voltage ? Number(obj.voltage) : null;

  // 2) jeżeli brak jawnego alarmu, ale mamy ppm -> sprawdź próg z DB
  if (src === '' && ppm != null) {
    const threshold = Number(dev.co_threshold_ppm || 50);
    alarm = ppm >= threshold;
    src = `ppm>=${threshold}`;
  }

  // 3) cooldown (jak w leak) – ale my i tak wysyłamy TYLKO przy zmianie → tu tylko blok do CALL/SMS, jeśli potrzeba
  const cooldownMin = dev.co_alert_cooldown_min || 180;
  const canAlert = !dev.co_last_alert_ts || now.diff(dev.co_last_alert_ts, 'minutes') >= cooldownMin;

  console.log(`[CO] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  console.log(`[CO] PARSED serial=${dev.serial_number} alarm=${alarm} (src=${src}) ppm=${ppm ?? 'n/a'} battV=${battV ?? 'n/a'} prev=${!!dev.co_status} cooldown=${cooldownMin}m canAlert=${canAlert} last_alert=${dev.co_last_alert_ts || 'never'}`);

  // 4) zmiana stanu → zapis + (ew.) alert
  if (alarm !== !!dev.co_status) {
    console.log(`[CO] CHANGE ${dev.serial_number}: ${!!dev.co_status} → ${alarm}`);

    await db.query(
      `UPDATE devices
          SET co_status=$1,
              co_last_change_ts=now(),
              co_ppm = COALESCE($2, co_ppm),
              battery_v = COALESCE($3, battery_v)
        WHERE id=$4`,
      [ alarm, ppm, battV, dev.id ]
    );

    // WYŚLIJ ALERT TYLKO GDY PRZECHODZIMY W ALARM
    if (alarm && canAlert) {
      // odbiorcy – niezależni od septic (per-device)
      const nums = [dev.phone, dev.phone2].map(normalisePhone).filter(Boolean);
      const name = (dev.name && dev.name.trim()) ? dev.name : dev.serial_number;
      const msg  = `ALARM CO: ${name}${ppm != null ? ` (${ppm} ppm)` : ''}. Natychmiast przewietrz i opuść pomieszczenie!`;

      let smsSent = 0;
      if (nums.length && (dev.sms_limit == null || Number(dev.sms_limit) > 0)) {
        // SMS do wszystkich numerów – jeśli brak limitu, przepuszczamy (0 = zablokuj)
        try {
          for (const n of nums) {
            if (dev.sms_limit != null && Number(dev.sms_limit) <= 0) break;
            await sendSMS(n, msg, 'co');
            smsSent++;
            // zdejmujemy limit po każdym skutecznym SMS
            await db.query('UPDATE devices SET sms_limit = GREATEST(0,(COALESCE(sms_limit,0) - 1)) WHERE id=$1', [dev.id]);
          }
        } catch (e) {
          console.error('[CO] SMS ERR', e.message || e);
        }
      } else {
        console.log('[CO] SMS skipped (no numbers or sms_limit=0)');
      }

      // CALL tylko JEŚLI wysłaliśmy przynajmniej 1 SMS i (opcjonalnie) chcesz liczyć CALL do limitu
      if (smsSent > 0) {
        for (const n of nums) {
          const ok = await twilioCallOnce(n);
          if (ok) {
            // jeśli chcesz liczyć CALL do sms_limit – odkomentuj:
            // await db.query('UPDATE devices SET sms_limit = GREATEST(0,(COALESCE(sms_limit,0) - 1)) WHERE id=$1', [dev.id]);
          }
        }
      } else {
        console.log('[CO] CALL skipped (no prior SMS sent)');
      }

      await db.query('UPDATE devices SET co_last_alert_ts=now() WHERE id=$1', [dev.id]);
    }
  } else {
    // bez zmiany – tylko update pól pomocniczych
    if (ppm != null || battV != null) {
      await db.query(
        'UPDATE devices SET co_ppm=COALESCE($1,co_ppm), battery_v=COALESCE($2,battery_v) WHERE id=$3',
        [ppm, battV, dev.id]
      );
    }
  }

  // 5) SSE dla dashboardu / list
  sendEvent({
    serial: dev.serial_number,
    co: alarm,
    co_ppm: ppm,
    battery_v: battV,
    ts: now.toISOString(),
  });
};

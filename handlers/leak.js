// handlers/leak.js
module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

  const obj = body.object || {};
  const now = moment();

  // ───────────────── LOG: surowy payload ─────────────────
  try {
    console.log(`[LEAK] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  } catch (_) {
    console.log(`[LEAK] RX ${dev.serial_number} obj=<unstringifiable>`);
  }

  // ───────────────── 1) Parsowanie statusu ─────────────────
  // Akceptujemy kilka wariantów:
  //  • leak: 1 / "1" / true
  //  • leakage_status: "leak" | "normal" | "alarm" | "ok"
  //  • status/state: jw.
  let leak = false;
  let leakSrc = 'unknown';
  let rawVal = null;

  if (Object.prototype.hasOwnProperty.call(obj, 'leak')) {
    rawVal = obj.leak;
    leakSrc = 'leak';
    leak = rawVal === 1 || rawVal === '1' || rawVal === true || rawVal === 'true';
  } else {
    const statusStr = (
      obj.leakage_status ??
      obj.status ??
      obj.state ??
      ''
    ).toString().toLowerCase().trim();
    if (statusStr) {
      rawVal = statusStr;
      leakSrc = 'leakage_status';
      // zmapuj na boolean
      leak = ['leak', 'alarm', 'alert', 'wet', 'water'].includes(statusStr) ? true
           : ['normal', 'ok', 'dry', 'clear'].includes(statusStr) ? false
           : false; // default
    }
  }

  // ───────────────── 2) Napięcie baterii (fallbacki) ─────────────────
  // próbujemy kilku popularnych kluczy
  let battV = null;
  const battCandidates = ['voltage', 'battery', 'batt', 'vbat', 'battery_v'];
  for (const k of battCandidates) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') {
      const num = Number(obj[k]);
      if (!Number.isNaN(num)) {
        battV = num;
        break;
      }
    }
  }

  // ───────────────── 3) Anti-spam (cooldown) ─────────────────
  const cooldownMin = Number(dev.leak_alert_cooldown_min) || 180;
  const prevLeak = dev.leak_status === true || dev.leak_status === 't';
  const lastAlertTs = dev.leak_last_alert_ts ? moment(dev.leak_last_alert_ts) : null;
  const minutesSinceLast = lastAlertTs ? now.diff(lastAlertTs, 'minutes') : null;
  const canAlert = !lastAlertTs || minutesSinceLast >= cooldownMin;

  console.log(
    `[LEAK] PARSED serial=${dev.serial_number} leak=${leak} (src=${leakSrc}, val=${rawVal}) `
    + `battV=${battV ?? 'n/a'} prev=${prevLeak} cooldown=${cooldownMin}m `
    + `canAlert=${canAlert} last_alert=${dev.leak_last_alert_ts || 'none'}`
  );

  // ───────────────── 4) Zmiana statusu → zapis + (ew.) alert ─────────────────
  try {
    if (leak !== prevLeak) {
      console.log(`[LEAK] CHANGE ${dev.serial_number}: ${prevLeak} → ${leak}`);

      await db.query(
        `UPDATE devices
            SET leak_status=$1,
                leak_last_change_ts=now(),
                battery_v=$2
          WHERE id=$3`,
        [leak, battV, dev.id]
      );

      if (leak) {
        if (canAlert && dev.phone) {
          try {
            const num = normalisePhone(dev.phone);
            if (num) {
              await sendSMS(num, '💧 Wykryto zalanie – sprawdź natychmiast!', 'leak');
              await db.query('UPDATE devices SET leak_last_alert_ts=now() WHERE id=$1', [dev.id]);
              console.log(`[LEAK] SMS sent to ${num}`);
            } else {
              console.log('[LEAK] phone present but not normalisable – SMS skipped');
            }
          } catch (e) {
            console.error('[LEAK] SMS error:', e);
          }
        } else if (!canAlert) {
          console.log(`[LEAK] cooldown – skip SMS (${minutesSinceLast}m since last)`);
        } else {
          console.log('[LEAK] no phone – skip SMS');
        }
      }
    } else if (battV !== null) {
      // tylko update napięcia
      await db.query('UPDATE devices SET battery_v=$1 WHERE id=$2', [battV, dev.id]);
      console.log(`[LEAK] battV updated → ${battV} V`);
    }
  } catch (e) {
    console.error('[LEAK] DB update error:', e);
    // nie przerywamy — wyślemy chociaż SSE
  }

  // ───────────────── 5) SSE dla dashboardu ─────────────────
  try {
    sendEvent({
      serial: dev.serial_number,
      leak,
      battery_v: battV,
      leak_source: leakSrc,
      ts: now.toISOString(),
    });
    console.log(`[LEAK] SSE emitted leak=${leak} battV=${battV ?? 'n/a'}`);
  } catch (e) {
    console.error('[LEAK] SSE error:', e);
  }
};

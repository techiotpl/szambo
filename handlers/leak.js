// handlers/leak.js
module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

  const obj = body.object || {};
  const now = moment();

  // ───── helper: znajdź "ankrowe" urządzenie puli SMS (septic tego samego usera)
  async function getSmsAnchor() {
    try {
      const { rows } = await db.query(
        `SELECT id, phone, sms_limit
           FROM devices
          WHERE user_id = $1 AND device_type = 'septic'
          ORDER BY created_at ASC
          LIMIT 1`,
        [dev.user_id]
      );
      if (rows.length) return rows[0];
    } catch (e) {
      console.error('[LEAK] anchor lookup error:', e);
    }
    // fallback: sam czujnik (gdy brak septic)
    return { id: dev.id, phone: dev.phone, sms_limit: dev.sms_limit };
  }

  // ───────────────── LOG: surowy payload ─────────────────
  try {
    console.log(`[LEAK] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`);
  } catch (_) {
    console.log(`[LEAK] RX ${dev.serial_number} obj=<unstringifiable>`);
  }

  // ───────── 1) Parsowanie statusu zalania ─────────
  let leak = false;
  let leakSrc = 'unknown';
  let rawVal = null;

  if (Object.prototype.hasOwnProperty.call(obj, 'leak')) {
    rawVal = obj.leak;
    leakSrc = 'leak';
    leak = rawVal === 1 || rawVal === '1' || rawVal === true || rawVal === 'true';
  } else {
    const statusStr = (
      obj.leakage_status ?? obj.status ?? obj.state ?? ''
    ).toString().toLowerCase().trim();
    if (statusStr) {
      rawVal = statusStr;
      leakSrc = 'leakage_status';
      leak = ['leak', 'alarm', 'alert', 'wet', 'water'].includes(statusStr)
        ? true
        : ['normal', 'ok', 'dry', 'clear'].includes(statusStr)
        ? false
        : false;
    }
  }

  // ───────── 2) Napięcie baterii (kilka aliasów) ─────────
  let battV = null;
  for (const k of ['voltage', 'battery', 'batt', 'vbat', 'battery_v']) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== '') {
      const num = Number(obj[k]);
      if (!Number.isNaN(num)) { battV = num; break; }
    }
  }

  // ───────── 3) Cooldown (anty-spam) ─────────
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

  // ───────── 4) Zmiana statusu + SMS z puli "septic" ─────────
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
        // wyślij SMS z puli "septic"
        const anchor = await getSmsAnchor();
        const targetPhone = dev.phone || anchor.phone; // najpierw phone z czujnika, potem z septic

        if (!canAlert) {
          console.log(`[LEAK] cooldown – skip SMS (${minutesSinceLast}m since last)`);
        } else if (!targetPhone) {
          console.log('[LEAK] no phone on leak or septic – skip SMS');
        } else {
          // sprawdź i dekrementuj atomowo (bez zejścia poniżej 0)
          const num = normalisePhone(targetPhone);
          try {
            // najpierw „spróbuj” odjąć 1 (warunkowo)
            const dec = await db.query(
              `UPDATE devices
                  SET sms_limit = sms_limit - 1
                WHERE id = $1 AND sms_limit > 0
              RETURNING sms_limit`,
              [anchor.id]
            );
            if (dec.rowCount === 0) {
              console.log(`[LEAK] no SMS credits on anchor=${anchor.id} – skip SMS`);
            } else {
              // mamy kredyt → wyślij
              await sendSMS(num, '💧 Wykryto zalanie – sprawdź natychmiast!', 'leak');
              await db.query('UPDATE devices SET leak_last_alert_ts=now() WHERE id=$1', [dev.id]);
              console.log(`[LEAK] SMS sent to ${num}; credits_left=${dec.rows[0].sms_limit}`);
            }
          } catch (e) {
            console.error('[LEAK] SMS send/decrement error:', e);
            // (opcjonalnie) przywrócić 1 kredyt, jeśli chcesz „refund” na błąd wysyłki:
            // await db.query('UPDATE devices SET sms_limit = sms_limit + 1 WHERE id=$1', [anchor.id]);
          }
        }
      }
    } else if (battV !== null) {
      // tylko update napięcia
      await db.query('UPDATE devices SET battery_v=$1 WHERE id=$2', [battV, dev.id]);
      console.log(`[LEAK] battV updated → ${battV} V`);
    }
  } catch (e) {
    console.error('[LEAK] DB update error:', e);
  }

  // ───────── 5) SSE ─────────
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

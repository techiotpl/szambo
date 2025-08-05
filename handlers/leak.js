// handlers/leak.js
module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

  const obj = body.object || {};
  const now = moment();

  // 1) Parsowanie statusu i baterii
  //    Akceptujemy: leak=1 / "1" OR leakage_status: "leak"/"normal"
  let leak = false;
  let src = 'unknown';
  let raw = null;

  if (obj.hasOwnProperty('leak')) {
    leak = obj.leak === 1 || obj.leak === '1' || obj.leak === true;
    src = 'leak';
    raw = obj.leak;
  } else if (obj.hasOwnProperty('leakage_status')) {
    const s = String(obj.leakage_status).toLowerCase();
    leak = (s === 'leak' || s === 'alarm' || s === 'alert');
    src = 'leakage_status';
    raw = obj.leakage_status;
  }

  const battV = obj.voltage !== undefined && obj.voltage !== null
    ? Number(obj.voltage)
    : null;

  // 2) Log wejścia
  console.log(
    `[LEAK] RX ${dev.serial_number} obj=${JSON.stringify(obj)}`
  );
  console.log(
    `[LEAK] PARSED serial=${dev.serial_number} leak=${leak} (src=${src}, val=${raw}) battV=${battV ?? 'n/a'} prev=${dev.leak_status === true}`
  );

  // 3) Aktualizacja tylko napięcia (gdy brak zmiany statusu) – wykonamy na końcu
  //    (zapiszemy battery_v razem z ewentualnym statusem, by nie robić dwóch UPDATE)

  // 4) Detekcja zmiany statusu
  const prev = dev.leak_status === true; // PG boolean potrafi być 't' – dev już jest zmergowany do bool w PG driverze
  const changed = leak !== prev;

  // 5) Bazowy UPDATE: status + znaczniki czasu
  //    (leak_last_change_ts aktualizujemy tylko gdy zaszła zmiana)
  if (changed) {
    console.log(`[LEAK] CHANGE ${dev.serial_number}: ${prev} → ${leak}`);
  }

  // 6) Wyślij SMS TYLKO gdy przejście normal -> leak
  if (changed && leak === true) {
    try {
      // a) znajdź „dawcę” pakietu SMS: najpierw septic tego samego usera,
      //    a jeśli brak/0, to cokolwiek z dodatnim sms_limit
      const donorSql = `
        SELECT id, device_type, phone, sms_limit
          FROM devices
         WHERE user_id = $1
           AND sms_limit > 0
         ORDER BY CASE WHEN device_type = 'septic' THEN 0 ELSE 1 END, created_at
         LIMIT 1`;
      const { rows: donors } = await db.query(donorSql, [dev.user_id]);

      if (!donors.length) {
        console.log(`[LEAK] SKIP SMS – brak urządzeń z dodatnim sms_limit u user_id=${dev.user_id}`);
      } else {
        const donor = donors[0];
        const phone = donor.phone ? normalisePhone(donor.phone) : null;

        if (!phone) {
          console.log(`[LEAK] SKIP SMS – dawca ${donor.id} nie ma numeru telefonu`);
        } else {
          // b) zbuduj nazwę w komunikacie
          const devName = (dev.name && String(dev.name).trim().length)
            ? String(dev.name).trim()
            : dev.serial_number;

          const msg = `Wykryto zalanie – ${devName}. Sprawdź natychmiast!`;

          // c) wyślij i dekrementuj pakiet u dawcy
          await sendSMS(phone, msg, 'leak');
          await db.query('UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1', [donor.id]);

          // znacznik kiedy wysłaliśmy ostatni alert – tylko gdy naprawdę wysłaliśmy
          await db.query('UPDATE devices SET leak_last_alert_ts = now() WHERE id = $1', [dev.id]);
          console.log(`[LEAK] SMS sent via donor ${donor.id} (type=${donor.device_type}) → ${phone}`);
        }
      }
    } catch (e) {
      console.error('[LEAK] SMS error:', e);
    }
  }

  // 7) Zapisz status/baterię w urządzeniu „leak”
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

  // 8) SSE do dashboardu
  sendEvent({
    serial: dev.serial_number,
    leak,
    battery_v: battV,
    ts: now.toISOString()
  });
};

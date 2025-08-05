// handlers/septic.js
// ===========================================================================
// Obsługa uplinku dla urządzeń typu „septic” (czujnik szamba)
// Wywoływana z server.js:
//     await handlers[dev.device_type].handleUplink(utils, dev, req.body);
// utils  → { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment }
// dev    → wiersz z tabeli devices (WHERE serial_number = …)
// body   → pełne payload z ChirpStack
// ===========================================================================

module.exports.handleUplink = async function handleUplink(utils, dev, body) {
  const {
    db, sendSMS, sendEmail, sendEvent,
    normalisePhone, moment
  } = utils;

  const devEui = dev.serial_number;           // EUI / serial
  const obj    = body.object || {};           // część z dekodera
  const snr    = body.rxInfo?.[0]?.snr ?? null;

  // ───────────────────────────────── ISSUE = 1 ────────────────────────────
  if (Object.keys(obj).length === 1 && (obj.issue === 1 || obj.issue === '1')) {
    const iso   = new Date().toISOString();
    const limit = Number(dev.sms_limit) || 0;
    const msg   = 'czujnik zabrudzony, kolejny pomiar może być błędny – sprawdź czujnik';

    let smsSent = false;
    if (dev.phone && limit > 0) {
      const num = normalisePhone(dev.phone);
      if (num) {
        try {
          await sendSMS(num, msg, 'issue');
          smsSent = true;
          await db.query(
            'UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1',
            [dev.id]
          );
        } catch (err) { console.error('❌ issue SMS err:', err); }
      }
    }

    if (!smsSent && dev.alert_email) {
      try { await sendEmail(dev.alert_email, '🚨 Czujnik zabrudzony', `<p>${msg}</p>`); }
      catch (err) { console.error('❌ issue mail err:', err); }
    }

    // mail wewnętrzny
    try { await sendEmail('biuro@techiot.pl', `ISSUE(1) – ${devEui}`, `<p>${iso}</p>`); }
    catch (err) { /* ignore */ }

    sendEvent({ serial: devEui, issue: 1, ts: iso });
    return;                                     // KONIEC dla issue=1
  }

  // ───────────────────────────────── ZWYKŁY POMIAR ─────────────────────────
  const distance = obj.distance ?? null;        // cm
  const voltage  = obj.voltage  ?? null;        // V

  // blokada 23-6 (do_not_disturb)
  const hour = moment().tz('Europe/Warsaw').hour();
  const dnd  = dev.do_not_disturb === true || dev.do_not_disturb === 't';
  const isNight = (hour >= 23 || hour < 6);

  // zapisuj pomiar zawsze, jeżeli mamy distance
  if (distance !== null) {
    await db.query(
      'INSERT INTO measurements (device_serial, distance_cm, snr) VALUES ($1,$2,$3)',
      [devEui, distance, snr]
    );
  }

  if (dnd && isNight) {
    sendEvent({ serial: devEui, distance, voltage, snr, ts: new Date().toISOString() });
    return;                                     // DND: nic więcej nie robimy
  }

  if (distance === null) return;                // brak odległości → stop

  // aktualizacja devices + obliczenie flagi trigger_dist
  const varsToSave = {
    distance,
    snr,
    voltage,
    ts: new Date().toISOString()
  };

  const { rows:[row] } = await db.query(`
    UPDATE devices
       SET params       = coalesce(params,'{}') || $3::jsonb,
           distance_cm  = $2::int,
           last_measurement_ts = now(),
           trigger_measurement = FALSE,
           trigger_dist = CASE
                            WHEN $2::int <= red_cm THEN TRUE
                            WHEN $2::int >= red_cm THEN FALSE
                            ELSE trigger_dist
                          END
     WHERE id = $1
     RETURNING trigger_dist AS new_flag,
               red_cm, sms_limit, phone, phone2, tel_do_szambiarza,
               street, stale_alert_sent, alert_email
  `, [dev.id, distance, JSON.stringify(varsToSave)]);

  // jeżeli czujnik znowu nadaje – skasuj znacznik 72 h alertu
  if (row.stale_alert_sent) {
    await db.query('UPDATE devices SET stale_alert_sent = FALSE WHERE id=$1',[dev.id]);
  }

  // ─────────────── DETEKCJA OPRÓŻNIENIA (flaga TRUE → FALSE) ──────────────
  if (dev.trigger_dist && !row.new_flag) {
    await db.query(`
      UPDATE devices SET empty_cm = $1, empty_ts = now() WHERE id=$2;
      INSERT INTO empties (device_id, prev_cm, empty_cm, removed_m3, from_ts)
      VALUES ($2, $3, $1,
              ROUND(capacity * (1 - ($3::numeric / $1))::numeric,2),
              now());
      UPDATE devices
         SET last_removed_m3 = ROUND(capacity * (1 - ($3::numeric / $1))::numeric,2)
       WHERE id = $2;
    `, [distance, dev.id, dev.distance_cm]);

    // opcjonalny SMS „opróżniono”
    if (dev.sms_after_empty && row.sms_limit > 0 && dev.phone) {
      const num = normalisePhone(dev.phone);
      try {
        await sendSMS(num, '✅ Zbiornik opróżniony (maks. 4 h temu).', 'after_empty');
        await db.query('UPDATE devices SET sms_limit = sms_limit - 1 WHERE id=$1',[dev.id]);
      } catch (e) { /* ignore */ }
    }
  }

  // ─────────────── PRÓG ALARMOWY (flaga FALSE → TRUE) ─────────────────────
  if (!dev.trigger_dist && row.new_flag) {
    const toNumbers = [];
    if (row.phone)  toNumbers.push(normalisePhone(row.phone));
    if (row.phone2) toNumbers.push(normalisePhone(row.phone2));

    // SMS-y (jeśli mamy limit)
    let used = 0;
    const msgBase = `⚠️ Poziom w zbiorniku ${distance} cm (próg ${row.red_cm} cm)`;
    for (const num of toNumbers) {
      if (row.sms_limit - used <= 0) break;
      try { await sendSMS(num, msgBase, 'threshold'); used++; }
      catch (e) { console.error('SMS err', e); }
    }
    // SMS do szambiarza
    if (row.tel_do_szambiarza && row.sms_limit - used > 0) {
      const szam = normalisePhone(row.tel_do_szambiarza);
      const msg2 = `${row.street || '(brak adresu)'} – zbiornik pełny. Proszę o opróżnienie.`;
      try { await sendSMS(szam, msg2, 'szambiarz'); used++; }
      catch (e) { /* ignore */ }
    }
    if (used)
      await db.query('UPDATE devices SET sms_limit = sms_limit - $1 WHERE id=$2',[used, dev.id]);

    // e-mail
    if (row.alert_email) {
      const html = `<p>${msgBase}</p>`;
      try { await sendEmail(row.alert_email, '⚠️ Pełny zbiornik', html); }
      catch (e) { /* ignore */ }
    }
  }

  // ─────────────── SSE do front-endu ──────────────────────────────────────
  sendEvent({ serial: devEui, distance, voltage, snr, ts: varsToSave.ts });

  return;   // wszystko OK
};

// handlers/septic.js
// ===========================================================================
// Obsługa uplinku dla urządzeń typu „septic” (czujnik szamba)
// Wywoływana z server.js:
//     await handlers[dev.device_type].handleUplink(utils, dev, req.body);
// utils  → { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment }
// dev    → wiersz z tabeli devices (WHERE serial_number = …)
// body   → pełne payload z ChirpStack
// ===========================================================================


// Pomocnik: reset watchdoga na KAŻDYM uplinku (ts_seen + flaga)
async function resetStaleAfterUplink(db, deviceId, tsIso) {
  await db.query(
    `UPDATE devices
        SET stale_alert_sent = FALSE,
            params = COALESCE(params, '{}'::jsonb) || jsonb_build_object('ts_seen', $2)
      WHERE id = $1`,
    [deviceId, tsIso]
  );
}


module.exports.handleUplink = async function handleUplink(utils, dev, body) {
  const {
    db, sendSMS, sendEmail, sendEvent,
    normalisePhone, moment,
    sendSmsWithQuota, consumeSms
  } = utils;

  const devEui = dev.serial_number;           // EUI / serial
  const obj    = body.object || {};           // część z dekodera
  const snr    = body.rxInfo?.[0]?.snr ?? null;

  const keys        = Object.keys(obj || {});
  const issue0Only  = (keys.length === 1) && (obj.issue === 0 || obj.issue === '0');
  const issue1Only  = (keys.length === 1) && (obj.issue === 1 || obj.issue === '1');
  const nowIso      = new Date().toISOString();


  // === RESET watchdoga po KAŻDYM uplinku ===
  const tsIso =
    (body?.ts && new Date(body.ts).toISOString()) ||
    (body?.time && new Date(body.time).toISOString()) ||
    new Date().toISOString();
  await resetStaleAfterUplink(db, dev.id, tsIso);


  // ───────────────────────────── ISSUE = 1 (czujnik zabrudzony) ─────────────────────────────
  // To też jest uplink → aktualizujemy ts_seen, żeby UI/48h się odświeżyło.
  if (issue1Only) {
    
    const msg   = 'czujnik zabrudzony, kolejny pomiar może być błędny – sprawdź czujnik';

    // 1) zapisz status + ts_seen (+ snr) do params
    await db.query(
      `UPDATE devices
          SET params = COALESCE(params,'{}'::jsonb)
                       || jsonb_build_object('issue','1','issue_ts',$2::text,'ts_seen',$2::text)
                       || jsonb_strip_nulls(jsonb_build_object('snr',$3::numeric))
        WHERE id = $1`,
      [dev.id, nowIso, snr]
    );

    // 2) powiadomienia
    let smsSent = false;
    if (dev.phone) {
      const num = normalisePhone(dev.phone);
      if (num) {
        try {
smsSent = await sendSmsWithQuota(db, dev.user_id, num, msg, 'issue');
        } catch (err) { console.error('❌ issue SMS err:', err); }
      }
    }

    if (!smsSent && dev.alert_email) {
      try { await sendEmail(dev.alert_email, '🚨 Czujnik zabrudzony', `<p>${msg}</p>`); }
      catch (err) { console.error('❌ issue mail err:', err); }
    }

    // mail wewnętrzny (opcjonalny)
    try { await sendEmail('biuro@techiot.pl', `ISSUE(1) – ${devEui}`, `<p>${nowIso}</p>`); }
    catch (err) { /* ignore */ }

    // 3) SSE – podajemy ts_seen (i ts dla kompatybilności z frontem)
    sendEvent({ serial: devEui, issue: 1, issue_ts: nowIso, ts_seen: nowIso, ts: nowIso, snr });
    return;
  }




  // ───────────────────────────── ISSUE = 0 (zły pomiar) ─────────────────────────────
  // Reagujemy TYLKO, gdy to jedyne pole (brak distance/voltage).
  if (issue0Only) {
    await db.query(
      `UPDATE devices
          SET params = COALESCE(params,'{}'::jsonb)
                       || jsonb_build_object('issue','0','issue_ts',$2::text,'ts_seen',$2::text)
                       || jsonb_strip_nulls(jsonb_build_object('snr',$3::numeric))
        WHERE id = $1`,
      [dev.id, nowIso, snr]
    );
    // SSE – odśwież UI i 48h
    sendEvent({ serial: devEui, issue: 0, issue_ts: nowIso, ts_seen: nowIso, ts: nowIso, snr });
    return;
  }

  // ───────────────────────────────── ZWYKŁY POMIAR ─────────────────────────
  const distance = obj.distance ?? null;        // cm
  const voltage  = obj.voltage  ?? null;        // V

  // Jeżeli mamy odległość → zapisz punkt w measurements (z TS po stronie DB)
  if (distance !== null) {
    await db.query(
      'INSERT INTO measurements (device_serial, distance_cm, ts) VALUES ($1,$2, now())',
      [devEui, distance]
    );
  }

  // blokada 23-6 (do_not_disturb)
  const hour    = moment().tz('Europe/Warsaw').hour();
  const dnd     = dev.do_not_disturb === true || dev.do_not_disturb === 't';
  const isNight = (hour >= 23 || hour < 6);

  // DND: zaktualizuj tylko „stan bieżący” (params z ts/ts_seen), wyślij SSE i wyjdź.
  if (dnd && isNight) {
    const paramsNow = {
      distance,
      snr,
      voltage,
      ts: nowIso,        // ostatni „dobry” – tu także dobry
      ts_seen: nowIso    // „ostatnio widziany uplink”
    };
    await db.query(
      `UPDATE devices
          SET params = (COALESCE(params,'{}') - 'issue' - 'issue_ts') || $2::jsonb
        WHERE id = $1`,
      [dev.id, JSON.stringify(paramsNow)]
    );
    sendEvent({ serial: devEui, distance, voltage, snr, ts: nowIso, ts_seen: nowIso });
    return; // DND: nie liczymy progów, nie wysyłamy alertów
  }

  // Jeżeli mimo wszystko brak odległości → nic więcej nie robimy
  if (distance === null) {
    // (gdyby kiedyś przyszło voltage bez distance – nie countujemy progów itd.)
    return;
  }

  // aktualizacja devices + obliczenie flagi trigger_dist
  const varsToSave = {
    distance,
    snr,
    voltage,
    ts: nowIso,        // ostatni DOBRY
    ts_seen: nowIso    // ostatnio widziany uplink (tu też DOBRY)
  };

  const { rows:[row] } = await db.query(`
    UPDATE devices
       SET params              = (COALESCE(params,'{}') - 'issue' - 'issue_ts') || $3::jsonb,
           distance_cm         = $2::int,
           last_measurement_ts = now(),
           trigger_measurement = FALSE,
           trigger_dist        = CASE
                                   WHEN $2::int <= red_cm THEN TRUE
                                   WHEN $2::int >= red_cm THEN FALSE
                                   ELSE trigger_dist
                                 END
     WHERE id = $1
     RETURNING trigger_dist AS new_flag,
               red_cm, sms_limit, phone, phone2, tel_do_szambiarza,
               street, stale_alert_sent, alert_email
  `, [dev.id, distance, JSON.stringify(varsToSave)]);



  // ─────────────── DETEKCJA OPRÓŻNIENIA (flaga TRUE → FALSE) ──────────────
  if (dev.trigger_dist && !row.new_flag) {
    const client = await db.connect();
    try {
      await client.query('BEGIN');

      // 1) zapisz empty_cm/empty_ts
      await client.query(
        'UPDATE devices SET empty_cm = $1::int, empty_ts = now() WHERE id = $2::uuid',
        [distance, dev.id]
      );

      // 2) wstaw wpis do empties i policz removed_m3 na bazie capacity z devices
      const ins = await client.query(
        `INSERT INTO empties (device_id, prev_cm, empty_cm, removed_m3, from_ts)
         VALUES (
           $1::uuid,
           $2::int,
           $3::int,
           ROUND(
             (SELECT capacity::numeric FROM devices WHERE id = $1::uuid)
             * (1 - ($2::numeric / $3::numeric)),
             2
           ),
           now()
         )
         RETURNING removed_m3`,
        [dev.id, dev.distance_cm, distance]
      );
      const removedM3 = ins.rows[0].removed_m3;

      // 3) zaktualizuj last_removed_m3
      await client.query(
        'UPDATE devices SET last_removed_m3 = $1::numeric WHERE id = $2::uuid',
        [removedM3, dev.id]
      );

      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    // opcjonalny SMS „opróżniono”
    if (dev.sms_after_empty && dev.phone) {
      const num = normalisePhone(dev.phone);
      try {
    await sendSmsWithQuota(db, dev.user_id, num, '✅ Zbiornik opróżniony (maks. 4 h temu).', 'after_empty');
      } catch (e) { /* ignore */ }
    }
  }

  // ─────────────── PRÓG ALARMOWY (flaga FALSE → TRUE) ─────────────────────
  if (!dev.trigger_dist && row.new_flag) {
    const toNumbers = [];
    if (row.phone)  toNumbers.push(normalisePhone(row.phone));
    if (row.phone2) toNumbers.push(normalisePhone(row.phone2));

    // SMS-y (jeśli mamy limit)
   
    const msgBase = `⚠️ Poziom w zbiorniku ${distance} cm (próg ${row.red_cm} cm)`;
    for (const num of toNumbers) {
      if (!num) continue;
      try {
        const ok = await sendSmsWithQuota(db, dev.user_id, num, msgBase, 'threshold');
        if (!ok) break; // zabrakło SMS-ów w globalnej puli
      }
      catch (e) { console.error('SMS err', e); }
    }
    // SMS do szambiarza (spróbuj, jeśli są jeszcze SMS-y)
    if (row.tel_do_szambiarza) {
      const szam = normalisePhone(row.tel_do_szambiarza);
      if (szam) {
        const msg2 = `${row.street || '(brak adresu)'} – zbiornik pełny. Proszę o opróżnienie.`;
        try {
          await sendSmsWithQuota(db, dev.user_id, szam, msg2, 'szambiarz');
        } catch (e) { /* ignore */ }
      }
    }


    // e-mail
    if (row.alert_email) {
      const html = `<p>${msgBase}</p>`;
      try { await sendEmail(row.alert_email, '⚠️ Pełny zbiornik', html); }
      catch (e) { /* ignore */ }
    }
  }

  // ─────────────── SSE do front-endu ──────────────────────────────────────
  sendEvent({ serial: devEui, distance, voltage, snr, ts: nowIso, ts_seen: nowIso });

  return;   // wszystko OK
};

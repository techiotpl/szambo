module.exports.handleUplink = async function (
  utils,   // { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment }
  dev,     // wiersz z tabeli devices (device_type === 'septic')
  body     // całe req.body z ChirpStack
) {
  const {
    db, sendSMS, sendEmail, sendEvent,
    normalisePhone, moment
  } = utils;

  // ─────────────────────────────────────────────────────────────────────────────
// /uplink: odbiór pomiaru z ChirpStack → zapis do bazy + e-mail/SMS + SSE
// ─────────────────────────────────────────────────────────────────────────────
app.post('/uplink', async (req, res) => {
  try {
    /* 1) devEUI ---------------------------------------------------------- */
    const devEui = req.body.dev_eui
                 || req.body.devEUI
                 || req.body.deviceInfo?.devEui;
    if (!devEui) {
      console.log('🚫 [POST /uplink] Brak dev_eui w body');
      return res.status(400).send('dev_eui missing');
    }

/* 2) urządzenie w bazie --------------------------------------------- */
const dev = await db.query(
  `SELECT 
     id,
     distance_cm,        -- poprzedni pomiar [cm]
     empty_cm,           -- poziom „pustego” z params
     capacity,           -- objętość zbiornika [m³]
     phone, 
     phone2, 
     tel_do_szambiarza, 
     street,
     red_cm, 
     trigger_dist AS old_flag, 
     do_not_disturb,
     sms_limit,
     sms_after_empty,
     alert_email
   FROM devices
  WHERE serial_number = $1`,
  [devEui]
);

    if (!dev.rowCount) {
      console.log(`⚠️ [POST /uplink] Nieznane urządzenie: ${devEui}`);
      return res.status(404).send('Unknown device');
    }



    const d = dev.rows[0];
    /* 3) payload --------------------------------------------------------- */
    
    const obj      = req.body.object || {};

    /*────────────────  ISSUE‑ONLY payload  ──────────────────
      Uplink:
        "object": { "issue": 1 }
      → log, SMS (jeśli jest numer i sms_limit > 0) + decrement,
        inaczej fallback na e‑mail. Emitujemy też SSE.
    */
    if (Object.keys(obj).length === 1 && (obj.issue === 1 || obj.issue === '1')) {
      const iso = new Date().toISOString();
      const msg = ' czujnik zabrudzony, twoj kolejny pomiar moze byc falszywy – sprawdz czujnik';
      const limit = Number(d.sms_limit) || 0;

      console.warn(
        `🚨 ISSUE(1) flag received from ${devEui} (${iso}) phone=${d.phone || '-'} sms_limit=${limit}`
      );

      let smsSent = false;
      if (d.phone && limit > 0) {
        const num = normalisePhone(d.phone);
        if (num) {
          try {
            await sendSMS(num, msg, 'issue');
            smsSent = true;
            const { rows: [lim] } = await db.query(
              'UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1 RETURNING sms_limit',
              [d.id]
            );
            console.log(`📤 issue:1 → SMS sent to ${num}, new sms_limit=${lim.sms_limit}`);
          } catch (e) {
            console.error('❌ issue:1 SMS send error:', e);
          }
        } else {
          console.warn('⚠️ issue:1 → phone present but could not normalize');
        }
      } else {
        console.log(`ℹ️ issue:1 → SMS skipped (no phone or sms_limit=${limit})`);
      }

      if (!smsSent) {
        if (d.alert_email) {
          try {
            await sendEmail(
              d.alert_email,
              '🚨 Czujnik zabrudzony',
              `<p>${msg}</p>`
            );
            console.log(`✉️ issue:1 → email sent to ${d.alert_email}`);
          } catch (e) {
            console.error('❌ issue:1 e-mail send error:', e);
          }
        } else {
          console.warn('⚠️ issue:1 → no SMS and no alert_email – nothing sent');
        }
      }
      // dodatkowo: powiadomienie wewnętrzne
      try {
        await sendEmail(
          'biuro@techiot.pl',
          `ISSUE(1) – możliwy problem z czujnikiem ${devEui}`,
          `<p>Możliwy problem z czujnikiem o numerze seryjnym <b>${devEui}</b> (issue=1).<br/>Czas: ${iso}</p>`
        );
        console.log('✉️ issue:1 → email sent to biuro@techiot.pl');
      } catch (e) {
        console.error('❌ issue:1 internal email error:', e);
      }
      sendEvent({ serial: devEui, issue: 1, ts: iso });
      return res.send('OK (issue=1)');
    }

    const distance = obj.distance ?? null;  // cm
    const voltage  = obj.voltage  ?? null;  // V
    /* 3a) radio parameters ---------------------------------------------- */
const snr = req.body.rxInfo?.[0]?.snr ?? null;   // Helium-ChirpStack v4
      /* 3b) DND – blokujemy wysyłkę 23:00-6:00 */
    const hour = moment().tz('Europe/Warsaw').hour();     // lokalna godzina
    const dnd  = d.do_not_disturb === true || d.do_not_disturb === 't';
    if (dnd && (hour >= 23 || hour < 6)) {               // 6 = godzina testowa
      console.log(`🔕 [POST /uplink] DND active, skipping alerts for ${devEui}`);
    
  if (distance !== null) {                      // ✔︎ zapisuj tylko gdy jest pomiar
    await db.query(
      'INSERT INTO measurements (device_serial, distance_cm, snr) VALUES ($1,$2,$3)',
      [devEui, distance, snr]
   );
  }
      sendEvent({ serial: devEui, distance, voltage, snr, ts: new Date().toISOString() });
      return res.send('OK (DND)');
    }
    if (distance === null) {
      console.log(`ℹ️ [POST /uplink] Brak distance dla ${devEui}, pomijam`);
      return res.send('noop (no distance)');
    }
/* >>> TU DODAJ NOWĄ LINIKĘ – zapisujemy odczyt do measurements <<< */
await db.query(
  'INSERT INTO measurements (device_serial, distance_cm, snr) VALUES ($1,$2,$3)',
  [devEui, distance, snr]
);

    // dodajemy znacznik czasu ISO-8601
    const varsToSave = {
      distance,
      snr,
      voltage,
      ts: new Date().toISOString()
    };

    /* 4) zapis + obliczenie nowej flagi ---------------------------------- */
    const q = `
      UPDATE devices
         SET params       = coalesce(params,'{}'::jsonb) || $3::jsonb,
             distance_cm  = $2::int,
             last_measurement_ts   = now(),
             trigger_measurement   = FALSE,
             trigger_dist = CASE
                              WHEN $2::int <= red_cm THEN TRUE
                              WHEN $2::int >= red_cm THEN FALSE
                              ELSE trigger_dist
                            END
       WHERE id = $1
       RETURNING 
         trigger_dist AS new_flag, 
         red_cm, 
         sms_limit,
         phone, 
         phone2, 
         tel_do_szambiarza, 
         do_not_disturb,
         street,
         stale_alert_sent,
         alert_email`;
    const { rows: [row] } = await db.query(q, [d.id, distance, JSON.stringify(varsToSave)]);

    // --- jeśli czujnik znowu wysłał pomiar – kasujemy znacznik „72 h alert wysłany”
    if (row.stale_alert_sent) {
      await db.query(
        'UPDATE devices SET stale_alert_sent = FALSE WHERE id = $1',
        [d.id]
      );
      console.log(`🔄  Flaga stale_alert_sent wyzerowana dla ${devEui}`);
    }

/* 4a) zapis empty_* przy opróżnieniu + log do empties + update last_removed_m3 */
if (d.old_flag && !row.new_flag) {
  console.log(`⚡ [POST /uplink] Detekcja opróżnienia dla ${devEui}`);

  // 1) zaktualizuj devices.empty_cm oraz empty_ts
  await db.query(
    'UPDATE devices SET empty_cm = $1, empty_ts = now() WHERE id = $2',
    [distance, d.id]
  );

  // 2) oblicz ile m³ zostało opróżnione:
  //    removed_m3 = capacity * (1 - (prev_cm / empty_cm))
  const prevCm = d.distance_cm;
  const emptyCm = distance;         // <-- TU bierzesz nowy odczyt
  const cap     = d.capacity;
  const removed = emptyCm > 0
    ? +(cap * (1 - (prevCm / emptyCm))).toFixed(2)
    : 0;

  // 3) wstaw wpis do tabeli empties
  await db.query(
    `INSERT INTO empties 
       (device_id, prev_cm, empty_cm, removed_m3, from_ts) 
     VALUES ($1,$2,$3,$4, now())`,
    [d.id, prevCm, distance, removed]
  );

  // 4) zapisz ostatnie opróżnienie w devices.last_removed_m3
  await db.query(
    'UPDATE devices SET last_removed_m3 = $1 WHERE id = $2',
    [removed, d.id]
  );
    /* 5) jednorazowy SMS „opróżniono” ---------------------------------- */
  if (d.sms_after_empty && d.sms_limit > 0 && d.phone) {
    const num = normalisePhone(d.phone);
    if (num) {
     try {
        await sendSMS(num, '✅ Zbiornik opróżniony,  nie dłuzej niż 4h temu.', 'after_empty');
        await db.query(
          'UPDATE devices SET sms_limit = sms_limit - 1 WHERE id = $1',
          [d.id]
        );
        console.log(`📤 SMS po opróżnieniu wysłany do ${num}`);
      } catch (e) {
        console.error('❌ SMS po opróżnieniu – błąd:', e);
      }
    }
  }


  console.log(`   → empties log: prev=${prevCm}cm, now=${distance}cm, removed=${removed}m³`);
}


    /* 4b) logowanie wartości ------------------------------------------------ */
    const ref = row.red_cm;  // próg alarmu
    const pct = Math.round(((distance - ref) / -ref) * 100);
    console.log(
      `🚀 Saved uplink ${devEui}: ${distance} cm (≈${pct}%); red=${ref}; flag ${d.old_flag}→${row.new_flag}`
    );

    /* 5) ALARM SMS + ALARM E-MAIL (po przekroczeniu progu) ---------------- */
    if (!d.old_flag && row.new_flag) {
      console.log(`📲 [POST /uplink] Próg przekroczony dla ${devEui} → wysyłam alerty`);

      // 5a) SMS na phone i phone2 (jeśli istnieją i jeśli sms_limit > 0)
      const toNumbers = [];
      if (row.phone) {
        const p = normalisePhone(row.phone);
        if (p) toNumbers.push(p);
      }
      if (row.phone2) {
        const p2 = normalisePhone(row.phone2);
        if (p2) toNumbers.push(p2);
      }
      // Czy w tym samym uplinku mamy także issue:1?
      const issueInPayload = (obj.issue === 1 || obj.issue === '1');
      if (toNumbers.length && row.sms_limit > 0) {
        // Treść SMS zależna od obecności issue:1 oraz tego, czy mamy tel_do_szambiarza
        let msg;
        if (issueInPayload) {
          if (!row.tel_do_szambiarza) {
            msg = `Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm - TEN POMIAR PRAWDOPODOBNIE JEST NIE WŁASCIWY - SPRAWDZ CZUJNIK`;
          } else {
            msg = `Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm - TEN POMIAR PRAWDOPODOBNIE JEST NIE WŁASCIWY,SMS DO FIRMY ASENIZACYJNEJ NIE ZOSTAŁ WYSŁANY`;
          }
        } else {
          msg = `⚠️ Poziom w zbiorniku wynosi ${distance} cm przekroczył wartosc  alarmowa ${row.red_cm} cm`;
        }
        console.log(`📲 [POST /uplink] Wysyłam SMS na: ${toNumbers.join(', ')}`);
        let usedSms = 0;
        for (const num of toNumbers) {
          if (row.sms_limit - usedSms <= 0) break; // nie ma już limitu
          try {
            await sendSMS(num, msg, 'threshold');
            usedSms++;
          } catch (smsErr) {
            console.error(`❌ Błąd przy wysyłaniu SMS do ${num}:`, smsErr);
          }
        }
        row.sms_limit -= usedSms;
      } else {
        console.log(`⚠️ [POST /uplink] sms_limit=0 lub brak numerów, pomijam SMS`);
      }

      // 5b) SMS dla szambiarza (jeśli istnieje i jeśli sms_limit > 0)
      //     Gdy issue:1 jest w tym samym uplinku → NIE wysyłamy do szambiarza.
      if (issueInPayload && row.tel_do_szambiarza) {
        console.log(`⏭️ [POST /uplink] Pomijam SMS do szambiarza (issue:1 w tym samym uplinku).`);
      } else if (row.tel_do_szambiarza && row.sms_limit > 0) {
        const szam = normalisePhone(row.tel_do_szambiarza);
        if (szam) {
          const msg2 = `${row.street || '(brak adresu)'} – zbiornik pełny. Prosze o oproznienie. Tel: ${toNumbers[0] || 'brak'}`;
          try {
            console.log(`📲 [POST /uplink] Wysyłam SMS do szambiarza: ${szam}`);
            await sendSMS(szam, msg2, 'szambiarz');
            row.sms_limit--;
          } catch (smsErr) {
            console.error(`❌ Błąd przy wysyłaniu SMS do szambiarza (${szam}):`, smsErr);
          }
        }
      }

      // 5c) Zaktualizuj pozostały sms_limit
      await db.query('UPDATE devices SET sms_limit=$1 WHERE id=$2', [row.sms_limit, d.id]);
      console.log(`📉 [POST /uplink] Zaktualizowano sms_limit → ${row.sms_limit}`);

      // 5d) WYŚLIJ e-mail, jeśli alert_email jest ustawione
      if (row.alert_email) {
        const mailTo = row.alert_email;
        const subj   = `⚠️ Poziom ${distance} cm przekroczył próg na ${devEui}`;
        const html   = `
      <!-- 3. Alert wysokiego poziomu cieczy (/uplink) -->
<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Alert: Wysoki poziom cieczy</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial,sans-serif;">
  <table role="presentation" style="width:100%; border-collapse:collapse;">
    <tr>
      <td align="center" style="padding:20px 0;">
        <table role="presentation" style="width:600px; border-collapse:collapse; background-color:#ffffff; box-shadow:0 0 10px rgba(0,0,0,0.1);">
          <tr>
            <td align="center" style="padding:20px;">
              <img src="https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg"
                   alt="TechioT Logo" style="max-width:150px; height:auto;">
            </td>
          </tr>
          <tr>
            <td style="padding:0 20px; border-bottom:1px solid #eeeeee;">
              <h2 style="color:#c62828; font-size:24px; margin:0;">
                ⚠️ Poziom cieczy przekroczył próg!
              </h2>
            </td>
          </tr>
          <tr>
            <td style="padding:20px;">
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Poziom cieczy <strong>${distance} cm</strong>,
                przekraczył ustawiony próg alarmowy <strong>${row.red_cm} cm</strong>.
              </p>
              <p style="color:#555555; font-size:16px; line-height:1.5;">
                Prosimy o pilne opróżnienie zbiornika.
              </p>
              <p style="color:#999999; font-size:12px; line-height:1.4; margin-top:30px;">
                Ta wiadomość została wysłana automatycznie, prosimy na nią nie odpowiadać.
              </p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:10px 20px; background-color:#fafafa;">
              <p style="color:#777777; font-size:14px; margin:0;">
                Pozdrawiamy,<br>
                <strong>TechioT</strong>
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>

        `;
        console.log(`✉️ [POST /uplink] Wysyłam e-mail na: ${mailTo}`);
        try {
          await sendEmail(mailTo, subj, html);
        } catch (emailErr) {
          console.error(`❌ Błąd przy wysyłaniu e-maila do ${mailTo}:`, emailErr);
        }
      } else {
        console.log(`⚠️ [POST /uplink] alert_email nie jest ustawione, pomijam e-mail`);
      }
    }

    /** ◾️ TU wypychamy SSE do wszystkich podłączonych: */
    sendEvent({
      serial: devEui,
      distance,
      voltage,
      snr,
      ts: varsToSave.ts
    });

    return res.send('OK');
  } catch (err) {
    console.error('❌ Error in /uplink:', err);
    return res.status(500).send('uplink error');
  }
});

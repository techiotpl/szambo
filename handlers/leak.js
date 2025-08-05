// handlers/leak.js
module.exports.handleUplink = async function (utils, dev, body) {
  const { db, sendSMS, sendEmail, sendEvent, normalisePhone, moment } = utils;

  const obj = body.object || {};
  const now = moment();

  // 1) odczyt statusu / baterii
  const leak   = obj.leak   === 1 || obj.leak === '1';
  const battV  = obj.voltage ? Number(obj.voltage) : null;

  // 2) anty-spam (cool-down)
  const cooldownMin = dev.leak_alert_cooldown_min || 180;
  const canAlert = !dev.leak_last_alert_ts ||
                   now.diff(dev.leak_last_alert_ts, 'minutes') >= cooldownMin;

  // 3) gdy status się zmienił – zapis + (ew.) alert
  if (leak !== dev.leak_status) {
    await db.query(
      `UPDATE devices SET leak_status=$1, leak_last_change_ts=now(), 
                          battery_v=$2 WHERE id=$3`,
      [ leak, battV, dev.id ]
    );

    if (leak && canAlert && dev.phone) {
      await sendSMS(normalisePhone(dev.phone),
        '💧 Wykryto zalanie – sprawdź natychmiast!', 'leak');
      await db.query('UPDATE devices SET leak_last_alert_ts=now() WHERE id=$1', [dev.id]);
    }
  } else if (battV !== null) {
    // tylko update napięcia
    await db.query('UPDATE devices SET battery_v=$1 WHERE id=$2', [battV, dev.id]);
  }

  // 4) SSE dla dashboardu
  sendEvent({
    serial: dev.serial_number,
    leak,
    battery_v: battV,
    ts: now.toISOString()
  });
};

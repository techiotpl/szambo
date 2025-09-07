// handlers/logi.js
// Zwięzłe logowanie „karty” urządzenia przy /uplink – tylko wypełnione pola.

function isPresent(v) {
  return v !== null && v !== undefined && !(typeof v === 'string' && v.trim() === '');
}
function compact(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) if (isPresent(v)) out[k] = v;
  return out;
}

async function buildDeviceSummary(db, dev) {
  const type = (dev.device_type || '').toLowerCase();

  // dane właściciela
  let user = null;
  try {
    const r = await db.query(
      'SELECT email, sms_limit, abonament_expiry FROM users WHERE id = $1',
      [dev.user_id]
    );
    user = r.rows[0] || null;
  } catch {
    /* no-op */
  }

  const base = {
    serial: dev.serial_number,
    type,
    name: dev.name,
    street: dev.street,
    user_email: user?.email,
    sms_limit: user?.sms_limit,
    abonament_expiry: user?.abonament_expiry,
  };

  let extra = {};
  if (type === 'co') {
    extra = {
      co_status: dev.co_status,
      co_ppm: dev.co_ppm,
      co_threshold_ppm: dev.co_threshold_ppm,
      co_last_uplink_ts: dev.co_last_uplink_ts,
      co_last_change_ts: dev.co_last_change_ts,
      co_last_alert_ts: dev.co_last_alert_ts,
      battery_v: dev.battery_v,
      phones: [dev.co_phone1, dev.co_phone2].filter(isPresent),
    };
  } else if (type === 'septic') {
    extra = {
      distance_cm: dev.distance_cm,   // jeśli kolumna istnieje – inaczej będzie po prostu pominięte
      red_cm: dev.red_cm,
      capacity: dev.capacity,
      trigger_dist: dev.trigger_dist,
      empty_cm: dev.empty_cm,
      empty_ts: dev.empty_ts,
      phones: [dev.phone, dev.phone2].filter(isPresent),
      tel_do_szambiarza: dev.tel_do_szambiarza,
    };
  } else if (type === 'leak') {
    extra = {
      leak_status: dev.leak_status,
      leak_last_uplink_ts: dev.leak_last_uplink_ts,
      leak_last_change_ts: dev.leak_last_change_ts,
      phones: [dev.leak_phone1, dev.leak_phone2].filter(isPresent),
    };
  }

  return compact({ ...base, ...extra });
}

async function logDeviceSummary(db, dev) {
  try {
    const payload = await buildDeviceSummary(db, dev);
    console.log('[UPLINK][DEV]', JSON.stringify(payload));
  } catch (e) {
    console.warn('[UPLINK][DEV] summary error:', e.message);
  }
}

module.exports = {
  isPresent,
  compact,
  buildDeviceSummary,
  logDeviceSummary,
};

// migration.js
// Idempotentna migracja schematu – bezpieczna kolejność DDL

async function runMigration(db) {
  const MIGRATION_SQL = String.raw`
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ───────────────────────── USERS ─────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email               TEXT UNIQUE NOT NULL,
  password_hash       TEXT NOT NULL,
  role                TEXT DEFAULT 'client',
  name                TEXT,
  company             TEXT,
  street              TEXT,
  phone               TEXT,
  is_active           BOOLEAN DEFAULT TRUE,
  confirmed           BOOLEAN DEFAULT FALSE,
  customer_type       TEXT DEFAULT 'client',
  sms_limit           INT DEFAULT 30,
  abonament_expiry    DATE DEFAULT (CURRENT_DATE + INTERVAL '365 days')::date,
  allow_company_attach BOOLEAN DEFAULT FALSE,
  lat                 NUMERIC(9,6),
  lon                 NUMERIC(9,6),
  created_at          TIMESTAMPTZ DEFAULT now()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'chk_users_customer_type'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_users_customer_type
      CHECK (customer_type IN ('client','firmowy'));
  END IF;
END$$;

-- tokeny do potwierdzania konta
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
  token      TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evt_token ON email_verification_tokens(token);

-- ───────────────────────── DEVICES ────────────────────────
CREATE TABLE IF NOT EXISTS devices (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               UUID REFERENCES users(id) ON DELETE CASCADE,
  name                  TEXT,
  serial_number         TEXT UNIQUE NOT NULL,
  eui                   TEXT,
  phone                 TEXT,
  phone2                TEXT,
  tel_do_szambiarza     TEXT,
  street                TEXT,
  _limit                INT DEFAULT 30,
  red_cm                INT DEFAULT 30,
  empty_cm              INT DEFAULT 150,
  capacity              INT DEFAULT 8,
  empty_ts              TIMESTAMPTZ,
  distance_cm           INT,
  trigger_dist          BOOLEAN DEFAULT FALSE,
  params                JSONB DEFAULT '{}'::jsonb,
  abonament_expiry      DATE,
  alert_email           TEXT,
  last_removed_m3       NUMERIC(6,2),
  device_type           TEXT DEFAULT 'septic',
  sms_limit             INT DEFAULT 30,
  do_not_disturb        BOOLEAN DEFAULT FALSE,
  sms_after_empty       BOOLEAN DEFAULT FALSE,
  -- LEAK
  leak_phone1           TEXT,
  leak_phone2           TEXT,
  leak_status           BOOLEAN DEFAULT FALSE,
  leak_last_change_ts   TIMESTAMPTZ,
  leak_last_alert_ts    TIMESTAMPTZ,
  leak_last_uplink_ts   TIMESTAMPTZ,
  -- CO
  co_phone1             TEXT,
  co_phone2             TEXT,
  co_threshold_ppm      INT DEFAULT 50,
  co_status             BOOLEAN DEFAULT FALSE,
  co_ppm                INT,
  co_last_change_ts     TIMESTAMPTZ,
  co_last_alert_ts      TIMESTAMPTZ,
  co_last_uplink_ts     TIMESTAMPTZ,
  -- wspólne
  battery_v             NUMERIC(5,2),
  lat                   NUMERIC(9,6),
  lon                   NUMERIC(9,6),
  stale_alert_sent      BOOLEAN DEFAULT FALSE,
  created_at            TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devices_devicetype ON devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_phone  ON devices(phone);
CREATE INDEX IF NOT EXISTS idx_devices_phone2 ON devices(phone2);

-- ───────────────────────── ORDERS ─────────────────────────
CREATE TABLE IF NOT EXISTS _orders (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id     UUID REFERENCES devices(id) ON DELETE CASCADE,
  serial_number TEXT NOT NULL,
  amount        NUMERIC(10,2) NOT NULL DEFAULT 50.00,
  status        TEXT NOT NULL DEFAULT 'new',
  redirect_url  TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  paid_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx__orders_serial ON _orders(serial_number);

CREATE OR REPLACE FUNCTION _order_after_paid() RETURNS trigger AS $$
BEGIN
  IF NEW.status = 'paid' AND OLD.status <> 'paid' THEN
    UPDATE devices
      SET _limit = 30,
          abonament_expiry = COALESCE(abonament_expiry, CURRENT_DATE) + INTERVAL '365 days'
    WHERE id = NEW.device_id;
    NEW.paid_at := now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg__order_after_paid ON _orders;
CREATE TRIGGER trg__order_after_paid
  AFTER UPDATE ON _orders
  FOR EACH ROW EXECUTE FUNCTION _order_after_paid();

-- ───────────────────────── EMPTIES ────────────────────────
CREATE TABLE IF NOT EXISTS empties (
  id            BIGSERIAL PRIMARY KEY,
  device_id     UUID REFERENCES devices(id) ON DELETE CASCADE,
  prev_cm       INT NOT NULL,
  empty_cm      INT NOT NULL,
  removed_m3    NUMERIC(6,2) NOT NULL,
  from_ts       TIMESTAMPTZ,
  to_ts         TIMESTAMPTZ DEFAULT now()
);

CREATE OR REPLACE FUNCTION check_removed_le_capacity()
RETURNS TRIGGER AS $$
DECLARE cap INT;
BEGIN
  SELECT capacity INTO cap FROM devices WHERE id = NEW.device_id LIMIT 1;
  IF NEW.removed_m3 > cap THEN
    RAISE EXCEPTION 'removed_m3 (%) exceeds capacity (%)', NEW.removed_m3, cap;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_check_removed_capacity ON empties;
CREATE TRIGGER trg_check_removed_capacity
  BEFORE INSERT OR UPDATE ON empties
  FOR EACH ROW EXECUTE FUNCTION check_removed_le_capacity();

-- ─────────────────────── MEASUREMENTS ─────────────────────
CREATE TABLE IF NOT EXISTS measurements (
  device_serial TEXT NOT NULL,
  distance_cm   INT  NOT NULL,
  ts            TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (device_serial, ts)
);
CREATE INDEX IF NOT EXISTS idx_meas_device_ts ON measurements(device_serial, ts DESC);

-- ─────────────── firm/company relacje (obie) ─────────────
CREATE TABLE IF NOT EXISTS firm_clients (
  firm_user_id   UUID REFERENCES users(id) ON DELETE CASCADE,
  client_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  label          TEXT,
  note           TEXT,
  created_at     TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (firm_user_id, client_user_id)
);

CREATE TABLE IF NOT EXISTS company_clients (
  company_id UUID REFERENCES users(id) ON DELETE CASCADE,
  client_id  UUID REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (company_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_company_clients_company ON company_clients(company_id);
CREATE INDEX IF NOT EXISTS idx_company_clients_client  ON company_clients(client_id);

-- ─────────────── uzupełnienia / migracje danych ──────────
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_name='devices' AND column_name='_limit'
  ) THEN
    UPDATE devices SET sms_limit = COALESCE(sms_limit, _limit, 30);
  END IF;
END$$;

UPDATE users u
SET sms_limit        = COALESCE(u.sms_limit, x.sms_limit),
    abonament_expiry = COALESCE(u.abonament_expiry, x.abonament_expiry)
FROM (
  SELECT user_id,
         COALESCE(MAX(sms_limit), 30) AS sms_limit,
         MAX(abonament_expiry)        AS abonament_expiry
  FROM devices
  GROUP BY user_id
) x
WHERE u.id = x.user_id
  AND (u.sms_limit IS NULL OR u.abonament_expiry IS NULL);
`;

  const client = await db.connect();
  try {
    const { rows: [{ ok }] } =
      await client.query('SELECT pg_try_advisory_lock(42) AS ok');
    if (!ok) {
      console.log('⏩ Inna instancja trzyma lock – pomijam migrację');
      return;
    }

    await client.query('BEGIN');
    await client.query(MIGRATION_SQL);
    await client.query('COMMIT');
    console.log('✅ Migration executed.');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('❌ Migration error:', e);
    throw e; // pozwól server.js zdecydować co dalej (np. exit)
  } finally {
    client.release();
  }
}

module.exports = { runMigration };

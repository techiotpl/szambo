// jobs/decrement-abonament.js

const { Pool } = require('pg');
require('dotenv').config();

(async () => {
  // Używamy wyłącznie DATABASE_URL z environment:
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  try {
    // Załóżmy, że abonament_expiry to data wygaśnięcia (DATE),
    // a wiesz, że chcesz codziennie dekrementować jakiś licznik.
    // Dla uproszczenia: odejmij 1 od kolumny sms_limit, gdy abonament_expiry < today.
    const client = await pool.connect();

    // Przykład: dla każdego device, u którego abonament_expiry < dziś, resetuj sms_limit = 0
    const now = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const updateQuery = `
      UPDATE devices
         SET sms_limit = 0
       WHERE abonament_expiry IS NOT NULL
         AND abonament_expiry < $1
    `;
    const { rowCount } = await client.query(updateQuery, [now]);
    console.log(`✅ Abonamenty przetworzone, zresetowano sms_limit dla ${rowCount} urządzeń.`);

    client.release();
    process.exit(0);
  } catch (err) {
    console.error('❌ Błąd podczas dekremantacji abonamentów:', err);
    process.exit(1);
  }
})();

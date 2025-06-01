/**
 * jobs/decrement-abonament.js
 *
 * Ten skrypt:
 *  - Łączy się z bazą Postgres przez Pool (zmienna środowiskowa DATABASE_URL)
 *  - Ustawia sms_limit = 0 dla rekordów, których abonament_expiry <= CURRENT_DATE
 *  - Wypisuje w konsoli, ile wierszy zostało zaktualizowanych
 */

const { Pool } = require('pg');
require('dotenv').config();

(async () => {
  // 1) Inicjalizacja połączenia do bazy
  const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Jeżeli korzystasz z SSL, odkomentuj poniższe (jeśli potrzebujesz):
    // ssl: { rejectUnauthorized: false }
  });

  try {
    // 2) Wykonaj UPDATE, zwracając id zaktualizowanych wierszy
    const result = await db.query(
      `
      UPDATE devices
         SET sms_limit = 0
       WHERE abonament_expiry <= CURRENT_DATE
       RETURNING id
      `
    );

    const count = result.rows.length;
    console.log(`✅ Abonamenty przetworzone, zresetowano sms_limit dla ${count} urządzeń.`);
  } catch (err) {
    console.error('❌ Błąd podczas dekrementacji/resetu abonamentów:', err);
  } finally {
    // 3) Zamknij połączenie do bazy
    await db.end();
  }
})();

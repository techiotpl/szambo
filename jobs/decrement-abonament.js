// jobs/decrement-abonament.js
const { Pool } = require('pg');
require('dotenv').config();

(async () => {
  const db = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    await db.query(`
      UPDATE devices
         SET abonament = abonament - 1
       WHERE abonament > 0
    `);
    await db.query(`
      UPDATE devices
         SET sms_limit = 0
       WHERE abonament <= 0
    `);
    console.log('abonament –1; wyzerowano sms_limit tam, gdzie trzeba');
  } finally {
    await db.end();
  }
})();

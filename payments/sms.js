// payments/sms.js
//
// Zakup pakietu SMS przez Przelewy24.
// Użycie w server.js:
//    const smsPayments = require('./payments/sms');
//    smsPayments(app, db, auth);
//
// Endpoints:
//  • POST /sms/orders            — zakup dla JEDNEGO urządzenia (stała cena w groszach)
//  • POST /sms/orders/for-user   — zakup „na konto”, suma po typach urządzeń (ceny w groszach)
//  • POST /sms/verify            — wspólna weryfikacja (obsługuje oba powyższe)
//
// USTAWIENIA CEN (w groszach!):
//   - 100   = 1,00 zł
//   - 5999  = 59,99 zł
//   - 25000 = 250,00 zł
//
// Przykład: chcesz 59,99 zł → wpisujesz 5999.

const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser');
require('dotenv').config();

// ───────────────────────────────────────────────────────────────────────────
// CENNIK (GROSZE = integer)
// ───────────────────────────────────────────────────────────────────────────

+// Cena dla pojedynczego urządzenia (endpoint /sms/orders)
+// ← USTAW REALNĄ: 50,00 zł = 5000
const PRICE_SINGLE_DEVICE_GROSZE = 5000; // 50,00 zł

// Ceny per typ urządzenia (endpoint /sms/orders/for-user)
const PRICES_GROSZE = {
  septic: 100,  // 1,00 zł  → ustaw np. 5999 dla 59,99 zł
  leak:   200,  // 2,00 zł
  co:     300   // 3,00 zł
};

// Ile SMS dodać po udanej płatności (top-up na konto – tabela users)
const SMS_TOPUP_PER_ORDER = 30;

// Formatowanie groszy do stringa "xx,yy zł"
function formatPLN(grosze) {
  const zloty = Math.floor(grosze / 100);
  const gr = Math.abs(grosze % 100).toString().padStart(2, '0');
  return `${zloty},${gr} zł`;
}

module.exports = (app, db, auth) => {
  function calculateSHA384(data) {
    const hash = crypto.createHash('sha384');
    hash.update(data);
    return hash.digest('hex');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // POST /sms/orders  (STARY TRYB – JEDNO urządzenie)
  // body: { serial }
  // Kwota = PRICE_SINGLE_DEVICE_GROSZE (grosze).
  // ─────────────────────────────────────────────────────────────────────────
  app.post('/sms/orders', auth, async (req, res) => {
    try {
      const userId = req.user.id;
      const { serial } = req.body;
      if (!serial) return res.status(400).json({ error: 'Brakuje pola "serial"' });

      const { rows: devices } = await db.query(
        `SELECT id, name 
           FROM devices 
          WHERE serial_number = $1 AND user_id = $2
          LIMIT 1`,
        [serial, userId]
      );
      if (!devices.length) {
        return res.status(404).json({ error: 'Urządzenie nie znalezione lub nie należy do Ciebie' });
      }
      const device = devices[0];

      const amountGrosze = PRICE_SINGLE_DEVICE_GROSZE;
      const currency     = 'PLN';
      const sessionId    = `SMS_${device.id}_${Date.now()}`;

            // LOG: pojedyncze urządzenie
      console.log(`[P24 register:/sms/orders] user=${req.user.email} device_serial=${serial} name="${device.name}" amount=${formatPLN(amountGrosze)}`);

      const posId      = process.env.P24_POS_ID?.trim();
      const apiKey     = process.env.P24_API_KEY?.trim();
      const crcKey     = process.env.P24_CRC_KEY?.trim();
      const merchantId = process.env.P24_MERCHANT_ID?.trim();
      const useSandbox = (process.env.P24_SANDBOX || '').trim() === 'true';
      if (!posId || !apiKey || !crcKey || !merchantId) {
        return res.status(500).json({ error: 'Brakuje zmiennych środowiskowych P24_*' });
      }

      const sign = calculateSHA384(JSON.stringify({
        sessionId,
        merchantId: Number(merchantId),
        amount: amountGrosze,
        currency,
        crc: crcKey
      }));

      const orderData = {
        merchantId: Number(merchantId),
        posId: Number(posId),
        sessionId,
        amount: amountGrosze,
        currency,
        description: `Pakiet 30 SMS – urządzenie ${device.name} (${formatPLN(amountGrosze)})`,
        email: req.user.email || '',
        country: 'PL',
        language: 'pl',
        urlReturn: `https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html`,
        urlStatus: `https://${req.get('host')}/sms/verify`,
        timeLimit: 20,
        encoding: 'UTF-8',
        sign
      };

      const baseUrl = useSandbox
        ? 'https://sandbox.przelewy24.pl/api/v1'
        : 'https://secure.przelewy24.pl/api/v1';

      const client = axios.create({
        baseURL: baseUrl,
        auth: { username: posId.toString(), password: apiKey },
        headers: { 'Content-Type': 'application/json' }
      });

      const response = await client.post('/transaction/register', orderData);
      const tokenP24 = response.data.data.token;
      const redirectUrl = useSandbox
        ? `https://sandbox.przelewy24.pl/trnRequest/${tokenP24}`
        : `https://secure.przelewy24.pl/trnRequest/${tokenP24}`;

      return res.json({ redirectUrl });
    } catch (err) {
      console.error('❌ [POST /sms/orders] Błąd:', err);
      return res.status(500).json({ error: 'sms/orders failed' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // POST /sms/orders/for-user  (NOWY TRYB – „na konto”)
  // body: {}  (nic nie trzeba podawać)
  // Kwota = Σ (liczba_urzadzen_typu * PRICES_GROSZE[typ])
  // ─────────────────────────────────────────────────────────────────────────
  app.post('/sms/orders/for-user', auth, async (req, res) => {
    try {
      const userId = req.user.id;

      // policz urządzenia usera per device_type
      const { rows } = await db.query(
        `SELECT LOWER(device_type) AS device_type, COUNT(*)::int AS cnt
           FROM devices
          WHERE user_id = $1
          GROUP BY LOWER(device_type)`,
        [userId]
      );

      const counts = { septic: 0, leak: 0, co: 0 };
      for (const r of rows) {
        if (r.device_type === 'septic' || r.device_type === 'leak' || r.device_type === 'co') {
          counts[r.device_type] = Number(r.cnt || 0);
        }
      }

      const amountGrosze =
        counts.septic * (PRICES_GROSZE.septic || 0) +
        counts.leak   * (PRICES_GROSZE.leak   || 0) +
        counts.co     * (PRICES_GROSZE.co     || 0);

      if (amountGrosze <= 0) {
        return res.status(400).json({ error: 'Brak urządzeń do rozliczenia' });
      }

      const currency  = 'PLN';
      const sessionId = `SMS_USER_${userId}_${Date.now()}`;

           // LOG: zamówienie „na konto”
      console.log(
        `[P24 register:/sms/orders/for-user] user=${req.user.email} ` +
        `counts={septic:${counts.septic}, leak:${counts.leak}, co:${counts.co}} ` +
        `amount=${formatPLN(amountGrosze)}`
      );

      const posId      = process.env.P24_POS_ID?.trim();
      const apiKey     = process.env.P24_API_KEY?.trim();
      const crcKey     = process.env.P24_CRC_KEY?.trim();
      const merchantId = process.env.P24_MERCHANT_ID?.trim();
      const useSandbox = (process.env.P24_SANDBOX || '').trim() === 'true';
      if (!posId || !apiKey || !crcKey || !merchantId) {
        return res.status(500).json({ error: 'Brakuje zmiennych środowiskowych P24_*' });
      }

      const desc = `Abonament – ${counts.septic}× septic, ${counts.leak}× leak, ${counts.co}× CO (${formatPLN(amountGrosze)})`;

      const sign = calculateSHA384(JSON.stringify({
        sessionId,
        merchantId: Number(merchantId),
        amount: amountGrosze,
        currency,
        crc: crcKey
      }));

      const orderData = {
        merchantId: Number(merchantId),
        posId: Number(posId),
        sessionId,
        amount: amountGrosze,
        currency,
        description: desc,
        email: req.user.email || '',
        country: 'PL',
        language: 'pl',
        urlReturn: `https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html`,
        urlStatus: `https://${req.get('host')}/sms/verify`,
        timeLimit: 20,
        encoding: 'UTF-8',
        sign
      };

      const baseUrl = useSandbox
        ? 'https://sandbox.przelewy24.pl/api/v1'
        : 'https://secure.przelewy24.pl/api/v1';

      const client = axios.create({
        baseURL: baseUrl,
        auth: { username: posId.toString(), password: apiKey },
        headers: { 'Content-Type': 'application/json' }
      });

      const response = await client.post('/transaction/register', orderData);
      const tokenP24 = response.data.data.token;
      const redirectUrl = useSandbox
        ? `https://sandbox.przelewy24.pl/trnRequest/${tokenP24}`
        : `https://secure.przelewy24.pl/trnRequest/${tokenP24}`;

      return res.json({ redirectUrl });
    } catch (err) {
      console.error('❌ [POST /sms/orders/for-user] Błąd:', err);
      return res.status(500).json({ error: 'sms/orders/for-user failed' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // POST /sms/verify  – wspólna weryfikacja (single-device i konto)
  // P24 wysyła POST (x-www-form-urlencoded)
  // ─────────────────────────────────────────────────────────────────────────
  app.post('/sms/verify', bodyParser.urlencoded({ extended: false }), async (req, res) => {
    try {
      const {
        merchantId, posId, sessionId, amount, originAmount,
        currency, orderId, methodId, statement, sign
      } = req.body;

      if (
        !merchantId || !posId || !sessionId || !amount || !originAmount ||
        !currency || !orderId || !methodId || !statement || !sign
      ) {
        return res.status(400).send('Brak parametrów');
      }

      const merchantIdEnv = process.env.P24_MERCHANT_ID?.trim();
      const posIdEnv      = process.env.P24_POS_ID?.trim();
      const apiKeyEnv     = process.env.P24_API_KEY?.trim();
      const crcKey        = process.env.P24_CRC_KEY?.trim();
      const useSandbox    = (process.env.P24_SANDBOX || '').trim() === 'true';

      if (!merchantIdEnv || !posIdEnv || !apiKeyEnv || !crcKey) {
        return res.status(500).send('Błąd konfiguracji');
      }

      // 1) Sprawdzenie podpisu notyfikacji
      const notificationPayload = {
        merchantId:   Number(merchantIdEnv),
        posId:        Number(posIdEnv),
        sessionId,
        amount:       Number(amount),
        originAmount: Number(originAmount),
        currency,
        orderId:      Number(orderId),
        methodId:     Number(methodId),
        statement,
        crc:          crcKey
      };
      const computedSign = calculateSHA384(JSON.stringify(notificationPayload));
      if (computedSign !== sign) return res.status(400).send('Nieprawidłowy podpis');

      // 2) Verify (PUT)
      const baseUrl = useSandbox
        ? 'https://sandbox.przelewy24.pl/api/v1'
        : 'https://secure.przelewy24.pl/api/v1';

      const clientVerify = axios.create({
        baseURL: baseUrl,
        auth: { username: posIdEnv, password: apiKeyEnv },
        headers: { 'Content-Type': 'application/json' }
      });

      const verifyResp = await clientVerify.put('/transaction/verify', {
        merchantId: Number(merchantIdEnv),
        posId:      Number(posIdEnv),
        sessionId,
        orderId:    Number(orderId),
        amount:     Number(amount),
        currency,
        sign: calculateSHA384(JSON.stringify({
          sessionId,
          orderId: Number(orderId),
          amount:  Number(amount),
          currency,
          crc:     crcKey
        }))
      });

      const ok = verifyResp.data?.data?.status;
      if (!(ok === true || ok === 'TRUE' || ok === 'success')) {
        return res.status(400).send('Transakcja niepotwierdzona');
      }

      // 3) Rozpoznanie typu sesji:
      //  • SMS_<deviceId>_<ts>
      //  • SMS_USER_<userId>_<ts>
      const mDevice = /^SMS_([0-9a-f-]{36})_/i.exec(sessionId);
      const mUser   = /^SMS_USER_([0-9a-f-]{36})_/i.exec(sessionId);

      if (mUser) {
        const userId = mUser[1];
        // ↑ Globalny top-up na KONTO: +30 SMS oraz +365 dni od max(dziś, obecna data)
        await db.query(
          `UPDATE users
              SET sms_limit = COALESCE(sms_limit,0) + $2,
                  abonament_expiry =
                    (CASE
                      WHEN abonament_expiry IS NULL OR abonament_expiry < CURRENT_DATE
                        THEN CURRENT_DATE
                      ELSE abonament_expiry
                     END + INTERVAL '365 days')::date
            WHERE id = $1::uuid`,
          [userId, SMS_TOPUP_PER_ORDER]
        );
        // (opcjonalnie) zsynchronizuj devices, jeśli gdzieś jeszcze je czytasz
        await db.query(
          `UPDATE devices d
              SET sms_limit = u.sms_limit,
                  abonament_expiry = u.abonament_expiry
             FROM users u
            WHERE d.user_id = u.id AND u.id = $1::uuid`,
          [userId]
        ).catch(()=>{});

        // LOG
        const { rows:[u] } = await db.query(`SELECT email, sms_limit, abonament_expiry FROM users WHERE id=$1::uuid`, [userId]);
        console.log(`[P24 verify:USER] ok user=${u?.email||userId} +${SMS_TOPUP_PER_ORDER} SMS, expiry→ ${u?.abonament_expiry}`);

        return res.send(`
          <html><body style="font-family:sans-serif; text-align:center; margin-top:50px;">
            <h2>Płatność zakończona pomyślnie 😊</h2>
            <p>Pakiet 30 SMS dodany do Twojego konta i abonament przedłużony o 365 dni.</p>
            <a href="https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html">Wróć do aplikacji</a>
          </body></html>
        `);
      }

      if (mDevice) {
        const deviceId = mDevice[1];
        // Pojedyncze urządzenie
        await db.query(
          `UPDATE devices
              SET sms_limit = 30,
                  abonament_expiry = (COALESCE(abonament_expiry, CURRENT_DATE) + INTERVAL '365 days')::date
            WHERE id = $1::uuid`,
          [deviceId]
        );
        return res.send(`
          <html><body style="font-family:sans-serif; text-align:center; margin-top:50px;">
            <h2>Płatność zakończona pomyślnie 😊</h2>
            <p>Pakiet 30 SMS przypisany do Twojego urządzenia.</p>
            <a href="https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html">Wróć do aplikacji</a>
          </body></html>
        `);
      }

      return res.status(400).send('Nieprawidłowy sessionId');
    } catch (err) {
      console.error('❌ [POST /sms/verify] Błąd:', err);
      return res.status(500).send('Verification error');
    }
  });
};

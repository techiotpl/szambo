// payments/sms.js
//
// 2025-06-05 – trasy do zakupu pakietu SMS przez Przelewy24.
// Aby używać tego pliku, w server.js wywołujesz:
//    const smsPayments = require('./payments/sms');
//    smsPayments(app, db, auth);
//
// Parametry:
//   • app  : instancja Expressa
//   • db   : Pool (PostgreSQL)
//   • auth : middleware autoryzujący (funkcja auth(req, res, next))

const axios = require('axios');
const crypto = require('crypto');
const bodyParser = require('body-parser'); // do parsowania application/x-www-form-urlencoded
require('dotenv').config();

module.exports = (app, db, auth) => {
  //
  // ─────────────────────────────────────────────────────────────────────────────
  // Helper: liczy SHA384 (Przelewy24 wymaga tej funkcji do podpisu)
  // ─────────────────────────────────────────────────────────────────────────────
  function calculateSHA384(data) {
    const hash = crypto.createHash('sha384');
    hash.update(data);
    return hash.digest('hex');
  }

  //
  // ─────────────────────────────────────────────────────────────────────────────
  // POST /sms/orders
  //  - wymaga TOKEN JWT (middleware auth)
  //  - w ciele żądania oczekujemy { serial: "NUMER_URZĄDZENIA" }
  //  - sprawdzamy, czy podane urządzenie należy do zalogowanego użytkownika
  //  - rejestrujemy transakcję w Przelewy24 i zwracamy klientowi URL do przekierowania
  // ─────────────────────────────────────────────────────────────────────────────
  app.post('/sms/orders', auth, async (req, res) => {
    try {
      // 1) Użytkownik musi być zalogowany – auth ustawi req.user.id
      const userId = req.user.id;
      console.log('▶️ [sms/orders] Zalogowany userId =', userId);

      // 2) W ciele żądania musi być serial urządzenia
      const { serial } = req.body;
      console.log('▶️ [sms/orders] Otrzymany serial =', serial);
      if (!serial) {
        return res.status(400).json({ error: 'Brakuje pola "serial"' });
      }

      // 3) Sprawdź, czy w tabeli devices istnieje urządzenie o podanym serial i user_id = userId
      const { rows: devices } = await db.query(
        `SELECT id, name 
           FROM devices 
          WHERE serial_number = $1 
            AND user_id = $2
          LIMIT 1`,
        [serial, userId]
      );
      if (devices.length === 0) {
        console.log('❌ [sms/orders] Urządzenie nie znalezione lub nie należy do usera');
        return res
          .status(404)
          .json({ error: 'Urządzenie nie znalezione lub nie należy do Ciebie' });
      }
      const device = devices[0]; // { id, name }
      console.log('▶️ [sms/orders] Znalezione device =', device);

      // 4) Przygotuj parametry transakcji:
      //    • Cena pakietu: 1 zł → Przelewy24 wymaga kwoty w groszach (x100)
      const amountPLN = 1;            // w złotych
      const amount    = amountPLN * 100; // w groszach
      const currency  = 'PLN';
      // Unikalne sessionId: SMS_<deviceId>_<timestamp>
      const sessionId = `SMS_${device.id}_${Date.now()}`;
      console.log('▶️ [sms/orders] sessionId =', sessionId);

      // 5) Pobierz z .env niezbędne dane autoryzacyjne i przytnij białe znaki:
      //    • P24_POS_ID      – numer POS (jako string lub liczba)
      //    • P24_API_KEY     – API Key (hasło do Basic Auth)
      //    • P24_CRC_KEY     – klucz CRC (do SHA384)
      //    • P24_MERCHANT_ID – Twój MERCHANT ID w Panelu Przelewy24
      //    • P24_SANDBOX     – "true" → sandbox, inaczej produkcja
      const posId      = process.env.P24_POS_ID?.trim();
      const apiKey     = process.env.P24_API_KEY?.trim();
      const crcKey     = process.env.P24_CRC_KEY?.trim();
      const merchantId = process.env.P24_MERCHANT_ID?.trim();
      const useSandbox = (process.env.P24_SANDBOX || '').trim() === 'true';

      // Dodane logi, aby zweryfikować wartości z env:
      console.log('▶️ [sms/orders] process.env.P24_POS_ID      =', posId);
      console.log('▶️ [sms/orders] process.env.P24_API_KEY     =', apiKey ? '***wczytane***' : null);
      console.log('▶️ [sms/orders] process.env.P24_CRC_KEY     =', crcKey ? '***wczytane***' : null);
      console.log('▶️ [sms/orders] process.env.P24_MERCHANT_ID =', merchantId);
      console.log('▶️ [sms/orders] process.env.P24_SANDBOX     =', process.env.P24_SANDBOX);

      if (!posId || !apiKey || !crcKey || !merchantId) {
        console.warn('❌ [sms/orders] Brakuje zmiennych środowiskowych P24_*');
        return res
          .status(500)
          .json({ error: 'Brakuje zmiennych środowiskowych P24_*' });
      }

      // 6) Oblicz sygnaturę (sign) SHA-384 wg dokumentacji P24:
      //    sign = SHA384( JSON.stringify({ sessionId, merchantId, amount, currency, crc: crcKey }) )
      const hashData = {
        sessionId: sessionId,
        merchantId: Number(merchantId),
        amount: amount,
        currency: currency,
        crc: crcKey
      };
      console.log('▶️ [sms/orders] hashData (do SHA384) =', hashData);

      const sign = calculateSHA384(JSON.stringify(hashData));
      console.log('▶️ [sms/orders] Obliczone sign =', sign);

      // 7) Przygotuj payload do rejestracji transakcji w Przelewy24
      const orderData = {
        merchantId: Number(merchantId),
        posId: Number(posId),
        sessionId: sessionId,
        amount: amount,
        currency: currency,
        description: `Pakiet 30 SMS – urządzenie ${device.name}`,
        email: req.user.email || '',  // jeśli w tokenie masz email
        country: 'PL',
        language: 'pl',
        urlReturn: `https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html`,                 // przekierowanie front-endowe
        urlStatus: `https://${req.get('host')}/sms/verify`,   // callback po HTTPS
        timeLimit: 20,
        encoding: 'UTF-8',
        sign: sign
      };

      console.log('▶️ [sms/orders] orderData przed wysłaniem do P24 =', orderData);

      // 8) Wybierz odpowiednią bazę URL (sandbox lub produkcja)
      const baseUrl = useSandbox
        ? 'https://sandbox.przelewy24.pl/api/v1'
        : 'https://secure.przelewy24.pl/api/v1';
      console.log('▶️ [sms/orders] Wybrany baseUrl P24 =', baseUrl);

      const client = axios.create({
        baseURL: baseUrl,
        auth: {
          username: posId.toString(),
          password: apiKey
        },
        headers: {
          'Content-Type': 'application/json'
        }
      });

      // 9) Wyślij żądanie do P24: /transaction/register
      console.log('▶️ [sms/orders] Wysyłam żądanie POST do P24 /transaction/register …');
      const response = await client.post('/transaction/register', orderData);

      // 10) Odczytaj token P24, zbuduj redirectUrl
      const tokenP24 = response.data.data.token;
      console.log('▶️ [sms/orders] P24 zwróciło token =', tokenP24);

      const redirectUrl = useSandbox
        ? `https://sandbox.przelewy24.pl/trnRequest/${tokenP24}`
        : `https://secure.przelewy24.pl/trnRequest/${tokenP24}`;
      console.log('▶️ [sms/orders] Finalny redirectUrl =', redirectUrl);

      // 11) (Opcjonalnie) W tym miejscu można dodać INSERT do tabeli sms_orders, by zachować historię.

      // 12) Zwróć klientowi JSON z redirectUrl
      return res.json({ redirectUrl });
    } catch (err) {
      console.error('❌ [POST /sms/orders] Błąd w trakcie całego flow:', err);
      return res.status(500).json({ error: 'sms/orders failed' });
    }
  });

  //
  // ─────────────────────────────────────────────────────────────────────────────
  // POST /sms/verify
  //  – Przelewy24 wyśle tu callback metodą POST (application/x-www-form-urlencoded)
  //  – Weryfikujemy sygnaturę (p24_sign), przy pomocy JSON.stringify(…)
  //  – Jeśli OK, wywołujemy /transaction/verify (METODĄ PUT!)
  //  – Jeśli to też OK, aktualizujemy devices (sms_limit, abonament_expiry)
  // ─────────────────────────────────────────────────────────────────────────────
  app.post(
    '/sms/verify',
    bodyParser.urlencoded({ extended: false }),
    async (req, res) => {
      try {
        //
        // 1) Odbierz właściwe pola z req.body:
        //
        const {
          merchantId,
          posId,
          sessionId,
          amount,
          originAmount,
          currency,
          orderId,
          methodId,
          statement,
          sign
        } = req.body;

        console.log('▶️ [sms/verify] Otrzymane parametry P24 (POST):', {
          merchantId,
          posId,
          sessionId,
          amount,
          originAmount,
          currency,
          orderId,
          methodId,
          statement,
          sign
        });

        //
        // 2) Sprawdź, czy wszystkie niezbędne pola są obecne:
        //
        if (!(
          merchantId &&
          posId &&
          sessionId &&
          amount &&
          originAmount &&
          currency &&
          orderId &&
          methodId &&
          statement &&
          sign
        )) {
          console.warn('⚠️ [sms/verify] Brakuje kluczowych parametrów:', req.body);
          return res.status(400).send('Brak parametrów');
        }

        //
        // 3) Pobierz parametry z .env:
        //
        const merchantIdEnv = process.env.P24_MERCHANT_ID?.trim();
        const posIdEnv      = process.env.P24_POS_ID?.trim();
        const apiKeyEnv     = process.env.P24_API_KEY?.trim();
        const crcKey        = process.env.P24_CRC_KEY?.trim();
        const useSandbox    = (process.env.P24_SANDBOX || '').trim() === 'true';

        if (!merchantIdEnv || !posIdEnv || !apiKeyEnv || !crcKey) {
          console.warn('❌ [sms/verify] Brakuje P24_MERCHANT_ID, P24_POS_ID, P24_API_KEY lub P24_CRC_KEY w env');
          return res.status(500).send('Błąd konfiguracji');
        }

        //
        // 4) Wyliczamy sign notyfikacji (z JSON, nie ’|’):
        //
        const notificationPayload = {
          merchantId:   Number(merchantIdEnv),
          posId:        Number(posIdEnv),
          sessionId:    sessionId,
          amount:       Number(amount),
          originAmount: Number(originAmount),
          currency:     currency,
          orderId:      Number(orderId),
          methodId:     Number(methodId),
          statement:    statement,
          crc:          crcKey
        };

        const computedSign = calculateSHA384(JSON.stringify(notificationPayload));
        console.log('▶️ [sms/verify] Obliczony sign notyfikacji =', computedSign);
        console.log('▶️ [sms/verify] Odebrany sign             =', sign);

        if (computedSign !== sign) {
          console.warn('⚠️ [sms/verify] Niezgodność podpisów:', {
            computed: computedSign,
            received: sign
          });
          return res.status(400).send('Nieprawidłowy podpis');
        }

        //
        // 5) Skoro notyfikacja ma poprawny podpis, wywołujemy /transaction/verify METODĄ PUT:
        //
        const baseUrl = useSandbox
          ? 'https://sandbox.przelewy24.pl/api/v1'
          : 'https://secure.przelewy24.pl/api/v1';

        const clientVerify = axios.create({
          baseURL: baseUrl,
          auth: {
            username: posIdEnv,
            password: apiKeyEnv
          },
          headers: {
            'Content-Type': 'application/json'
          }
        });

        console.log('▶️ [sms/verify] Wysyłam PUT do /transaction/verify …');
        const verifyResp = await clientVerify.put('/transaction/verify', {
          merchantId: Number(merchantIdEnv),
          posId:      Number(posIdEnv),
          sessionId:  sessionId,
          orderId:    Number(orderId),
          amount:     Number(amount),
          currency:   currency,
          // Sign do weryfikacji:
          sign: calculateSHA384(
            JSON.stringify({
              sessionId: sessionId,
              orderId:   Number(orderId),
              amount:    Number(amount),
              currency:  currency,
              crc:       crcKey
            })
          )
        });

        console.log('▶️ [sms/verify] Odpowiedź z /transaction/verify:', verifyResp.data);

        const verifyStatus = verifyResp.data?.data?.status;
        // Akceptujemy boolean true lub string "TRUE"/"success"
        if (!(verifyStatus === true || verifyStatus === 'TRUE' || verifyStatus === 'success')) {
          console.warn('⚠️ [sms/verify] P24 NIE potwierdziło transakcji');
          return res.status(400).send('Transakcja niepotwierdzona');
        }

        //
        // 6) Jeżeli P24 faktycznie potwierdziło płatność, aktualizujemy bazę:
        //    sessionId = "SMS_<deviceId>_<ts>"
        //
        const parts = sessionId.split('_');
        if (parts.length < 2) {
          console.warn('⚠️ [sms/verify] Nieprawidłowy format sessionId:', sessionId);
          return res.status(400).send('Nieprawidłowy sessionId');
        }
        const deviceId = parts[1];

        await db.query(
          `UPDATE devices
              SET sms_limit       = 30,
                  abonament_expiry = (CURRENT_DATE + INTERVAL '365 days')::date
            WHERE id = $1`,
          [deviceId]
        );
        console.log('▶️ [sms/verify] Zaktualizowano devices (sms_limit, abonament_expiry) dla deviceId =', deviceId);

        //
        // 7) Zwracamy użytkownikowi prostą stronę potwierdzenia
        //
        return res.send(`
          <html>
            <body style="font-family:sans-serif; text-align:center; margin-top:50px;">
              <h2>Płatność zakończona pomyślnie 😊</h2>
              <p>Pakiet 30 SMS przypisany do Twojego urządzenia.</p>
              <a href="https://api.tago.io/file/64482e832567a60008e515fa/icons/dziekuje.html">Wróć do aplikacji</a>
            </body>
          </html>
        `);
      } catch (err) {
        console.error('❌ [POST /sms/verify] Błąd:', err);
        return res.status(500).send('Verification error');
      }
    }
  );
};

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
        return res.status(404).json({ error: 'Urządzenie nie znalezione lub nie należy do Ciebie' });
      }
      const device = devices[0]; // { id, name }
      console.log('▶️ [sms/orders] Znalezione device =', device);

      // 4) Przygotuj parametry transakcji:
      //    • Cena pakietu: 50 zł brutto → Przelewy24 wymaga kwoty w groszach (x100)
      const amountPLN = 50;           // w złotych
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
        return res.status(500).json({ error: 'Brakuje zmiennych środowiskowych P24_*' });
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
        urlReturn: `${req.protocol}://${req.get('host')}/sms/verify`,
        urlStatus: `${req.protocol}://${req.get('host')}/sms/verify`,
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
      console.log('▶️ [sms/orders] Wysyłam żądanie POST do P24 /transaction/register ...');
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
  // GET /sms/verify
  //  – Przelewy24 przekieruje tu po zakończonej płatności, z parametrami w query string
  //  – Weryfikujemy sygnaturę (p24_sign), sprawdzamy p24_result
  //  – Jeśli OK, oznaczamy transakcję jako zapłaconą i aktualizujemy devices:
  //       • sms_limit = 30
  //       • abonament_expiry = teraz + 365 dni
  // ─────────────────────────────────────────────────────────────────────────────
  app.get('/sms/verify', async (req, res) => {
    try {
      // 1) Odebrane parametry z P24:
      //    p24_sessionId, p24_orderId, p24_amount, p24_currency, p24_result, p24_sign
      const {
        p24_sessionId,
        p24_orderId,
        p24_amount,
        p24_currency,
        p24_result,
        p24_sign
      } = req.query;

      console.log('▶️ [sms/verify] Otrzymane parametry:', {
        p24_sessionId,
        p24_orderId,
        p24_amount,
        p24_currency,
        p24_result,
        p24_sign
      });

      // 2) Najpierw weryfikujemy poprawność p24_sign.
      //    wg dokumentacji: sign = SHA384( merchantId + "|" + sessionId + "|" + orderId + "|" + amount + "|" + currency + "|" + crcKey )
      const merchantId = process.env.P24_MERCHANT_ID?.trim();
      const crcKey     = process.env.P24_CRC_KEY?.trim();
      if (!merchantId || !crcKey) {
        console.warn('❌ [sms/verify] Brakuje P24_MERCHANT_ID lub P24_CRC_KEY w env');
        return res.status(500).send('Brakuje P24_MERCHANT_ID lub P24_CRC_KEY');
      }

      const dataToHash = `${merchantId}|${p24_sessionId}|${p24_orderId}|${p24_amount}|${p24_currency}|${crcKey}`;
      console.log('▶️ [sms/verify] dataToHash (do SHA384) =', dataToHash);

      const actualSign = calculateSHA384(dataToHash);
      console.log('▶️ [sms/verify] Obliczone actualSign =', actualSign);
      console.log('▶️ [sms/verify] Odebrane p24_sign =', p24_sign);

      if (actualSign !== p24_sign) {
        console.warn('⚠️ [sms/verify] sign mismatch', { actualSign, p24_sign });
        return res.status(400).send('Invalid signature');
      }

      // 3) Sprawdź status transakcji: p24_result === "OK" oznacza sukces
      if (p24_result === 'OK') {
        // 4) Wyciągnij deviceId z sessionId (format: "SMS_<deviceId>_<timestamp>")
        const parts = (p24_sessionId || '').split('_');
        if (parts.length < 2) {
          console.warn('⚠️ [sms/verify] Nieprawidłowy p24_sessionId:', p24_sessionId);
          return res.status(400).send('Invalid sessionId');
        }
        const deviceId = parts[1];
        console.log('▶️ [sms/verify] Wyodrębniony deviceId =', deviceId);

        // 5) Zaktualizuj devices: sms_limit = 30, abonament_expiry = teraz + 365 dni
        await db.query(
          `UPDATE devices
              SET sms_limit = 30,
                  abonament_expiry = (CURRENT_DATE + INTERVAL '365 days')::date
            WHERE id = $1`,
          [deviceId]
        );
        console.log('▶️ [sms/verify] Zaktualizowano devices dla deviceId =', deviceId);

        // 7) Wyślij prosty HTML z potwierdzeniem
        return res.send(`
          <html>
            <body style="font-family:sans-serif; text-align:center; margin-top:50px;">
              <h2>Płatność zakończona sukcesem &#128512;</h2>
              <p>Pakiet 30 SMS został przypisany do Twojego urządzenia.</p>
              <a href="/">Wróć do aplikacji</a>
            </body>
          </html>
        `);
      } else {
        console.warn('⚠️ [sms/verify] p24_result != OK:', p24_result);
        return res.send(`
          <html>
            <body style="font-family:sans-serif; text-align:center; margin-top:50px;">
              <h2>Płatność nieudana &#10060;</h2>
              <p>Pakiet SMS nie został przypisany.</p>
              <a href="/">Wróć do aplikacji</a>
            </body>
          </html>
        `);
      }
    } catch (err) {
      console.error('❌ [GET /sms/verify] Błąd:', err);
      return res.status(500).send('Verification error');
    }
  });
};

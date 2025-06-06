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

const axios  = require('axios');
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
        urlReturn: `https://www.techiot.pl/`, // klient wróci na stronę techiot.pl
        urlStatus: `https://${req.get('host')}/sms/verify`, // produkcyjne https
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
  // ────────────────────────────────────────────────────────────────────────
  // POST /sms/verify
  //  – Przelewy24 w produkcji wywołuje TEN endpoint metodą POST (application/x-www-form-urlencoded),
  //    przesyłając w body: { merchantId, posId, sessionId, amount, currency, orderId, sign, (…) }.
  //  – Jeśli podpis się zgadza, uznajemy to za pomyślną płatność i ładujemy SMS.
  // ────────────────────────────────────────────────────────────────────────
  app.post('/sms/verify', async (req, res) => {
    try {
      // 1) Otrzymane od P24 pola (produkcja):
      const {
        merchantId,
        posId,
        sessionId,
        amount,
        currency,
        orderId,
        sign
      } = req.body;

      console.log('▶️ [sms/verify] Otrzymane parametry P24 (POST):', req.body);

      // 2) Sprawdź, czy przynajmniej kluczowe parametry istnieją:
      if (!sessionId || !amount || !currency || !orderId || !sign) {
        console.warn('⚠️ [sms/verify] Brakuje wymaganych parametrów:', req.body);
        return res.status(400).send('Brakuje parametrów');
      }

      // 3) Weryfikuj sygnaturę:
      //    Dokładnie wg formuły: SHA384( merchantId + "|" + sessionId + "|" + orderId + "|" + amount + "|" + currency + "|" + crcKey )
      const cfgMerchantId = process.env.P24_MERCHANT_ID?.trim();
      const cfgCrcKey     = process.env.P24_CRC_KEY?.trim();
      if (!cfgMerchantId || !cfgCrcKey) {
        console.warn('❌ [sms/verify] Brakuje P24_MERCHANT_ID lub P24_CRC_KEY w env');
        return res.status(500).send('Brakuje P24_MERCHANT_ID lub P24_CRC_KEY');
      }

      const dataToHash = `${cfgMerchantId}|${sessionId}|${orderId}|${amount}|${currency}|${cfgCrcKey}`;
      console.log('▶️ [sms/verify] dataToHash (do SHA384) =', dataToHash);

      const actualSign = calculateSHA384(dataToHash);
      console.log('▶️ [sms/verify] Obliczone actualSign =', actualSign);
      console.log('▶️ [sms/verify] Odebrane sign         =', sign);

      if (actualSign !== sign) {
        console.warn('⚠️ [sms/verify] sign mismatch', { actualSign, sign });
        return res.status(400).send('Invalid signature');
      }

      // 4) Produkcyjny callback nie przesyła p24_result – jeśli podpis poprawny,
      //    uznajemy, że płatność się powiodła (można też dodatkowo wywołać /transaction/verify).

      // 5) Wyciągnij deviceId z sessionId (format: "SMS_<deviceId>_<timestamp>")
      const parts = sessionId.split('_');
      if (parts.length < 2) {
        console.warn('⚠️ [sms/verify] Nieprawidłowy sessionId:', sessionId);
        return res.status(400).send('Invalid sessionId');
      }
      const deviceId = parts[1];
      console.log('▶️ [sms/verify] Wyodrębniony deviceId =', deviceId);

      // 6) Aktualizujemy bazę: sms_limit = 30, abonament_expiry += 365 dni
      await db.query(
        `UPDATE devices
            SET sms_limit = 30,
                abonament_expiry = (CURRENT_DATE + INTERVAL '365 days')::date
          WHERE id = $1`,
        [deviceId]
      );
      console.log('▶️ [sms/verify] Zaktualizowano devices dla deviceId =', deviceId);

      // 7) Zwrotka do Przelewy24: HTTP 200, „OK”
      return res.send('OK');
    } catch (err) {
      console.error('❌ [POST /sms/verify] Błąd:', err);
      return res.status(500).send('Verification error');
    }
  });
};

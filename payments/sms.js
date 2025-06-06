// ----------------------
// Ścieżka: POST /sms/verify
// Obsługa webhooka od Przelewy24
// ----------------------

app.post(
  '/sms/verify',
  bodyParser.urlencoded({ extended: false }),  // P24 wysyła POST w formacie x-www-form-urlencoded
  async (req, res) => {
    try {
      //
      // 1) Odbierz (właściwe) pola z req.body:
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
      // 4) Wyliczamy sign od P24–owej notyfikacji (z JSON, a nie z „|”):
      //
      //    Obiekt w dokładnej kolejności:
      //    {
      //      merchantId:   Number(merchantIdEnv),
      //      posId:        Number(posIdEnv),
      //      sessionId:    sessionId,
      //      amount:       Number(amount),
      //      originAmount: Number(originAmount),
      //      currency:     currency,
      //      orderId:      Number(orderId),
      //      methodId:     Number(methodId),
      //      statement:    statement,
      //      crc:          crcKey
      //    }
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
      // 5) Skoro notyfikacja ma poprawny podpis, wywołujemy /transaction/verify:
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

      console.log('▶️ [sms/verify] Wysyłam POST do /transaction/verify …');
      const verifyResp = await clientVerify.post('/transaction/verify', {
        merchantId: Number(merchantIdEnv),
        posId:      Number(posIdEnv),
        sessionId:  sessionId,
        orderId:    Number(orderId),
        amount:     Number(amount),
        currency:   currency,
        // UWAGA: w tej weryfikacji sign liczymy tylko z { sessionId, orderId, amount, currency, crc }
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
      // Czasem zwraca "TRUE", czasem "success" (w starszych wersjach) — zawsze traktujemy to jako „potwierdzone”
      if (!(verifyStatus === true || verifyStatus === 'TRUE' || verifyStatus === 'success')) {
        console.warn('⚠️ [sms/verify] P24 NIE potwierdziło transakcji');
        return res.status(400).send('Transakcja niepotwierdzona');
      }

      //
      // 6) Jeżeli faktycznie P24 potwierdziło płatność, aktualizujemy bazę:
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
            <a href="https://www.techiot.pl/">Wróć do aplikacji</a>
          </body>
        </html>
      `);
    } catch (err) {
      console.error('❌ [POST /sms/verify] Błąd:', err);
      return res.status(500).send('Verification error');
    }
  }
);

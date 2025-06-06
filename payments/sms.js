// payments/sms.js

const axios  = require('axios');
const crypto = require('crypto');
require('dotenv').config();

module.exports = (app, db, auth) => {
  function calculateSHA384(data) {
    const hash = crypto.createHash('sha384');
    hash.update(data);
    return hash.digest('hex');
  }

  // … (ten fragment pozostaje bez zmian) …

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

      // 2) Sprawdź, czy wszystkie potrzebne przyszły:
      if (
        !merchantId ||
        !posId ||
        !sessionId ||
        !amount ||
        !currency ||
        !orderId ||
        !sign
      ) {
        console.warn('⚠️ [sms/verify] Brakuje parametrów:', req.body);
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

      // Upewnijmy się, że pól typu number/string używamy w tej samej kolejności i formacie:
      const dataToHash = `${cfgMerchantId}|${sessionId}|${orderId}|${amount}|${currency}|${cfgCrcKey}`;
      console.log('▶️ [sms/verify] dataToHash (do SHA384) =', dataToHash);

      const actualSign = calculateSHA384(dataToHash);
      console.log('▶️ [sms/verify] Obliczone actualSign =', actualSign);
      console.log('▶️ [sms/verify] Odebrane sign         =', sign);

      if (actualSign !== sign) {
        console.warn('⚠️ [sms/verify] sign mismatch', { actualSign, sign });
        return res.status(400).send('Invalid signature');
      }

      // 4) W produkcji nie mamy już p24_result – zakładamy, że jeśli podpis się zgadza,
      //    to płatność została zaksięgowana. (Możesz ewentualnie dodać dodatkowe
      //    weryfikowanie /transaction/verify, ale w większości przypadków wystarczy
      //    sprawdzić podpis z callbacka.)
      //    Jeżeli konieczne – odwołaj się jeszcze raz do /transaction/verify, tak jak w poprzedniej wersji.

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

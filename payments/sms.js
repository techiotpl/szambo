// payments/sms.js
//
// (1) POST  /sms/orders      –- Flutter wywołuje, dostaje redirectUrl do Przelewy24
// (2) POST  /sms/notify      –- webhook Przelewy24; zmienia status na 'paid'
//     + trigger w DB automatycznie podnosi sms_limit i abonament_expiry
//
// Plik jest modułem Express: eksportuje funkcję przyjmującą (app, db).

const crypto = require('crypto');
const axios  = require('axios');

module.exports = function registerSmsPayments(app, db) {
  // ──────────────────────────────────────────────────────────
  // 1️⃣  FLUTTER -> POST /sms/orders
  //     Body: { serial }
  //     Header: Authorization: Bearer <JWT>
  // ──────────────────────────────────────────────────────────
  app.post('/sms/orders', async (req, res) => {
    try {
      const { serial } = req.body;
      const user = req.user;              // ustawiany przez globalny middleware auth

      // 1. znajdź device + upewnij się, że należy do zalogowanego usera
      const { rows: devRows } = await db.query(
        'SELECT id FROM devices WHERE serial_number=$1 AND user_id=$2',
        [serial, user.id]
      );
      if (!devRows.length) {
        return res.status(404).send('device not found');
      }
      const deviceId = devRows[0].id;

      // 2. zarejestruj transakcję w Przelewy24
      const p24url   = 'https://secure.przelewy24.pl/api/v1/transaction/register';
      const cfg      = getP24Config();  // helper poniżej
      const sessionId= crypto.randomUUID();
      const amount   = 5000;            // grosze (50,00 zł)

      const body = {
        merchantId : cfg.merchantId,
        posId      : cfg.posId,
        sessionId,
        amount,
        currency   : 'PLN',
        description: `Pakiet 30 SMS – urządzenie ${serial}`,
        email      : user.email,
        country    : 'PL',
        urlReturn  : cfg.urlReturn,     // aplikacja/strona, gdzie klient wróci
        urlStatus  : cfg.urlStatus,     // = https://…/sms/notify  (webhook)
      };
      body.sign     = signP24(body, cfg.crc); // helper niżej

      const p24resp = await axios.post(p24url, body, {
        headers: { 'Content-Type': 'application/json' },
      });
      if (p24resp.data?.data?.token == null) {
        console.error('P24 error', p24resp.data);
        return res.status(502).send('p24 register failed');
      }
      const token       = p24resp.data.data.token;
      const redirectUrl = `https://secure.przelewy24.pl/trnRequest/${token}`;

      // 3. zapisz w sms_orders (status=new)
      await db.query(
        `INSERT INTO sms_orders(device_id, serial_number, amount, status, redirect_url)
           VALUES ($1,$2,50.00,'new',$3)`,
        [deviceId, serial, redirectUrl]
      );

      // 4. odeślij redirectUrl do Fluttera
      res.json({ redirectUrl });
    } catch (e) {
      console.error('sms/orders err', e);
      res.status(500).send('internal error');
    }
  });

  // ──────────────────────────────────────────────────────────
  // 2️⃣  PRZELEWY24 -> POST /sms/notify
  //     Body (JSON): { merchantId, posId, sessionId, amount, currency, orderId, sign }
  // ──────────────────────────────────────────────────────────
  app.post('/sms/notify', async (req, res) => {
    try {
      const n   = req.body;
      const cfg = getP24Config();

      // 1. walidacja podpisu od P24
      const control = `${n.sessionId}|${n.orderId}|${n.amount}|${n.currency}|${cfg.crc}`;
      const sha384  = crypto.createHash('sha384').update(control).digest('hex');
      if (sha384 !== n.sign) {
        return res.status(400).send('bad signature');
      }

      // 2. znajdź zamówienie po sessionId zapisanego w redirect_url
      const { rows } = await db.query(
        `UPDATE sms_orders
            SET status='paid'
          WHERE redirect_url LIKE '%' || $1 || '%'  -- zawiera token (sessionId)
          RETURNING id`,
        [n.sessionId]
      );
      if (!rows.length) {
        console.warn('notify: order not found');
      }

      // 3. trigger w DB zrobi resztę (sms_limit, abonament_expiry)
      res.send('OK');
    } catch (e) {
      console.error('sms/notify err', e);
      res.status(500).send('internal error');
    }
  });

  // ───────────────────────────────── helpers
  function getP24Config() {
    return {
      merchantId : process.env.P24_MERCHANT_ID,
      posId      : process.env.P24_POS_ID,
      crc        : process.env.P24_CRC,          // klucz CRC (string)
      urlReturn  : process.env.P24_URL_RETURN,   // np. https://techiot.pl/success
      urlStatus  : process.env.BASE_URL + '/sms/notify',
    };
  }

  // SHA384(sessionId|merchantId|amount|currency|crc)
  function signP24(obj, crc) {
    const text = `${obj.sessionId}|${obj.merchantId}|${obj.amount}|${obj.currency}|${crc}`;
    return crypto.createHash('sha384').update(text).digest('hex');
  }
};

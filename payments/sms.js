// payments/sms.js
//
// (1)  POST  /sms/orders   –  Flutter → backend
//       ▸ rejestruje transakcję w P24 REST API
//       ▸ zapisuje w sms_orders (status='new')
//       ▸ zwraca redirectUrl do przeglądarki
//
// (2)  POST  /sms/notify   –  webhook Przelewy24
//       ▸ sprawdza podpis SHA-384
//       ▸ ustawia status='paid' → trigger SQL podnosi sms_limit & abonament_expiry
//
// Użycie:  const smsPayments = require('./payments/sms'); smsPayments(app, db);

const crypto = require('crypto');
const axios  = require('axios');

module.exports = function registerSmsPayments(app, db) {
  /**──────────────────────────────────────────────────────────
   * 1️⃣  Tworzenie zamówienia – POST /sms/orders
   *     Body: { serial }
   *     Auth: Bearer <JWT>
   *──────────────────────────────────────────────────────────*/
  app.post('/sms/orders', async (req, res) => {
    try {
      const { serial } = req.body;
      const user = req.user;                       // przychodzi z middleware auth

      /* 1. sprawdź czy urządzenie należy do usera */
      const { rows: devRows } = await db.query(
        'SELECT id FROM devices WHERE serial_number=$1 AND user_id=$2',
        [serial, user.id]
      );
      if (!devRows.length) return res.status(404).send('device not found');
      const deviceId = devRows[0].id;

      /* 2. przygotuj dane do rejestracji P24 */
      const cfg       = getP24Config();
      const baseUrl   = cfg.sandbox
                       ? 'https://sandbox.przelewy24.pl'
                       : 'https://secure.przelewy24.pl';
      const registerUrl = baseUrl + '/api/v1/transaction/register';

      const sessionId = crypto.randomUUID(); // unikalny identyfikator transakcji
      const amountGr  = 5000;               // 50 zł -> grosze
      const body = {
        merchantId : cfg.merchantId,
        posId      : cfg.posId,
        sessionId,
        amount     : amountGr,
        currency   : 'PLN',
        description: `Pakiet 30 SMS – ${serial}`,
        email      : user.email,
        country    : 'PL',
        urlReturn  : cfg.urlReturn,
        urlStatus  : cfg.urlStatus,
      };
      body.sign = makeSign(body, cfg.crc);

      /* 3. wywołaj REST API P24 (Basic Auth: POS-ID + API-KEY) */
      const p24resp = await axios.post(registerUrl, body, {
        auth: { username: cfg.posId.toString(), password: cfg.apiKey },
        headers: { 'Content-Type': 'application/json' },
      });

      const token = p24resp.data?.data?.token;
      if (!token) {
        console.error('P24 register error', p24resp.data);
        return res.status(502).send('p24 register failed');
      }
      const redirectUrl = `${baseUrl}/trnRequest/${token}`;

      /* 4. zapisz zamówienie w bazie */
      await db.query(
        `INSERT INTO sms_orders(device_id, serial_number, amount, status, redirect_url)
         VALUES ($1,$2,50.00,'new',$3)`,
        [deviceId, serial, redirectUrl]
      );

      /* 5. odeślij URL do Fluttera */
      res.json({ redirectUrl });
    } catch (err) {
      console.error('sms/orders', err);
      res.status(500).send('internal error');
    }
  });

  /**──────────────────────────────────────────────────────────
   * 2️⃣  Webhook P24 – POST /sms/notify
   *──────────────────────────────────────────────────────────*/
  app.post('/sms/notify', async (req, res) => {
    try {
      const n   = req.body;          // JSON: { sessionId, orderId, amount, …, sign }
      const cfg = getP24Config();

      /* 1. weryfikacja podpisu */
      const control = `${n.sessionId}|${n.orderId}|${n.amount}|${n.currency}|${cfg.crc}`;
      const sha384  = crypto.createHash('sha384').update(control).digest('hex');
      if (sha384 !== n.sign) return res.status(400).send('bad signature');

      /* 2. aktualizacja statusu -> trigger SQL zrobi resztę */
      await db.query(
        `UPDATE sms_orders SET status='paid'
          WHERE redirect_url LIKE '%'||$1||'%'`,
        [n.sessionId]
      );

      res.send('OK');
    } catch (err) {
      console.error('sms/notify', err);
      res.status(500).send('internal error');
    }
  });

  /*──────────────────────────────── helpery ───────────────────────────────*/
  function getP24Config() {
    return {
      merchantId : process.env.P24_MERCHANT_ID,
      posId      : process.env.P24_POS_ID,
      apiKey     : process.env.P24_API_KEY,     // nowy klucz REST (Basic Auth)
      crc        : process.env.P24_CRC,
      sandbox    : process.env.P24_SANDBOX === 'true',
      urlReturn  : process.env.P24_URL_RETURN,
      urlStatus  : process.env.BASE_URL + '/sms/notify',
    };
  }

  /* SHA-384(sessionId|merchantId|amount|currency|crc) */
  function makeSign(obj, crc) {
    const txt = `${obj.sessionId}|${obj.merchantId}|${obj.amount}|${obj.currency}|${crc}`;
    return crypto.createHash('sha384').update(txt).digest('hex');
  }
};

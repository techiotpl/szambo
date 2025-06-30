// lib/updateOnLns.js
const axios = require('axios');

const TARGETS = [
  {
    name: 'Helium',
    base: 'https://console.helium-iot.xyz',
    appId: '3e34a4f5-8234-46b8-b7bc-076e431ea18c',
    profileId: '8a862a36-3aba-4c14-9a47-a41a5e33684e',
    tokenEnv: 'HELIUMBEARER',
  },
  {
    name: 'Oracle',
    base: 'http://141.145.220.65:8080/',
    appId: '0ae7a15d-a123-4deb-b085-e4dcc5a7c486',
    profileId: 'c9143688-eef4-4d8d-b69a-e3238af2be10',
    tokenEnv: 'ORACLEBEARER',
  },
];

module.exports = async function updateOnLns(serie, name, street) {
  const results = [];

  for (const t of TARGETS) {
    const token = (process.env[t.tokenEnv] || '').trim();
    if (!token) {
      results.push({ ok: false, target: t.name, error: 'brak tokenu' });
      continue;
    }

    try {
      const url = `${t.base}/api/devices/${serie}`;
      const resp = await axios.put(
        url,
        {
          device: {
            applicationId: t.appId,
            deviceProfileId: t.profileId,
            name,
            description: street,
            tags: {},
            variables: {},
          },
        },
        {
          headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${token}`,
          },
          validateStatus: () => true, // nie rzuca wyjątku przy 4xx
        }
      );

            const ok = String(resp.status).startsWith('2');
      results.push({
        ok,
        target: t.name,
        status: resp.status,
        error: ok ? undefined : resp.data?.message ?? 'HTTP ' + resp.status
      });
      // jeżeli wystarczy pierwszy sukces – break;
    } catch (err) {
      results.push({
        ok: false,
        target: t.name,
        error: err.message ?? 'unknown',
      });
    }
  }
  return results; // tablica z wynikiem każdego LNS
};

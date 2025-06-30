// lib/updateOnLns.js
const axios = require('axios');

const TARGETS = [
  {
    name: 'Helium',
    base: 'https://console.helium-iot.xyz',
    appId: 'b1b1bc39-ce10-49f3-88de-3999b1da5cf4',
    profileId: '8a862a36-3aba-4c14-9a47-a41a5e33684e',
    tokenEnv: 'HELIUMBEARER',
  },
  {
    name: 'Techiot LNS',
    base: 'https://lns.techiot.pl',
    appId: 'inny',
    profileId: 'inny',
    tokenEnv: 'TECHIOTBEARER',
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
      await axios.put(
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

      results.push({ ok: true, target: t.name });
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

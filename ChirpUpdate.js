// jobs/updateOnLns.js
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
    base: 'http://141.145.220.65:8090',
    appId: '0ae7a15d-a123-4deb-b085-e4dcc5a7c486',
    profileId: 'c9143688-eef4-4d8d-b69a-e3238af2be10',
    tokenEnv: 'ORACLEBEARER',
  },
];

// Normalizacja EUI (16-znakowy hex, wielkie litery)
function normalizeDevEui(eui) {
  return String(eui || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
}

/**
 * Próbuje zaktualizować device w każdym z LNS.
 * Jeśli PUT zwróci 404 (lub błąd z "expected length 32"), wykonuje POST.
 */
module.exports = async function updateOnLns(serie, name, street) {
  const results = [];
  const devEUI = normalizeDevEui(serie);
  if (devEUI.length !== 16) {
    return [{ ok: false, target: 'local', status: 0, error: `devEUI musi mieć 16 znaków HEX, dostałem "${devEUI}"` }];
  }

  for (const t of TARGETS) {
    const token = (process.env[t.tokenEnv] || '').trim();
    if (!token) {
      results.push({ ok: false, target: t.name, error: 'brak tokenu' });
      continue;
    }

    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`, // <— ważne: backticki!
    };

    const devName = (name && name.trim()) ? name.trim() : devEUI;

    // UUID z i bez myślników
    const appDashed = (t.appId || '').trim();
    const profDashed = (t.profileId || '').trim();
    const appSimple = appDashed.replace(/-/g, '');
    const profSimple = profDashed.replace(/-/g, '');

    // Jeden payload zgodny z obiema konwencjami nazw
    const devicePayload = {
      device: {
        // oba warianty, backend wybierze właściwe:
        applicationId: appDashed,
        applicationID: appSimple,
        deviceProfileId: profDashed,
        deviceProfileID: profSimple,

        devEUI: devEUI,           // podaj też przy PUT
        name: devName,
        description: street || '',
        tags: {},
        variables: {},
      },
    };

    try {
      // 1) PUT (update, jeśli istnieje)
      const putUrl = `${t.base}/api/devices/${devEUI}`;
      let resp = await axios.put(putUrl, devicePayload, {
        headers,
        validateStatus: () => true,
      });

      const msg = (resp.data && (resp.data.message || resp.data.error)) || '';
      const isLenErr = /expected length 32/i.test(msg);

      // 2) Jeśli nie ma (404) albo walnął błąd z "expected length 32" → spróbuj POST (create)
      if (resp.status === 404 || resp.status === 400 && isLenErr) {
        const postUrl = `${t.base}/api/devices`;
        resp = await axios.post(postUrl, devicePayload, {
          headers,
          validateStatus: () => true,
        });
      }

      const ok = String(resp.status).startsWith('2');
      results.push({
        ok,
        target: t.name,
        status: resp.status,
        error: ok ? undefined : (msg || `HTTP ${resp.status}`),
      });
    } catch (err) {
      results.push({
        ok: false,
        target: t.name,
        status: 0,
        error: err.response?.data?.message || err.message || 'unknown',
      });
    }
  }

  return results;
};

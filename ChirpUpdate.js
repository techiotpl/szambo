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
    base: 'http://141.145.220.65:8080',
    appId: '0ae7a15d-a123-4deb-b085-e4dcc5a7c486',
    profileId: 'c9143688-eef4-4d8d-b69a-e3238af2be10',
    tokenEnv: 'ORACLEBEARER',
  },
];

/**
 * Próbuje zaktualizować device w każdym z LNS.
 * Jeśli PUT zwróci 404, wykonuje POST.
 * Zwraca tablicę wyników: { ok, target, status, error? }.
 */
module.exports = async function updateOnLns(serie, name, street) {
  const results = [];

  for (const t of TARGETS) {
    const token = (process.env[t.tokenEnv] || '').trim();
    if (!token) {
      results.push({ ok: false, target: t.name, error: 'brak tokenu' });
      continue;
    }

    const headers = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    };
    const devName = name && name.trim() ? name.trim() : serie;

    try {
      // Spróbuj PUT
      const putUrl = `${t.base}/api/devices/${serie}`;
      let resp = await axios.put(
        putUrl,
        {
          device: {
            applicationId: t.appId,
            deviceProfileId: t.profileId,
            name: devName,
            description: street,
            tags: {},
            variables: {},
          },
        },
        {
          headers,
          validateStatus: () => true,
        }
      );

      // Jeśli nie ma (404), spróbuj utworzyć
      if (resp.status === 404) {
        const postUrl = `${t.base}/api/devices`;
        resp = await axios.post(
          postUrl,
          {
            device: {
              applicationId: t.appId,
              deviceProfileId: t.profileId,
              devEUI: serie,
              name: devName,
              description: street,
              tags: {},
              variables: {},
            },
          },
          {
            headers,
            validateStatus: () => true,
          }
        );
      }

      const ok = String(resp.status).startsWith('2');
      results.push({
        ok,
        target: t.name,
        status: resp.status,
        error: ok ? undefined : (resp.data?.message || `HTTP ${resp.status}`),
      });

    } catch (err) {
      results.push({
        ok: false,
        target: t.name,
        error: err.message || 'unknown',
      });
    }
  }

  return results;
};

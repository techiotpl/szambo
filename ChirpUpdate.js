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
    name: 'lns.techiot.pl',
    base: 'http://16.170.194.35:8090',
    appId: 'e400ccbd-ab70-4f8b-893b-3b4d4381f806',
    profileId: '7258a97f-5dde-4686-a63e-299bb52c24bf',
    tokenEnv: 'LNSBEARER',
  },
  {
    name: 'Oracle',
    base: 'http://141.145.220.65:8090',
    appId: '0ae7a15d-a123-4deb-b085-e4dcc5a7c486',
    profileId: 'c9143688-eef4-4d8d-b69a-e3238af2be10',
    tokenEnv: 'ORACLEBEARER',
  },
];

// 16 hex, wielkie litery
function normalizeDevEui(eui) {
  return String(eui || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
}

// wyciąga nazwy pól z odpowiedzi (ChirpStack/Helium różnie nazywają camelCase/idCase)
function pickIdFieldNames(deviceObj = {}) {
  const has = (k) => Object.prototype.hasOwnProperty.call(deviceObj, k);
  const appKey   = has('applicationId')   ? 'applicationId'   : (has('applicationID')   ? 'applicationID'   : null);
  const profKey  = has('deviceProfileId') ? 'deviceProfileId' : (has('deviceProfileID') ? 'deviceProfileID' : null);
  const devEuiKey= has('devEUI')          ? 'devEUI'          : (has('devEui')          ? 'devEui'          : 'devEUI');
  return { appKey, profKey, devEuiKey };
}

// GET urządzenia z LNS
async function getDevice(t, devEUI, headers) {
  const url = `${t.base}/api/devices/${devEUI}`;
  const resp = await axios.get(url, { headers, validateStatus: () => true });
  return resp;
}

/**
 * Aktualizuje nazwę/opis w LNS bez zmiany profilu:
 *  - jeśli device istnieje → PUT z tym samym applicationId/deviceProfileId (skopiowanymi z GET)
 *  - jeśli nie istnieje (404/len err) → POST (z appId/profileId z TARGETS)
 */
async function updateOnLns(serie, name, description) {
  const results = [];
  const devEUI = normalizeDevEui(serie);
  if (devEUI.length !== 16) {
    return [{ ok: false, target: 'local', status: 0, error: `devEUI musi mieć 16 znaków HEX, dostałem "${devEUI}"` }];
  }

  for (const t of TARGETS) {
    const token = (process.env[t.tokenEnv] || '').trim();
    if (!token) {
      results.push({ ok: false, target: t.name, status: 0, error: 'brak tokenu' });
      continue;
    }
    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };
    const devName = (name && String(name).trim()) ? String(name).trim() : devEUI;
    // Jeśli description == null/'' → NIE nadpisujemy istniejącego opisu w LNS
    const desc = (description != null && String(description).trim() !== '') ? String(description).trim() : null;
 
  

    try {
      // 1) Spróbuj odczytać aktualną definicję, żeby NIE zmieniać profilu
      const getResp = await getDevice(t, devEUI, headers);

      // a) ISTNIEJE → PUT z tymi samymi ID (tylko name/description)
      if (String(getResp.status).startsWith('2') && getResp.data) {
        const devObj = getResp.data.device || getResp.data;
        const foundDescription = (devObj && devObj.description != null) ? String(devObj.description) : '';
        const { appKey, profKey, devEuiKey } = pickIdFieldNames(devObj);

        // składamy payload tak, aby skopiować identyfikatory dokładnie w tej samej konwencji
        const devicePayload = { device: {} };
        devicePayload.device[devEuiKey] = devEUI;
        if (appKey && devObj[appKey])  devicePayload.device[appKey]  = devObj[appKey];
        if (profKey && devObj[profKey]) devicePayload.device[profKey] = devObj[profKey];
        devicePayload.device.name = devName;
        if (desc !== null) devicePayload.device.description = desc;

        //dodajemy  29.11.2025
                // 🔓 Wymuś włączenie urządzenia na LNS
        // ChirpStack v4: isDisabled (bool). Niektóre API używają disabled.
        // Dodajemy oba – nadmiarowe pola zostaną zignorowane po stronie LNS, a gdzie wspierane, włączą device.
        devicePayload.device.isDisabled = false;
        devicePayload.device.disabled = false;
///koniec  tego  co  dodalem 29.11.2025
        
        const putUrl = `${t.base}/api/devices/${devEUI}`;
        const putResp = await axios.put(putUrl, devicePayload, { headers, validateStatus: () => true });

        const ok = String(putResp.status).startsWith('2');
        results.push({
          ok,
          target: t.name,
          status: putResp.status,
          foundDescription,
          error: ok ? undefined : (putResp.data?.message || putResp.data?.error || `HTTP ${putResp.status}`),
        });
        continue;
      }

      // b) NIE ISTNIEJE → POST (tu trzeba podać app/profile z konfiguracji)
      const appDashed  = (t.appId || '').trim();
      const profDashed = (t.profileId || '').trim();
      const appSimple  = appDashed.replace(/-/g, '');
      const profSimple = profDashed.replace(/-/g, '');

      const createPayload = {
        device: {
          // podajemy oba warianty, backend wybierze właściwy
          applicationId: appDashed,
          applicationID: appSimple,
          deviceProfileId: profDashed,
          deviceProfileID: profSimple,
          devEUI: devEUI,
          name: devName,
          ...(desc !== null ? { description: desc } : {}),
          //dodalem 29.11.2025
          // 🔓 Domyślnie tworzymy urządzenie jako włączone
          isDisabled: false,
          disabled: false,
        //koniec dodanego 29.11.2025
          
          tags: {},
          variables: {},
        },
      };

      const postUrl = `${t.base}/api/devices`;
      const postResp = await axios.post(postUrl, createPayload, { headers, validateStatus: () => true });

      const msg = postResp.data && (postResp.data.message || postResp.data.error);
      const ok = String(postResp.status).startsWith('2');
      results.push({
        ok,
        target: t.name,
        status: postResp.status,
        foundDescription: desc || '' ,
        error: ok ? undefined : (msg || `HTTP ${postResp.status}`),
      });
    } catch (err) {
      results.push({
        ok: false,
        target: t.name,
        status: err.response?.status || 0,
        error: err.response?.data?.message || err.response?.data?.error || err.message || 'unknown',
      });
    }
  }

  return results;
  }
// ⬇️ Nowa funkcja: TYLKO odczyt description z któregoś ChirpStacka (TARGETS)
async function getDeviceDescription(serie) {
  const devEUI = normalizeDevEui(serie);
  if (devEUI.length !== 16) {
    return { ok: false, target: 'local', status: 0, description: '' };
  }

  const DBG = String(process.env.SUPPORT_CONTACT_DEBUG || '').toLowerCase() === 'true';
  const dlog = (...a) => { if (DBG) console.log('[getDeviceDescription]', ...a); };



  
  for (const t of TARGETS) {
    const token = (process.env[t.tokenEnv] || '').trim();
        if (!token) {
      dlog(`skip target=${t.name} reason=no_token env=${t.tokenEnv}`);
      continue;
    }

    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    };

    try {
      const getResp = await getDevice(t, devEUI, headers);
      dlog(`target=${t.name} GET /api/devices/${devEUI} status=${getResp.status}`);
      if (String(getResp.status).startsWith('2') && getResp.data) {
        const devObj = getResp.data.device || getResp.data;
        const desc = (devObj && devObj.description != null) ? String(devObj.description).trim() : '';
        dlog(`target=${t.name} ok descLen=${desc.length} desc="${desc.slice(0, 40)}"`);
        return { ok: true, target: t.name, status: getResp.status, description: desc };
      }
            // nie-2xx – loguj krótko body (bez spamowania)
      const msg = getResp?.data?.message || getResp?.data?.error || '';
      dlog(`target=${t.name} non2xx status=${getResp.status} msg="${String(msg).slice(0, 80)}"`);
    } catch (_) {}
     dlog(`target=${t.name} ERROR: ${e?.message || e}`);
  }

  return { ok: false, target: 'none', status: 404, description: '' };
}

module.exports = updateOnLns;
module.exports.getDeviceDescription = getDeviceDescription;

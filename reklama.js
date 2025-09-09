// reklama.js – moduł obsługujący banery /ads
// Wystarczy require('./reklama')(app, db) i trasa /ads będzie aktywna.

const geoip = require('geoip-lite');
const axios = require('axios');
const jwt = require('jsonwebtoken');

// ─────────────────────────────────────────────────────────────────────────────
// MAPOWANIE KODÓW REGION → NAZWA WOJEWÓDZTWA
// ─────────────────────────────────────────────────────────────────────────────
const _regionMapPL = {
  '02': 'Dolnośląskie',
  '04': 'Kujawsko-Pomorskie',
  '06': 'Lubelskie',
  '08': 'Lubuskie',
  '10': 'Łódzkie',
  '12': 'Małopolskie',
  '14': 'Mazowieckie',
  '16': 'Opolskie',
  '18': 'Podkarpackie',
  '20': 'Podlaskie',
  '22': 'Pomorskie',
  '24': 'Śląskie',
  '26': 'Świętokrzyskie',
  '28': 'Warmińsko-Mazurskie',
  '30': 'Wielkopolskie',
  '32': 'Zachodniopomorskie',
};

// ─────────────────────────────────────────────────────────────────────────────
// MINI „Baza” banerów – grupy A (premium), B (standard), C (ekonomiczna)
// ─────────────────────────────────────────────────────────────────────────────
const ADS = {
  // MIASTA ───────────────────────────────────────────────────────────────────
  Szczecin: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+999' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+8888' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+777' }
    ],
    C: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: 'https://uniwersal-szambiarka.pl' }
    ],
  },
  Stargard: {
    A: [
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+48123456789' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+48987654321' }
    ],
    C: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: 'tel:+48111222333' }
    ],
  },
  Bydgoszcz: {
    A: [
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+4444' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:5555' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+55555' }
    ],
    C: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: 'tel:+485000' }
    ],
  },

  // WOJEWÓDZTWA (fallback) ──────────────────────────────────────────────────
  'Kujawsko-Pomorskie': {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+111' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+2222' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: '333' }
    ],
    C: [
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+48101010' }
    ],
  },
  'Zachodniopomorskie': {
    A: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: 'tel:+11223344' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+55667788' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: '997' }
    ],
    C: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: 'tel:+48202020' }
    ],
  },

  // DOMYŚLNY koszyk ─────────────────────────────────────────────────────────
  OTHER: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+0000002' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:00001' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: '000000' }
    ],
    C: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+48000003' }
    ],
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// STREFY GEO (promień od miasta) + dystans Haversine
// Priorytet: mniejszy promień = bardziej „precyzyjna” strefa
// ─────────────────────────────────────────────────────────────────────────────
const GEO_ZONES = [
  { name: 'Szczecin-10km',  bucket: 'Szczecin',  lat: 53.42894, lon: 14.55302, radiusKm: 10 },
  { name: 'Stargard-30km',  bucket: 'Stargard',  lat: 53.33689, lon: 15.04953, radiusKm: 30 },
];

function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = d => (d * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat/2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon/2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function matchGeoZone(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return null;
  const hits = GEO_ZONES
    .map(z => ({ z, dist: haversineKm(lat, lon, z.lat, z.lon) }))
    .filter(x => x.dist <= x.z.radiusKm);
  if (!hits.length) return null;
  hits.sort((a,b) => (a.z.radiusKm - b.z.radiusKm) || (a.dist - b.dist));
  return hits[0].z.bucket; // np. 'Szczecin' | 'Stargard'
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse-geocode z cache (city/region po lat/lon) – TTL 24h
// ─────────────────────────────────────────────────────────────────────────────
const _revCache = new Map(); // key: "lat,lon" (3 miejsca po przecinku)
async function reverseCityRegion(lat, lon) {
  if (typeof lat !== 'number' || typeof lon !== 'number') return { city: null, region: null };
  const key = `${lat.toFixed(3)},${lon.toFixed(3)}`;
  const hit = _revCache.get(key);
  const now = Date.now();
  if (hit && now - hit.t < 24 * 3600 * 1000) return hit.v;
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lon}&zoom=10&addressdetails=1&accept-language=pl`;
    const r = await axios.get(url, {
      timeout: 5000,
      headers: {
        'User-Agent': `TechioT-Ads/1.0 (${process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl'})`
      }
    });
    const a = r?.data?.address || {};
    const val = { city: a.city || a.town || a.village || a.hamlet || null, region: a.state || null };
    _revCache.set(key, { t: now, v: val });
    return val;
  } catch {
    return { city: null, region: null };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wybór miasta/regionu + współrzędnych po urządzeniu (?serial lub JWT usera)
// ─────────────────────────────────────────────────────────────────────────────
async function pickCityRegionFromDevice(req, db) {
  // 1) Priorytet: ?serial=EUI (bez auth)
  const serial = String(req.query.serial || '').trim().toUpperCase();
  if (/^[0-9A-F]{16}$/.test(serial) && db) {
    try {
      const { rows } = await db.query('SELECT lat, lon FROM devices WHERE serial_number = $1 LIMIT 1', [serial]);
      if (rows.length && rows[0].lat != null && rows[0].lon != null) {
        const lat = Number(rows[0].lat), lon = Number(rows[0].lon);
        const r = await reverseCityRegion(lat, lon);
        return { ...r, lat, lon, source: 'device-serial' };
      }
    } catch {}
  }
  // 2) Drugi priorytet: Authorization: Bearer <jwt> → najnowsze urządzenie usera
  const hdr = (req.headers.authorization || '').trim();
  if (!hdr || !db) return null;
  try {
    const token = hdr.replace(/^Bearer\s+/i, '').trim();
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret');
    if (!payload?.id || payload.id === 'admin') return null;
    const { rows } = await db.query(
      `SELECT lat, lon
         FROM devices
        WHERE user_id = $1 AND lat IS NOT NULL AND lon IS NOT NULL
        ORDER BY coalesce(updated_at, created_at) DESC NULLS LAST, id DESC
        LIMIT 1`,
      [payload.id]
    );
    if (rows.length) {
      const lat = Number(rows[0].lat), lon = Number(rows[0].lon);
      const r = await reverseCityRegion(lat, lon);
      return { ...r, lat, lon, source: 'device-of-user' };
    }
  } catch {}
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Eksport: pojedyncza funkcja → registerAdsRoute(app, db)
// ─────────────────────────────────────────────────────────────────────────────
module.exports = function registerAdsRoute(app, db) {
  // LISTY WYŁĄCZEŃ (miasta/regiony) – na przyszłość
  const DISABLED_CITIES  = new Set();
  const DISABLED_REGIONS = new Set();

  const cors = require('cors');
  app.options('/ads', cors()); // preflight
  app.get('/ads', cors({ origin: true }), async (req, res) => {
    if (process.env.ADS_ENABLED !== 'true') {
      return res.json([]);
    }

    // 1) Grupa: 'A' | 'B' | 'C' (domyślnie 'B')
    const group = ['A','B','C'].includes(req.query.group) ? req.query.group : 'B';

    // 2) Zebrać dane lokalizacyjne
    const cap = s => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : s);
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const geo = geoip.lookup(ip);
    const geoRegionName = (geo && geo.country === 'PL' && _regionMapPL[geo.region]) || null;

    // miasto z query (jeśli ktoś ręcznie poda)
    let city = ((req.query.city || '') + '').trim();
    if (city) city = cap(city);

    // spróbuj pobrać współrzędne/miasto po urządzeniu (ulica → geokod lat/lon)
    let prof = null;
    try { prof = await pickCityRegionFromDevice(req, db); } catch {}
    const lat = (prof && typeof prof.lat === 'number') ? prof.lat
              : (geo?.ll && Array.isArray(geo.ll) ? Number(geo.ll[0]) : null);
    const lon = (prof && typeof prof.lon === 'number') ? prof.lon
              : (geo?.ll && Array.isArray(geo.ll) ? Number(geo.ll[1]) : null);

    // 3) Strefa promieniowa (PREFEROWANA) – działa, gdy mamy lat/lon z urządzenia
    const zoneBucket = (typeof lat === 'number' && typeof lon === 'number') ? matchGeoZone(lat, lon) : null;

    // 4) Wyłączenia
    const regionName = (!zoneBucket && !city) ? (prof?.region || geoRegionName) : null;
    if (DISABLED_CITIES.has(city) || DISABLED_CITIES.has(zoneBucket) || DISABLED_REGIONS.has(regionName)) {
      return res.json([]);
    }

    // 5) Wybór koszyka: strefa → miasto → województwo → OTHER
    let bucketKey = 'OTHER';
    if (zoneBucket && ADS[zoneBucket]) {
      bucketKey = zoneBucket;
    } else if (city && ADS[city]) {
      bucketKey = city;
    } else if (regionName && ADS[regionName]) {
      bucketKey = regionName;
    }
    const bucket = ADS[bucketKey] || ADS['OTHER'];

    // Fallback grup: spróbuj żądanej, jak pusta → B → A → C
    const groupOrder = [group, 'B', 'A', 'C'].filter((g, i, arr) => arr.indexOf(g) === i);
    let rawBanners = [];
    for (const g of groupOrder) {
      if (Array.isArray(bucket[g]) && bucket[g].length) { rawBanners = bucket[g]; break; }
    }

    // 6) Log diagnostyczny
    try {
      console.log(
        '🧭 [ADS] ip=%s geo.city=%s geo.region=%s | prof.city=%s prof.region=%s | lat=%s lon=%s | zone=%s | bucket=%s | group=%s → %d',
        ip,
        geo?.city || null, geoRegionName || null,
        prof?.city || null, prof?.region || null,
        (typeof lat==='number'?lat.toFixed(4):null),
        (typeof lon==='number'?lon.toFixed(4):null),
        zoneBucket || null,
        bucketKey, group, rawBanners.length
      );
    } catch {}

    // 7) Odpowiedź z metadanymi
    const enriched = rawBanners.map((b, idx) => ({
      id: `${bucketKey}-${group}-${idx}`,
      img: b.img,
      href: b.href,
      // dla wglądu: co „zdecydowało”
      city: zoneBucket || city || prof?.city || null,
      region: (!zoneBucket && !city) ? (prof?.region || geoRegionName) : null,
    }));

    return res.json(enriched);
  });
};

// Przydatne w testach
module.exports.ADS = ADS;

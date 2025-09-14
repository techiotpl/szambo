// reklama.js – moduł obsługujący banery /ads
// Wystarczy require('./reklama')(app, db) i trasa /ads będzie aktywna.

const geoip = require('geoip-lite');
const axios = require('axios');
const jwt = require('jsonwebtoken');

/* ────────────────────────────────────────────────────────────────────────────
   MAPOWANIE KODÓW REGION → NAZWA WOJEWÓDZTWA
   ──────────────────────────────────────────────────────────────────────────── */
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

/* ────────────────────────────────────────────────────────────────────────────
   MINI „Baza” banerów – grupy A (premium), B (standard), C (ekonomiczna)
   ──────────────────────────────────────────────────────────────────────────── */
const ADS = {
  // MIASTA
  Szczecin: {
    A: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' },
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  },
  Stargard: {
    A: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  },
  Bydgoszcz: {
    A: [
     
      { img: 'https://files.us-e1.tago.io/644b882c02d9480009f89817/storage/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  },

  // WOJEWÓDZTWA (fallback)
  'Kujawsko-Pomorskie': {
    A: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' },
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  },
  'Zachodniopomorskie': {
    A: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' },
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  },

  // DOMYŚLNY koszyk
  OTHER: {
    A: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' },
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    B: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
    C: [
      { img: 'https://files.us-e1.tago.io/666338f30e99fc00097a38e6/storage/jpg/Logo%20IOT.jpg', href: 'tel:573009475' }
    ],
  }
};


/* ────────────────────────────────────────────────────────────────────────────
   STREFY GEO (promień od miasta) + dystans Haversine
   Priorytet: mniejszy promień = bardziej „precyzyjna” strefa
   ──────────────────────────────────────────────────────────────────────────── */
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

/* ────────────────────────────────────────────────────────────────────────────
   Reverse- i Forward-geocode z cache – TTL 24h
   ──────────────────────────────────────────────────────────────────────────── */
const _revCache = new Map(); // key: "lat,lon" (3 miejsca po przecinku)
const _fwdCache = new Map(); // key: full address string

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
      headers: { 'User-Agent': `TechioT-Ads/1.0 (${process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl'})` }
    });
    const a = r?.data?.address || {};
    const val = { city: a.city || a.town || a.village || a.hamlet || null, region: a.state || null };
    _revCache.set(key, { t: now, v: val });
    return val;
  } catch {
    return { city: null, region: null };
  }
}

async function geocodeAddress(addr) {
  const key = String(addr || '').trim();
  if (!key) return null;
  const hit = _fwdCache.get(key);
  const now = Date.now();
  if (hit && now - hit.t < 24 * 3600 * 1000) return hit.v;
  try {
    const url = `https://nominatim.openstreetmap.org/search?format=jsonv2&q=${encodeURIComponent(key)}&limit=1&accept-language=pl`;
    const r = await axios.get(url, {
      timeout: 6000,
      headers: { 'User-Agent': `TechioT-Ads/1.0 (${process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl'})` }
    });
    if (Array.isArray(r.data) && r.data.length) {
      const it = r.data[0];
      const v = { lat: Number(it.lat), lon: Number(it.lon) };
      _fwdCache.set(key, { t: now, v });
      return v;
    }
  } catch {}
  return null;
}

/* ────────────────────────────────────────────────────────────────────────────
   Wybór miasta/regionu + współrzędnych po urządzeniu (?serial lub JWT usera)
   Najpierw lat/lon, jeśli brak → geokod po ulicy
   ──────────────────────────────────────────────────────────────────────────── */
async function pickCityRegionFromDevice(req, db) {
  // 1) Priorytet: ?serial=EUI (bez auth)
  const serial = String(req.query.serial || '').trim().toUpperCase();
  if (/^[0-9A-F]{16}$/.test(serial)) {
    if (!db) {
      console.log('⚠️  [ADS] serial=%s podany, ale DB nie jest dostępne w reklama.js', serial);
      return null;
    }
    try {
      console.log('🔎 [ADS] pick by serial=%s', serial);
      const { rows } = await db.query(
        'SELECT lat, lon, street FROM devices WHERE serial_number = $1 LIMIT 1',
        [serial]
      );
      if (rows.length) {
        let { lat, lon, street } = rows[0];
        if (lat != null && lon != null) {
          lat = Number(lat); lon = Number(lon);
          const r = await reverseCityRegion(lat, lon);
          console.log('✅ [ADS] device-serial: lat=%s lon=%s → city=%s region=%s',
            lat.toFixed(5), lon.toFixed(5), r.city, r.region);
          return { ...r, lat, lon, source: 'device-serial' };
        }
        if (street) {
          console.log('ℹ️  [ADS] device-serial: brak lat/lon, próbuję geocode ulicy "%s"', street);
          const g = await geocodeAddress(`${street}, Polska`);
          if (g) {
            const r = await reverseCityRegion(g.lat, g.lon);
            console.log('✅ [ADS] geocode(street) OK: lat=%s lon=%s → city=%s region=%s',
              g.lat.toFixed(5), g.lon.toFixed(5), r.city, r.region);
            return { ...r, lat: g.lat, lon: g.lon, source: 'device-serial:street' };
          }
          console.log('⚠️  [ADS] geocode(street) NIEUDANE');
        }
      } else {
        console.log('⚠️  [ADS] serial nie znaleziony w devices');
      }
    } catch (e) {
      console.log('🛑 [ADS] błąd pick by serial: %s', e?.message || e);
    }
  }

  // 2) Drugi priorytet: Authorization: Bearer <jwt> → najnowsze urządzenie usera
  const hdr = (req.headers.authorization || req.query.token || '').trim();
  if (!hdr || !db) {
    if (!hdr) console.log('ℹ️  [ADS] brak Authorization → ominę pick by user.');
    return null;
  }
  try {
    const token = hdr.replace(/^Bearer\s+/i, '').trim();
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret');
    if (!payload?.id || payload.id === 'admin') {
      console.log('ℹ️  [ADS] JWT bez id lub admin → ominę pick by user.');
      return null;
    }
    console.log('🔎 [ADS] pick by user id=%s', payload.id);
    const { rows } = await db.query(
      `SELECT lat, lon, street
         FROM devices
        WHERE user_id = $1
        ORDER BY coalesce(updated_at, created_at) DESC NULLS LAST, id DESC
        LIMIT 1`,
      [payload.id]
    );
    if (rows.length) {
      let { lat, lon, street } = rows[0];
      if (lat != null && lon != null) {
        lat = Number(lat); lon = Number(lon);
        const r = await reverseCityRegion(lat, lon);
        console.log('✅ [ADS] device-of-user: lat=%s lon=%s → city=%s region=%s',
          lat.toFixed(5), lon.toFixed(5), r.city, r.region);
        return { ...r, lat, lon, source: 'device-of-user' };
      }
      if (street) {
        console.log('ℹ️  [ADS] device-of-user: brak lat/lon, geocode ulicy "%s"', street);
        const g = await geocodeAddress(`${street}, Polska`);
        if (g) {
          const r = await reverseCityRegion(g.lat, g.lon);
          console.log('✅ [ADS] geocode(street,user) OK: lat=%s lon=%s → city=%s region=%s',
            g.lat.toFixed(5), g.lon.toFixed(5), r.city, r.region);
          return { ...r, lat: g.lat, lon: g.lon, source: 'device-of-user:street' };
        }
        console.log('⚠️  [ADS] geocode(street,user) NIEUDANE');
      }
    } else {
      console.log('⚠️  [ADS] user nie ma urządzeń');
    }
  } catch (e) {
    console.log('🛑 [ADS] błąd pick by user: %s', e?.message || e);
  }
  return null;
}

/* ────────────────────────────────────────────────────────────────────────────
   Eksport: pojedyncza funkcja → registerAdsRoute(app, db)
   ──────────────────────────────────────────────────────────────────────────── */
module.exports = function registerAdsRoute(app, db) {
  // LISTY WYŁĄCZEŃ (miasta/regiony) – na przyszłość
  const DISABLED_CITIES  = new Set();
  const DISABLED_REGIONS = new Set();

  const cors = require('cors');
  app.options('/ads', cors()); // preflight

  app.get('/ads', cors({ origin: true }), async (req, res) => {
    if (process.env.ADS_ENABLED !== 'true') {
      console.log('⛔ [ADS] wyłączone (ADS_ENABLED!=true)');
      return res.json([]);
    }

    // 1) Grupa: 'A' | 'B' | 'C' (domyślnie 'B')
    const group = ['A','B','C'].includes(req.query.group) ? req.query.group : 'B';

    // 2) Wejścia: miasto z query + IP + urządzenie
    const cap = s => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : s);
    let city = ((req.query.city || '') + '').trim();
    if (city) city = cap(city);

    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const geo = geoip.lookup(ip);
    const geoRegionName = (geo && geo.country === 'PL' && _regionMapPL[geo.region]) || null;

    // Priorytet: URZĄDZENIE → (ew. query lat/lon do testów) → GEOIP
    let prof = null;
    try { prof = await pickCityRegionFromDevice(req, db); } catch {}
    let lat = (prof && typeof prof.lat === 'number') ? prof.lat : null;
    let lon = (prof && typeof prof.lon === 'number') ? prof.lon : null;

    // (opcjonalnie) ręczne testy: ?lat=&lon= (nadpisze geoip, ale NIE nadpisze prof)
    if (lat == null && lon == null && req.query.lat && req.query.lon) {
      const qLat = Number(req.query.lat), qLon = Number(req.query.lon);
      if (Number.isFinite(qLat) && Number.isFinite(qLon)) {
        lat = qLat; lon = qLon;
        console.log('🧪 [ADS] override lat/lon z query: %s, %s', qLat, qLon);
      }
    }
    if (lat == null && lon == null && geo?.ll && Array.isArray(geo.ll)) {
      lat = Number(geo.ll[0]); lon = Number(geo.ll[1]);
    }

    // 3) Strefa promieniowa – działa tylko jeśli MAMY lat/lon
    const zoneBucket = (typeof lat === 'number' && typeof lon === 'number') ? matchGeoZone(lat, lon) : null;

    // 4) Wyłączenia
     const effectiveCity = city || prof?.city || null;
  const regionName = (!zoneBucket && !effectiveCity) ? (prof?.region || geoRegionName) : null;
    if (DISABLED_CITIES.has(city) || DISABLED_CITIES.has(zoneBucket) || DISABLED_REGIONS.has(regionName)) {
      console.log('🚫 [ADS] wyłączone dla city=%s zone=%s region=%s', city, zoneBucket, regionName);
      return res.json([]);
    }

    // 5) Wybór koszyka: STREFA → MIASTO → WOJEW. → OTHER
    let bucketKey = 'OTHER';
  if (zoneBucket && ADS[zoneBucket]) {
    bucketKey = zoneBucket;
  } else if (effectiveCity && ADS[effectiveCity]) {
    bucketKey = effectiveCity;
  } else if (regionName && ADS[regionName]) {
    bucketKey = regionName;
  }
    const bucket = ADS[bucketKey] || ADS['OTHER'];

    // Fallback grup: spróbuj żądanej, jak pusta → B → A → C (bez duplikatów)
    const groupOrder = [group, 'B', 'A', 'C'].filter((g, i, arr) => arr.indexOf(g) === i);
    let rawBanners = [];
    for (const g of groupOrder) {
      if (Array.isArray(bucket[g]) && bucket[g].length) { rawBanners = bucket[g]; break; }
    }

    // 6) Log diagnostyczny (bogatszy)
    try {
      console.log(
        '🧭 [ADS] ip=%s geo.city=%s geo.region=%s | source=%s | prof.city=%s prof.region=%s | lat=%s lon=%s | zone=%s | bucket=%s | group=%s → %d',
        ip,
        geo?.city || null, geoRegionName || null,
        prof?.source || (geo ? 'geoip' : 'none'),
        prof?.city || null, prof?.region || null,
        (typeof lat==='number'?lat.toFixed(5):null),
        (typeof lon==='number'?lon.toFixed(5):null),
        zoneBucket || null,
        bucketKey, group, rawBanners.length
      );
    } catch {}

    // Opcjonalny nagłówek debug (łatwiej podglądać z klienta / curl)
    try {
      const debug = {
        ip, geoCity: geo?.city || null, geoRegion: geoRegionName || null,
        source: prof?.source || (geo ? 'geoip' : 'none'),
        profCity: prof?.city || null, profRegion: prof?.region || null,
        lat: (typeof lat==='number'?Number(lat.toFixed(5)):null),
        lon: (typeof lon==='number'?Number(lon.toFixed(5)):null),
        zone: zoneBucket || null, bucket: bucketKey,
        groupRequested: group, banners: rawBanners.length
      };
      res.setHeader('X-Ads-Debug', encodeURIComponent(JSON.stringify(debug)));
    } catch {}

    // 7) Odpowiedź z metadanymi
    const enriched = rawBanners.map((b, idx) => ({
      id: `${bucketKey}-${group}-${idx}`,
      img: b.img,
      href: b.href,
  city: zoneBucket || effectiveCity,
  region: (!zoneBucket && !effectiveCity) ? (prof?.region || geoRegionName) : null,
    }));

    return res.json(enriched);
  });
};

// Przydatne w testach
module.exports.ADS = ADS;

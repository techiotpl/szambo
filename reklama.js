// reklama.js – moduł obsługujący banery /ads
// Wydzielone z server.js, aby uprościć główny plik backendu.
// Wystarczy require('./reklama')(app) i trasa /ads będzie aktywna.

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
// MINI „Baza” banerów – grupa A (premium) i B (standard)
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
    ]
  },
  Bydgoszcz: {
    A: [
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+4444' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:5555' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+55555' }
    ]
  },

  // WOJEWÓDZTWA (fallback) ──────────────────────────────────────────────────
  'Kujawsko-Pomorskie': {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+111' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+2222' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: '333' }
    ]
  },
  'Zachodniopomorskie': {
    A: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: 'tel:+11223344' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+55667788' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: '997' }
    ]
  },

  // DOMYŚLNY koszyk ─────────────────────────────────────────────────────────
  OTHER: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+0000002' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:00001' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: '000000' }
    ]
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Eksport: pojedyncza funkcja, którą wywołujesz z server.js → registerAdsRoute(app)
// ─────────────────────────────────────────────────────────────────────────────
module.exports = function registerAdsRoute(app,db) {
  // WYŁĄCZONE REKLAMY – na razie pusto, ale zostawiamy miejsce na przyszłość


      /*──────────────────────────────────────────────
    WYŁĄCZONE REKLAMY  – listy miast / regionów
    Dodajesz tu kolejne pozycje, jeśli zajdzie potrzeba
  ──────────────────────────────────────────────*/

  //jesli wyłączamy tu odkomenetowac a na dole zakomentowac 

//  const DISABLED_CITIES   = new Set(['Bydgoszcz']);
 //  const DISABLED_REGIONS  = new Set(['Kujawsko-Pomorskie']);
  
  ///jesli wyłączamy  reklamy to odkomentowac to nizej
  const DISABLED_CITIES  = new Set();
  const DISABLED_REGIONS = new Set();


///jest
    const cors = require('cors');
  app.options('/ads', cors()); // preflight (na zapas)
  app.get('/ads', cors({ origin: true }), async (req, res) => {
    //koniec jest
    if (process.env.ADS_ENABLED !== 'true') {
      return res.json([]);
    }

    // 1) Grupa cenowa: 'A' – premium, 'B' – standard (domyślna)
    const group = req.query.group === 'A' ? 'A' : 'B';

    // 2) Ustal lokalizację: ?city → (opcjonalnie) coords z urządzenia → GeoIP
    const cap = s => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : s);
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const geo = geoip.lookup(ip);
    const geoRegionName = (geo && geo.country === 'PL' && _regionMapPL[geo.region]) || null;
    let city = ((req.query.city || '') + '').trim();
    if (city) city = cap(city);

    // (A) próba nadpisania miasto/województwo po współrzędnych urządzenia:
    //     najpierw ?serial=EUI, a gdy go brak – spróbuj z JWT (użytkownik → jego urządzenie)
    let profCity = null, profRegion = null, usedSource = 'geoip/default';
    try {
      const chosen = await pickCityRegionFromDevice(req, db);
      if (chosen && (chosen.city || chosen.region)) {
        profCity = chosen.city ? cap(chosen.city) : null;
        profRegion = chosen.region || null;
        usedSource = chosen.source || usedSource;
      }
    } catch {}

    if (!city && profCity) city = profCity;

    // 3) Sprawdź, czy lokalizacja jest wyłączona
    const regionName = city ? null : (profRegion || geoRegionName);
    if (DISABLED_CITIES.has(city) || DISABLED_REGIONS.has(regionName)) {
      return res.json([]); // zero banerów
    }

    // 4) Wybierz koszyk: najpierw miasto, potem województwo, potem OTHER
    let bucketKey = 'OTHER';
    if (city && ADS[city]) bucketKey = city;
    else if (regionName && ADS[regionName]) bucketKey = regionName;
    const bucket = ADS[bucketKey] || ADS['OTHER'];
    const rawBanners = bucket[group].length ? bucket[group] : bucket['B'];

        // 5) Logi diagnostyczne
    try {
      console.log('🧭 [ADS] ip=%s geo.city=%s geo.region=%s | prof.city=%s prof.region=%s | used=%s bucket=%s banners=%d',
        ip,
        geo?.city || null, geoRegionName || null,
        profCity || null, profRegion || null,
        city ? 'city' : (regionName ? 'region' : 'OTHER'),
        bucketKey, rawBanners.length
      );
    } catch {}


    // 6) Doklej metadane
    const enriched = rawBanners.map((b, idx) => ({
      id: `${bucketKey}-${group}-${idx}`,
      img: b.img,
      href: b.href,
      city: city || null,
      region: regionName || null
    }));

    return res.json(enriched);
  });
};

// Przydatne w testach
module.exports.ADS = ADS;
// ─────────────────────────────────────────────────────────────
// Pomocnicze: reverse-geocode + wybór miasta/regionu z urządzenia
// ─────────────────────────────────────────────────────────────
const _revCache = new Map(); // key: "lat,lon" zaokrąglone do 3 miejsc, TTL 24h
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

async function pickCityRegionFromDevice(req, db) {
  // 1) Priorytet: ?serial=EUI (bez auth)
  const serial = String(req.query.serial || '').trim().toUpperCase();
  if (/^[0-9A-F]{16}$/.test(serial) && db) {
    try {
      const { rows } = await db.query(
        'SELECT lat, lon FROM devices WHERE serial_number = $1 LIMIT 1',
        [serial]
      );
      if (rows.length && rows[0].lat != null && rows[0].lon != null) {
        const r = await reverseCityRegion(Number(rows[0].lat), Number(rows[0].lon));
        return { ...r, source: 'device-serial' };
      }
    } catch {}
  }
  // 2) Drugi priorytet: Authorization: Bearer <jwt> → najbliższe urządzenie usera
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
      const r = await reverseCityRegion(Number(rows[0].lat), Number(rows[0].lon));
      return { ...r, source: 'device-of-user' };
    }
  } catch {}
  return null;
}

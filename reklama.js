// reklama.js – moduł obsługujący banery /ads
// Wydzielone z server.js, aby uprościć główny plik backendu.
// Wystarczy require('./reklama')(app) i trasa /ads będzie aktywna.

const geoip = require('geoip-lite');

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
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+515490145' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+515490145' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+48911223344' }
    ]
  },
  Bydgoszcz: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+51' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+52' }
    ],
    B: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Logo/logoase.jpg', href: 'tel:+663229464' }
    ]
  },

  // WOJEWÓDZTWA (fallback) ──────────────────────────────────────────────────
  'Kujawsko-Pomorskie': {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+515490145' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+515490145' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: '515490145' }
    ]
  },
  'Zachodniopomorskie': {
    A: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/fb_resized.jpg', href: 'tel:+1111' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+222222' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: '997' }
    ]
  },

  // DOMYŚLNY koszyk ─────────────────────────────────────────────────────────
  OTHER: {
    A: [
      { img: 'https://api.tago.io/file/644b882c02d9480009f89817/Zdjecia/JPG/Inne/szambiarka_czat2.png', href: 'tel:+515490145' },
      { img: 'https://api.tago.io/file/666338f30e99fc00097a38e6/jpg/Logo%20IOT.jpg', href: 'tel:+515490145' }
    ],
    B: [
      { img: 'https://api.tago.io/file/64482e832567a60008e515fa/pszczolka_resized.jpg', href: 'https://uniwersal-szambiarka.pl' }
    ]
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Eksport: pojedyncza funkcja, którą wywołujesz z server.js → registerAdsRoute(app)
// ─────────────────────────────────────────────────────────────────────────────
module.exports = function registerAdsRoute(app) {
  // WYŁĄCZONE REKLAMY – na razie pusto, ale zostawiamy miejsce na przyszłość


      /*──────────────────────────────────────────────
    WYŁĄCZONE REKLAMY  – listy miast / regionów
    Dodajesz tu kolejne pozycje, jeśli zajdzie potrzeba
  ──────────────────────────────────────────────*/

  //jesli wyłączamy tu odkomenetowac a na dole zakomentowac 

 // const DISABLED_CITIES   = new Set(['Bydgoszcz']);
 //  const DISABLED_REGIONS  = new Set(['Kujawsko-Pomorskie']);
  
  ///jesli wyłączamy  reklamy to tak  
  const DISABLED_CITIES  = new Set();
  const DISABLED_REGIONS = new Set();

  app.get('/ads', (req, res) => {
    if (process.env.ADS_ENABLED !== 'true') {
      return res.json([]);
    }

    // 1) Grupa cenowa: 'A' – premium, 'B' – standard (domyślna)
    const group = req.query.group === 'A' ? 'A' : 'B';

    // 2) Ustal miasto / województwo – najpierw query-param, potem GeoIP
    let city = (req.query.city || '').trim();
    const ip = (req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();
    const geo = geoip.lookup(ip);

    if (!city && geo) {
      city = geo.city || (geo.country === 'PL' && _regionMapPL[geo.region]) || '';
    }
    if (city) {
      city = city[0].toUpperCase() + city.slice(1).toLowerCase();
    }

    // 3) Sprawdź, czy lokalizacja jest wyłączona
    const regionName = (geo && geo.country === 'PL' && _regionMapPL[geo.region]) || null;
    if (DISABLED_CITIES.has(city) || DISABLED_REGIONS.has(regionName)) {
      return res.json([]); // zero banerów
    }

    // 4) Wybierz odpowiedni koszyk; gdy brak w grupie A → fallback do B
    const bucket = ADS[city] || ADS['OTHER'];
    const rawBanners = bucket[group].length ? bucket[group] : bucket['B'];

    // 5) Doklej metadane
    const enriched = rawBanners.map((b, idx) => ({
      id: `${city || 'OTHER'}-${group}-${idx}`,
      img: b.img,
      href: b.href,
      city: city || null,
      region: regionName
    }));

    return res.json(enriched);
  });
};

// Przydatne w testach
module.exports.ADS = ADS;

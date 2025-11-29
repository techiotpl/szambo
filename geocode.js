// geocode.js
const axios = require('axios');

const OPENCAGE_KEY = (process.env.OPENCAGE_KEY || '').trim();
const NOMINATIM_CONTACT = (process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl').trim();

// ── Helpers ───────────────────────────────────────────────────────────────────
function pickCityLike(addr = {}) {
  return addr.city || addr.town || addr.village || addr.hamlet || addr.municipality || null;
}
function pickRegionLike(addr = {}) {
  // w PL zwykle 'state' = województwo
  return addr.state || addr.region || addr.county || null;
}

function stripDiacritics(s = '') {
  return s
    .replace(/ą/gi, m => (m === 'ą' ? 'a' : 'A'))
    .replace(/ć/gi, m => (m === 'ć' ? 'c' : 'C'))
    .replace(/ę/gi, m => (m === 'ę' ? 'e' : 'E'))
    .replace(/ł/gi, m => (m === 'ł' ? 'l' : 'L'))
    .replace(/ń/gi, m => (m === 'ń' ? 'n' : 'N'))
    .replace(/ó/gi, m => (m === 'ó' ? 'o' : 'O'))
    .replace(/ś/gi, m => (m === 'ś' ? 's' : 'S'))
    .replace(/ż/gi, m => (m === 'ż' ? 'z' : 'Z'))
    .replace(/ź/gi, m => (m === 'ź' ? 'z' : 'Z'));
}

function normalizeSpaces(s = '') {
  return s.replace(/\s*,\s*/g, ', ').replace(/\s{2,}/g, ' ').trim();
}

function dropCountryTokens(s = '') {
  // usuń samodzielne wystąpienia "Polska"/"Poland" i zbędne przecinki/spacje
  return s
    .replace(/\bPolska\b/gi, '')
    .replace(/\bPoland\b/gi, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/\s*,\s*,\s*/g, ', ')
    .trim()
    .replace(/^,|,$/g, '');
}

function normalizeStreet(s = '') {
  // "ul elbląska 1/2" -> "ul. Elbląska 1/2" (zachowujemy numer i slash)
  let t = s.trim();
  t = t.replace(/^ul\b\.?\s*/i, 'ul. ');
  // kapitalizacja pierwszej litery w nazwie ulicy (zostawiamy numer i resztę)
  return t.replace(/(ul\.\s*)?([^\d,]+)/i, (_, u, name) => {
    const cap = name.trim().replace(/^./, c => c.toUpperCase());
    return (u || '') + cap + ' ';
  }).trim();
}

/**
 * Usuwa część numerową z ulicy:
 * - "ul. Elbląska 1/3"   -> "ul. Elbląska"
 * - "Elbląska 12A"       -> "Elbląska"
 * - "Elbląska12/3"       -> "Elbląska"
 * Zachowuje ewentualny prefiks "ul. ".
 */
function removeHouseNumber(street = '') {
  let t = street.trim();
  t = t.replace(/^ul\b\.?\s*/i, 'ul. ');
  // próba „klasyczna”: nazwa + spacja + numer (+ opcjonalnie litera, /drugi numer, zakres)
  const m = t.match(/^(ul\.\s*)?([^\d,]+)\s+\d+[A-Za-z]?(?:\s*[-/]\s*\d+[A-Za-z]?)?.*$/);
  if (m) return ((m[1] || '') + m[2].trim()).trim();
  // przypadek bez spacji: "Elbląska12/3"
  const compact = t.replace(/^(ul\.\s*)?(\D+?)\d.*$/, (_, u, name) => ((u || '') + name).trim());
  return compact || t;
}

// Prosty parser: "Miasto, ul coś 1/2" / "ul coś 1/2, Miasto"
function parseCityStreet(input = '') {
  const s = normalizeSpaces(input);
  // rozbij po przecinkach, usuń puste i "Polska/Poland"
  const parts = s
    .split(',')
    .map(p => dropCountryTokens(p.trim()))
    .filter(Boolean);

  if (parts.length === 1) return null;

  let city = null, street = null;

  // Heurystyka 1: „Miasto, ul …”
  if (/^ul\b\.?/i.test(parts[1]) || /\d/.test(parts[1])) {
    city = parts[0];
    street = parts.slice(1).join(', ');
  }
  // Heurystyka 2: „ul …, Miasto”
  if (!city && (/^ul\b\.?/i.test(parts[0]) || /\d/.test(parts[0]))) {
    street = parts[0];
    city = parts.slice(1).join(', ');
  }
  if (!city || !street) return null;

  return {
    city: city.trim(),
    streetLoose: street.trim(),
    street: normalizeStreet(street)
  };
}

// ── Providers ────────────────────────────────────────────────────────────────
async function geocodeWithOpenCage(q) {
  if (!OPENCAGE_KEY) return null;
  const url =
    'https://api.opencagedata.com/geocode/v1/json'
    + `?key=${encodeURIComponent(OPENCAGE_KEY)}`
    + `&q=${encodeURIComponent(q)}`
    + '&limit=1&no_annotations=1&language=pl&countrycode=pl';
  try {
    const r = await axios.get(url, { timeout: 8000 });
    const res = r?.data?.results?.[0];
    const g = res?.geometry;
    if (g && typeof g.lat === 'number' && typeof g.lng === 'number') {
      const c = res?.components || {};
      return {
        lat: g.lat,
        lon: g.lng,
        city: pickCityLike(c),
        region: pickRegionLike(c)
      };
    }
  } catch (_) {}
  return null;
}

async function geocodeWithNominatim(q) {
  const url =
    'https://nominatim.openstreetmap.org/search'
    + `?format=jsonv2&limit=1&addressdetails=1&countrycodes=pl&q=${encodeURIComponent(q)}`;
  try {
    const r = await axios.get(url, {
      timeout: 8000,
      headers: {
        'User-Agent': `TechioT/1.0 (${NOMINATIM_CONTACT})`,
        'Accept-Language': 'pl'
      }
    });
    const hit = Array.isArray(r.data) ? r.data[0] : null;
    if (hit && hit.lat && hit.lon) {
      const a = hit.address || {};
      return {
        lat: parseFloat(hit.lat),
        lon: parseFloat(hit.lon),
        city: pickCityLike(a),
        region: pickRegionLike(a)
      };
    }
  } catch (_) {}
  return null;
}

// Nominatim structured (lepsza precyzja, gdy mamy street/city)
async function geocodeWithNominatimStructured({ street, city }) {
  const params = new URLSearchParams({
    format: 'jsonv2',
    addressdetails: '1',
    countrycodes: 'pl',
    limit: '1',
    street,
    city
  }).toString();
  const url = `https://nominatim.openstreetmap.org/search?${params}`;
  try {
    const r = await axios.get(url, {
      timeout: 8000,
      headers: {
        'User-Agent': `TechioT/1.0 (${NOMINATIM_CONTACT})`,
        'Accept-Language': 'pl'
      }
    });
    const hit = Array.isArray(r.data) ? r.data[0] : null;
    if (hit && hit.lat && hit.lon) {
      const a = hit.address || {};
      return {
        lat: parseFloat(hit.lat),
        lon: parseFloat(hit.lon),
        city: pickCityLike(a),
        region: pickRegionLike(a)
      };
    }
  } catch (_) {}
  return null;
}

// ── Main API ────────────────────────────────────────────────────────────────
async function geocodeAddress(address, logPrefix = '') {
  const raw = String(address || '').trim();
  console.log(`geo: start address=${JSON.stringify(raw)}`);

  if (raw.length < 3) return null;

  // Jeżeli brak przecinka, a jest "ul"/"ul.", wstaw przecinek przed "ul"
  let pre = raw;
  if (!/,/.test(pre) && /\bul\.?\s/i.test(pre)) {
    pre = pre.replace(/\bul\.?\s*/i, ', ul. ');
  }
  // toleruj ; i | jako separatory – NIE ruszamy "/" (np. "1/3")
  const q = normalizeSpaces(pre.replace(/[;|]+/g, ','));

  // 0) Structured first (jeśli uda się sparsować)
  const parsed = parseCityStreet(q);
  if (parsed) {
    // warianty dla street: z „ul.” oraz bez; + wersje bez znaków PL
    const streetNoPrefix = parsed.street.replace(/^ul\.\s*/i, '').trim();
    const structuredVariants = [
      { street: dropCountryTokens(parsed.street),               city: dropCountryTokens(parsed.city) },
      { street: dropCountryTokens(streetNoPrefix),              city: dropCountryTokens(parsed.city) },
      { street: stripDiacritics(dropCountryTokens(parsed.street)),  city: stripDiacritics(dropCountryTokens(parsed.city)) },
      { street: stripDiacritics(dropCountryTokens(streetNoPrefix)), city: stripDiacritics(dropCountryTokens(parsed.city)) }
    ];

    for (const v of structuredVariants) {
      console.log(`geo: try structured street=${JSON.stringify(v.street)} city=${JSON.stringify(v.city)}`);
      const ns = await geocodeWithNominatimStructured(v);
      if (ns) {
        console.log(`geo: hit structured lat=${ns.lat} lon=${ns.lon}`);
        return ns;
      }
    }
  }

  // 1) Free-text warianty
  const baseStreet = parsed ? parsed.street : q;
  const baseCity   = parsed ? parsed.city   : '';
  const variants = Array.from(new Set([
    q,
    parsed ? `${dropCountryTokens(parsed.street)}, ${dropCountryTokens(parsed.city)}, Polska` : q,
    parsed ? `${dropCountryTokens(parsed.city)}, ${dropCountryTokens(parsed.street)}, Polska` : q,
    parsed ? `${dropCountryTokens(baseStreet.replace(/^ul\.\s*/i, ''))}, ${dropCountryTokens(baseCity)}, Polska` : q,
    stripDiacritics(q),
    parsed ? `${stripDiacritics(dropCountryTokens(parsed.street))}, ${stripDiacritics(dropCountryTokens(parsed.city))}, Polska` : stripDiacritics(q),
  ])).filter(v => v && v.length >= 3);

  // 2) OpenCage (jeśli mamy klucz) → 3) Nominatim free-text
  for (const v of variants) {
    console.log(`geo: try ${JSON.stringify(v)} via OpenCage→Nominatim`);
    const oc = await geocodeWithOpenCage(v);
    if (oc) {
      console.log(`geo: hit OpenCage lat=${oc.lat} lon=${oc.lon}`);
      return oc;
    }
    console.log(`geo: try Nominatim ${JSON.stringify(v)}`);
    const nm = await geocodeWithNominatim(v);
    if (nm) {
      console.log(`geo: hit Nominatim lat=${nm.lat} lon=${nm.lon}`);
      return nm;
    }
  }

  // 4) OSTATNI FALLBACK: ulica BEZ NUMERU (częsty przypadek na wsi)
  if (parsed) {
    const streetNoNum = removeHouseNumber(parsed.street);
    if (streetNoNum && streetNoNum !== parsed.street) {
      const streetNoPrefix = streetNoNum.replace(/^ul\.\s*/i, '').trim();
      const streetOnlyVariants = [
        { street: dropCountryTokens(streetNoNum),               city: dropCountryTokens(parsed.city) },
        { street: dropCountryTokens(streetNoPrefix),            city: dropCountryTokens(parsed.city) },
        { street: stripDiacritics(dropCountryTokens(streetNoNum)),    city: stripDiacritics(dropCountryTokens(parsed.city)) },
        { street: stripDiacritics(dropCountryTokens(streetNoPrefix)), city: stripDiacritics(dropCountryTokens(parsed.city)) }
      ];
      for (const v of streetOnlyVariants) {
        console.log(`geo: try structured (street-only) street=${JSON.stringify(v.street)} city=${JSON.stringify(v.city)}`);
        const ns = await geocodeWithNominatimStructured(v);
        if (ns) {
          console.log(`geo: hit (street-only) lat=${ns.lat} lon=${ns.lon}`);
          return ns;
        }
      }

      // free-text bez numeru
      const ftNoNum = Array.from(new Set([
        `${dropCountryTokens(streetNoNum)}, ${dropCountryTokens(parsed.city)}, Polska`,
        `${dropCountryTokens(parsed.city)}, ${dropCountryTokens(streetNoNum)}, Polska`,
        `${streetNoPrefix}, ${dropCountryTokens(parsed.city)}, Polska`,
        `${stripDiacritics(dropCountryTokens(streetNoNum))}, ${stripDiacritics(dropCountryTokens(parsed.city))}, Polska`,
      ]));

      for (const v of ftNoNum) {
        console.log(`geo: try (street-only) ${JSON.stringify(v)} via OpenCage→Nominatim`);
        const oc = await geocodeWithOpenCage(v);
        if (oc) {
          console.log(`geo: hit OpenCage (street-only) lat=${oc.lat} lon=${oc.lon}`);
          return oc;
        }
        console.log(`geo: try Nominatim (street-only) ${JSON.stringify(v)}`);
        const nm = await geocodeWithNominatim(v);
        if (nm) {
          console.log(`geo: hit Nominatim (street-only) lat=${nm.lat} lon=${nm.lon}`);
          return nm;
        }
      }
    }
  }

  console.log('geo: miss (no coordinates)');
  return null;
}

module.exports = { geocodeAddress };

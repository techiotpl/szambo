
 b/geocode.js

 const axios = require('axios');
 
 const OPENCAGE_KEY = (process.env.OPENCAGE_KEY || '').trim();
 const NOMINATIM_CONTACT = (process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl').trim();
 
// --- helpers ---
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

function normalizeStreet(s = '') {
  // "ul elbląska 1/2" -> "ul. Elbląska 1/2" (lub bez „ul.” poniżej)
  let t = s.trim();
  t = t.replace(/^ul\b\.?\s*/i, 'ul. ');
  // kapitalizacja pierwszej litery w nazwie ulicy (zostawiamy numer)
  return t.replace(/(ul\.\s*)?([^\d,]+)/i, (_, u, name) => {
    const cap = name.trim().replace(/^./, c => c.toUpperCase());
    return (u || '') + cap + ' ';
  }).trim();
}

// Prosty parser: "Miasto, ul coś 1/2" / "ul coś 1/2, Miasto"
function parseCityStreet(input = '') {
  const s = normalizeSpaces(input);
  const parts = s.split(',').map(p => p.trim()).filter(Boolean);
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

 async function geocodeWithOpenCage(q) {
   if (!OPENCAGE_KEY) return null;
   const url =
     'https://api.opencagedata.com/geocode/v1/json'
     + `?key=${encodeURIComponent(OPENCAGE_KEY)}`
     + `&q=${encodeURIComponent(q)}`
     + '&limit=1&no_annotations=1&language=pl&countrycode=pl';

   return null;
 }
 
 async function geocodeWithNominatim(q) {
   const url =
     'https://nominatim.openstreetmap.org/search'
    + `?format=jsonv2&limit=1&addressdetails=1&countrycodes=pl&q=${encodeURIComponent(q)}`;

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
        city:   pickCityLike(a),
        region: pickRegionLike(a)
      };
    }
  } catch (_) {}
  return null;
}

 async function geocodeAddress(address) {

  const raw = String(address || '').trim();
  if (raw.length < 3) return null;
  const q = normalizeSpaces(raw);

  // 0) spróbuj zapytania strukturalnego (jeśli uda się sparsować)
  const parsed = parseCityStreet(q);
  if (parsed) {
    // warianty dla street: z „ul.” oraz bez
    const streetNoPrefix = parsed.street.replace(/^ul\.\s*/i, '').trim();
    const structuredVariants = [
      { street: parsed.street,         city: parsed.city },
      { street: streetNoPrefix,        city: parsed.city },
      { street: stripDiacritics(parsed.street),  city: stripDiacritics(parsed.city) },
      { street: stripDiacritics(streetNoPrefix), city: stripDiacritics(parsed.city) }
    ];
    for (const v of structuredVariants) {
      const ns = await geocodeWithNominatimStructured(v);
      if (ns) return ns;
    }
  }

  // 1) zbuduj kilka sensownych wariantów free-text
  const baseStreet = parsed ? parsed.street : q;
  const baseCity   = parsed ? parsed.city   : '';
  const variants = Array.from(new Set([
    q,
    parsed ? `${parsed.street}, ${parsed.city}, Polska` : q,
    parsed ? `${parsed.city}, ${parsed.street}, Polska` : q,
    parsed ? `${baseStreet.replace(/^ul\.\s*/i, '')}, ${baseCity}, Polska` : q,
    stripDiacritics(q),
    parsed ? `${stripDiacritics(parsed.street)}, ${stripDiacritics(parsed.city)}, Polska` : stripDiacritics(q),
  ])).filter(v => v && v.length >= 3);

  // 2) OpenCage (jeśli mamy klucz) → 3) Nominatim free-text
  for (const v of variants) {
    const oc = await geocodeWithOpenCage(v);
    if (oc) return oc;
  }
  for (const v of variants) {
    const nm = await geocodeWithNominatim(v);
    if (nm) return nm;
  }
  return null;
 }
 
 module.exports = { geocodeAddress };

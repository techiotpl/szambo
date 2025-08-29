// geocode.js
const axios = require('axios');

const OPENCAGE_KEY = (process.env.OPENCAGE_KEY || '').trim();
const NOMINATIM_CONTACT = (process.env.NOMINATIM_CONTACT || 'contact@techiot.pl').trim();

async function geocodeWithOpenCage(q) {
  if (!OPENCAGE_KEY) return null;
  const url =
    'https://api.opencagedata.com/geocode/v1/json'
    + `?key=${encodeURIComponent(OPENCAGE_KEY)}`
    + `&q=${encodeURIComponent(q)}`
    + '&limit=1&no_annotations=1&language=pl&countrycode=pl';
  try {
    const r = await axios.get(url, { timeout: 8000 });
    const g = r?.data?.results?.[0]?.geometry;
    if (g && typeof g.lat === 'number' && typeof g.lng === 'number') {
      return { lat: g.lat, lon: g.lng };
    }
  } catch (e) {}
  return null;
}

async function geocodeWithNominatim(q) {
  const url =
    'https://nominatim.openstreetmap.org/search'
    + `?format=jsonv2&limit=1&countrycodes=pl&q=${encodeURIComponent(q)}`;
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
      return { lat: parseFloat(hit.lat), lon: parseFloat(hit.lon) };
    }
  } catch (e) {}
  return null;
}

async function geocodeAddress(address) {
  const q = String(address || '').trim();
  if (q.length < 3) return null;
  // 1) spróbuj OpenCage (jeśli kiedyś dodasz klucz)
  const oc = await geocodeWithOpenCage(q);
  if (oc) return oc;
  // 2) fallback: Nominatim (bez klucza)
  return await geocodeWithNominatim(q);
}

module.exports = { geocodeAddress };

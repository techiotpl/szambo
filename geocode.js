// geocode.js
const axios = require('axios');

const OPENCAGE_KEY = (process.env.OPENCAGE_KEY || '').trim();
const NOMINATIM_CONTACT = (process.env.NOMINATIM_CONTACT || 'biuro@techiot.pl').trim();

function pickCityLike(addr = {}) {
  return addr.city || addr.town || addr.village || addr.hamlet || addr.municipality || null;
}
function pickRegionLike(addr = {}) {
  // w PL zwykle 'state' = województwo
  return addr.state || addr.region || addr.county || null;
}

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
        city:   pickCityLike(c),
        region: pickRegionLike(c)
      };
    }
  } catch (e) {}
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
        city:   pickCityLike(a),
        region: pickRegionLike(a)
      };
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

// komunikaty.js
// Ogłoszenia (Announcements) — templates + publish + dismiss
// Eksport: registerAnnouncements({ app, db, auth, adminOnly, consentGuard })

function renderTpl(str, vars = {}) {
  return String(str || '').replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_, k) =>
    (vars[k] != null ? String(vars[k]) : '')
  );
}

// Trzymamy szablony w backendzie.
// body może być tekstem albo HTML — front decyduje jak renderować.
const ANNOUNCEMENT_TEMPLATES = {
  christmas: {
    title: '🎄 Wesołych Świąt od TechioT!',
    theme: 'christmas',
    body: `
<div style="font-family:Arial,sans-serif; line-height:1.5;">
  <p style="margin:0 0 8px 0;"><b>Wesołych Świąt!</b></p>
  <p style="margin:0 0 8px 0;">
    Dziękujemy, że korzystasz z TechioT. Życzymy spokojnych i rodzinnych Świąt 🎁
  </p>
  <p style="margin:0; color:#666; font-size:12px;">{{date}}</p>
</div>`.trim()
  },

  maintenance: {
    title: '🛠️ Przerwa techniczna',
    theme: 'warning',
    body: `
<div style="font-family:Arial,sans-serif; line-height:1.5;">
  <p style="margin:0 0 8px 0;">
    W dniu <b>{{when}}</b> planujemy prace serwisowe.
  </p>
  <p style="margin:0 0 8px 0;">
    W tym czasie aplikacja może działać wolniej lub chwilowo niedostępna.
  </p>
  <p style="margin:0; color:#666; font-size:12px;">Dziękujemy za wyrozumiałość.</p>
</div>`.trim()
  },

  new_feature: {
    title: '✨ Nowość w aplikacji',
    theme: 'default',
    body: `
<div style="font-family:Arial,sans-serif; line-height:1.5;">
  <p style="margin:0 0 8px 0;"><b>{{featureTitle}}</b></p>
  <p style="margin:0 0 8px 0;">{{featureBody}}</p>
  <p style="margin:0; color:#666; font-size:12px;">{{date}}</p>
</div>`.trim()
  },

  info: {
    title: 'ℹ️ Informacja',
    theme: 'default',
    body: `
<div style="font-family:Arial,sans-serif; line-height:1.5;">
  <p style="margin:0 0 8px 0;">{{msg}}</p>
  <p style="margin:0; color:#666; font-size:12px;">{{date}}</p>
</div>`.trim()
  }
};

function registerAnnouncements({ app, db, auth, adminOnly, consentGuard }) {
  if (!app || !db) throw new Error('komunikaty.js: missing app/db');
  if (typeof auth !== 'function') throw new Error('komunikaty.js: missing auth middleware');
  if (typeof adminOnly !== 'function') throw new Error('komunikaty.js: missing adminOnly middleware');
  if (typeof consentGuard !== 'function') throw new Error('komunikaty.js: missing consentGuard middleware');

    // wspólny warunek: "nie pokazuj, jeśli user już zamknął"
  function _notDismissedWhere() {
    return `
      NOT EXISTS (
        SELECT 1
          FROM announcement_dismissals d
         WHERE d.announcement_id = a.id
           AND (
             ($1::uuid IS NOT NULL AND d.user_id = $1::uuid)
             OR
             ($2::text IS NOT NULL AND $2::text <> '' AND lower(d.user_email) = lower($2::text))
           )
      )
    `;
  }

  // ── USER: pobierz aktualne ogłoszenia (których user nie zamknął)
  app.get('/announcements', auth, consentGuard, async (req, res) => {
    try {
      const q = `
        SELECT a.id, a.title, a.body, a.theme, a.starts_at, a.ends_at, a.min_app_version, a.created_at, a.updated_at
          FROM announcements a
         WHERE a.is_active = TRUE
           AND (a.starts_at IS NULL OR a.starts_at <= now())
                     AND (a.ends_at   IS NULL OR a.ends_at   >= now())
           AND ${_notDismissedWhere()}
         ORDER BY a.created_at DESC
         LIMIT 20
      `;
      const userId = (req.user?.id && req.user.id !== 'admin') ? req.user.id : null;
      const userEmail = req.user?.email || '';
      const { rows } = await db.query(q, [userId, userEmail]);
      return res.json(rows);
    } catch (e) {
      console.error('GET /announcements error:', e);
      return res.status(500).send('server error');
    }
  });

  // ── USER: pobierz JEDNO aktywne ogłoszenie (dla appki: /announcements/active)
  app.get('/announcements/active', auth, consentGuard, async (req, res) => {
    try {
      const q = `
        SELECT a.id, a.title, a.body, a.theme, a.starts_at, a.ends_at, a.min_app_version, a.created_at, a.updated_at
          FROM announcements a
         WHERE a.is_active = TRUE
           AND (a.starts_at IS NULL OR a.starts_at <= now())
           AND (a.ends_at   IS NULL OR a.ends_at   >= now())
           AND ${_notDismissedWhere()}
         ORDER BY a.created_at DESC
         LIMIT 1
      `;
      const userId = (req.user?.id && req.user.id !== 'admin') ? req.user.id : null;
      const userEmail = req.user?.email || '';
      const { rows } = await db.query(q, [userId, userEmail]);

      if (!rows.length) {
        console.log(`ℹ️ GET /announcements/active -> none (user=${userEmail || userId || 'unknown'})`);
        return res.sendStatus(204); // Flutter oczekuje 204 -> null
      }

      console.log(`✅ GET /announcements/active -> id=${rows[0].id} (user=${userEmail || userId || 'unknown'})`);
      return res.json(rows[0]);
    } catch (e) {
      console.error('GET /announcements/active error:', e);
      return res.status(500).send('server error');
    }
  });

  
  // ── USER: oznacz jako przeczytane / zamknięte
  app.post('/announcements/:id/dismiss', auth, consentGuard, async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id) || id <= 0) return res.status(400).send('bad id');

      const userId = (req.user?.id && req.user.id !== 'admin') ? req.user.id : null;
      const userEmail = req.user?.email || null;

      await db.query(
        `INSERT INTO announcement_dismissals (announcement_id, user_id, user_email)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING`,
        [id, userId, userEmail]
      );

      console.log(`✅ POST /announcements/${id}/dismiss (user=${userEmail || userId || 'unknown'})`);
      return res.sendStatus(200);
    } catch (e) {
      console.error('POST /announcements/:id/dismiss error:', e);
      return res.status(500).send('server error');
    }
  });

  // ── ADMIN: lista dostępnych szablonów (do panelu)
  app.get('/admin/announcement-templates', auth, adminOnly, async (_req, res) => {
    const list = Object.entries(ANNOUNCEMENT_TEMPLATES).map(([key, t]) => ({
      key,
      title: t.title,
      theme: t.theme
    }));
    res.json(list);
  });

  // ── ADMIN: opublikuj szablon
  // body: { templateKey, vars?, starts_at?, ends_at?, min_app_version? }
  app.post('/admin/announcements/publish-template', auth, adminOnly, async (req, res) => {
    try {
      const templateKey = String(req.body?.templateKey || '').trim();
      const tpl = ANNOUNCEMENT_TEMPLATES[templateKey];
      if (!tpl) return res.status(400).json({ message: 'UNKNOWN_TEMPLATE' });

      const vars = (req.body?.vars && typeof req.body.vars === 'object') ? req.body.vars : {};
      const mergedVars = { date: new Date().toISOString().slice(0, 10), ...vars };

      const title = renderTpl(tpl.title, mergedVars);
      const body  = renderTpl(tpl.body, mergedVars);
      const theme = tpl.theme || 'default';

      const startsAt = req.body?.starts_at ? String(req.body.starts_at) : null; // ISO albo null
      const endsAt   = req.body?.ends_at   ? String(req.body.ends_at)   : null;
      const minVer   = req.body?.min_app_version ? String(req.body.min_app_version) : null;

      const { rows } = await db.query(
        `INSERT INTO announcements (title, body, theme, is_active, starts_at, ends_at, min_app_version, created_at, updated_at)
         VALUES ($1, $2, $3, TRUE, $4, $5, $6, now(), now())
         RETURNING id, title, theme, created_at`,
        [title, body, theme, startsAt, endsAt, minVer]
      );
console.log(`✅ Published announcement id=${rows[0].id} template=${templateKey} starts_at=${startsAt || 'null'} ends_at=${endsAt || 'null'} min_ver=${minVer || 'null'}`);
      return res.status(201).json({ ok: true, announcement: rows[0] });
    } catch (e) {
      console.error('POST /admin/announcements/publish-template error:', e);
      return res.status(500).send('server error');
    }
  });

  // ── ADMIN (opcjonalnie): dezaktywuj ogłoszenie
  app.post('/admin/announcements/:id/deactivate', auth, adminOnly, async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isFinite(id) || id <= 0) return res.status(400).send('bad id');

      const r = await db.query(
        `UPDATE announcements
            SET is_active = FALSE,
                updated_at = now()
          WHERE id = $1
          RETURNING id`,
        [id]
      );

      if (!r.rowCount) return res.status(404).send('not found');
      return res.sendStatus(200);
    } catch (e) {
      console.error('POST /admin/announcements/:id/deactivate error:', e);
      return res.status(500).send('server error');
    }
  });

  console.log('✅ Announcements routes registered (/announcements, /admin/announcements/*)');
}

module.exports = registerAnnouncements;

import express from 'express';
import crypto from 'node:crypto';
import { db } from './db.js';
import { normalizeNumber, isArcepDemarchage } from './normalize.js';
import { updateLists } from './update-lists.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Clé admin : celle de l'environnement si fournie, sinon générée au
// premier démarrage et conservée dans la base (affichée une seule fois
// dans les logs à la génération).
function resolveAdminKey() {
  if (process.env.ADMIN_KEY) return process.env.ADMIN_KEY;
  db.exec(
    'CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)'
  );
  const row = db.prepare("SELECT value FROM meta WHERE key = 'admin_key'").get();
  if (row) return row.value;
  const key = crypto.randomBytes(24).toString('hex');
  db.prepare("INSERT INTO meta (key, value) VALUES ('admin_key', ?)").run(key);
  console.log(`Clé admin générée (conservée dans la base) : ${key}`);
  return key;
}
const ADMIN_KEY = resolveAdminKey();

// --- Auth : chaque proche a sa clé personnelle (header X-Api-Key) ---
function auth(req, res, next) {
  const key = req.get('X-Api-Key');
  const user = key
    ? db.prepare('SELECT id, name FROM users WHERE api_key = ?').get(key)
    : null;
  if (!user) return res.status(401).json({ error: 'Clé API invalide' });
  req.user = user;
  next();
}

function adminAuth(req, res, next) {
  if (!ADMIN_KEY || req.get('X-Admin-Key') !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Clé admin invalide' });
  }
  next();
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// --- Signaler un numéro ---
app.post('/api/reports', auth, (req, res) => {
  const number = normalizeNumber(req.body?.number);
  if (!number) return res.status(400).json({ error: 'Numéro invalide' });
  const { category = null, comment = null } = req.body;
  db.prepare(
    `INSERT INTO reports (user_id, number, category, comment) VALUES (?, ?, ?, ?)
     ON CONFLICT (user_id, number) DO UPDATE SET category = excluded.category, comment = excluded.comment`
  ).run(req.user.id, number, category, comment);
  const count = db
    .prepare('SELECT COUNT(*) AS c FROM reports WHERE number = ?')
    .get(number).c;
  res.json({ number, reportCount: count });
});

// --- Retirer son propre signalement (faux positif) ---
app.delete('/api/reports/:number', auth, (req, res) => {
  const number = normalizeNumber(req.params.number);
  if (!number) return res.status(400).json({ error: 'Numéro invalide' });
  const info = db
    .prepare('DELETE FROM reports WHERE user_id = ? AND number = ?')
    .run(req.user.id, number);
  res.json({ number, removed: info.changes > 0 });
});

// --- Lookup temps réel (appel entrant sur Android) ---
app.get('/api/lookup/:number', auth, (req, res) => {
  const number = normalizeNumber(req.params.number);
  if (!number) return res.status(400).json({ error: 'Numéro invalide' });
  const reports = db
    .prepare(
      `SELECT COUNT(*) AS c, GROUP_CONCAT(DISTINCT category) AS cats
       FROM reports WHERE number = ?`
    )
    .get(number);
  const imported =
    db.prepare('SELECT source, label FROM imported_numbers WHERE number = ?').get(number) ||
    db.prepare("SELECT source, label FROM imported_prefixes WHERE ? LIKE prefix || '%'").get(number);
  const arcep = isArcepDemarchage(number);
  res.json({
    number,
    reportCount: reports.c,
    categories: reports.cats ? reports.cats.split(',') : [],
    importedFrom: imported?.source ?? null,
    importedLabel: imported?.label ?? null,
    arcepDemarchage: arcep,
    suspicious: reports.c > 0 || !!imported || arcep,
  });
});

// --- Liste complète pour la synchro (iOS / cache hors-ligne Android) ---
app.get('/api/numbers', auth, (_req, res) => {
  const community = db
    .prepare(
      `SELECT number, COUNT(*) AS reportCount, MAX(created_at) AS lastReport
       FROM reports GROUP BY number`
    )
    .all();
  const imported = db
    .prepare('SELECT number, source, label FROM imported_numbers')
    .all();
  res.json({ community, imported });
});

// --- Admin : créer un utilisateur (proche) et sa clé ---
app.post('/api/users', adminAuth, (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Nom requis' });
  const apiKey = crypto.randomBytes(24).toString('hex');
  try {
    db.prepare('INSERT INTO users (name, api_key) VALUES (?, ?)').run(name, apiKey);
  } catch {
    return res.status(409).json({ error: 'Ce nom existe déjà' });
  }
  res.json({ name, apiKey });
});

// --- Admin : forcer la mise à jour des listes publiques ---
app.post('/api/update-lists', adminAuth, async (_req, res) => {
  res.json(await updateLists());
});

// Mise à jour automatique des listes publiques (spamtel, begone-fr…) :
// au démarrage puis toutes les 24 h. Désactivable avec UPDATE_LISTS=0.
async function refreshLists() {
  const results = await updateLists();
  for (const r of results) {
    if (r.error) console.warn(`Liste "${r.source}" : échec (${r.error})`);
    else console.log(`Liste "${r.source}" : ${r.prefixes} préfixes, ${r.numbers} numéros`);
  }
}

app.listen(PORT, () => {
  console.log(`Backend anti-spam démarré sur le port ${PORT}`);
  if (process.env.UPDATE_LISTS !== '0') {
    refreshLists().catch((e) => console.warn('Mise à jour des listes impossible :', e.message));
    setInterval(() => refreshLists().catch(() => {}), 24 * 60 * 60 * 1000);
  }
});

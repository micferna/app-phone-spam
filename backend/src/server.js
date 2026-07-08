import express from 'express';
import crypto from 'node:crypto';
import { db } from './db.js';
import { normalizeNumber, isArcepDemarchage } from './normalize.js';
import { updateLists } from './update-lists.js';

const app = express();
app.use(express.json({ limit: '8kb' }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));

// En-têtes de sécurité. Le CSP n'autorise que le style inline de la page
// d'accueil et l'envoi du formulaire d'adhésion vers ce même serveur ;
// aucun script, aucune ressource externe.
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'",
  });
  next();
});

const PORT = process.env.PORT || 3000;

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Échappe le HTML : toute donnée fournie par un utilisateur qui finit
// dans une page est passée par ici (anti-XSS stocké/réfléchi).
const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

// Nettoie un champ texte libre : retire les caractères de contrôle
// (dont \0), normalise les espaces, coupe à la longueur max. On ne
// "détecte" pas le code — on neutralise : stockage nettoyé + échappement
// systématique à l'affichage.
const cleanText = (v, max) => {
  if (v == null) return null;
  const s = String(v)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
  return s.length ? s : null;
};

const safeEqual = (a, b) => {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
};

// IP client : derrière Cloudflare, CF-Connecting-IP est posé par l'edge
// et non falsifiable à travers lui (contrairement à X-Forwarded-For).
const clientIp = (req) =>
  req.get('cf-connecting-ip') || req.socket.remoteAddress || 'inconnu';

// --- Limitation de débit en mémoire (anti-bots / anti-bruteforce) ---
const buckets = new Map();
function hit(key, windowMs, max) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < now) {
    b = { count: 0, reset: now + windowMs };
    buckets.set(key, b);
  }
  b.count += 1;
  return b.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
}, 60_000).unref();

const rateLimit = (name, windowMs, max) => (req, res, next) => {
  if (!hit(`${name}:${clientIp(req)}`, windowMs, max)) {
    return res.status(429).json({ error: 'Trop de requêtes, réessaie plus tard' });
  }
  next();
};

// Limite globale grossière, puis limites serrées sur les routes sensibles.
app.use(rateLimit('global', 60_000, 240));

// Clé admin : ADMIN_KEY d'environnement si fournie, sinon celle créée à
// l'initialisation (/api/bootstrap) — seule son empreinte SHA-256 est en
// base, la clé en clair n'est jamais stockée ni journalisée.
function isAdminKeyValid(provided) {
  if (!provided) return false;
  if (process.env.ADMIN_KEY) return safeEqual(provided, process.env.ADMIN_KEY);
  const row = db
    .prepare("SELECT value FROM meta WHERE key = 'admin_key_hash'")
    .get();
  return !!row && safeEqual(sha256(provided), row.value);
}

// Anti-bruteforce : au-delà de 20 clés invalides en 10 min, l'IP est
// bloquée sur les routes authentifiées jusqu'à expiration de la fenêtre.
function authFailed(req, res, message) {
  hit(`authfail:${clientIp(req)}`, 600_000, 20);
  return res.status(401).json({ error: message });
}
function tooManyAuthFails(req) {
  const b = buckets.get(`authfail:${clientIp(req)}`);
  return !!b && b.reset > Date.now() && b.count >= 20;
}

// --- Auth : chaque proche a sa clé personnelle (header X-Api-Key) ---
function auth(req, res, next) {
  if (tooManyAuthFails(req)) {
    return res.status(429).json({ error: 'Trop de tentatives, réessaie plus tard' });
  }
  const key = req.get('X-Api-Key');
  const user = key
    ? db.prepare('SELECT id, name FROM users WHERE api_key = ?').get(key)
    : null;
  if (!user) return authFailed(req, res, 'Clé API invalide');
  req.user = user;
  next();
}

function adminAuth(req, res, next) {
  if (tooManyAuthFails(req)) {
    return res.status(429).json({ error: 'Trop de tentatives, réessaie plus tard' });
  }
  if (!isAdminKeyValid(req.get('X-Admin-Key'))) {
    return authFailed(req, res, 'Clé admin invalide');
  }
  next();
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Petite page de confirmation réutilisable (titre + texte déjà échappés
// par l'appelant si besoin).
function confirmationPage(title, htmlBody) {
  return `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font:17px/1.6 system-ui, sans-serif; max-width:560px;
    margin:0 auto; padding:56px 24px; }
  a { color:#c43c2e; }
</style></head>
<body>
<h1>${escapeHtml(title)}</h1>
<p>${htmlBody}</p>
<p><a href="/">← Retour à l'accueil</a></p>
</body></html>`;
}

// --- Page d'accueil publique : présentation du projet ---
app.get('/', (_req, res) => {
  const numbers = db
    .prepare('SELECT COUNT(DISTINCT number) AS c FROM reports')
    .get().c;
  const prefixes = db
    .prepare('SELECT COUNT(*) AS c FROM imported_prefixes')
    .get().c;
  const users = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  res.type('html').send(`<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anti-Spam Collectif</title>
<style>
  :root { color-scheme: light dark;
    --bg:#fdfaf7; --fg:#2b2320; --muted:#8a7a72; --accent:#c43c2e;
    --card:#f4ece6; --border:#e5d8cf; }
  @media (prefers-color-scheme: dark) { :root {
    --bg:#191412; --fg:#ece4de; --muted:#a08d84; --accent:#e05548;
    --card:#231c19; --border:#372c27; } }
  * { margin:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--fg);
    font:17px/1.65 system-ui, sans-serif;
    max-width:680px; margin:0 auto; padding:48px 24px; }
  h1 { font-size:2rem; line-height:1.2; letter-spacing:-.02em; }
  h1 span { color:var(--accent); }
  .pitch { color:var(--muted); margin:12px 0 32px; font-size:1.05rem; }
  .stats { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:36px; }
  .stat { background:var(--card); border:1px solid var(--border);
    border-radius:12px; padding:14px 20px; flex:1; min-width:150px; }
  .stat b { display:block; font-size:1.6rem; }
  .stat small { color:var(--muted); }
  h2 { font-size:1.1rem; margin:28px 0 10px; }
  ol { padding-left:22px; } li { margin-bottom:8px; }
  a { color:var(--accent); }
  .foot { margin-top:40px; padding-top:20px; border-top:1px solid var(--border);
    color:var(--muted); font-size:.9rem; }
  code { background:var(--card); padding:2px 6px; border-radius:6px; font-size:.88em; }
  form { display:flex; flex-direction:column; gap:10px; margin-top:12px; }
  input, textarea { font:inherit; padding:10px 12px; border-radius:10px;
    border:1px solid var(--border); background:var(--card); color:var(--fg); }
  textarea { resize:vertical; min-height:64px; }
  button { font:inherit; font-weight:600; padding:12px; border:none;
    border-radius:10px; background:var(--accent); color:#fff; cursor:pointer; }
</style>
</head>
<body>
<h1>📵 Anti-Spam <span>Collectif</span></h1>
<p class="pitch">Le démarchage harcèle chacun de nous séparément.
Ici, un seul signalement protège tout le groupe : quand quelqu'un
signale un numéro, tous les téléphones sont alertés dès que ce
numéro rappelle.</p>

<div class="stats">
  <div class="stat"><b>${numbers}</b><small>numéros signalés par le groupe</small></div>
  <div class="stat"><b>${prefixes}</b><small>préfixes suivis (ARCEP + listes publiques)</small></div>
  <div class="stat"><b>${users}</b><small>membres protégés</small></div>
</div>

<h2>Comment ça marche</h2>
<ol>
  <li>Installe l'app Android et entre ta clé personnelle.</li>
  <li>À chaque appel entrant, ton téléphone vérifie le numéro ici :
      s'il est connu, tu vois <em>« ⚠️ Signalé par N personnes »</em>
      pendant la sonnerie.</li>
  <li>Numéro inconnu et c'était du démarchage ? Un bouton
      <em>« Signaler »</em> dans la notification, et tout le groupe
      est protégé.</li>
</ol>

<h2>Déjà inclus, sans rien faire</h2>
<p>Les préfixes officiels de démarchage imposés par
l'<a href="https://www.arcep.fr">ARCEP</a> (0162, 0270, 0377,
0424, 0568, 0948…) et les listes communautaires publiques,
remises à jour automatiquement toutes les 24&nbsp;heures.</p>

<h2>Rejoindre le groupe</h2>
<p>L'accès se fait sur invitation (une clé personnelle par membre, pour
éviter les faux signalements). Envoie une demande, l'administrateur te
transmettra ta clé.</p>
<form method="POST" action="/api/join-requests">
  <input name="name" maxlength="64" required
    placeholder="Prénom ou pseudo" autocomplete="off">
  <input name="contact" maxlength="128"
    placeholder="Comment te joindre ? (Signal, e-mail, tel…)" autocomplete="off">
  <textarea name="message" maxlength="280"
    placeholder="Un mot (facultatif) : qui es-tu, qui te connaît dans le groupe…"></textarea>
  <button type="submit">Envoyer ma demande</button>
</form>

<h2>Code source</h2>
<p>Projet libre :
<a href="https://github.com/micferna/app-phone-spam">github.com/micferna/app-phone-spam</a>
— backend Node.js + SQLite, app Flutter. Auto-hébergeable par
n'importe quel groupe (famille, amis, asso).</p>

<p class="foot">API : <code>GET /api/health</code> ·
<code>GET /api/lookup/:numero</code> ·
<code>POST /api/reports</code> — accès sur invitation
(clé personnelle par membre).</p>
</body>
</html>`);
});

// --- Signaler un numéro ---
app.post('/api/reports', rateLimit('report', 3_600_000, 60), auth, (req, res) => {
  const number = normalizeNumber(req.body?.number);
  if (!number) return res.status(400).json({ error: 'Numéro invalide' });
  let { category = null, comment = null } = req.body;
  if (category != null) category = String(category).slice(0, 32);
  if (comment != null) comment = String(comment).slice(0, 500);
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

// --- Initialisation « premier arrivé » : crée le fondateur + la clé admin.
// Ouvert uniquement tant qu'aucun utilisateur n'existe, puis verrouillé
// à jamais. La clé admin n'apparaît que dans cette unique réponse HTTP.
app.post('/api/bootstrap', rateLimit('bootstrap', 3_600_000, 5), (req, res) => {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count > 0) return res.status(403).json({ error: 'Serveur déjà initialisé' });
  const name = (req.body?.name || '').trim().slice(0, 64);
  if (!name) return res.status(400).json({ error: 'Nom requis' });
  const apiKey = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO users (name, api_key) VALUES (?, ?)').run(name, apiKey);
  let adminKey = null;
  if (!process.env.ADMIN_KEY) {
    adminKey = crypto.randomBytes(24).toString('hex');
    db.prepare(
      "INSERT OR REPLACE INTO meta (key, value) VALUES ('admin_key_hash', ?)"
    ).run(sha256(adminKey));
  }
  res.json({
    name,
    apiKey,
    adminKey,
    note: 'Conserve précieusement adminKey : elle ne sera plus jamais affichée.',
  });
});

// --- Demande d'adhésion depuis la page publique (formulaire HTML) ---
// Ouvert à tous mais fortement limité ; l'admin approuve ensuite.
app.post('/api/join-requests', rateLimit('join', 3_600_000, 5), (req, res) => {
  const name = cleanText(req.body?.name, 64);
  const contact = cleanText(req.body?.contact, 128);
  const message = cleanText(req.body?.message, 280);
  if (!name) {
    return res
      .status(400)
      .type('html')
      .send(confirmationPage('Nom manquant', 'Indique au moins un prénom ou pseudo.'));
  }
  const pending = db
    .prepare("SELECT COUNT(*) AS c FROM join_requests WHERE status = 'pending'")
    .get().c;
  // Garde-fou anti-flood global : file d'attente plafonnée.
  if (pending >= 200) {
    return res
      .status(429)
      .type('html')
      .send(confirmationPage('File pleine', 'Trop de demandes en attente, réessaie plus tard.'));
  }
  db.prepare(
    'INSERT INTO join_requests (name, contact, message, ip) VALUES (?, ?, ?, ?)'
  ).run(name, contact, message, clientIp(req));
  res
    .status(201)
    .type('html')
    .send(
      confirmationPage(
        'Demande envoyée ✅',
        `Merci ${escapeHtml(name)} ! L'administrateur du groupe va examiner ta demande et te transmettra ta clé d'accès.`
      )
    );
});

// --- Admin : lister les demandes d'adhésion en attente ---
app.get('/api/join-requests', adminAuth, (_req, res) => {
  const rows = db
    .prepare(
      "SELECT id, name, contact, message, created_at FROM join_requests WHERE status = 'pending' ORDER BY created_at"
    )
    .all();
  res.json(rows);
});

// --- Admin : approuver une demande → crée l'utilisateur + sa clé ---
app.post('/api/join-requests/:id/approve', adminAuth, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID invalide' });
  const reqRow = db
    .prepare("SELECT name FROM join_requests WHERE id = ? AND status = 'pending'")
    .get(id);
  if (!reqRow) return res.status(404).json({ error: 'Demande introuvable' });
  // Nom unique : suffixe si nécessaire.
  let name = reqRow.name;
  for (let i = 2; db.prepare('SELECT 1 FROM users WHERE name = ?').get(name); i++) {
    name = `${reqRow.name} (${i})`;
  }
  const apiKey = crypto.randomBytes(24).toString('hex');
  const tx = db.transaction(() => {
    db.prepare('INSERT INTO users (name, api_key) VALUES (?, ?)').run(name, apiKey);
    db.prepare("UPDATE join_requests SET status = 'approved' WHERE id = ?").run(id);
  });
  tx();
  res.json({ name, apiKey });
});

// --- Admin : rejeter une demande ---
app.post('/api/join-requests/:id/reject', adminAuth, (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'ID invalide' });
  const info = db
    .prepare("UPDATE join_requests SET status = 'rejected' WHERE id = ? AND status = 'pending'")
    .run(id);
  res.json({ rejected: info.changes > 0 });
});

// --- Admin : créer un utilisateur (proche) et sa clé ---
app.post('/api/users', adminAuth, (req, res) => {
  const name = (req.body?.name || '').trim().slice(0, 64);
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

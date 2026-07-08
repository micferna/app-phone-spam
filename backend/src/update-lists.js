// Met à jour les listes publiques de numéros/préfixes spam depuis les
// sources déclarées dans sources.json. Chaque source est remplacée
// entièrement à chaque mise à jour : un numéro retiré en amont (faux
// positif corrigé) disparaît donc aussi de notre base.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { db } from './db.js';
import { normalizeNumber } from './normalize.js';

const SOURCES_PATH =
  process.env.SOURCES_PATH ||
  join(dirname(fileURLToPath(import.meta.url)), '..', 'sources.json');

function normalizePrefix(raw) {
  let p = raw.replace(/[\s.-]/g, '');
  if (p.startsWith('00')) p = '+' + p.slice(2);
  if (/^0[1-9]\d*$/.test(p)) p = '+33' + p.slice(1);
  // Minimum 6 caractères (+33 + 2 chiffres) : une source compromise qui
  // publierait un préfixe ultra-court (ex : "+3") marquerait sinon tous
  // les numéros comme spam.
  return /^\+\d{5,14}$/.test(p) ? p : null;
}

// Format spamtel : une ligne = "0162*,Label" (préfixe) ou "0612345678,Label".
function parseCsvPrefix(text) {
  const prefixes = [];
  const numbers = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const [entry, label = null] = line.split(',').map((s) => s.trim());
    if (entry.endsWith('*')) {
      const p = normalizePrefix(entry.slice(0, -1));
      if (p) prefixes.push({ prefix: p, label });
    } else {
      const n = normalizeNumber(entry);
      if (n) numbers.push({ number: n, label });
    }
  }
  return { prefixes, numbers };
}

// Format begone-fr : YAML avec numéros à wildcards, ex :
//   - title: Démarchage
//     numbers:
//       - '+33 1 62 ## ## ##'
// On extrait le préfixe = la partie avant le premier '#'.
function parseBegoneYaml(text) {
  const prefixes = [];
  const numbers = [];
  let title = null;
  for (const raw of text.split('\n')) {
    const t = raw.match(/^-\s+title:\s*(.+)$/m) || raw.match(/^\s*title:\s*(.+)$/);
    if (t) { title = t[1].trim(); continue; }
    const m = raw.match(/^\s*-\s*'(\+[\d\s#]+)'\s*$/);
    if (!m) continue;
    const entry = m[1].replace(/\s/g, '');
    if (entry.includes('#')) {
      const p = normalizePrefix(entry.slice(0, entry.indexOf('#')));
      if (p) prefixes.push({ prefix: p, label: title });
    } else {
      const n = normalizeNumber(entry);
      if (n) numbers.push({ number: n, label: title });
    }
  }
  return { prefixes, numbers };
}

const PARSERS = { 'csv-prefix': parseCsvPrefix, 'begone-yaml': parseBegoneYaml };

// Hôtes autorisés pour les sources : même si sources.json était altéré, on
// ne peut fetch que des dépôts publics connus — pas de SSRF vers un service
// interne (métadonnées cloud, localhost, réseau privé…).
const ALLOWED_HOSTS = new Set([
  'raw.githubusercontent.com',
  'gist.githubusercontent.com',
]);

function isAllowedUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  return u.protocol === 'https:' && ALLOWED_HOSTS.has(u.hostname);
}

export async function updateLists() {
  const sources = JSON.parse(readFileSync(SOURCES_PATH, 'utf8'));
  const results = [];
  for (const src of sources) {
    const parser = PARSERS[src.format];
    if (!parser) {
      results.push({ source: src.name, error: `format inconnu : ${src.format}` });
      continue;
    }
    if (!isAllowedUrl(src.url)) {
      results.push({ source: src.name, error: 'URL non autorisée (hôte hors allowlist)' });
      continue;
    }
    try {
      const res = await fetch(src.url, { signal: AbortSignal.timeout(30_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // Plafond de taille : une source compromise servant plusieurs Go ne
      // doit pas provoquer d'OOM. On coupe au Content-Length si présent,
      // puis on revérifie la taille réellement lue.
      const MAX_BYTES = 5_000_000;
      const declared = Number(res.headers.get('content-length') || 0);
      if (declared > MAX_BYTES) throw new Error('source trop volumineuse');
      const text = await res.text();
      if (text.length > MAX_BYTES) throw new Error('source trop volumineuse');
      const { prefixes, numbers } = parser(text);
      if (prefixes.length === 0 && numbers.length === 0) {
        // Une source qui renvoie zéro entrée est probablement cassée :
        // on garde les données précédentes plutôt que de tout effacer.
        throw new Error('source vide, données existantes conservées');
      }
      const apply = db.transaction(() => {
        db.prepare('DELETE FROM imported_prefixes WHERE source = ?').run(src.name);
        db.prepare('DELETE FROM imported_numbers WHERE source = ?').run(src.name);
        const insP = db.prepare(
          'INSERT OR REPLACE INTO imported_prefixes (prefix, source, label) VALUES (?, ?, ?)'
        );
        const insN = db.prepare(
          'INSERT OR REPLACE INTO imported_numbers (number, source, label) VALUES (?, ?, ?)'
        );
        for (const { prefix, label } of prefixes) insP.run(prefix, src.name, label ?? src.label);
        for (const { number, label } of numbers) insN.run(number, src.name, label ?? src.label);
      });
      apply();
      results.push({ source: src.name, prefixes: prefixes.length, numbers: numbers.length });
    } catch (err) {
      results.push({ source: src.name, error: err.message });
    }
  }
  return results;
}

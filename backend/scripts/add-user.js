// Crée un utilisateur directement dans la base (sans passer par l'API).
// Usage : npm run add-user -- "Prénom"
//
// La clé générée est écrite dans un fichier à permissions restreintes
// (et non affichée à l'écran) pour ne pas laisser traîner un secret dans
// l'historique/scrollback du terminal.
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { db } from '../src/db.js';

const name = (process.argv[2] || '').trim();
if (!name) {
  console.error('Usage : npm run add-user -- "Prénom"');
  process.exit(1);
}

const apiKey = crypto.randomBytes(24).toString('hex');
try {
  db.prepare('INSERT INTO users (name, api_key) VALUES (?, ?)').run(name, apiKey);
} catch {
  console.error(`L'utilisateur "${name}" existe déjà.`);
  process.exit(1);
}

const safeName = name.replace(/[^\p{L}\p{N}_-]/gu, '_').slice(0, 40) || 'user';
const outFile = `cle-${safeName}.txt`;
writeFileSync(outFile, apiKey + '\n', { mode: 0o600 });
console.log(`Utilisateur "${name}" créé.`);
console.log(`Sa clé API a été écrite dans ${outFile} (permissions 600).`);
console.log('Transmets-la lui de façon sûre, puis supprime le fichier.');

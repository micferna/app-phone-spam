// Crée un utilisateur directement dans la base (sans passer par l'API).
// Usage : npm run add-user -- "Prénom"
import crypto from 'node:crypto';
import { db } from '../src/db.js';

const name = (process.argv[2] || '').trim();
if (!name) {
  console.error('Usage : npm run add-user -- "Prénom"');
  process.exit(1);
}

const apiKey = crypto.randomBytes(24).toString('hex');
try {
  db.prepare('INSERT INTO users (name, api_key) VALUES (?, ?)').run(name, apiKey);
  console.log(`Utilisateur "${name}" créé.`);
  console.log(`Clé API à mettre dans son app : ${apiKey}`);
} catch {
  console.error(`L'utilisateur "${name}" existe déjà.`);
  process.exit(1);
}

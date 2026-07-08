// Affiche la clé admin conservée en base (accès local à la base requis).
// Usage : npm run print-admin-key   (ou via docker exec sur le conteneur)
import { db } from '../src/db.js';

const row = db
  .prepare("SELECT value FROM meta WHERE key = 'admin_key'")
  .get?.() ?? null;

if (process.env.ADMIN_KEY) {
  console.log('La clé admin vient de la variable d\'environnement ADMIN_KEY.');
} else if (row) {
  console.log(row.value);
} else {
  console.log('Aucune clé admin en base (elle sera générée au premier démarrage).');
}

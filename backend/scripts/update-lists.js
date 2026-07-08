// Mise à jour manuelle des listes publiques : npm run update-lists
import { updateLists } from '../src/update-lists.js';

const results = await updateLists();
for (const r of results) {
  if (r.error) console.error(`Liste "${r.source}" : échec (${r.error})`);
  else console.log(`Liste "${r.source}" : ${r.prefixes} préfixes, ${r.numbers} numéros`);
}

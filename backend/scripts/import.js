// Importe une liste publique de numéros ou de préfixes spam dans la base.
//
// Usage :
//   node scripts/import.js <fichier> <nom-de-la-source> [label]
//
// Format du fichier : un numéro par ligne (formats FR acceptés).
// Une ligne se terminant par * est traitée comme un PRÉFIXE couvrant
// toute la plage (ex : "+337000*" ou "0162*").
// Les lignes vides et celles commençant par # sont ignorées.
import { readFileSync } from 'node:fs';
import { db } from '../src/db.js';
import { normalizeNumber } from '../src/normalize.js';

const [file, source, label = null] = process.argv.slice(2);
if (!file || !source) {
  console.error('Usage : node scripts/import.js <fichier> <nom-de-la-source> [label]');
  process.exit(1);
}

const lines = readFileSync(file, 'utf8').split('\n');
const insNumber = db.prepare(
  'INSERT OR REPLACE INTO imported_numbers (number, source, label) VALUES (?, ?, ?)'
);
const insPrefix = db.prepare(
  'INSERT OR REPLACE INTO imported_prefixes (prefix, source, label) VALUES (?, ?, ?)'
);

let numbers = 0;
let prefixes = 0;
let skipped = 0;

const importAll = db.transaction(() => {
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.endsWith('*')) {
      // Préfixe : normalisation légère (0162 -> +33162)
      let p = line.slice(0, -1).replace(/[\s.\-]/g, '');
      if (p.startsWith('00')) p = '+' + p.slice(2);
      if (/^0[1-9]\d*$/.test(p)) p = '+33' + p.slice(1);
      if (!/^\+\d{3,14}$/.test(p)) { skipped++; continue; }
      insPrefix.run(p, source, label);
      prefixes++;
    } else {
      const n = normalizeNumber(line);
      if (!n) { skipped++; continue; }
      insNumber.run(n, source, label);
      numbers++;
    }
  }
});
importAll();

console.log(`Import "${source}" terminé : ${numbers} numéros, ${prefixes} préfixes, ${skipped} lignes ignorées.`);

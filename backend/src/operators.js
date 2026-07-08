// Identification de l'opérateur attributaire d'un numéro, à partir de
// l'open data ARCEP MAJNUM (associe chaque tranche de numéros à
// l'opérateur qui l'a reçue). Permet d'enrichir le lookup : « ce numéro
// appartient à la plage de l'opérateur X », et de repérer les grossistes
// VoIP massivement utilisés par les centres d'appels de démarchage.
//
// Format MAJNUM : EZABPQM;Tranche_Debut;Tranche_Fin;Mnémo;Territoire;Date
// (CSV latin-1, séparateur ';'). Tranches en national 10 chiffres (0XXXXXXXXX).

const MAJNUM_URL = 'https://extranet.arcep.fr/uploads/MAJNUM.csv';

// Opérateurs grossistes / VoIP fréquemment associés au démarchage
// téléphonique (mnémoniques ARCEP → libellé lisible). Non exhaustif ;
// informatif, n'entraîne pas de blocage à lui seul.
const KNOWN_OPERATORS = {
  OXIL: 'Oxilog',
  UBIC: 'Ubicentrex',
  KAVE: 'Kav El International',
  GETG: 'Getg',
  QWLK: 'Quewilk',
  YAAT: 'Yaat',
  FLCA: 'Foliateam',
  MANI: 'Manifone',
  COMU: 'Comunik CRM',
  IPDI: 'IP Directions',
  DVSV: 'Diabolocom',
  OING: 'Ovanet',
  FREE: 'Free',
  SFR0: 'SFR',
  F000: 'Orange',
  BYTL: 'Bouygues Telecom',
};

// Index trié en mémoire : [ [debut, fin, mnemo], ... ] trié par debut.
let ranges = [];
let starts = [];

function buildIndex(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const cols = line.split(';');
    if (cols.length < 4) continue;
    const deb = Number.parseInt(cols[1], 10);
    const fin = Number.parseInt(cols[2], 10);
    const mnemo = (cols[3] || '').trim();
    if (!Number.isInteger(deb) || !Number.isInteger(fin) || !mnemo) continue;
    out.push([deb, fin, mnemo]);
  }
  out.sort((a, b) => a[0] - b[0]);
  ranges = out;
  starts = out.map((r) => r[0]);
  return out.length;
}

// Recherche dichotomique de la tranche contenant le numéro national.
function mnemoForNational(nat) {
  let lo = 0;
  let hi = starts.length - 1;
  let ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= nat) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (ans >= 0 && ranges[ans][0] <= nat && nat <= ranges[ans][1]) {
    return ranges[ans][2];
  }
  return null;
}

// e164 (+33XXXXXXXXX) → { mnemo, name } ou null. Métropole uniquement.
export function operatorFor(e164) {
  if (typeof e164 !== 'string' || !e164.startsWith('+33')) return null;
  const nat = Number.parseInt('0' + e164.slice(3), 10);
  if (!Number.isInteger(nat)) return null;
  const mnemo = mnemoForNational(nat);
  if (!mnemo) return null;
  return { mnemo, name: KNOWN_OPERATORS[mnemo] || null };
}

export async function refreshOperators() {
  const res = await fetch(MAJNUM_URL, { signal: AbortSignal.timeout(60_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  if (buf.byteLength > 20_000_000) throw new Error('MAJNUM trop volumineux');
  // ARCEP publie en latin-1.
  const text = new TextDecoder('latin1').decode(buf);
  const n = buildIndex(text);
  if (n === 0) throw new Error('MAJNUM vide');
  return n;
}

export function operatorsLoaded() {
  return ranges.length;
}

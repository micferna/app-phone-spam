// Normalise un numéro de téléphone en format E.164 (+33612345678).
// Gère les formats français courants : 06 12 34 56 78, 0612345678,
// +33 6 12 34 56 78, 0033612345678, etc.
export function normalizeNumber(raw) {
  if (typeof raw !== 'string') return null;
  let n = raw.replace(/[\s.\-()]/g, '');
  if (n.startsWith('00')) n = '+' + n.slice(2);
  if (/^0[1-9]\d{8}$/.test(n)) n = '+33' + n.slice(1);
  if (!/^\+[1-9]\d{6,14}$/.test(n)) return null;
  return n;
}

// Préfixes réservés au démarchage téléphonique en France par l'ARCEP
// (décision n° 2022-1583) : tout appel de prospection commerciale doit
// obligatoirement provenir de ces plages depuis le 1er janvier 2023.
// Métropole : 0162, 0163, 0270, 0271, 0377, 0378, 0424, 0425, 0568, 0569, 0948, 0949
// Outre-mer : 09475 à 09479
const ARCEP_DEMARCHAGE_PREFIXES = [
  '+33162', '+33163', '+33270', '+33271', '+33377', '+33378',
  '+33424', '+33425', '+33568', '+33569', '+33948', '+33949',
  '+339475', '+339476', '+339477', '+339478', '+339479',
];

export function isArcepDemarchage(e164) {
  return ARCEP_DEMARCHAGE_PREFIXES.some((p) => e164.startsWith(p));
}

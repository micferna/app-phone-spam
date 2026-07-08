// Heuristiques anti-smishing (SMS de phishing / démarchage). On ne
// « prouve » pas qu'un SMS est frauduleux — on repère des signaux
// caractéristiques et on alerte, façon prudente (seuils conservateurs pour
// limiter les faux positifs sur des SMS légitimes type code OTP).

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s]+/gi;

// Raccourcisseurs d'URL : très utilisés par le smishing pour masquer la
// destination réelle.
const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 'is.gd', 't.co', 'ow.ly',
  'buff.ly', 'shorturl.at', 'urlz.fr', 'lc.cx', 'tiny.cc',
];

// Domaines officiels usurpés par les arnaques (marque → domaine légitime).
// Un lien qui cite la marque sans être sur son vrai domaine = suspect.
const BRAND_DOMAINS = {
  'laposte': 'laposte.fr',
  'colissimo': 'laposte.fr',
  'chronopost': 'chronopost.fr',
  'ameli': 'ameli.fr',
  'impots': 'impots.gouv.fr',
  'cpf': 'moncompteformation.gouv.fr',
  'netflix': 'netflix.com',
  'paypal': 'paypal.com',
  'vinted': 'vinted.fr',
};

// Formulations typiques des arnaques par SMS.
const SCAM_KEYWORDS = [
  'colis', 'livraison', 'suivi de votre', 'frais de douane', 'frais de port',
  'compte a ete', 'compte bloque', 'compte suspendu', 'compte suspendu',
  'suspendu', 'verifiez vos informations', 'mettre a jour vos',
  'cliquez', 'cliquez ici', 'urgent', 'derniere relance', 'dernier avis',
  'cpf', 'compte formation', 'remboursement', 'vous avez gagne', 'cadeau',
  'carte vitale', 'carte grise', 'amende', 'penalite', 'identifiant',
  'mot de passe', 'code de securite', 'confirmez',
];

const stripAccents = (s) =>
  s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

export function analyzeSms(text) {
  const raw = String(text || '');
  const norm = stripAccents(raw);
  const signals = [];

  const urls = raw.match(URL_RE) || [];
  const hasUrl = urls.length > 0;
  if (hasUrl) signals.push('contient un lien');

  const usesShortener = urls.some((u) =>
    SHORTENERS.some((s) => u.toLowerCase().includes(s))
  );
  if (usesShortener) signals.push('lien raccourci (destination masquée)');

  // Marque citée dans le texte + lien qui ne pointe pas vers son vrai domaine.
  let brandSpoof = false;
  for (const [brand, domain] of Object.entries(BRAND_DOMAINS)) {
    if (norm.includes(brand) && hasUrl) {
      const onOfficial = urls.some((u) => u.toLowerCase().includes(domain));
      if (!onOfficial) {
        brandSpoof = true;
        break;
      }
    }
  }
  if (brandSpoof) signals.push('marque connue + lien non officiel');

  const keywordHits = SCAM_KEYWORDS.filter((k) => norm.includes(k));

  return {
    hasUrl,
    usesShortener,
    brandSpoof,
    keywordHits: keywordHits.length,
    signals,
  };
}

// Décision : suspect si l'un des cas nets est réuni. Conservateur pour ne
// pas alarmer sur un SMS légitime (ex : un simple code OTP sans lien).
export function isSuspiciousSms(analysis) {
  if (analysis.brandSpoof) return true;
  if (analysis.usesShortener && analysis.keywordHits >= 1) return true;
  if (analysis.hasUrl && analysis.keywordHits >= 2) return true;
  if (analysis.keywordHits >= 3) return true;
  return false;
}

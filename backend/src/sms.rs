//! Heuristiques anti-smishing (SMS de phishing / démarchage). Détection +
//! alerte : on repère des signaux caractéristiques, seuils conservateurs
//! pour ne pas alarmer sur un SMS légitime (ex : code OTP).

const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "t.co",
    "ow.ly",
    "buff.ly",
    "shorturl.at",
    "urlz.fr",
    "lc.cx",
    "tiny.cc",
];

/// (marque citée dans le texte, domaine officiel légitime)
const BRAND_DOMAINS: &[(&str, &str)] = &[
    ("laposte", "laposte.fr"),
    ("colissimo", "laposte.fr"),
    ("chronopost", "chronopost.fr"),
    ("ameli", "ameli.fr"),
    ("impots", "impots.gouv.fr"),
    ("cpf", "moncompteformation.gouv.fr"),
    ("netflix", "netflix.com"),
    ("paypal", "paypal.com"),
    ("vinted", "vinted.fr"),
];

const SCAM_KEYWORDS: &[&str] = &[
    "colis",
    "livraison",
    "suivi de votre",
    "frais de douane",
    "frais de port",
    "compte a ete",
    "compte bloque",
    "compte suspendu",
    "suspendu",
    "verifiez vos informations",
    "mettre a jour vos",
    "cliquez",
    "cliquez ici",
    "urgent",
    "derniere relance",
    "dernier avis",
    "cpf",
    "compte formation",
    "remboursement",
    "vous avez gagne",
    "cadeau",
    "carte vitale",
    "carte grise",
    "amende",
    "penalite",
    "identifiant",
    "mot de passe",
    "code de securite",
    "confirmez",
];

pub struct SmsAnalysis {
    pub has_url: bool,
    pub uses_shortener: bool,
    pub brand_spoof: bool,
    pub keyword_hits: usize,
    pub signals: Vec<String>,
}

fn strip_accents(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            other => other,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Extrait grossièrement les URLs (http/https/www).
fn extract_urls(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut urls = Vec::new();
    for token in lower.split_whitespace() {
        if token.starts_with("http://")
            || token.starts_with("https://")
            || token.starts_with("www.")
        {
            urls.push(token.trim_end_matches(['.', ',', ')', ']']).to_string());
        }
    }
    urls
}

pub fn analyze_sms(text: &str) -> SmsAnalysis {
    let norm = strip_accents(text);
    let urls = extract_urls(text);
    let has_url = !urls.is_empty();
    let mut signals = Vec::new();
    if has_url {
        signals.push("contient un lien".to_string());
    }

    let uses_shortener = urls
        .iter()
        .any(|u| SHORTENERS.iter().any(|s| u.contains(s)));
    if uses_shortener {
        signals.push("lien raccourci (destination masquée)".to_string());
    }

    let mut brand_spoof = false;
    for (brand, domain) in BRAND_DOMAINS {
        if norm.contains(brand) && has_url {
            let on_official = urls.iter().any(|u| u.contains(domain));
            if !on_official {
                brand_spoof = true;
                break;
            }
        }
    }
    if brand_spoof {
        signals.push("marque connue + lien non officiel".to_string());
    }

    let keyword_hits = SCAM_KEYWORDS.iter().filter(|k| norm.contains(*k)).count();

    SmsAnalysis {
        has_url,
        uses_shortener,
        brand_spoof,
        keyword_hits,
        signals,
    }
}

/// Décision conservatrice pour limiter les faux positifs.
pub fn is_suspicious_sms(a: &SmsAnalysis) -> bool {
    a.brand_spoof
        || (a.uses_shortener && a.keyword_hits >= 1)
        || (a.has_url && a.keyword_hits >= 2)
        || a.keyword_hits >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smishing_colis_raccourci() {
        let a = analyze_sms("Votre colis est en attente. Cliquez: https://bit.ly/xyz");
        assert!(is_suspicious_sms(&a));
    }

    #[test]
    fn phishing_marque() {
        let a = analyze_sms("Ameli: votre carte vitale expire. http://ameli-secure.co/maj");
        assert!(is_suspicious_sms(&a));
    }

    #[test]
    fn otp_legitime_non_flagge() {
        let a = analyze_sms("Votre code de securite est 458213");
        assert!(!is_suspicious_sms(&a));
    }

    #[test]
    fn sms_normal_non_flagge() {
        let a = analyze_sms("On se voit a 20h ?");
        assert!(!is_suspicious_sms(&a));
    }
}

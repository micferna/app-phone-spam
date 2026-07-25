//! Normalisation E.164 des numéros FR + détection des préfixes ARCEP
//! réservés au démarchage (décision 2022-1583).

/// Normalise un numéro en E.164 (`+33612345678`). Gère 06…, 0033…, +33…, etc.
/// Renvoie `None` si ce n'est pas un numéro valide (donc tout code / payload
/// injecté est rejeté).
pub fn normalize_number(raw: &str) -> Option<String> {
    let mut n: String = raw
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-' | '(' | ')' | '\t'))
        .collect();
    if let Some(rest) = n.strip_prefix("00") {
        n = format!("+{rest}");
    }
    // 0[1-9]xxxxxxxx (10 chiffres) -> +33...
    if n.len() == 10
        && n.starts_with('0')
        && n.as_bytes()[1] != b'0'
        && n[1..].chars().all(|c| c.is_ascii_digit())
    {
        n = format!("+33{}", &n[1..]);
    }
    // +[1-9] puis 6 à 14 chiffres
    let ok = n.starts_with('+')
        && n.len() >= 8
        && n.len() <= 16
        && n[1..].chars().all(|c| c.is_ascii_digit())
        && n.as_bytes()[1] != b'0';
    if ok {
        Some(n)
    } else {
        None
    }
}

/// Racines des « numéros polyvalents vérifiés » (décision ARCEP 2022-1583,
/// § 2.3.7a) : la catégorie qu'un professionnel doit présenter comme
/// identifiant d'appelant pour du démarchage.
///
/// Outre-mer, ces racines vivent sous leur PROPRE indicatif pays (+590, +594,
/// +596, +262), pas sous +33 : un appel guadeloupéen arrive en `+5909475…`.
/// Les formes en `+339475…` sont conservées en plus, car `normalize_number`
/// préfixe en +33 tout numéro national à 10 chiffres — c'est sous cette forme
/// qu'un tel numéro composé localement nous parvient. Aucun risque de
/// collision : en métropole 0947 n'est attribué à rien (les polyvalents
/// métropolitains sont 0940–0946, les vérifiés 0948–0949).
const ARCEP_PREFIXES: &[&str] = &[
    // France métropolitaine (+33)
    "+33162", "+33163", "+33270", "+33271", "+33377", "+33378", "+33424", "+33425", "+33568",
    "+33569", "+33948", "+33949",   // Outre-mer, indicatif pays propre
    "+5909475", // Guadeloupe, Saint-Martin, Saint-Barthélemy
    "+5949476", // Guyane
    "+5969477", // Martinique
    "+2629478", "+2629479", // Mayotte, La Réunion et autres territoires de l'Océan Indien
    // Mêmes racines vues via la normalisation nationale à 10 chiffres
    "+339475", "+339476", "+339477", "+339478", "+339479",
];

pub fn is_arcep_demarchage(e164: &str) -> bool {
    ARCEP_PREFIXES.iter().any(|p| e164.starts_with(p))
}

/// Liste servie aux téléphones lors de la synchro.
///
/// Ces racines ne sont publiées par l'ARCEP que dans le PDF d'une décision —
/// aucun des 12 fichiers open data ne décrit les catégories du plan. Elles
/// restent donc écrites à la main ici, relues et versionnées. Mais les servir
/// évite qu'une correction n'exige une release de l'app *et* que chaque membre
/// l'installe : le serveur suffit, les téléphones s'alignent à la synchro
/// suivante. Leur liste compilée reste leur filet hors-ligne.
pub fn arcep_prefixes() -> &'static [&'static str] {
    ARCEP_PREFIXES
}

/// Analyse déterministe d'un numéro E.164 (aucune donnée envoyée à un tiers) :
/// renvoie (code, libellé lisible, indice de risque 0-3).
/// Le risque n'est qu'une heuristique liée au *type* de ligne, pas un verdict.
pub fn classify_number(e164: &str) -> (&'static str, String, u8) {
    if is_arcep_demarchage(e164) {
        return (
            "demarchage",
            "Plage réservée au démarchage (ARCEP)".into(),
            3,
        );
    }
    // Numéros français : +33 puis l'indicatif national (le 0 est retiré).
    if let Some(rest) = e164.strip_prefix("+33") {
        let d = rest.as_bytes().first().copied().unwrap_or(0);
        return match d {
            b'6' | b'7' => ("mobile", "Mobile".into(), 0),
            b'9' => (
                "voip",
                "VoIP / non géographique (09) — fréquent en démarchage".into(),
                2,
            ),
            b'8' => {
                // 080x = gratuit/service ; 081x-089x = surtaxé.
                let second = rest.as_bytes().get(1).copied().unwrap_or(0);
                if second == b'0' {
                    ("numero_vert", "Numéro vert / service (080)".into(), 1)
                } else {
                    ("surtaxe", "Numéro spécial surtaxé (08)".into(), 2)
                }
            }
            b'1'..=b'5' => {
                let zone = match d {
                    b'1' => "Île-de-France",
                    b'2' => "Nord-Ouest",
                    b'3' => "Nord-Est",
                    b'4' => "Sud-Est",
                    _ => "Sud-Ouest",
                };
                ("fixe", format!("Fixe géographique · {zone}"), 0)
            }
            _ => ("autre", "Numéro français".into(), 0),
        };
    }
    // Indicatif international non-FR.
    let cc: String = e164
        .chars()
        .skip(1)
        .take_while(|c| c.is_ascii_digit())
        .take(3)
        .collect();
    ("etranger", format!("Numéro international (+{cc}…)"), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepte_formats_fr() {
        assert_eq!(
            normalize_number("06 12 34 56 78").as_deref(),
            Some("+33612345678")
        );
        assert_eq!(
            normalize_number("0612345678").as_deref(),
            Some("+33612345678")
        );
        assert_eq!(
            normalize_number("+33 6 12 34 56 78").as_deref(),
            Some("+33612345678")
        );
        assert_eq!(
            normalize_number("0033612345678").as_deref(),
            Some("+33612345678")
        );
    }

    #[test]
    fn rejette_les_injections() {
        for bad in [
            "'; DROP TABLE users;--",
            "<img src=x onerror=alert(1)>",
            "$(rm -rf /)",
            "not_a_number",
            "",
            "   ",
            "06123",
        ] {
            assert_eq!(normalize_number(bad), None, "devrait rejeter: {bad}");
        }
    }

    #[test]
    fn detecte_arcep() {
        assert!(is_arcep_demarchage("+33948123456"));
        assert!(is_arcep_demarchage("+33162000000"));
        assert!(!is_arcep_demarchage("+33612345678"));
    }

    #[test]
    fn les_racines_servies_sont_exploitables_par_le_client() {
        // L'app revalide chaque entrée (« + » puis 5 à 15 chiffres) avant de
        // s'en servir : une racine non conforme serait silencieusement ignorée.
        for p in arcep_prefixes() {
            assert!(p.starts_with('+'), "{p} doit commencer par +");
            let digits = &p[1..];
            assert!(
                digits.len() >= 5 && digits.len() <= 15,
                "{p} : longueur hors bornes"
            );
            assert!(
                digits.chars().all(|c| c.is_ascii_digit()),
                "{p} : caractère non numérique"
            );
        }
        assert!(!arcep_prefixes().is_empty());
    }

    #[test]
    fn detecte_arcep_outre_mer() {
        // Sous leur indicatif pays réel (appel reçu depuis la métropole).
        assert!(is_arcep_demarchage("+5909475123456"));
        assert!(is_arcep_demarchage("+5949476123456"));
        assert!(is_arcep_demarchage("+5969477123456"));
        assert!(is_arcep_demarchage("+2629478123456"));
        assert!(is_arcep_demarchage("+2629479123456"));
        // Et via la normalisation d'un national à 10 chiffres composé sur place.
        assert_eq!(
            normalize_number("0947512345").as_deref(),
            Some("+33947512345")
        );
        assert!(is_arcep_demarchage("+33947512345"));
        // Un fixe guadeloupéen ordinaire (0590…) ne doit pas être pris.
        assert!(!is_arcep_demarchage("+590590123456"));
    }
}

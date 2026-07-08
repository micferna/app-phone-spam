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

const ARCEP_PREFIXES: &[&str] = &[
    "+33162", "+33163", "+33270", "+33271", "+33377", "+33378", "+33424", "+33425", "+33568",
    "+33569", "+33948", "+33949", "+339475", "+339476", "+339477", "+339478", "+339479",
];

pub fn is_arcep_demarchage(e164: &str) -> bool {
    ARCEP_PREFIXES.iter().any(|p| e164.starts_with(p))
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
}

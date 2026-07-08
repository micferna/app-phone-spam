//! Identification de l'opérateur attributaire d'un numéro via l'open data
//! ARCEP MAJNUM (tranche de numéros -> opérateur). Index trié en mémoire,
//! recherche dichotomique.

use std::collections::HashMap;

pub const MAJNUM_URL: &str = "https://extranet.arcep.fr/uploads/MAJNUM.csv";

/// Mnémoniques ARCEP -> libellé lisible (grossistes VoIP souvent liés au
/// démarchage inclus). Informatif, ne déclenche pas de blocage.
fn known_name(mnemo: &str) -> Option<&'static str> {
    Some(match mnemo {
        "OXIL" => "Oxilog",
        "UBIC" => "Ubicentrex",
        "KAVE" => "Kav El International",
        "GETG" => "Getg",
        "QWLK" => "Quewilk",
        "YAAT" => "Yaat",
        "FLCA" => "Foliateam",
        "MANI" => "Manifone",
        "COMU" => "Comunik CRM",
        "IPDI" => "IP Directions",
        "DVSV" => "Diabolocom",
        "FREE" => "Free",
        "SFR0" => "SFR",
        "F000" => "Orange",
        "BYTL" => "Bouygues Telecom",
        _ => return None,
    })
}

#[derive(Clone)]
pub struct Operator {
    pub mnemo: String,
    pub name: Option<String>,
}

#[derive(Default)]
pub struct OperatorIndex {
    // (début, fin) en national i64 (0XXXXXXXXX) -> mnémo, trié par début.
    ranges: Vec<(i64, i64, String)>,
}

impl OperatorIndex {
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Reconstruit l'index depuis le CSV MAJNUM (latin-1 déjà décodé).
    pub fn build(text: &str) -> Self {
        let mut ranges = Vec::new();
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split(';').collect();
            if cols.len() < 4 {
                continue;
            }
            let (Ok(deb), Ok(fin)) = (cols[1].trim().parse::<i64>(), cols[2].trim().parse::<i64>())
            else {
                continue;
            };
            let mnemo = cols[3].trim();
            if mnemo.is_empty() {
                continue;
            }
            ranges.push((deb, fin, mnemo.to_string()));
        }
        ranges.sort_by_key(|r| r.0);
        OperatorIndex { ranges }
    }

    fn mnemo_for_national(&self, nat: i64) -> Option<&str> {
        // dernière tranche dont le début <= nat
        let idx = self.ranges.partition_point(|r| r.0 <= nat);
        if idx == 0 {
            return None;
        }
        let (deb, fin, mnemo) = &self.ranges[idx - 1];
        if *deb <= nat && nat <= *fin {
            Some(mnemo)
        } else {
            None
        }
    }

    /// e164 (+33XXXXXXXXX) -> opérateur (métropole).
    pub fn operator_for(&self, e164: &str) -> Option<Operator> {
        let rest = e164.strip_prefix("+33")?;
        let nat: i64 = format!("0{rest}").parse().ok()?;
        let mnemo = self.mnemo_for_national(nat)?;
        Some(Operator {
            mnemo: mnemo.to_string(),
            name: known_name(mnemo).map(str::to_string),
        })
    }

    /// Réputation : combien de numéros distincts d'une liste appartiennent à
    /// chaque opérateur, trié décroissant.
    pub fn reputation(&self, numbers: &[String]) -> Vec<(String, Option<String>, i64)> {
        let mut counts: HashMap<String, i64> = HashMap::new();
        for num in numbers {
            if let Some(op) = self.operator_for(num) {
                *counts.entry(op.mnemo).or_insert(0) += 1;
            }
        }
        let mut out: Vec<_> = counts
            .into_iter()
            .map(|(m, c)| {
                let name = known_name(&m).map(str::to_string);
                (m, name, c)
            })
            .collect();
        out.sort_by_key(|x| std::cmp::Reverse(x.2));
        out
    }
}

/// Télécharge et parse MAJNUM. `text` récupéré en latin-1 par l'appelant.
pub async fn fetch_majnum() -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(MAJNUM_URL)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    if bytes.len() > 20_000_000 {
        return Err("MAJNUM trop volumineux".into());
    }
    // ARCEP publie en latin-1 (ISO-8859-1) : conversion octet -> char.
    Ok(bytes.iter().map(|&b| b as char).collect())
}

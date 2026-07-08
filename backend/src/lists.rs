//! Mise à jour des listes publiques de préfixes/numéros spam depuis des
//! sources allowlistées (anti-SSRF), + rafraîchissement de l'annuaire ARCEP.

use sqlx::SqlitePool;

use crate::normalize::normalize_number;

struct Source {
    name: &'static str,
    url: &'static str,
    format: Format,
}

enum Format {
    CsvPrefix,
    BegoneYaml,
}

const SOURCES: &[Source] = &[
    Source {
        name: "spamtel",
        url: "https://raw.githubusercontent.com/guiguiabloc/spamtel/master/spamlist.csv",
        format: Format::CsvPrefix,
    },
    Source {
        name: "begone-fr",
        url: "https://raw.githubusercontent.com/danroc/begone-fr/main/data/numbers.yaml",
        format: Format::BegoneYaml,
    },
];

// Hôtes autorisés pour les sources (défense en profondeur anti-SSRF).
const ALLOWED_HOSTS: &[&str] = &["raw.githubusercontent.com", "gist.githubusercontent.com"];

fn is_allowed(url: &str) -> bool {
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };
    let host = rest.split('/').next().unwrap_or("");
    ALLOWED_HOSTS.contains(&host)
}

fn normalize_prefix(raw: &str) -> Option<String> {
    let mut p: String = raw
        .chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-' | '\t'))
        .collect();
    if let Some(rest) = p.strip_prefix("00") {
        p = format!("+{rest}");
    }
    if p.starts_with('0')
        && p.len() > 1
        && p.as_bytes()[1] != b'0'
        && p[1..].chars().all(|c| c.is_ascii_digit())
    {
        p = format!("+33{}", &p[1..]);
    }
    // min 5 chiffres après le + (anti-empoisonnement).
    if p.starts_with('+') && p.len() >= 6 && p[1..].chars().all(|c| c.is_ascii_digit()) {
        Some(p)
    } else {
        None
    }
}

struct Parsed {
    prefixes: Vec<String>,
    numbers: Vec<String>,
}

fn parse_csv_prefix(text: &str) -> Parsed {
    let mut prefixes = Vec::new();
    let mut numbers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = line.split(',').next().unwrap_or("").trim();
        if let Some(pref) = entry.strip_suffix('*') {
            if let Some(p) = normalize_prefix(pref) {
                prefixes.push(p);
            }
        } else if let Some(n) = normalize_number(entry) {
            numbers.push(n);
        }
    }
    Parsed { prefixes, numbers }
}

fn parse_begone_yaml(text: &str) -> Parsed {
    let mut prefixes = Vec::new();
    let numbers = Vec::new();
    for line in text.lines() {
        // lignes du type:  - '+33 1 62 ## ## ##'
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("- '") {
            if let Some(entry) = rest.strip_suffix('\'') {
                let cleaned: String = entry.chars().filter(|c| !c.is_whitespace()).collect();
                if cleaned.contains('#') {
                    let head = &cleaned[..cleaned.find('#').unwrap()];
                    if let Some(p) = normalize_prefix(head) {
                        prefixes.push(p);
                    }
                }
            }
        }
    }
    Parsed { prefixes, numbers }
}

pub struct ListResult {
    pub source: String,
    pub prefixes: usize,
    pub numbers: usize,
    pub error: Option<String>,
}

pub async fn update_lists(pool: &SqlitePool) -> Vec<ListResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let mut results = Vec::new();

    for src in SOURCES {
        if !is_allowed(src.url) {
            results.push(ListResult {
                source: src.name.into(),
                prefixes: 0,
                numbers: 0,
                error: Some("URL non autorisée".into()),
            });
            continue;
        }
        match fetch_and_apply(&client, pool, src).await {
            Ok((p, n)) => results.push(ListResult {
                source: src.name.into(),
                prefixes: p,
                numbers: n,
                error: None,
            }),
            Err(e) => results.push(ListResult {
                source: src.name.into(),
                prefixes: 0,
                numbers: 0,
                error: Some(e),
            }),
        }
    }
    results
}

async fn fetch_and_apply(
    client: &reqwest::Client,
    pool: &SqlitePool,
    src: &Source,
) -> Result<(usize, usize), String> {
    let resp = client
        .get(src.url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if text.len() > 5_000_000 {
        return Err("source trop volumineuse".into());
    }
    let parsed = match src.format {
        Format::CsvPrefix => parse_csv_prefix(&text),
        Format::BegoneYaml => parse_begone_yaml(&text),
    };
    if parsed.prefixes.is_empty() && parsed.numbers.is_empty() {
        return Err("source vide, données conservées".into());
    }

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM imported_prefixes WHERE source = ?")
        .bind(src.name)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM imported_numbers WHERE source = ?")
        .bind(src.name)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    for p in &parsed.prefixes {
        sqlx::query(
            "INSERT OR REPLACE INTO imported_prefixes (prefix, source, label) VALUES (?, ?, ?)",
        )
        .bind(p)
        .bind(src.name)
        .bind(src.name)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    for n in &parsed.numbers {
        sqlx::query(
            "INSERT OR REPLACE INTO imported_numbers (number, source, label) VALUES (?, ?, ?)",
        )
        .bind(n)
        .bind(src.name)
        .bind(src.name)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok((parsed.prefixes.len(), parsed.numbers.len()))
}

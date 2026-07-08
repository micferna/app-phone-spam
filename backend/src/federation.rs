//! Fédération : importe le flux public d'autres serveurs anti-spam
//! (numéros confirmés par ≥2 membres chez eux). Configuré via l'env
//! FEDERATION_PEERS (URLs de base séparées par des virgules).

use sqlx::SqlitePool;

use crate::normalize::normalize_number;

pub fn parse_peers(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| s.starts_with("https://") || s.starts_with("http://"))
        .collect()
}

fn host_of(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("peer")
        .to_string()
}

pub async fn pull_peers(pool: &SqlitePool, peers: &[String]) {
    if peers.is_empty() {
        return;
    }
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    for peer in peers {
        let url = format!("{peer}/api/federation/feed");
        match pull_one(&client, pool, peer, &url).await {
            Ok(n) => println!("Fédération {peer} : {n} numéros importés"),
            Err(e) => eprintln!("Fédération {peer} : échec ({e})"),
        }
    }
}

async fn pull_one(
    client: &reqwest::Client,
    pool: &SqlitePool,
    peer: &str,
    url: &str,
) -> Result<usize, String> {
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    if text.len() > 10_000_000 {
        return Err("flux trop volumineux".into());
    }
    let body: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let arr = body
        .get("numbers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if arr.len() > 50_000 {
        return Err("flux trop volumineux".into());
    }
    if arr.is_empty() {
        return Ok(0); // rien de confirmé chez le pair : on garde l'existant
    }
    let source = format!("federation:{}", host_of(peer));
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM imported_numbers WHERE source = ?")
        .bind(&source)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    let mut n = 0;
    for item in arr {
        if let Some(num) = item
            .get("number")
            .and_then(|v| v.as_str())
            .and_then(normalize_number)
        {
            let _ = sqlx::query(
                "INSERT OR REPLACE INTO imported_numbers (number, source, label) VALUES (?, ?, 'Fédération')",
            )
            .bind(&num)
            .bind(&source)
            .execute(&mut *tx)
            .await;
            n += 1;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(n)
}

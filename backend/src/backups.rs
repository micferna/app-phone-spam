//! Sauvegardes de la base SQLite : snapshot cohérent (VACUUM INTO), rotation
//! quotidienne sur le volume + export à la demande (pour off-site).

use sqlx::SqlitePool;

/// Écrit une copie propre et cohérente de la base dans `path` (écrase).
async fn snapshot_to(pool: &SqlitePool, path: &str) -> Result<(), String> {
    let _ = std::fs::remove_file(path); // VACUUM INTO exige un fichier absent
                                        // Chemin serveur (pas d'entrée utilisateur) ; on échappe les quotes et on
                                        // atteste explicitement que le SQL est sûr (audité).
    let safe = path.replace('\'', "''");
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("VACUUM INTO '{safe}'")))
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Snapshot en mémoire (pour l'endpoint d'export admin).
pub async fn snapshot_bytes(pool: &SqlitePool) -> Result<Vec<u8>, String> {
    let tmp = std::env::temp_dir().join(format!("antispam-export-{}.db", std::process::id()));
    let tmp = tmp.to_string_lossy().to_string();
    snapshot_to(pool, &tmp).await?;
    let bytes = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    Ok(bytes)
}

/// Sauvegarde quotidienne rotative (7 emplacements = 1 semaine glissante).
pub async fn run_daily_backup(pool: &SqlitePool, backup_dir: &str) {
    if let Err(e) = std::fs::create_dir_all(backup_dir) {
        eprintln!("Backup : dossier inaccessible ({e})");
        return;
    }
    let slot = day_slot();
    let path = format!("{backup_dir}/backup-{slot}.db");
    match snapshot_to(pool, &path).await {
        Ok(()) => println!("Backup écrit : {path}"),
        Err(e) => eprintln!("Backup échoué : {e}"),
    }
}

fn day_slot() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400 % 7)
        .unwrap_or(0)
}

//! Initialisation SQLite. Schéma IDENTIQUE à la version JS pour réutiliser
//! sans migration la base existante (utilisateurs, signalements, clés).

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions, SqlitePool};
use std::str::FromStr;

pub async fn init_pool(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        // Avec WAL, NORMAL est le réglage recommandé : durabilité préservée
        // (hors crash OS au checkpoint), moins de fsync sur les écritures →
        // fenêtres de contention plus courtes pour les lectures (lookups).
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .disable_statement_logging();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        "#,
    )
    .execute(&pool)
    .await?;

    // sqlx exécute une requête à la fois : on lance chaque CREATE séparément.
    for stmt in [
        r#"CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              api_key TEXT NOT NULL UNIQUE,
              trusted INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
           )"#,
        r#"CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL REFERENCES users(id),
              number TEXT NOT NULL,
              category TEXT,
              comment TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE (user_id, number)
           )"#,
        r#"CREATE TABLE IF NOT EXISTS imported_numbers (
              number TEXT PRIMARY KEY,
              source TEXT NOT NULL,
              label TEXT,
              imported_at TEXT NOT NULL DEFAULT (datetime('now'))
           )"#,
        r#"CREATE TABLE IF NOT EXISTS imported_prefixes (
              prefix TEXT PRIMARY KEY,
              source TEXT NOT NULL,
              label TEXT,
              imported_at TEXT NOT NULL DEFAULT (datetime('now'))
           )"#,
        r#"CREATE TABLE IF NOT EXISTS join_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              contact TEXT,
              message TEXT,
              status TEXT NOT NULL DEFAULT 'pending',
              ip TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
           )"#,
        // Retour utilisateur « était-ce du spam ? » (1 = spam, 0 = légitime)
        // pour affiner le score et réduire les faux positifs.
        r#"CREATE TABLE IF NOT EXISTS feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              number TEXT NOT NULL,
              was_spam INTEGER NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE (user_id, number)
           )"#,
        // Invitations à usage unique (onboarding par QR / lien).
        r#"CREATE TABLE IF NOT EXISTS invites (
              token TEXT PRIMARY KEY,
              used INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              expires_at TEXT NOT NULL
           )"#,
        "CREATE INDEX IF NOT EXISTS idx_reports_number ON reports(number)",
        "CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_join_status ON join_requests(status)",
        "CREATE INDEX IF NOT EXISTS idx_feedback_number ON feedback(number)",
    ] {
        sqlx::query(stmt).execute(&pool).await?;
    }

    Ok(pool)
}

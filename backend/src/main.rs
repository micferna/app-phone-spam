//! Backend anti-spam communautaire — Rust (axum + SQLite).

mod backups;
mod federation;
mod handlers;
mod lists;
mod normalize;
mod operators;
mod pages;
mod schema;
mod sms;
mod state;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::json;

use operators::OperatorIndex;
use state::AppState;

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "./data/spam.db".into());
    if let Some(dir) = std::path::Path::new(&db_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let pool = schema::init_pool(&db_path).await.expect("init base SQLite");

    // Migration : hashe les clés API en clair héritées (SHA-256). Discriminant :
    // une empreinte hex fait 64 caractères, une clé brute en fait 48. Idempotent.
    // Doit tourner avant de servir la moindre requête pour ne verrouiller personne.
    {
        let legacy: Vec<(i64, String)> =
            sqlx::query_as("SELECT id, api_key FROM users WHERE length(api_key) <> 64")
                .fetch_all(&pool)
                .await
                .unwrap_or_default();
        for (id, k) in &legacy {
            let _ = sqlx::query("UPDATE users SET api_key = ? WHERE id = ?")
                .bind(handlers::sha256_hex(k))
                .bind(id)
                .execute(&pool)
                .await;
        }
        if !legacy.is_empty() {
            println!("Migration : {} clé(s) API hashée(s).", legacy.len());
        }
    }

    let backup_dir = std::path::Path::new(&db_path)
        .parent()
        .map(|p| p.join("backups").to_string_lossy().to_string())
        .unwrap_or_else(|| "./data/backups".into());

    let st = AppState {
        pool,
        admin_key: env_nonempty("ADMIN_KEY"),
        bootstrap_token: env_nonempty("BOOTSTRAP_TOKEN"),
        operators: Arc::new(RwLock::new(OperatorIndex::default())),
        buckets: Arc::new(Mutex::new(HashMap::new())),
        rep: Arc::new(Mutex::new(HashMap::new())),
        rep_dirty: Arc::new(AtomicBool::new(true)),
        federation_peers: federation::parse_peers(
            &std::env::var("FEDERATION_PEERS").unwrap_or_default(),
        ),
        backup_dir,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    // Sauvegarde quotidienne de la base (rotation 7 jours sur le volume).
    {
        let bg = st.clone();
        tokio::spawn(async move {
            loop {
                backups::run_daily_backup(&bg.pool, &bg.backup_dir).await;
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });
    }

    // Rafraîchissement des données publiques : au démarrage puis toutes les 24 h.
    if std::env::var("UPDATE_LISTS").as_deref() != Ok("0") {
        let bg = st.clone();
        tokio::spawn(async move {
            loop {
                refresh_all(&bg).await;
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });
    }

    let app = Router::new()
        .route("/", get(handlers::landing))
        .route("/api/health", get(handlers::health))
        .route("/api/status", get(handlers::status))
        .route("/api/bootstrap", post(handlers::bootstrap))
        .route(
            "/api/join-requests",
            post(handlers::join_request).get(handlers::list_join_requests),
        )
        .route(
            "/api/join-requests/{id}/approve",
            post(handlers::approve_join),
        )
        .route(
            "/api/join-requests/{id}/reject",
            post(handlers::reject_join),
        )
        .route("/api/reports", post(handlers::create_report))
        .route("/api/reports/bulk", post(handlers::bulk_import))
        .route("/api/reports/{number}", delete(handlers::delete_report))
        .route("/api/lookup/{number}", get(handlers::lookup))
        .route("/api/numbers", get(handlers::numbers))
        .route("/api/operators", get(handlers::operators))
        .route("/api/check-sms", post(handlers::check_sms))
        .route("/api/feedback", post(handlers::feedback))
        .route("/api/alerts", get(handlers::alerts))
        .route("/api/federation/feed", get(handlers::federation_feed))
        .route("/api/stats", get(handlers::stats))
        .route("/api/export", get(handlers::export_db))
        .route(
            "/api/users",
            post(handlers::create_user).get(handlers::list_users),
        )
        .route("/api/users/{id}", delete(handlers::delete_user))
        .route("/api/invites", post(handlers::create_invite))
        .route("/api/invite/redeem", post(handlers::redeem_invite))
        .route("/api/update-lists", post(handlers::update_lists))
        .route(
            "/admin",
            get(handlers::admin_login).post(handlers::admin_dashboard),
        )
        .route("/admin/logout", get(handlers::admin_logout))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn_with_state(st.clone(), global_rate))
        .layer(middleware::from_fn(security_headers))
        .with_state(st);

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("Backend anti-spam (Rust) démarré sur {addr}");
    axum::serve(listener, app).await.expect("serve");
}

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

async fn refresh_all(st: &AppState) {
    for r in lists::update_lists(&st.pool).await {
        match &r.error {
            Some(err) => eprintln!("Liste \"{}\" : échec ({err})", r.source),
            None => println!(
                "Liste \"{}\" : {} préfixes, {} numéros",
                r.source, r.prefixes, r.numbers
            ),
        }
    }
    match operators::fetch_majnum().await {
        Ok(text) => {
            let idx = OperatorIndex::build(&text);
            let n = idx.len();
            *st.operators.write().unwrap() = idx;
            println!("Annuaire opérateurs ARCEP : {n} tranches chargées");
        }
        Err(err) => eprintln!("Annuaire opérateurs ARCEP indisponible : {err}"),
    }
    federation::pull_peers(&st.pool, &st.federation_peers).await;
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'",
        ),
    );
    // Force TLS (anti-downgrade / SSL-strip) — 2 ans, sous-domaines inclus.
    h.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    // Les réponses sont dynamiques et le dashboard admin contient un secret :
    // on interdit toute mise en cache (navigateur, back/forward, proxys).
    h.insert(
        "Cache-Control",
        HeaderValue::from_static("no-store, max-age=0"),
    );
    res
}

async fn global_rate(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let ip = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("inconnu")
        .to_string();
    if !st.rate_ok(&format!("global:{ip}"), Duration::from_secs(60), 240) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Trop de requêtes, réessaie plus tard" })),
        )
            .into_response();
    }
    next.run(req).await
}

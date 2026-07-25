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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use serde_json::json;

use operators::OperatorIndex;
use state::{AppState, ClientIp};

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

    // Migration : colonne `trusted` (anti-empoisonnement) sur les bases héritées.
    // Erreur « duplicate column » ignorée si la colonne existe déjà (idempotent).
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN trusted INTEGER NOT NULL DEFAULT 1")
        .execute(&pool)
        .await;

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
        block_score_threshold: std::env::var("BLOCK_SCORE_THRESHOLD")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(70),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        probe: Arc::new(state::ProxyProbe::default()),
        trust_proxy: matches!(
            std::env::var("TRUST_PROXY").as_deref(),
            Ok("1") | Ok("true")
        ),
    };
    if !st.trust_proxy {
        println!(
            "Limitation de débit basée sur l'IP du socket. Derrière Cloudflare \
             ou un reverse-proxy, poser TRUST_PROXY=1 pour utiliser CF-Connecting-IP."
        );
    }

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
        // L'import en masse accepte 5 000 numéros par lot (~80 ko) : le plafond
        // global de 8 ko le coupait à ~510 avec un 413. Limite dédiée, route
        // réservée à l'admin authentifié.
        .route(
            "/api/reports/bulk",
            post(handlers::bulk_import).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route("/api/reports/{number}", delete(handlers::delete_report))
        .route("/api/imported/{number}", delete(handlers::delete_imported))
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
        .route("/api/users/{id}/trust", post(handlers::set_trust))
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
    // `into_make_service_with_connect_info` : sans ça, l'IP réelle du client
    // n'est pas disponible dans les extensions et la limitation de débit
    // n'aurait plus qu'un compteur global unique.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
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

/// Une IP privée/loopback vient de l'infrastructure (ingress, healthcheck) et
/// ne prouve pas que l'origine est exposée publiquement.
fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            !(v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            // `is_unique_local`/`is_unicast_link_local` ne sont pas stables :
            // on teste les préfixes fc00::/7 et fe80::/10 à la main.
            let o = v6.octets();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (o[0] & 0xfe) == 0xfc
                || (o[0] == 0xfe && (o[1] & 0xc0) == 0x80))
        }
        Err(_) => false,
    }
}

/// Journalise l'incohérence détectée, au plus une fois par heure : c'est un
/// problème de déploiement, pas un évènement par requête.
fn warn_proxy_misconfig(st: &AppState) {
    let Some(msg) = st.proxy_misconfig() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = st.probe.last_warn.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 3600
        || st
            .probe
            .last_warn
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    eprintln!("ATTENTION — configuration de proxy incohérente : {msg}");
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

/// Résout l'IP du client et la dépose dans les extensions de la requête, puis
/// applique le plafond global.
///
/// L'IP vient du SOCKET, pas d'un en-tête : `CF-Connecting-IP` est envoyé par
/// le client et n'a de valeur que derrière un proxy qui l'écrase (Cloudflare).
/// Le croire sans condition rendait tous les quotas inopérants — il suffisait
/// de faire tourner l'en-tête à chaque requête — et, en accès direct (sans
/// proxy), il n'y avait plus qu'un seul compteur partagé par tout le monde :
/// un client pouvait saturer le plafond global et faire échouer les lookups
/// des membres, donc désarmer le filtrage de tout le groupe.
async fn global_rate(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string());
    // Sonde de configuration : `cf-ray` n'est posé que par Cloudflare. On ne
    // s'en sert PAS pour décider de faire confiance à l'en-tête d'IP (un
    // attaquant atteignant l'origine en direct le poserait aussi) — uniquement
    // pour signaler une `TRUST_PROXY` incohérente avec le trafic observé.
    let via_cf = req.headers().contains_key("cf-ray");
    if via_cf {
        st.probe.seen_cf.store(true, Ordering::Relaxed);
    } else if peer.as_deref().is_some_and(is_public_ip) {
        // Les sondes internes (healthcheck, ingress) arrivent d'IP privées :
        // seule une IP publique atteste d'une origine réellement exposée.
        st.probe.seen_direct.store(true, Ordering::Relaxed);
    }
    warn_proxy_misconfig(&st);

    let forwarded = if st.trust_proxy {
        req.headers()
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(64).collect::<String>())
    } else {
        None
    };
    let ip = forwarded.or(peer).unwrap_or_else(|| "inconnu".into());
    req.extensions_mut().insert(ClientIp(ip.clone()));
    if !st.rate_ok(&format!("global:{ip}"), Duration::from_secs(60), 240) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "Trop de requêtes, réessaie plus tard" })),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::is_public_ip;

    #[test]
    fn ip_privees_et_loopback_ne_prouvent_pas_une_origine_exposee() {
        // Ingress, healthcheck, réseau Docker : ne doivent pas déclencher
        // l'alerte « origine joignable en direct ».
        for ip in [
            "127.0.0.1",
            "::1",
            "10.10.40.10",
            "172.17.0.2",
            "192.168.1.20",
            "169.254.1.1",
            "fd00::1",
            "fe80::1",
            "0.0.0.0",
            "pas-une-ip",
        ] {
            assert!(
                !is_public_ip(ip),
                "{ip} ne devrait pas compter comme public"
            );
        }
    }

    #[test]
    fn ip_publiques_comptent() {
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700::1111", "172.32.0.1"] {
            assert!(is_public_ip(ip), "{ip} devrait compter comme public");
        }
    }
}

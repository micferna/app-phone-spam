//! Handlers HTTP (axum). Parité avec la version JS.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::normalize::{is_arcep_demarchage, normalize_number};
use crate::sms::{analyze_sms, is_suspicious_sms};
use crate::state::AppState;

type Resp = (StatusCode, Json<Value>);
type ApiResult = Result<Resp, Resp>;
/// Ligne d'une demande d'adhésion : (id, nom, contact, message, créée le).
type JoinRow = (i64, String, Option<String>, Option<String>, String);

fn ok(v: Value) -> ApiResult {
    Ok((StatusCode::OK, Json(v)))
}
fn e(code: StatusCode, msg: &str) -> Resp {
    (code, Json(json!({ "error": msg })))
}

// --- petites primitives ---
fn client_ip(h: &HeaderMap) -> String {
    h.get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("inconnu")
        .to_string()
}
fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}
pub(crate) fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
fn gen_key() -> String {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).expect("OS RNG indisponible");
    hex::encode(b)
}
fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.ct_eq(b).into()
}
fn take(s: &str, n: usize) -> String {
    s.trim().chars().take(n).collect()
}
fn clean_text(s: Option<&str>, max: usize) -> Option<String> {
    let s = s?;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let trimmed: String = collapsed.chars().take(max).collect();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// --- auth ---
// Pas de verrou par IP sur les échecs (voir AppState::rate_ok) : le débit
// global + l'entropie des clés (192 bits) suffisent, et un verrou par IP
// permettrait de bloquer un membre en spoofant son IP (DoS ciblé).
async fn require_user(st: &AppState, h: &HeaderMap) -> Result<(i64, String), Resp> {
    let key = header(h, "x-api-key");
    if key.is_empty() {
        return Err(e(StatusCode::UNAUTHORIZED, "Clé API invalide"));
    }
    // Les clés sont stockées hashées (SHA-256) : une fuite de base n'expose
    // pas de jetons réutilisables. Le client envoie toujours la clé en clair.
    let row: Option<(i64, String)> = sqlx::query_as("SELECT id, name FROM users WHERE api_key = ?")
        .bind(sha256_hex(key))
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten();
    row.ok_or_else(|| e(StatusCode::UNAUTHORIZED, "Clé API invalide"))
}

async fn admin_key_valid(st: &AppState, provided: &str) -> bool {
    if provided.is_empty() {
        return false;
    }
    if let Some(env) = &st.admin_key {
        return ct_eq(provided, env);
    }
    let hash: Option<String> =
        sqlx::query_scalar("SELECT value FROM meta WHERE key = 'admin_key_hash'")
            .fetch_optional(&st.pool)
            .await
            .ok()
            .flatten();
    matches!(hash, Some(h) if ct_eq(&sha256_hex(provided), &h))
}

async fn require_admin(st: &AppState, h: &HeaderMap) -> Result<(), Resp> {
    if admin_key_valid(st, header(h, "x-admin-key")).await {
        Ok(())
    } else {
        Err(e(StatusCode::UNAUTHORIZED, "Clé admin invalide"))
    }
}

async fn reputation_map(st: &AppState) -> HashMap<String, i64> {
    if !st.rep_dirty.load(Ordering::Relaxed) {
        return st.rep.lock().unwrap().clone();
    }
    let numbers: Vec<String> = sqlx::query_scalar("SELECT DISTINCT number FROM reports")
        .fetch_all(&st.pool)
        .await
        .unwrap_or_default();
    let rep_list = {
        let idx = st.operators.read().unwrap();
        idx.reputation(&numbers)
    };
    let map: HashMap<String, i64> = rep_list.into_iter().map(|(m, _n, c)| (m, c)).collect();
    *st.rep.lock().unwrap() = map.clone();
    st.rep_dirty.store(false, Ordering::Relaxed);
    map
}

// ===================== endpoints =====================

pub async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

pub async fn status(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "ok": true, "operatorsLoaded": st.operators.read().unwrap().len() }))
}

pub async fn lookup(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(number): Path<String>,
) -> ApiResult {
    require_user(&st, &headers).await?;
    let number =
        normalize_number(&number).ok_or_else(|| e(StatusCode::BAD_REQUEST, "Numéro invalide"))?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE number = ?")
        .bind(&number)
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    let cats: Option<String> =
        sqlx::query_scalar("SELECT GROUP_CONCAT(DISTINCT category) FROM reports WHERE number = ?")
            .bind(&number)
            .fetch_one(&st.pool)
            .await
            .unwrap_or(None);
    let imported: Option<(String, Option<String>)> =
        match sqlx::query_as("SELECT source, label FROM imported_numbers WHERE number = ?")
            .bind(&number)
            .fetch_optional(&st.pool)
            .await
            .ok()
            .flatten()
        {
            Some(x) => Some(x),
            None => sqlx::query_as(
                "SELECT source, label FROM imported_prefixes WHERE ? LIKE prefix || '%'",
            )
            .bind(&number)
            .fetch_optional(&st.pool)
            .await
            .ok()
            .flatten(),
        };
    let arcep = is_arcep_demarchage(&number);
    let op = st.operators.read().unwrap().operator_for(&number);
    let rep = reputation_map(&st).await;
    let op_rep = op
        .as_ref()
        .and_then(|o| rep.get(&o.mnemo))
        .copied()
        .unwrap_or(0);

    // Détection de campagne : nb de numéros distincts de la même plage
    // (préfixe +33 + 3 chiffres) signalés dans les dernières 24 h.
    let prefix: String = number.chars().take(6).collect();
    let burst: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT number) FROM reports WHERE number LIKE ? || '%' \
         AND created_at > datetime('now','-1 day')",
    )
    .bind(&prefix)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);
    // Retour des membres sur ce numéro.
    let fb_spam: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM feedback WHERE number = ? AND was_spam = 1")
            .bind(&number)
            .fetch_one(&st.pool)
            .await
            .unwrap_or(0);
    let fb_ok: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM feedback WHERE number = ? AND was_spam = 0")
            .bind(&number)
            .fetch_one(&st.pool)
            .await
            .unwrap_or(0);

    let (score, campaign) = suspicion_score(
        count,
        arcep,
        imported.is_some(),
        op_rep,
        burst,
        fb_spam,
        fb_ok,
    );
    // Binaire fiable (blocage) inchangé ; le score ajoute la nuance.
    let suspicious = count > 0 || imported.is_some() || arcep;

    let categories: Vec<&str> = cats
        .as_deref()
        .map(|c| c.split(',').collect())
        .unwrap_or_default();
    ok(json!({
        "number": number,
        "reportCount": count,
        "categories": categories,
        "importedFrom": imported.as_ref().map(|x| &x.0),
        "importedLabel": imported.as_ref().and_then(|x| x.1.clone()),
        "arcepDemarchage": arcep,
        "operator": op.as_ref().map(|o| &o.mnemo),
        "operatorName": op.as_ref().and_then(|o| o.name.clone()),
        "operatorReportCount": op_rep,
        "suspicionScore": score,
        "campaignActive": campaign,
        "suspicious": suspicious,
    }))
}

/// Score de confiance 0-100 + campagne active. Combine signalements, ARCEP,
/// listes, réputation de l'opérateur, pic récent sur la plage (campagne),
/// et tempère si les membres ont marqué le numéro comme légitime.
fn suspicion_score(
    report_count: i64,
    arcep: bool,
    imported: bool,
    op_rep: i64,
    burst: i64,
    fb_spam: i64,
    fb_ok: i64,
) -> (i64, bool) {
    let mut s = 0i64;
    s += (report_count * 25).min(60);
    if arcep {
        s += 45;
    }
    if imported {
        s += 40;
    }
    s += (op_rep * 3).min(15);
    let campaign = burst >= 3;
    if campaign {
        s += 25;
    }
    // Feedback négatif majoritaire (plus de « pas spam » que de « spam ») :
    // on tempère fortement pour éviter les faux positifs.
    if fb_ok > fb_spam && fb_ok > 0 {
        s -= 40;
    }
    (s.clamp(0, 100), campaign)
}

pub async fn create_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let (uid, _) = require_user(&st, &headers).await?;
    if !st.rate_ok(
        &format!("report:{}", client_ip(&headers)),
        Duration::from_secs(3600),
        60,
    ) {
        return Err(e(
            StatusCode::TOO_MANY_REQUESTS,
            "Trop de requêtes, réessaie plus tard",
        ));
    }
    let number = normalize_number(body["number"].as_str().unwrap_or(""))
        .ok_or_else(|| e(StatusCode::BAD_REQUEST, "Numéro invalide"))?;
    let category = body["category"].as_str().map(|s| take(s, 32));
    let comment = body["comment"].as_str().map(|s| take(s, 500));
    sqlx::query(
        "INSERT INTO reports (user_id, number, category, comment) VALUES (?, ?, ?, ?)
         ON CONFLICT (user_id, number) DO UPDATE SET category = excluded.category, comment = excluded.comment",
    )
    .bind(uid)
    .bind(&number)
    .bind(&category)
    .bind(&comment)
    .execute(&st.pool)
    .await
    .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "erreur base"))?;
    st.rep_dirty.store(true, Ordering::Relaxed);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE number = ?")
        .bind(&number)
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    ok(json!({ "number": number, "reportCount": count }))
}

pub async fn delete_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(number): Path<String>,
) -> ApiResult {
    let (uid, _) = require_user(&st, &headers).await?;
    let number =
        normalize_number(&number).ok_or_else(|| e(StatusCode::BAD_REQUEST, "Numéro invalide"))?;
    let res = sqlx::query("DELETE FROM reports WHERE user_id = ? AND number = ?")
        .bind(uid)
        .bind(&number)
        .execute(&st.pool)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "erreur base"))?;
    if res.rows_affected() > 0 {
        st.rep_dirty.store(true, Ordering::Relaxed);
    }
    ok(json!({ "number": number, "removed": res.rows_affected() > 0 }))
}

pub async fn numbers(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_user(&st, &headers).await?;
    let community: Vec<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT number, COUNT(*) AS c, MAX(created_at) AS last FROM reports GROUP BY number",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    let imported: Vec<(String, String, Option<String>)> =
        sqlx::query_as("SELECT number, source, label FROM imported_numbers")
            .fetch_all(&st.pool)
            .await
            .unwrap_or_default();
    ok(json!({
        "community": community.iter().map(|(n, c, l)| json!({"number": n, "reportCount": c, "lastReport": l})).collect::<Vec<_>>(),
        "imported": imported.iter().map(|(n, s, l)| json!({"number": n, "source": s, "label": l})).collect::<Vec<_>>(),
    }))
}

pub async fn operators(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_user(&st, &headers).await?;
    let numbers: Vec<String> = sqlx::query_scalar("SELECT DISTINCT number FROM reports")
        .fetch_all(&st.pool)
        .await
        .unwrap_or_default();
    let rep = {
        let idx = st.operators.read().unwrap();
        idx.reputation(&numbers)
    };
    ok(json!({
        "operators": rep.iter().map(|(m, n, c)| json!({"mnemo": m, "name": n, "count": c})).collect::<Vec<_>>()
    }))
}

pub async fn check_sms(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    require_user(&st, &headers).await?;
    let sender = take(body["sender"].as_str().unwrap_or(""), 32);
    let text: String = body["text"]
        .as_str()
        .unwrap_or("")
        .chars()
        .take(1200)
        .collect();
    let number = normalize_number(&sender);

    let mut reasons: Vec<String> = Vec::new();
    let mut sender_reports = 0i64;
    let mut number_suspicious = false;
    if let Some(n) = &number {
        sender_reports = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE number = ?")
            .bind(n)
            .fetch_one(&st.pool)
            .await
            .unwrap_or(0);
        let imported: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM imported_numbers WHERE number = ?")
                .bind(n)
                .fetch_optional(&st.pool)
                .await
                .ok()
                .flatten()
                .or(sqlx::query_scalar(
                    "SELECT 1 FROM imported_prefixes WHERE ? LIKE prefix || '%'",
                )
                .bind(n)
                .fetch_optional(&st.pool)
                .await
                .ok()
                .flatten());
        let arcep = is_arcep_demarchage(n);
        if sender_reports > 0 {
            reasons.push(format!("expéditeur signalé {sender_reports} fois"));
        }
        if arcep {
            reasons.push("expéditeur en plage de démarchage (ARCEP)".into());
        }
        if imported.is_some() {
            reasons.push("expéditeur dans une liste de spam".into());
        }
        number_suspicious = sender_reports > 0 || imported.is_some() || arcep;
    }

    let analysis = analyze_sms(&text);
    reasons.extend(analysis.signals.clone());
    let suspicious = number_suspicious || is_suspicious_sms(&analysis);

    ok(json!({
        "sender": sender,
        "number": number,
        "suspicious": suspicious,
        "senderReportCount": sender_reports,
        "reasons": reasons,
        "canReport": number.is_some(),
    }))
}

// --- bootstrap (public sérieux : BOOTSTRAP_TOKEN obligatoire) ---
pub async fn bootstrap(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    if !st.rate_ok(
        &format!("bootstrap:{}", client_ip(&headers)),
        Duration::from_secs(3600),
        5,
    ) {
        return Err(e(
            StatusCode::TOO_MANY_REQUESTS,
            "Trop de requêtes, réessaie plus tard",
        ));
    }
    match &st.bootstrap_token {
        Some(tok) if ct_eq(header(&headers, "x-bootstrap-token"), tok) => {}
        Some(_) => return Err(e(StatusCode::FORBIDDEN, "Token de bootstrap invalide")),
        None => {
            return Err(e(
                StatusCode::FORBIDDEN,
                "Bootstrap désactivé : définir BOOTSTRAP_TOKEN et fournir X-Bootstrap-Token",
            ))
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    if count > 0 {
        return Err(e(StatusCode::FORBIDDEN, "Serveur déjà initialisé"));
    }
    let name = take(body["name"].as_str().unwrap_or(""), 64);
    if name.is_empty() {
        return Err(e(StatusCode::BAD_REQUEST, "Nom requis"));
    }
    let api_key = gen_key();
    sqlx::query("INSERT INTO users (name, api_key) VALUES (?, ?)")
        .bind(&name)
        .bind(sha256_hex(&api_key))
        .execute(&st.pool)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "erreur base"))?;
    let admin_key = if st.admin_key.is_none() {
        let k = gen_key();
        let _ =
            sqlx::query("INSERT OR REPLACE INTO meta (key, value) VALUES ('admin_key_hash', ?)")
                .bind(sha256_hex(&k))
                .execute(&st.pool)
                .await;
        Some(k)
    } else {
        None
    };
    ok(json!({
        "name": name,
        "apiKey": api_key,
        "adminKey": admin_key,
        "note": "Conserve précieusement adminKey : elle ne sera plus jamais affichée.",
    }))
}

// --- admin : créer un utilisateur ---
pub async fn create_user(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    require_admin(&st, &headers).await?;
    let name = take(body["name"].as_str().unwrap_or(""), 64);
    if name.is_empty() {
        return Err(e(StatusCode::BAD_REQUEST, "Nom requis"));
    }
    let api_key = gen_key();
    let res = sqlx::query("INSERT INTO users (name, api_key) VALUES (?, ?)")
        .bind(&name)
        .bind(sha256_hex(&api_key))
        .execute(&st.pool)
        .await;
    if res.is_err() {
        return Err(e(StatusCode::CONFLICT, "Ce nom existe déjà"));
    }
    ok(json!({ "name": name, "apiKey": api_key }))
}

// --- admin : lister les membres (sans les clés) ---
pub async fn list_users(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers).await?;
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT u.id, u.name, u.created_at, \
         (SELECT COUNT(*) FROM reports r WHERE r.user_id = u.id) AS c \
         FROM users u ORDER BY u.id",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    ok(json!(rows
        .iter()
        .map(|(id, name, created, c)| json!({
            "id": id, "name": name, "created_at": created, "reportCount": c
        }))
        .collect::<Vec<_>>()))
}

// --- admin : supprimer un membre + ses données (RGPD : erasure) ---
pub async fn delete_user(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    require_admin(&st, &headers).await?;
    let mut tx = st
        .pool
        .begin()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("DELETE FROM feedback WHERE user_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("DELETE FROM reports WHERE user_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let res = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    tx.commit()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    let removed = res.rows_affected() > 0;
    if removed {
        st.rep_dirty.store(true, Ordering::Relaxed);
    }
    ok(json!({ "deleted": removed }))
}

// --- admin : créer une invitation à usage unique (onboarding QR) ---
pub async fn create_invite(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers).await?;
    let token = gen_key();
    sqlx::query("INSERT INTO invites (token, expires_at) VALUES (?, datetime('now','+7 days'))")
        .bind(&token)
        .execute(&st.pool)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "token": token, "expiresInDays": 7 }))
}

// --- public : consommer une invitation → crée le membre + sa clé ---
pub async fn redeem_invite(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    if !st.rate_ok(
        &format!("invite:{}", client_ip(&headers)),
        Duration::from_secs(3600),
        10,
    ) {
        return Err(e(StatusCode::TOO_MANY_REQUESTS, "Trop de requêtes"));
    }
    let token = body["token"].as_str().unwrap_or("");
    let name = take(body["name"].as_str().unwrap_or(""), 64);
    if name.is_empty() {
        return Err(e(StatusCode::BAD_REQUEST, "Nom requis"));
    }
    // Nom unique (best-effort ; la contrainte UNIQUE de users tranche in fine).
    let mut uname = name.clone();
    let mut i = 2;
    while sqlx::query_scalar::<_, i64>("SELECT 1 FROM users WHERE name = ?")
        .bind(&uname)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        uname = format!("{name} ({i})");
        i += 1;
    }
    let api_key = gen_key();
    let mut tx = st
        .pool
        .begin()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    // Verrou atomique : la consommation de l'invitation (used 0→1) EST le
    // contrôle. Une seule requête concurrente peut basculer la ligne ; les
    // autres obtiennent 0 ligne affectée → rejetées (pas de double-usage).
    let consumed = sqlx::query(
        "UPDATE invites SET used = 1 WHERE token = ? AND used = 0 AND expires_at > datetime('now')",
    )
    .bind(token)
    .execute(&mut *tx)
    .await
    .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    if consumed.rows_affected() != 1 {
        return Err(e(StatusCode::FORBIDDEN, "Invitation invalide ou expirée"));
        // tx non commit → rollback automatique.
    }
    // Collision de nom concurrente → l'INSERT échoue, on annule tout (l'invitation
    // reste consommable puisque la transaction est annulée).
    if sqlx::query("INSERT INTO users (name, api_key) VALUES (?, ?)")
        .bind(&uname)
        .bind(sha256_hex(&api_key))
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return Err(e(StatusCode::CONFLICT, "Réessaie"));
    }
    tx.commit()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "name": uname, "apiKey": api_key }))
}

// --- alertes : campagnes de démarchage actives (l'app poll ceci) ---
pub async fn alerts(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_user(&st, &headers).await?;
    let campaigns: Vec<(String, i64)> = sqlx::query_as(
        "SELECT substr(number,1,6) AS pfx, COUNT(DISTINCT number) AS c FROM reports \
         WHERE created_at > datetime('now','-1 day') GROUP BY pfx HAVING c >= 3 ORDER BY c DESC LIMIT 20",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    ok(json!({
        "campaigns": campaigns.iter().map(|(p, c)| json!({"prefix": p, "count": c})).collect::<Vec<_>>()
    }))
}

// --- admin : export de la base (dump SQLite propre, pour backup off-site) ---
pub async fn export_db(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if require_admin(&st, &headers).await.is_err() {
        return (StatusCode::UNAUTHORIZED, "Clé admin invalide").into_response();
    }
    match crate::backups::snapshot_bytes(&st.pool).await {
        Ok(bytes) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                (
                    "content-disposition",
                    "attachment; filename=\"antispam-backup.db\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "export impossible").into_response(),
    }
}

// --- admin : import en masse ---
pub async fn bulk_import(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    require_admin(&st, &headers).await?;
    let list = body["numbers"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return Err(e(StatusCode::BAD_REQUEST, "numbers[] requis"));
    }
    if list.len() > 5000 {
        return Err(e(StatusCode::BAD_REQUEST, "max 5000 par lot"));
    }
    let label = clean_text(body["label"].as_str(), 64).unwrap_or_else(|| "Import manuel".into());
    let mut added = 0;
    let mut skipped = 0;
    let mut tx = st
        .pool
        .begin()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    for raw in &list {
        match raw.as_str().and_then(normalize_number) {
            Some(n) => {
                let _ = sqlx::query(
                    "INSERT OR REPLACE INTO imported_numbers (number, source, label) VALUES (?, 'import-admin', ?)",
                )
                .bind(&n)
                .bind(&label)
                .execute(&mut *tx)
                .await;
                added += 1;
            }
            None => skipped += 1,
        }
    }
    tx.commit()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "added": added, "skipped": skipped }))
}

// --- admin : forcer la mise à jour des listes ---
pub async fn update_lists(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers).await?;
    let results = crate::lists::update_lists(&st.pool).await;
    ok(json!({
        "results": results.iter().map(|r| json!({"source": r.source, "prefixes": r.prefixes, "numbers": r.numbers, "error": r.error})).collect::<Vec<_>>()
    }))
}

// --- demandes d'adhésion (public, formulaire HTML) ---
pub async fn join_request(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !st.rate_ok(
        &format!("join:{}", client_ip(&headers)),
        Duration::from_secs(3600),
        5,
    ) {
        return confirmation(
            "Trop de demandes",
            "Réessaie plus tard.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let name = clean_text(form.get("name").map(String::as_str), 64);
    let contact = clean_text(form.get("contact").map(String::as_str), 128);
    let message = clean_text(form.get("message").map(String::as_str), 280);
    let Some(name) = name else {
        return confirmation(
            "Nom manquant",
            "Indique au moins un prénom ou pseudo.",
            StatusCode::BAD_REQUEST,
        );
    };
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM join_requests WHERE status = 'pending'")
            .fetch_one(&st.pool)
            .await
            .unwrap_or(0);
    if pending >= 200 {
        return confirmation(
            "File pleine",
            "Trop de demandes en attente, réessaie plus tard.",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let _ =
        sqlx::query("INSERT INTO join_requests (name, contact, message, ip) VALUES (?, ?, ?, ?)")
            .bind(&name)
            .bind(&contact)
            .bind(&message)
            .bind(client_ip(&headers))
            .execute(&st.pool)
            .await;
    confirmation(
        "Demande envoyée ✅",
        &format!(
            "Merci {} ! L'administrateur du groupe va examiner ta demande.",
            escape_html(&name)
        ),
        StatusCode::CREATED,
    )
}

pub async fn list_join_requests(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers).await?;
    let rows: Vec<JoinRow> = sqlx::query_as(
        "SELECT id, name, contact, message, created_at FROM join_requests WHERE status = 'pending' ORDER BY created_at",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    ok(json!(rows
        .iter()
        .map(|(id, name, contact, message, created)| json!({
            "id": id, "name": name, "contact": contact, "message": message, "created_at": created
        }))
        .collect::<Vec<_>>()))
}

pub async fn approve_join(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    require_admin(&st, &headers).await?;
    let base: Option<String> =
        sqlx::query_scalar("SELECT name FROM join_requests WHERE id = ? AND status = 'pending'")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .ok()
            .flatten();
    let Some(base) = base else {
        return Err(e(StatusCode::NOT_FOUND, "Demande introuvable"));
    };
    let mut name = base.clone();
    let mut i = 2;
    while sqlx::query_scalar::<_, i64>("SELECT 1 FROM users WHERE name = ?")
        .bind(&name)
        .fetch_optional(&st.pool)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        name = format!("{base} ({i})");
        i += 1;
    }
    let api_key = gen_key();
    let mut tx = st
        .pool
        .begin()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("INSERT INTO users (name, api_key) VALUES (?, ?)")
        .bind(&name)
        .bind(sha256_hex(&api_key))
        .execute(&mut *tx)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    sqlx::query("UPDATE join_requests SET status = 'approved' WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    tx.commit()
        .await
        .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "name": name, "apiKey": api_key }))
}

pub async fn reject_join(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult {
    require_admin(&st, &headers).await?;
    let res = sqlx::query(
        "UPDATE join_requests SET status = 'rejected' WHERE id = ? AND status = 'pending'",
    )
    .bind(id)
    .execute(&st.pool)
    .await
    .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "rejected": res.rows_affected() > 0 }))
}

// --- retour utilisateur : était-ce vraiment du spam ? ---
pub async fn feedback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult {
    let (uid, _) = require_user(&st, &headers).await?;
    let number = normalize_number(body["number"].as_str().unwrap_or(""))
        .ok_or_else(|| e(StatusCode::BAD_REQUEST, "Numéro invalide"))?;
    let was_spam: i64 = if body["wasSpam"].as_bool().unwrap_or(false) {
        1
    } else {
        0
    };
    sqlx::query(
        "INSERT INTO feedback (user_id, number, was_spam) VALUES (?, ?, ?)
         ON CONFLICT (user_id, number) DO UPDATE SET was_spam = excluded.was_spam",
    )
    .bind(uid)
    .bind(&number)
    .bind(was_spam)
    .execute(&st.pool)
    .await
    .map_err(|_| e(StatusCode::INTERNAL_SERVER_ERROR, "db"))?;
    ok(json!({ "number": number, "recorded": true }))
}

// --- fédération : flux public des numéros confirmés (≥2 membres distincts),
// anonymisé (numéro + nb de signalements), pour qu'un autre serveur s'y abonne.
pub async fn federation_feed(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    if !st.rate_ok(
        &format!("fedfeed:{}", client_ip(&headers)),
        Duration::from_secs(60),
        30,
    ) {
        return Err(e(StatusCode::TOO_MANY_REQUESTS, "Trop de requêtes"));
    }
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT number, COUNT(DISTINCT user_id) AS c FROM reports \
         GROUP BY number HAVING c >= 2 ORDER BY c DESC LIMIT 5000",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    ok(json!({
        "numbers": rows.iter().map(|(n, c)| json!({"number": n, "reports": c})).collect::<Vec<_>>()
    }))
}

// --- stats (admin) : alimente le dashboard ---
pub async fn stats(State(st): State<AppState>, headers: HeaderMap) -> ApiResult {
    require_admin(&st, &headers).await?;
    ok(json!(collect_stats(&st).await))
}

async fn collect_stats(st: &AppState) -> Value {
    let scalar = |q: &'static str| {
        let pool = st.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(q)
                .fetch_one(&pool)
                .await
                .unwrap_or(0)
        }
    };
    let members = scalar("SELECT COUNT(*) FROM users").await;
    let reported = scalar("SELECT COUNT(DISTINCT number) FROM reports").await;
    let total_reports = scalar("SELECT COUNT(*) FROM reports").await;
    let imported = scalar("SELECT COUNT(*) FROM imported_numbers").await;
    let prefixes = scalar("SELECT COUNT(*) FROM imported_prefixes").await;
    let pending = scalar("SELECT COUNT(*) FROM join_requests WHERE status = 'pending'").await;
    let last24 =
        scalar("SELECT COUNT(*) FROM reports WHERE created_at > datetime('now','-1 day')").await;
    let fb_spam = scalar("SELECT COUNT(*) FROM feedback WHERE was_spam = 1").await;
    let fb_ok = scalar("SELECT COUNT(*) FROM feedback WHERE was_spam = 0").await;

    let all_numbers: Vec<String> = sqlx::query_scalar("SELECT DISTINCT number FROM reports")
        .fetch_all(&st.pool)
        .await
        .unwrap_or_default();
    let top_ops = {
        let idx = st.operators.read().unwrap();
        idx.reputation(&all_numbers)
    };
    let campaigns: Vec<(String, i64)> = sqlx::query_as(
        "SELECT substr(number,1,6) AS pfx, COUNT(DISTINCT number) AS c FROM reports \
         WHERE created_at > datetime('now','-1 day') GROUP BY pfx HAVING c >= 3 ORDER BY c DESC",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();
    let recent: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT number, COUNT(*) AS c, MAX(created_at) AS last FROM reports \
         GROUP BY number ORDER BY last DESC LIMIT 15",
    )
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();

    json!({
        "members": members,
        "reportedNumbers": reported,
        "totalReports": total_reports,
        "importedNumbers": imported,
        "importedPrefixes": prefixes,
        "pendingJoinRequests": pending,
        "reportsLast24h": last24,
        "feedbackSpam": fb_spam,
        "feedbackLegit": fb_ok,
        "topOperators": top_ops.iter().take(10).map(|(m,n,c)| json!({"mnemo":m,"name":n,"count":c})).collect::<Vec<_>>(),
        "activeCampaigns": campaigns.iter().map(|(p,c)| json!({"prefix":p,"count":c})).collect::<Vec<_>>(),
        "recentReports": recent.iter().map(|(n,c,l)| json!({"number":n,"reportCount":c,"lastReport":l})).collect::<Vec<_>>(),
    })
}

// --- dashboard admin (HTML) ---
// Auth : la clé n'est saisie qu'à la connexion (POST). On émet alors un
// cookie de session aléatoire (HttpOnly/Secure/SameSite=Strict) ; le
// dashboard et son rafraîchissement s'appuient sur ce cookie. La clé admin
// n'apparaît donc JAMAIS dans le HTML rendu.
const ADMIN_SESSION_TTL: u64 = 8 * 3600; // 8 h

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_admin_session(st: &AppState) -> String {
    let token = gen_key(); // 192 bits
    let now = now_secs();
    let mut m = st.sessions.lock().unwrap();
    m.retain(|_, exp| *exp > now); // purge des sessions expirées
    m.insert(token.clone(), now + ADMIN_SESSION_TTL);
    token
}

fn cookie_token(h: &HeaderMap) -> Option<String> {
    let raw = h.get("cookie")?.to_str().ok()?;
    raw.split(';').find_map(|part| {
        part.trim()
            .strip_prefix("admin_session=")
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    })
}

fn admin_session_ok(st: &AppState, h: &HeaderMap) -> bool {
    let Some(tok) = cookie_token(h) else {
        return false;
    };
    let now = now_secs();
    let mut m = st.sessions.lock().unwrap();
    match m.get(&tok) {
        Some(exp) if *exp > now => true,
        Some(_) => {
            m.remove(&tok);
            false
        }
        None => false,
    }
}

fn set_cookie(resp: &mut Response, value: &str) {
    if let Ok(hv) = axum::http::HeaderValue::from_str(value) {
        resp.headers_mut()
            .append(axum::http::header::SET_COOKIE, hv);
    }
}

pub async fn admin_login(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if admin_session_ok(&st, &headers) {
        let s = collect_stats(&st).await;
        return Html(crate::pages::admin_dashboard_page(&s)).into_response();
    }
    Html(crate::pages::admin_login_page(false)).into_response()
}

pub async fn admin_dashboard(
    State(st): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let key = form.get("key").map(String::as_str).unwrap_or("");
    if !admin_key_valid(&st, key).await {
        return (
            StatusCode::UNAUTHORIZED,
            Html(crate::pages::admin_login_page(true)),
        )
            .into_response();
    }
    let token = new_admin_session(&st);
    let s = collect_stats(&st).await;
    let mut resp = Html(crate::pages::admin_dashboard_page(&s)).into_response();
    set_cookie(
        &mut resp,
        &format!(
            "admin_session={token}; Max-Age={ADMIN_SESSION_TTL}; Path=/admin; \
             HttpOnly; Secure; SameSite=Strict"
        ),
    );
    resp
}

pub async fn admin_logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(tok) = cookie_token(&headers) {
        st.sessions.lock().unwrap().remove(&tok);
    }
    let mut resp = Html(crate::pages::admin_login_page(false)).into_response();
    set_cookie(
        &mut resp,
        "admin_session=; Max-Age=0; Path=/admin; HttpOnly; Secure; SameSite=Strict",
    );
    resp
}

// --- page d'accueil ---
pub async fn landing(State(st): State<AppState>) -> Html<String> {
    let numbers: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT number) FROM reports")
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    let prefixes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM imported_prefixes")
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&st.pool)
        .await
        .unwrap_or(0);
    Html(crate::pages::landing_page(numbers, prefixes, users))
}

fn confirmation(title: &str, body_html: &str, code: StatusCode) -> Response {
    (
        code,
        Html(crate::pages::confirmation_page(title, body_html)),
    )
        .into_response()
}

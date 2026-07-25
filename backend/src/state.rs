//! État partagé de l'application + limitation de débit en mémoire.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use sqlx::SqlitePool;

use crate::operators::OperatorIndex;

pub struct Bucket {
    pub count: u32,
    pub reset: Instant,
}

/// IP client retenue pour la limitation de débit, résolue UNE fois par le
/// middleware et déposée dans les extensions de la requête. Les handlers
/// lisent cette valeur et jamais un en-tête : `CF-Connecting-IP` est fourni
/// par le client et ne vaut que derrière un proxy qui le réécrit.
#[derive(Clone)]
pub struct ClientIp(pub String);

const MAX_BUCKETS: usize = 50_000;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub admin_key: Option<String>,
    pub bootstrap_token: Option<String>,
    pub operators: Arc<RwLock<OperatorIndex>>,
    pub buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Cache de la réputation par opérateur (mnémo -> nb de numéros signalés).
    pub rep: Arc<Mutex<HashMap<String, i64>>>,
    pub rep_dirty: Arc<AtomicBool>,
    /// Serveurs pairs dont on importe le flux (fédération), via FEDERATION_PEERS.
    pub federation_peers: Vec<String>,
    /// Dossier des sauvegardes quotidiennes.
    pub backup_dir: String,
    /// Seuil de score (0-100) au-delà duquel un numéro est jugé suspect même
    /// sans signalement direct ni présence en liste. 0 = clause de score
    /// désactivée (seule la campagne active joue). Réglable via
    /// `BLOCK_SCORE_THRESHOLD` (défaut 70).
    pub block_score_threshold: i64,
    /// Sessions admin actives : token de session -> expiration (epoch secondes).
    /// En mémoire : une redéploiement invalide les sessions (l'admin se
    /// reconnecte). Évite d'embarquer la clé admin dans le HTML du dashboard.
    pub sessions: Arc<Mutex<HashMap<String, u64>>>,
    /// `true` seulement si le serveur est DERRIÈRE un proxy de confiance qui
    /// réécrit `CF-Connecting-IP` (Cloudflare le fait). Réglable via
    /// `TRUST_PROXY=1`. Par défaut `false` : on utilise l'IP réelle du socket,
    /// sinon n'importe quel client se donnerait une IP au hasard à chaque
    /// requête et annulerait tous les quotas.
    pub trust_proxy: bool,
}

impl AppState {
    /// Renvoie `true` si la requête est autorisée (sous le quota). Map bornée :
    /// un flood d'IP distinctes ne peut pas faire enfler la mémoire.
    ///
    /// Note sécurité : la clé de débit dérive de l'IP résolue par le
    /// middleware (socket, ou `CF-Connecting-IP` si `TRUST_PROXY=1`). On NE
    /// verrouille PAS d'IP sur les échecs d'auth (un attaquant pourrait
    /// spoofer l'IP d'un membre légitime pour le bloquer = DoS ciblé). La
    /// résistance au brute-force repose sur l'entropie des secrets (clés et
    /// token = 192 bits, infaisables à deviner) + ce plafond global.
    pub fn rate_ok(&self, key: &str, window: Duration, max: u32) -> bool {
        let mut map = self.buckets.lock().unwrap();
        bump(&mut map, key, window, max)
    }
}

fn bump(map: &mut HashMap<String, Bucket>, key: &str, window: Duration, max: u32) -> bool {
    let now = Instant::now();
    let entry = map.get(key);
    let expired = matches!(entry, Some(b) if b.reset < now);
    if entry.is_none() || expired {
        if entry.is_none() && map.len() >= MAX_BUCKETS {
            map.retain(|_, b| b.reset >= now);
            if map.len() >= MAX_BUCKETS {
                return false; // fail-closed borné
            }
        }
        map.insert(
            key.to_string(),
            Bucket {
                count: 1,
                reset: now + window,
            },
        );
        return 1 <= max;
    }
    let b = map.get_mut(key).unwrap();
    b.count += 1;
    b.count <= max
}

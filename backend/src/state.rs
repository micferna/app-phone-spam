//! État partagé de l'application + limitation de débit en mémoire.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
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

/// Observation du trafic réel pour détecter une `TRUST_PROXY` mal réglée.
///
/// Le réglage doit correspondre à la topologie de déploiement, et les deux
/// erreurs possibles sont silencieuses — d'où cette sonde plutôt qu'une
/// consigne dans un README que personne ne relit au moment du déploiement.
#[derive(Default)]
pub struct ProxyProbe {
    /// Une requête portant `cf-ray` a été vue : seul Cloudflare pose cet
    /// en-tête, on est donc bien derrière lui.
    pub seen_cf: AtomicBool,
    /// Une requête est arrivée d'une IP publique SANS `cf-ray` : l'origine est
    /// joignable en direct.
    pub seen_direct: AtomicBool,
    /// Dernier avertissement journalisé (epoch s) — sinon on inonderait les
    /// logs à chaque requête.
    pub last_warn: AtomicU64,
}

/// Confronte le réglage `TRUST_PROXY` au trafic réellement observé.
/// `None` = configuration cohérente.
pub fn proxy_misconfig_for(
    trust_proxy: bool,
    seen_cf: bool,
    seen_direct: bool,
) -> Option<&'static str> {
    if !trust_proxy && seen_cf {
        // Le socket voit l'edge Cloudflare, pas le client : tous les membres
        // se partagent alors le même quota et se limitent mutuellement.
        return Some(
            "TRUST_PROXY n'est pas activé alors que le trafic arrive via Cloudflare : \
             tous les clients partagent le quota de l'IP de l'edge. Poser TRUST_PROXY=1.",
        );
    }
    if trust_proxy && seen_direct {
        // Pire cas : on fait confiance à un en-tête que plus personne ne
        // réécrit, donc trivialement falsifiable.
        return Some(
            "TRUST_PROXY=1 mais des requêtes arrivent en direct (sans cf-ray) : \
             CF-Connecting-IP est falsifiable et les quotas contournables. \
             Filtrer l'origine aux IP du proxy, ou retirer TRUST_PROXY.",
        );
    }
    None
}

impl AppState {
    /// Décrit une incohérence entre `TRUST_PROXY` et le trafic observé.
    pub fn proxy_misconfig(&self) -> Option<&'static str> {
        use std::sync::atomic::Ordering::Relaxed;
        proxy_misconfig_for(
            self.trust_proxy,
            self.probe.seen_cf.load(Relaxed),
            self.probe.seen_direct.load(Relaxed),
        )
    }
}

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
    /// Sonde de cohérence de `trust_proxy` face au trafic réel.
    pub probe: Arc<ProxyProbe>,
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

#[cfg(test)]
mod tests {
    use super::proxy_misconfig_for;

    #[test]
    fn configurations_coherentes_ne_signalent_rien() {
        // Origine exposée en direct, sans proxy : correct.
        assert!(proxy_misconfig_for(false, false, true).is_none());
        // Derrière Cloudflare, en lui faisant confiance : correct.
        assert!(proxy_misconfig_for(true, true, false).is_none());
        // Rien d'observé encore (démarrage) : on ne crie pas.
        assert!(proxy_misconfig_for(false, false, false).is_none());
        assert!(proxy_misconfig_for(true, false, false).is_none());
    }

    #[test]
    fn derriere_cloudflare_sans_trust_proxy() {
        // Tous les membres partageraient le quota de l'edge.
        let msg = proxy_misconfig_for(false, true, false).expect("doit alerter");
        assert!(msg.contains("TRUST_PROXY=1"));
    }

    #[test]
    fn trust_proxy_sur_une_origine_exposee() {
        // Le cas dangereux : on croit un en-tête que personne ne réécrit.
        let msg = proxy_misconfig_for(true, false, true).expect("doit alerter");
        assert!(msg.contains("falsifiable"));
    }

    #[test]
    fn trafic_mixte_priorise_le_quota_partage() {
        // Les deux signaux présents : sans TRUST_PROXY, la limitation est déjà
        // dégradée pour tout le monde — c'est ça qu'on remonte d'abord.
        let msg = proxy_misconfig_for(false, true, true).expect("doit alerter");
        assert!(msg.contains("edge"));
    }
}

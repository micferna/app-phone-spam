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

const MAX_BUCKETS: usize = 50_000;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub admin_key: Option<String>,
    pub bootstrap_token: Option<String>,
    pub operators: Arc<RwLock<OperatorIndex>>,
    pub buckets: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Compteur d'échecs d'auth par IP (anti-bruteforce).
    pub auth_fails: Arc<Mutex<HashMap<String, Bucket>>>,
    /// Cache de la réputation par opérateur (mnémo -> nb de numéros signalés).
    pub rep: Arc<Mutex<HashMap<String, i64>>>,
    pub rep_dirty: Arc<AtomicBool>,
}

impl AppState {
    /// Renvoie `true` si la requête est autorisée (sous le quota). Map bornée :
    /// un flood d'IP distinctes ne peut pas faire enfler la mémoire.
    pub fn rate_ok(&self, key: &str, window: Duration, max: u32) -> bool {
        let mut map = self.buckets.lock().unwrap();
        bump(&mut map, key, window, max)
    }

    pub fn note_auth_fail(&self, ip: &str) {
        let mut map = self.auth_fails.lock().unwrap();
        bump(&mut map, ip, Duration::from_secs(600), 20);
    }

    pub fn too_many_auth_fails(&self, ip: &str) -> bool {
        let map = self.auth_fails.lock().unwrap();
        matches!(map.get(ip), Some(b) if b.reset > Instant::now() && b.count >= 20)
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

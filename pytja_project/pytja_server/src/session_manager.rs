use redis::AsyncCommands; // Import für async Redis calls
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use pytja_core::models::Role;

const SESSION_TTL: usize = 3600; // 1 Stunde
const ROLE_CACHE_TTL: usize = 300; // 5 Minuten

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub username: String,
    pub ip_address: String,
    pub role: String,
    pub login_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

pub struct SessionManager {
    client: redis::Client,
}

impl SessionManager {
    pub async fn new(redis_url: &str) -> Result<Self, String> {
        let client = redis::Client::open(redis_url).map_err(|e| e.to_string())?;
        // Test connection
        let mut con = client.get_async_connection().await.map_err(|e| format!("Redis connection failed: {}", e))?;
        let _: () = redis::cmd("PING").query_async(&mut con).await.map_err(|e| e.to_string())?;

        Ok(Self { client })
    }

    // --- SESSION MANAGEMENT ---

    pub async fn register_session(&self, username: &str, role: &str, ip: &str) -> Result<String, String> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = ActiveSession {
            session_id: session_id.clone(),
            username: username.to_string(),
            ip_address: ip.to_string(),
            role: role.to_string(),
            login_time: now,
            last_activity: now,
        };

        let json = serde_json::to_string(&session).map_err(|e| e.to_string())?;
        let key = format!("session:{}", session_id);

        let mut con = self.client.get_async_connection().await.map_err(|e| e.to_string())?;
        // FIX: Cast zu u64
        let _: () = con.set_ex(key, json, SESSION_TTL as u64).await.map_err(|e| e.to_string())?;

        tracing::info!("New Redis session: {} ({})", username, session_id);
        Ok(session_id)
    }

    pub async fn is_valid(&self, session_id: &str) -> bool {
        let key = format!("session:{}", session_id);
        if let Ok(mut con) = self.client.get_async_connection().await {
            // Check Existenz UND aktualisiere TTL (Heartbeat)
            let exists: bool = con.exists(&key).await.unwrap_or(false);
            if exists {
                // FIX: Cast zu i64 (Redis expire nutzt oft i64 oder usize, je nach crate version, hier i64 sicher)
                let _: () = con.expire(&key, SESSION_TTL as i64).await.unwrap_or(());
                return true;
            }
        }
        false
    }

    pub async fn remove_session(&self, session_id: &str) {
        let key = format!("session:{}", session_id);
        if let Ok(mut con) = self.client.get_async_connection().await {
            let _: () = con.del(&key).await.unwrap_or(());
        }
    }

    // ACHTUNG: SCAN ist teuer, nur für Admin-Zwecke!
    pub async fn get_all_sessions(&self) -> Vec<ActiveSession> {
        let mut sessions = Vec::new();
        if let Ok(mut con) = self.client.get_async_connection().await {
            // FIX: Borrow Checker Logic
            // Wir können 'con' nicht für 'scan_match' UND 'get' gleichzeitig nutzen.
            // 1. Keys sammeln
            let mut keys: Vec<String> = Vec::new();
            let mut iter: redis::AsyncIter<String> = con.scan_match("session:*").await.unwrap();

            while let Some(key) = iter.next_item().await {
                keys.push(key);
            }
            drop(iter); // Iterator freigeben, damit 'con' wieder frei ist

            // 2. Values holen
            for key in keys {
                if let Ok(json) = con.get::<_, String>(&key).await {
                    if let Ok(sess) = serde_json::from_str::<ActiveSession>(&json) {
                        sessions.push(sess);
                    }
                }
            }
        }
        sessions
    }

    // --- PERMISSION CACHING (NEU) ---

    pub async fn get_cached_role(&self, role_name: &str) -> Option<Role> {
        let key = format!("cache:role:{}", role_name);
        if let Ok(mut con) = self.client.get_async_connection().await {
            if let Ok(json) = con.get::<_, String>(key).await {
                return serde_json::from_str::<Role>(&json).ok();
            }
        }
        None
    }

    pub async fn cache_role(&self, role: &Role) {
        let key = format!("cache:role:{}", role.name);
        if let Ok(json) = serde_json::to_string(role) {
            if let Ok(mut con) = self.client.get_async_connection().await {
                // FIX: Cast zu u64
                let _: () = con.set_ex(key, json, ROLE_CACHE_TTL as u64).await.unwrap_or(());
            }
        }
    }
}
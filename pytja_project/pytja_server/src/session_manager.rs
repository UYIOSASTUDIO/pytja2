use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;
use pytja_core::models::Role;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ActiveSession {
    pub session_id: String,
    pub username: String,
    pub role: String,
    pub ip_address: String,
    pub login_time: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UploadState {
    pub owner: String,
    pub path: String,
    pub total_size_hint: u64,
    pub bytes_received: u64,
    pub started_at: i64,
    pub status: String,
}

pub struct SessionManager {
    client: redis::Client,
    role_cache: Arc<Mutex<std::collections::HashMap<String, Role>>>,
}

impl SessionManager {
    pub async fn new(redis_url: &str) -> Result<Self, pytja_core::PytjaError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| pytja_core::PytjaError::System(format!("Redis Init Error: {}", e)))?;

        Ok(Self {
            client,
            role_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    // --- SESSION LOGIC ---

    pub async fn register_session(&self, username: &str, role: &str, ip: &str) -> Result<String, redis::RedisError> {
        let mut conn = self.client.get_async_connection().await?;
        let session_id = uuid::Uuid::new_v4().to_string();
        let key = format!("session:{}", session_id);

        let session = ActiveSession {
            session_id: session_id.clone(),
            username: username.to_string(),
            role: role.to_string(),
            ip_address: ip.to_string(),
            login_time: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&session).unwrap();

        let _: () = redis::pipe()
            .atomic()
            .set(&key, json)
            .expire(&key, 3600)
            .sadd(format!("user_sessions:{}", username), &session_id)
            .query_async(&mut conn).await?;

        Ok(session_id)
    }

    pub async fn is_valid(&self, session_id: &str) -> bool {
        let mut conn = match self.client.get_async_connection().await {
            Ok(c) => c,
            Err(_) => return false,
        };
        let key = format!("session:{}", session_id);
        let exists: bool = conn.exists(&key).await.unwrap_or(false);
        if exists {
            let _: redis::RedisResult<()> = conn.expire(&key, 3600).await;
        }
        exists
    }

    pub async fn remove_session(&self, session_id: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = format!("session:{}", session_id);
            let _: redis::RedisResult<()> = conn.del(&key).await;
        }
    }

    pub async fn clear_user_sessions(&self, username: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let set_key = format!("user_sessions:{}", username);
            let sessions: Vec<String> = conn.smembers(&set_key).await.unwrap_or_default();
            for sid in sessions {
                let _: redis::RedisResult<()> = conn.del(format!("session:{}", sid)).await;
            }
            let _: redis::RedisResult<()> = conn.del(&set_key).await;
        }
    }

    pub async fn get_all_sessions(&self) -> Vec<ActiveSession> {
        let mut sessions = Vec::new();
        if let Ok(mut conn) = self.client.get_async_connection().await {
            if let Ok(keys) = conn.keys::<_, Vec<String>>("session:*").await {
                for key in keys {
                    if let Ok(json) = conn.get::<_, String>(&key).await {
                        if let Ok(sess) = serde_json::from_str::<ActiveSession>(&json) {
                            sessions.push(sess);
                        }
                    }
                }
            }
        }
        sessions
    }

    pub async fn update_session_role(&self, username: &str, new_role: &str) {
        let mut cache = self.role_cache.lock().await;
        cache.remove(new_role);
        self.clear_user_sessions(username).await;
    }

    pub async fn get_cached_role(&self, role_name: &str) -> Option<Role> {
        let cache = self.role_cache.lock().await;
        cache.get(role_name).cloned()
    }

    pub async fn cache_role(&self, role: &Role) {
        let mut cache = self.role_cache.lock().await;
        cache.insert(role.name.clone(), role.clone());
    }

    // --- UPLOAD TRACKING ---

    fn get_upload_key(owner: &str, path: &str) -> String {
        use base64::{Engine as _, engine::general_purpose};
        let path_b64 = general_purpose::STANDARD.encode(path);
        format!("upload:{}:{}", owner, path_b64)
    }

    pub async fn init_upload(&self, owner: &str, path: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = Self::get_upload_key(owner, path);
            let state = UploadState {
                owner: owner.to_string(), path: path.to_string(), total_size_hint: 0,
                bytes_received: 0, started_at: chrono::Utc::now().timestamp(), status: "uploading".to_string(),
            };
            let json = serde_json::to_string(&state).unwrap_or_default();
            let _: redis::RedisResult<()> = conn.set_ex(&key, json, 86400).await;
        }
    }

    pub async fn update_upload_progress(&self, owner: &str, path: &str, bytes_added: usize) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = Self::get_upload_key(owner, path);
            if let Ok(json) = conn.get::<_, String>(&key).await {
                if let Ok(mut state) = serde_json::from_str::<UploadState>(&json) {
                    state.bytes_received += bytes_added as u64;
                    let new_json = serde_json::to_string(&state).unwrap();
                    let _: redis::RedisResult<()> = conn.set_ex(&key, new_json, 86400).await;
                }
            }
        }
    }

    pub async fn complete_upload(&self, owner: &str, path: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = Self::get_upload_key(owner, path);
            let _: redis::RedisResult<()> = conn.del(&key).await;
        }
    }

    // --- NEU: DISTRIBUTED FILE LOCKING (Enterprise Feature) ---

    pub async fn try_lock_file(&self, path: &str, owner: &str) -> bool {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            // Wir nutzen Base64 für den Pfad im Key, um Probleme mit Sonderzeichen zu vermeiden
            use base64::{Engine as _, engine::general_purpose};
            let path_b64 = general_purpose::STANDARD.encode(path);
            let key = format!("lock:file:{}", path_b64);

            // SET NX PX: Setze Key nur, wenn er nicht existiert (NX), mit 30s TTL (PX)
            // Das ist der Standard "Distributed Lock" Pattern in Redis.
            let result: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg(owner) // Value ist der Owner, damit nur er unlocken kann
                .arg("NX")
                .arg("PX")
                .arg(30000) // 30 Sekunden Auto-Release bei Absturz
                .query_async(&mut conn).await.unwrap_or(None);

            return result.is_some(); // Wenn "OK" zurückkommt, haben wir den Lock
        }
        false // Fail-Closed: Wenn Redis weg ist, keine Schreibzugriffe erlauben
    }

    pub async fn unlock_file(&self, path: &str, owner: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            use base64::{Engine as _, engine::general_purpose};
            let path_b64 = general_purpose::STANDARD.encode(path);
            let key = format!("lock:file:{}", path_b64);

            // Lua Script für atomares "Check Owner & Delete"
            let script = redis::Script::new(r"
                if redis.call('get', KEYS[1]) == ARGV[1] then
                    return redis.call('del', KEYS[1])
                else
                    return 0
                end
            ");

            let _: redis::RedisResult<i32> = script.key(&key).arg(owner).invoke_async(&mut conn).await;
        }
    }

    // --- QUOTA CACHING (Enterprise Performance) ---

    pub async fn get_cached_quota(&self, username: &str) -> Option<u64> {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = format!("quota:{}", username);
            return conn.get(key).await.ok();
        }
        None
    }

    pub async fn set_cached_quota(&self, username: &str, bytes: u64) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = format!("quota:{}", username);
            // 3600 Sekunden (1h) TTL sorgt für den automatischen Sync mit der DB
            let _: redis::RedisResult<()> = conn.set_ex(key, bytes, 3600).await;
        }
    }

    pub async fn update_quota(&self, username: &str, delta: i64) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = format!("quota:{}", username);
            // Wir updaten nur, wenn der Key existiert.
            // Falls nicht, wird er beim nächsten Read eh sauber aus der DB geladen.
            if let Ok(true) = conn.exists::<_, bool>(&key).await {
                let _: redis::RedisResult<()> = conn.incr(&key, delta).await;
            }
        }
    }

    pub async fn invalidate_quota(&self, username: &str) {
        if let Ok(mut conn) = self.client.get_async_connection().await {
            let key = format!("quota:{}", username);
            let _: redis::RedisResult<()> = conn.del(key).await;
        }
    }
}
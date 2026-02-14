use std::sync::Arc;
use dashmap::DashMap;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub username: String,
    pub ip_address: String,
    pub role_level: i32,
    pub login_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

pub struct SessionManager {
    // DashMap ist perfekt für parallelen Zugriff (besser als RwLock<HashMap>)
    sessions: Arc<DashMap<String, ActiveSession>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub fn register_session(&self, username: &str, role_level: i32, ip: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = ActiveSession {
            session_id: session_id.clone(),
            username: username.to_string(),
            ip_address: ip.to_string(),
            role_level,
            login_time: now,
            last_activity: now,
        };

        self.sessions.insert(session_id.clone(), session);
        tracing::info!("New session started: {} ({})", username, session_id);
        session_id
    }

    pub fn update_activity(&self, session_id: &str) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.last_activity = Utc::now();
        }
    }

    pub fn remove_session(&self, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            tracing::info!("Session terminated: {}", session_id);
        }
    }

    pub fn get_all_sessions(&self) -> Vec<ActiveSession> {
        self.sessions.iter().map(|entry| entry.value().clone()).collect()
    }

    // Prüft, ob eine Session noch gültig ist (für Kicks)
    pub fn is_valid(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }
}
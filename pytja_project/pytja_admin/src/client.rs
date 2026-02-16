use pytja_proto::pytja_service_client::PytjaServiceClient;
use tonic::transport::Channel;
use tonic::Request;
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::path::Path;

pub struct AdminClient {
    pub client: PytjaServiceClient<Channel>,
    pub token: String,
    pub username: String,
}

impl AdminClient {
    pub async fn connect(url: String) -> anyhow::Result<Self> {
        let client = PytjaServiceClient::connect(url).await?;
        Ok(Self {
            client,
            token: String::new(),
            username: String::new()
        })
    }

    /// Liest eine Identitätsdatei und führt den Login-Handshake durch
    pub async fn login_with_identity(&mut self, identity_path: &str) -> anyhow::Result<bool> {
        // 1. Identität laden
        let content = fs::read_to_string(identity_path)
            .map_err(|_| anyhow::anyhow!("Could not read identity file"))?;

        let lines: Vec<&str> = content.lines().collect();
        let mut username = "";
        let mut priv_key_b64 = "";

        for line in lines {
            if line.starts_with("USER:") { username = line.strip_prefix("USER:").unwrap(); }
            if line.starts_with("PRIV:") { priv_key_b64 = line.strip_prefix("PRIV:").unwrap(); }
        }

        if username.is_empty() || priv_key_b64.is_empty() {
            return Err(anyhow::anyhow!("Invalid identity file format"));
        }

        self.username = username.to_string();

        // 2. Challenge vom Server holen
        let challenge_req = Request::new(pytja_proto::pytja::ChallengeRequest {
            username: username.to_string(),
        });
        let challenge_resp = self.client.get_challenge(challenge_req).await?.into_inner();

        if !challenge_resp.user_exists {
            return Err(anyhow::anyhow!("User '{}' does not exist on server.", username));
        }

        // 3. Challenge signieren
        let priv_bytes = base64::decode(priv_key_b64)?;
        let signing_key = SigningKey::from_bytes(&priv_bytes.try_into().unwrap());
        let signature = signing_key.sign(challenge_resp.challenge.as_bytes());
        let signature_bytes = signature.to_bytes().to_vec();

        // 4. Login Request senden
        let login_req = Request::new(pytja_proto::pytja::LoginRequest {
            username: username.to_string(),
            challenge: challenge_resp.challenge,
            signature: signature_bytes,
        });

        let login_resp = self.client.login(login_req).await?.into_inner();

        if login_resp.success {
            self.token = login_resp.token;
            return Ok(true);
        } else {
            return Err(anyhow::anyhow!("Login failed: {}", login_resp.message));
        }
    }

    // Helper für authentifizierte Requests
    pub fn request<T>(&self, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        if !self.token.is_empty() {
            let auth_value = format!("Bearer {}", self.token);
            if let Ok(val) = auth_value.parse() {
                req.metadata_mut().insert("authorization", val);
            }
        }
        req
    }

    // --- RPC WRAPPERS (Die Methoden von vorhin) ---

    pub async fn list_users(&mut self) -> anyhow::Result<Vec<pytja_proto::pytja::UserData>> {
        let req = self.request(pytja_proto::pytja::ListUsersRequest {});
        let resp = self.client.list_users(req).await?.into_inner();
        Ok(resp.users)
    }

    pub async fn register_user(&mut self, username: String, pub_key: Vec<u8>, role: String, quota: u64) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::RegisterUserRequest {
            username, public_key, role, quota_limit: quota
        });
        self.client.register_user(req).await?;
        Ok(())
    }

    pub async fn set_quota(&mut self, username: String, limit: u64) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::SetQuotaRequest { username, limit_bytes: limit });
        self.client.set_user_quota(req).await?;
        Ok(())
    }

    pub async fn get_mounts(&mut self) -> anyhow::Result<Vec<pytja_proto::pytja::MountInfo>> {
        let req = self.request(pytja_proto::pytja::GetMountsRequest {});
        let resp = self.client.get_mounts(req).await?.into_inner();
        Ok(resp.mounts)
    }

    pub async fn add_mount(&mut self, name: String, connection_string: String, db_type: String) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::AddMountRequest {
            name, connection_string, r#type: db_type,
        });
        self.client.add_mount(req).await?;
        Ok(())
    }

    pub async fn remove_mount(&mut self, name: String) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::RemoveMountRequest { name });
        self.client.remove_mount(req).await?;
        Ok(())
    }

    pub async fn list_roles(&mut self) -> anyhow::Result<Vec<pytja_proto::pytja::RoleInfo>> {
        let req = self.request(pytja_proto::pytja::ListRolesRequest {});
        let resp = self.client.list_roles(req).await?.into_inner();
        Ok(resp.roles)
    }

    pub async fn create_role(&mut self, name: String) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::CreateRoleRequest { name });
        self.client.create_role(req).await?;
        Ok(())
    }

    pub async fn add_permission(&mut self, role_name: String, permission: String) -> anyhow::Result<()> {
        let req = self.request(pytja_proto::pytja::AddPermissionRequest { role_name, permission });
        self.client.add_permission(req).await?;
        Ok(())
    }

    pub async fn get_system_stats(&mut self) -> anyhow::Result<pytja_proto::pytja::SystemStatsResponse> {
        let req = self.request(pytja_proto::pytja::SystemStatsRequest {});
        Ok(self.client.get_system_stats(req).await?.into_inner())
    }

    pub async fn get_audit_logs(&mut self, limit: u32, filter: Option<String>) -> anyhow::Result<Vec<pytja_proto::pytja::AuditLogEntry>> {
        let req = self.request(pytja_proto::pytja::GetAuditLogsRequest { limit, filter_user: filter.unwrap_or_default() });
        Ok(self.client.get_audit_logs(req).await?.into_inner().logs)
    }

    pub async fn stream_logs(&mut self) -> anyhow::Result<tonic::Streaming<pytja_proto::pytja::LogStreamEntry>> {
        let req = self.request(pytja_proto::pytja::LogStreamRequest {});
        Ok(self.client.stream_server_logs(req).await?.into_inner())
    }
}
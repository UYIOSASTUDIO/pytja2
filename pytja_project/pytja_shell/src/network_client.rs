use pytja_proto::pytja::pytja_service_client::PytjaServiceClient;
use pytja_proto::pytja::*;
use pytja_proto::pytja::upload_request::Data; // Wichtig für Upload Enums
use tonic::transport::{Channel, ClientTlsConfig, Certificate};
use tonic::{Request, Status};
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, anyhow, Context};
use colored::*;
use std::str::FromStr;
use futures_util::StreamExt; // Für next() bei Streams
use std::fs; // Für File IO
use std::path::Path;

#[derive(Clone)]
pub struct PytjaClient {
    // Thread-safe Client Wrapper mit Mutex für asynchronen Zugriff
    client: Arc<Mutex<PytjaServiceClient<Channel>>>,
    token: Arc<Mutex<Option<String>>>,
    pub signing_key: Vec<u8>,
    pub username: String,
}

impl PytjaClient {
    /// Verbindet sich mit dem Server (TLS Support).
    /// `server_url`: z.B. "https://127.0.0.1:50051"
    pub async fn connect(server_url: String, signing_key: Vec<u8>, username: String, ca_cert_pem: Option<String>) -> Result<Self> {
        let mut endpoint = Channel::from_shared(server_url.clone())
            .context("Invalid Server URL")?;

        // TLS Konfiguration
        if server_url.starts_with("https") {
            let mut tls = ClientTlsConfig::new()
                .domain_name("localhost"); // Muss zum CN im Zertifikat passen!

            if let Some(pem) = ca_cert_pem {
                let ca = Certificate::from_pem(pem);
                tls = tls.ca_certificate(ca);
            }

            endpoint = endpoint.tls_config(tls)?;
        }

        let channel = endpoint.connect().await
            .context(format!("Failed to connect to {}", server_url))?;

        Ok(Self {
            client: Arc::new(Mutex::new(PytjaServiceClient::new(channel))),
            token: Arc::new(Mutex::new(None)),
            signing_key,
            username,
        })
    }

    // Deprecated Helper (nutze connect stattdessen)
    pub fn new(_url: &str, _key: Vec<u8>, _user: String) -> Self {
        panic!("Please use PytjaClient::connect() instead of new() for async TLS support.");
    }

    pub async fn set_token(&self, t: &str) {
        let mut lock = self.token.lock().await;
        *lock = Some(t.to_string());
    }

    // Helper: Baut einen Request und fügt (falls vorhanden) das Auth-Token hinzu
    async fn auth_req<T>(&self, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        let lock = self.token.lock().await;

        if let Some(token) = &*lock {
            // Wir nutzen standardmäßig "Bearer <token>"
            let val = format!("Bearer {}", token);
            if let Ok(meta) = tonic::metadata::MetadataValue::from_str(&val) {
                req.metadata_mut().insert("authorization", meta);
            }
        }
        req
    }

    // --- API METHODS ---

    pub async fn check_uplink(&self) -> Result<bool> {
        let mut client = self.client.lock().await;
        // Ping braucht oft kein Auth, aber sicherheitshalber okay ohne
        let req = Request::new(PingRequest { message: "Ping".into() });
        match client.ping(req).await {
            Ok(r) => {
                println!(" [+] Server: {}", r.into_inner().server_version.cyan());
                Ok(true)
            },
            Err(_) => Ok(false),
        }
    }

    pub async fn get_challenge(&self, username: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = Request::new(ChallengeRequest { username: username.to_string() });
        let resp = client.get_challenge(req).await?.into_inner();
        if !resp.user_exists {
            return Err(anyhow!("User not found on server"));
        }
        Ok(resp.challenge)
    }

    pub async fn login(&self, username: &str, challenge: &str, signature: &[u8]) -> Result<LoginResponse, Status> {
        let mut client = self.client.lock().await;
        let req = Request::new(LoginRequest {
            username: username.to_string(),
            challenge: challenge.to_string(),
            signature: signature.to_vec(),
        });
        let resp = client.login(req).await?.into_inner();
        Ok(resp)
    }

    pub async fn list_files(&self, path: &str) -> Result<Vec<FileInfo>> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(ListRequest { path: path.to_string(), auth_token: "".into() }).await;
        let resp = client.list_directory(req).await?.into_inner();
        Ok(resp.files)
    }

    pub async fn create_node(&self, path: &str, is_folder: bool, content: Vec<u8>, lock_pass: Option<String>, owner: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(CreateNodeRequest {
            path: path.to_string(),
            is_folder,
            owner: owner.to_string(),
            content,
            lock_password: lock_pass.unwrap_or_default(),
        }).await;
        let resp = client.create_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn read_file(&self, path: &str, password: Option<String>) -> Result<(Vec<u8>, String)> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(ReadFileRequest {
            path: path.to_string(),
            password: password.unwrap_or_default()
        }).await;
        let resp = client.read_file(req).await?.into_inner();
        if resp.success { Ok((resp.content, resp.message)) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn delete_node(&self, path: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(DeleteNodeRequest { path: path.to_string() }).await;
        let resp = client.delete_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn move_node(&self, src: &str, dst: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(MoveNodeRequest { source_path: src.to_string(), dest_path: dst.to_string() }).await;
        let resp = client.move_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn copy_node(&self, src: &str, dst: &str, owner: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(CopyNodeRequest {
            source_path: src.to_string(),
            dest_path: dst.to_string(),
            owner: owner.to_string()
        }).await;
        let resp = client.copy_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn change_mode(&self, path: &str, perms: u32) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(ChangeModeRequest { path: path.to_string(), permissions: perms }).await;
        let resp = client.change_mode(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn chown_node(&self, path: &str, owner: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(ChownRequest { path: path.to_string(), new_owner: owner.to_string() }).await;
        let resp = client.chown_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn lock_node(&self, path: &str, password: Option<String>) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(LockRequest { path: path.to_string(), password: password.unwrap_or_default() }).await;
        let resp = client.lock_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow!(resp.message)) }
    }

    pub async fn get_usage(&self, owner: &str) -> Result<u64> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(UsageRequest { owner: owner.to_string() }).await;
        let resp = client.get_usage(req).await?.into_inner();
        Ok(resp.bytes)
    }

    pub async fn find_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(FindRequest { pattern: pattern.to_string() }).await;
        let resp = client.find_node(req).await?.into_inner();
        Ok(resp.paths)
    }

    pub async fn grep_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(GrepRequest { pattern: pattern.to_string() }).await;
        let resp = client.grep_node(req).await?.into_inner();
        Ok(resp.matches)
    }

    pub async fn stat_node(&self, path: &str) -> Result<(bool, bool, bool)> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(StatRequest { path: path.to_string() }).await;
        let resp = client.stat_node(req).await?.into_inner();
        Ok((resp.exists, resp.is_folder, resp.is_locked))
    }

    pub async fn get_tree(&self, root_path: &str) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(TreeRequest { root_path: root_path.to_string() }).await;
        let resp = client.get_tree(req).await?.into_inner();
        Ok(resp.tree_output)
    }

    // --- STREAMING METHODS ---

    pub async fn upload_file(&self, local_path: &str, remote_path: &str, lock: Option<String>, owner: &str) -> Result<String> {
        // Wir lesen die Datei sequentiell (nicht alles in RAM laden für große Dateien)
        // Aber hier ist eine einfache Implementierung mit Chunks

        let path = Path::new(local_path);
        if !path.exists() {
            return Err(anyhow!("File not found: {}", local_path));
        }

        // Metadata Payload
        let metadata = UploadMetadata { // FIX: Struct Name muss stimmen
            path: remote_path.to_string(),
            owner: owner.to_string(),
            lock_password: lock.unwrap_or_default(),
            is_folder: false,
        };

        // Stream Generator
        // Wir klonen local_path String, damit der Stream ihn besitzen kann
        let file_path = local_path.to_string();

        let outbound = async_stream::stream! {
            // 1. Metadata senden
            yield UploadRequest {
                data: Some(Data::Metadata(metadata))
            };

            // 2. Chunks lesen und senden
            // Wir nutzen std::fs hier synchron für Einfachheit, besser wäre tokio::fs
            // Für Performance: Blockgröße 64KB
            if let Ok(content) = fs::read(&file_path) {
                for chunk in content.chunks(64 * 1024) {
                    yield UploadRequest {
                        data: Some(Data::Chunk(chunk.to_vec()))
                    };
                }
            }
        };

        let mut client = self.client.lock().await;
        // Token in Stream-Request injecten ist tricky, da Stream ein Iterator ist.
        // Die Metadata muss am Server geprüft werden oder wir nutzen `tonic::Request::new(outbound)`
        // und setzen Metadata da drauf.

        let mut request = Request::new(outbound);

        // Token injecten
        let lock = self.token.lock().await;
        if let Some(token) = &*lock {
            let val = format!("Bearer {}", token);
            if let Ok(meta) = tonic::metadata::MetadataValue::from_str(&val) {
                request.metadata_mut().insert("authorization", meta);
            }
        }

        let response = client.upload_file(request).await?.into_inner();
        if response.success { Ok(response.message) } else { Err(anyhow!(response.message)) }
    }

    pub async fn download_file(&self, remote_path: &str, local_path: &str, password: Option<String>) -> Result<String> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(DownloadRequest {
            path: remote_path.to_string(),
            password: password.unwrap_or_default(),
        }).await;

        let mut stream = client.download_file(req).await?.into_inner();

        // Datei öffnen/erstellen
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(local_path).await
            .context("Failed to create local file")?;

        let mut total_bytes = 0;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.context("Stream error")?;
            file.write_all(&chunk.content).await?;
            total_bytes += chunk.content.len();
        }

        file.flush().await?;
        Ok(format!("Downloaded {} bytes to {}", total_bytes, local_path))
    }

    pub async fn exec_script(&self, path: &str) -> Result<()> {
        let mut client = self.client.lock().await;
        let req = self.auth_req(ExecRequest { script_path: path.to_string(), args: vec![] }).await;

        let mut stream = client.exec_script(req).await?.into_inner();

        println!("{}", "--- REMOTE OUTPUT START ---".cyan());
        while let Some(resp_result) = stream.next().await {
            match resp_result {
                Ok(resp) => println!("{}", resp.output_line),
                Err(e) => println!("Error in stream: {}", e),
            }
        }
        println!("{}", "--- REMOTE OUTPUT END ---".cyan());
        Ok(())
    }
}
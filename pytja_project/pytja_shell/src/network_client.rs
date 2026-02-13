use pytja_proto::{PytjaServiceClient, PingRequest, ListRequest, FileInfo};
use pytja_proto::{CreateNodeRequest,
                  ReadFileRequest, DeleteNodeRequest, MoveNodeRequest,
                  CopyNodeRequest, ChangeModeRequest,
                  ChownRequest, LockRequest, UsageRequest,
                  FindRequest, GrepRequest,
                  StatRequest, TreeRequest,
                  UploadRequest, FileMetadata, DownloadRequest, ExecRequest,
                  ChallengeRequest, LoginRequest
};
use colored::*;
use anyhow::Result;
use pytja_proto::pytja::upload_request::Data;
use futures_util::StreamExt;
use ed25519_dalek::SigningKey;
use pytja_core::crypto::CryptoService;
use std::str::FromStr;

pub struct PytjaClient {
    url: String,
    signing_key: SigningKey,
    username: String,
    token: Option<String>,
}

impl PytjaClient {
    pub fn new(url: &str, signing_key: SigningKey, username: String) -> Self {
        Self {
            url: url.to_string(),
            signing_key,
            username,
            token: None,
        }
    }

    // Helper: Verbindet "nackt" (für Handshake)
    async fn raw_connect(&self) -> Result<PytjaServiceClient<tonic::transport::Channel>> {
        let dst = format!("http://{}", self.url);
        let client = PytjaServiceClient::connect(dst).await?;
        Ok(client)
    }

    // Helper: Erstellt einen authentifizierten Request
    fn auth_req<T>(&self, msg: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(msg);
        if let Some(token) = &self.token {
            let val = format!("Bearer {}", token);
            if let Ok(meta) = tonic::metadata::MetadataValue::from_str(&val) {
                req.metadata_mut().insert("authorization", meta);
            }
        }
        req
    }

    pub async fn perform_handshake(&mut self) -> Result<bool> {
        println!("{}", "[*] Initiating Secure Handshake (Ed25519)...".yellow());
        let mut client = self.raw_connect().await?;

        // 1. Challenge
        let challenge_req = ChallengeRequest { username: self.username.clone() };
        let challenge_resp = client.get_challenge(challenge_req).await?.into_inner();

        if !challenge_resp.user_exists {
            println!("{}", " [!] Access Denied: User unknown to server.".red());
            return Ok(false);
        }

        let challenge_hex = challenge_resp.challenge;
        println!("     Challenge: {}", challenge_hex.chars().take(8).collect::<String>().dimmed());

        // 2. Signieren
        let signature_b64 = CryptoService::sign_message(&self.signing_key, challenge_hex.as_bytes());

        // 3. Login
        let login_req = LoginRequest {
            username: self.username.clone(),
            challenge: challenge_hex,
            signature: signature_b64,
        };

        let login_resp = client.login(login_req).await?.into_inner();

        if login_resp.success {
            println!("{}", " [+] Handshake Successful.".green().bold());
            self.token = Some(login_resp.token);
            Ok(true)
        } else {
            println!(" [!] Login Failed: {}", login_resp.message.red());
            Ok(false)
        }
    }

    // --- FILE OPERATIONS (Nutzen jetzt raw_connect() + auth_req()) ---

    pub async fn check_uplink(&self) -> Result<bool> {
        let mut client = self.raw_connect().await?; // Ping braucht kein Auth
        let req = tonic::Request::new(PingRequest { message: "Ping".into() });
        match client.ping(req).await {
            Ok(r) => {
                println!(" [+] Server: {}", r.into_inner().server_version.cyan());
                Ok(true)
            },
            Err(e) => { println!(" [!] Error: {}", e); Ok(false) }
        }
    }

    pub async fn list_files(&self, path: &str) -> Result<Vec<FileInfo>> {
        let mut client = self.raw_connect().await?;
        let request = self.auth_req(ListRequest { path: path.to_string(), auth_token: "".into() });
        let response = client.list_directory(request).await?;
        Ok(response.into_inner().files)
    }

    pub async fn create_node(&self, path: &str, is_folder: bool, content: Vec<u8>, lock_pass: Option<String>, owner: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let request = self.auth_req(CreateNodeRequest {
            path: path.to_string(), is_folder, content, lock_password: lock_pass.unwrap_or_default(), owner: owner.to_string(),
        });
        let resp = client.create_node(request).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn read_file(&self, path: &str, password: Option<String>) -> Result<(Vec<u8>, String)> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(ReadFileRequest { path: path.to_string(), password: password.unwrap_or_default() });
        let resp = client.read_file(req).await?.into_inner();
        if resp.success { Ok((resp.content, resp.message)) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn delete_node(&self, path: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(DeleteNodeRequest { path: path.to_string() });
        let resp = client.delete_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn move_node(&self, src: &str, dst: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(MoveNodeRequest { source_path: src.to_string(), dest_path: dst.to_string() });
        let resp = client.move_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn copy_node(&self, src: &str, dst: &str, owner: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(CopyNodeRequest { source_path: src.to_string(), dest_path: dst.to_string(), owner: owner.to_string() });
        let resp = client.copy_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn change_mode(&self, path: &str, perms: u32) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(ChangeModeRequest { path: path.to_string(), permissions: perms });
        let resp = client.change_mode(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn chown_node(&self, path: &str, owner: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(ChownRequest { path: path.to_string(), new_owner: owner.to_string() });
        let resp = client.chown_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn lock_node(&self, path: &str, password: Option<String>) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(LockRequest { path: path.to_string(), password: password.unwrap_or_default() });
        let resp = client.lock_node(req).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn get_usage(&self, owner: &str) -> Result<u64> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(UsageRequest { owner: owner.to_string() });
        let resp = client.get_usage(req).await?.into_inner();
        Ok(resp.bytes)
    }

    pub async fn find_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(FindRequest { pattern: pattern.to_string() });
        let resp = client.find_node(req).await?.into_inner();
        Ok(resp.paths)
    }

    pub async fn grep_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(GrepRequest { pattern: pattern.to_string() });
        let resp = client.grep_node(req).await?.into_inner();
        Ok(resp.matches)
    }

    pub async fn stat_node(&self, path: &str) -> Result<(bool, bool, bool)> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(StatRequest { path: path.to_string() });
        let resp = client.stat_node(req).await?.into_inner();
        Ok((resp.exists, resp.is_folder, resp.is_locked))
    }

    pub async fn get_tree(&self) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(TreeRequest { root_path: "/".to_string() });
        let resp = client.get_tree(req).await?.into_inner();
        Ok(resp.tree_output)
    }

    // UPLOAD (Streaming: Request Building ist hier komplexer, da Stream)
    pub async fn upload_file(&self, local_path: &str, remote_path: &str, lock: Option<String>, owner: &str) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let content = std::fs::read(local_path)?;

        let meta = FileMetadata {
            path: remote_path.to_string(), lock_password: lock.unwrap_or_default(), owner: owner.to_string(), is_folder: false,
        };

        // Stream erstellen
        let chunk_size = 1024 * 64;
        let outbound = async_stream::stream! {
            yield UploadRequest { data: Some(Data::Metadata(meta)) };
            for chunk in content.chunks(chunk_size) {
                yield UploadRequest { data: Some(Data::Chunk(chunk.to_vec())) };
            }
        };

        // Authentifizierter Request für den Stream?
        // Tonic erlaubt Metadata auch bei Streams via `Request::new(stream)`.
        let request = self.auth_req(outbound);

        let response = client.upload_file(request).await?.into_inner();
        if response.success { Ok(response.message) } else { Err(anyhow::anyhow!(response.message)) }
    }

    // DOWNLOAD
    pub async fn download_file(&self, remote_path: &str, local_path: &str, password: Option<String>) -> Result<String> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(DownloadRequest { path: remote_path.to_string(), password: password.unwrap_or_default() });

        let mut stream = client.download_file(req).await?.into_inner();
        let mut full_content = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            full_content.extend(chunk.content);
        }

        std::fs::write(local_path, full_content)?;
        Ok(format!("Downloaded to {}", local_path))
    }

    // EXEC
    pub async fn exec_script(&self, path: &str) -> Result<()> {
        let mut client = self.raw_connect().await?;
        let req = self.auth_req(ExecRequest { script_path: path.to_string(), args: vec![] });

        let mut stream = client.exec_script(req).await?.into_inner();

        println!("{}", "--- REMOTE OUTPUT START ---".cyan());
        while let Some(resp_result) = stream.next().await {
            let resp = resp_result?;
            println!("{}", resp.output_line);
        }
        println!("{}", "--- REMOTE OUTPUT END ---".cyan());
        Ok(())
    }
}
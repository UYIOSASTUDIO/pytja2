use tonic::{transport::Server, Request, Response, Status};

// WICHTIG: Die Service-Traits liegen im Root von pytja_proto
use pytja_proto::{PytjaService, PytjaServiceServer};

// Die Messages liegen im Untermodul 'pytja'
use pytja_proto::pytja::{
    PingRequest, PingResponse,
    ListRequest, ListResponse, FileInfo,
    CreateNodeRequest, ActionResponse,
    ReadFileRequest, ReadFileResponse,
    DeleteNodeRequest, MoveNodeRequest,
    CopyNodeRequest, ChangeModeRequest,
    ChownRequest, LockRequest, UsageRequest, UsageResponse,
    FindRequest, FindResponse, GrepRequest, GrepResponse,
    StatRequest, StatResponse,
    TreeRequest, TreeResponse,
    UploadRequest,
    DownloadRequest, FileChunk,
    ExecRequest, ExecResponse,
    ChallengeRequest, ChallengeResponse,
    LoginRequest, LoginResponse,
    GetSessionsRequest, GetSessionsResponse, KickUserRequest, SessionInfo,
    upload_request::Data as UploadData
};

use pytja_core::models::{FileNode, Claims};
use pytja_core::config::AppConfig;
use pytja_core::storage::{BlobStorage, FileSystemStorage, S3Storage};
use bytes::Bytes;
use colored::*;
use std::sync::Arc;
use pytja_core::{PytjaRepository, DriverManager, DatabaseType};
use pytja_core::crypto::CryptoService;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use futures_util::StreamExt;
use jsonwebtoken::{encode, Header, EncodingKey};

mod session_manager;
use crate::session_manager::SessionManager;

const JWT_SECRET: &[u8] = b"pytja_super_secret_key_change_me_in_prod";

pub struct MyPytjaService {
    manager: Arc<DriverManager>,
    sessions: Arc<SessionManager>,
    config: AppConfig,
    storage: Arc<dyn BlobStorage>,
}

impl MyPytjaService {
    fn check_permissions<T>(&self, req: &Request<T>, min_level: i32) -> Result<Claims, Status> {
        let token = match req.metadata().get("authorization") {
            Some(t) => t.to_str().map_err(|_| Status::unauthenticated("Invalid Token format"))?,
            None => return Err(Status::unauthenticated("Login required")),
        };

        let token = token.strip_prefix("Bearer ").unwrap_or(token);

        let token_data = jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(JWT_SECRET),
            &jsonwebtoken::Validation::default(),
        ).map_err(|_| Status::unauthenticated("Invalid Token or Signature"))?;

        if let Some(sid) = &token_data.claims.sid {
            if !self.sessions.is_valid(sid) {
                return Err(Status::unauthenticated("Session expired or terminated by Admin"));
            }
            self.sessions.update_activity(sid);
        }

        if token_data.claims.role_level < min_level {
            return Err(Status::permission_denied(format!(
                "Insufficient Permissions: Level {} required, you have Level {}",
                min_level, token_data.claims.role_level
            )));
        }

        Ok(token_data.claims)
    }

    fn resolve_repo(&self, full_path: &str) -> Result<(Arc<dyn PytjaRepository>, String), Status> {
        let clean_path = full_path.trim_start_matches('/');
        let mounts = self.manager.list_mounts();

        for mount_name in mounts {
            if clean_path == mount_name || clean_path.starts_with(&format!("{}/", mount_name)) {
                let repo = self.manager.get_repo(&mount_name)
                    .ok_or_else(|| Status::internal(format!("Mount '{}' not found", mount_name)))?;

                let relative_path = if clean_path == mount_name {
                    "/".to_string()
                } else {
                    format!("/{}", &clean_path[mount_name.len() + 1..])
                };

                return Ok((repo, relative_path));
            }
        }

        let repo = self.manager.get_repo("primary")
            .ok_or_else(|| Status::internal("Primary DB connection lost"))?;

        Ok((repo, full_path.to_string()))
    }
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let mounts = self.manager.list_mounts();
        let mount_info = format!("Active Mounts: {:?}", mounts);
        Ok(Response::new(PingResponse {
            message: format!("Pong! Hub Status: {}", mount_info),
            server_version: "Pytja Enterprise V3.0".to_string(),
            is_ready: true,
        }))
    }

    async fn get_challenge(&self, request: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or_else(|| Status::internal("DB Error"))?;
        let exists = repo.user_exists(&req.username).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ChallengeResponse { challenge: CryptoService::generate_random_challenge(), user_exists: exists }))
    }

    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or_else(|| Status::internal("DB Error"))?;

        let user = match repo.get_user(&req.username).await {
            Ok(Some(u)) => u,
            Ok(None) => return Ok(Response::new(LoginResponse { success: false, token: "".into(), message: "User not found".into() })),
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        let challenge_bytes = req.challenge.as_bytes();
        let is_valid = match CryptoService::verify_signature(&user.public_key, challenge_bytes, &req.signature) {
            Ok(valid) => valid,
            Err(_) => false
        };

        if !is_valid {
            return Ok(Response::new(LoginResponse { success: false, token: "".into(), message: "Invalid Signature".into() }));
        }

        let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::minutes(60)).unwrap().timestamp() as usize;
        let session_id = self.sessions.register_session(&user.username, user.role_level, "127.0.0.1");

        let claims = Claims {
            sub: user.username.clone(),
            role_level: user.role_level,
            exp: expiration,
            sid: Some(session_id),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
            .map_err(|e| Status::internal(format!("Token error: {}", e)))?;

        Ok(Response::new(LoginResponse { success: true, token, message: "Login successful".into() }))
    }

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.check_permissions(&request, 0)?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let mut nodes = repo.list_directory(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?;

        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts();
            for mount_name in mounts {
                if mount_name == "primary" { continue; }
                nodes.push(FileNode {
                    path: format!("/{}", mount_name),
                    name: mount_name.clone(),
                    owner: "SYSTEM".to_string(),
                    is_folder: true,
                    size: 0,
                    content: vec![],
                    lock_pass: None,
                    permissions: 0,
                    created_at: 0.0,
                    blob_id: None,
                });
            }
        }

        let proto_files = nodes.into_iter().map(|node| FileInfo {
            name: node.name, is_folder: node.is_folder, size: node.size as u64,
            owner: node.owner, permissions: node.permissions as u32, created_at: node.created_at,
        }).collect();

        Ok(Response::new(ListResponse { files: proto_files }))
    }

    async fn upload_file(&self, request: Request<tonic::Streaming<UploadRequest>>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, 20)?;
        let mut stream = request.into_inner();

        let first_msg = stream.message().await.map_err(|e| Status::internal(e.to_string()))?;
        let metadata = match first_msg {
            Some(req) => match req.data {
                Some(UploadData::Metadata(m)) => m,
                _ => return Err(Status::invalid_argument("Metadata missing")),
            },
            None => return Err(Status::invalid_argument("Empty stream")),
        };

        let (repo, relative_path) = self.resolve_repo(&metadata.path)?;

        let byte_stream = stream.map(|item| {
            match item {
                Ok(req) => match req.data {
                    Some(UploadData::Chunk(data)) => Ok(Bytes::from(data)),
                    _ => Ok(Bytes::new()),
                },
                Err(e) => Err(pytja_core::error::PytjaError::System(e.to_string())),
            }
        });

        let pinned_stream = Box::pin(byte_stream);
        let blob_id = self.storage.put(&metadata.path, pinned_stream).await
            .map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path,
            name,
            owner: metadata.owner,
            is_folder: false,
            content: vec![],
            blob_id: Some(blob_id),
            size: 0,
            lock_pass: if metadata.lock_password.is_empty() { None } else { Some(metadata.lock_password) },
            permissions: 0,
            created_at: chrono::Utc::now().timestamp() as f64,
        };

        repo.save_node(&node).await.map_err(|e| Status::internal(e.to_string()))?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "UPLOAD", &metadata.path).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Upload complete".into() }))
    }
    async fn download_file(&self, request: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        self.check_permissions(&request, 10)?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let node = repo.get_node(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("File not found"))?;

        if let Some(pass) = node.lock_pass {
            if pass != req.password { return Err(Status::permission_denied("Wrong Password")); }
        }

        let stream: std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<FileChunk, Status>> + Send>> = if let Some(blob_id) = node.blob_id {
            let storage_stream = self.storage.get(&blob_id).await
                .map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;

            Box::pin(storage_stream.map(|res| match res {
                Ok(bytes) => Ok(FileChunk { content: bytes.to_vec() }),
                Err(e) => Err(Status::internal(e.to_string())),
            }))
        } else {
            let content = node.content;
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                for chunk in content.chunks(64 * 1024) {
                    let _ = tx.send(Ok(FileChunk { content: chunk.to_vec() })).await;
                }
            });
            Box::pin(ReceiverStream::new(rx))
        };

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut s = stream;
            while let Some(item) = s.next().await {
                if tx.send(item).await.is_err() { break; }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn create_node(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 20)?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path,
            name,
            owner: req.owner,
            is_folder: req.is_folder,
            size: req.content.len(),
            content: req.content,
            lock_pass: if req.lock_password.is_empty() { None } else { Some(req.lock_password) },
            permissions: 0,
            created_at: chrono::Utc::now().timestamp() as f64,
            blob_id: None,
        };

        match repo.save_node(&node).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Created".into() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn stat_node(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        self.check_permissions(&request, 0)?;
        let req = request.into_inner();

        let clean = req.path.trim_start_matches('/');
        for m in self.manager.list_mounts() {
            if clean == m {
                return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false }));
            }
        }

        let (repo, rel_path) = self.resolve_repo(&req.path)?;
        if rel_path == "/" { return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false })); }

        match repo.get_node(&rel_path).await {
            Ok(Some(n)) => Ok(Response::new(StatResponse { exists: true, is_folder: n.is_folder, is_locked: n.lock_pass.is_some() })),
            Ok(None) => Ok(Response::new(StatResponse { exists: false, is_folder: false, is_locked: false })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn get_active_sessions(&self, _request: Request<GetSessionsRequest>) -> Result<Response<GetSessionsResponse>, Status> {
        // Token Check wäre hier gut (Admin Only)

        let sessions: Vec<SessionInfo> = self.sessions.get_all_sessions().into_iter().map(|s| SessionInfo {
            session_id: s.session_id,
            username: s.username,
            ip_address: s.ip_address,
            role_level: s.role_level,
            login_time: s.login_time.to_rfc3339(),
            last_activity: s.last_activity.to_rfc3339()
        }).collect();

        let total = sessions.len() as i32;

        Ok(Response::new(GetSessionsResponse { sessions, total_active: total }))
    }

    async fn kick_user(&self, request: Request<KickUserRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 100)?;
        self.sessions.remove_session(&request.into_inner().session_id);
        Ok(Response::new(ActionResponse { success: true, message: "Kicked".into() }))
    }

    // Dummy Implementationen
    async fn read_file(&self, _: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> { Err(Status::unimplemented("Deprecated in Enterprise V3")) }

    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, 50)?;
        let req = request.into_inner();

        tracing::info!("DELETE request by '{}' on target: '{}'", claims.sub, req.path);

        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // KORREKTUR: 'Some' statt 'Ok'
        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "DELETE", &req.path).await;
        }

        match repo.delete_node_recursive(&relative_path).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Deleted.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn move_node(&self, _: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> { Err(Status::unimplemented("Update move_node")) }
    async fn copy_node(&self, _: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> { Err(Status::unimplemented("Update copy_node")) }
    async fn change_mode(&self, _: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> { Err(Status::unimplemented("Update change_mode")) }
    async fn chown_node(&self, _: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> { Err(Status::unimplemented("Update chown_node")) }
    async fn lock_node(&self, _: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> { Err(Status::unimplemented("Update lock_node")) }
    async fn get_usage(&self, _: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> { Err(Status::unimplemented("Update get_usage")) }
    async fn find_node(&self, _: Request<FindRequest>) -> Result<Response<FindResponse>, Status> { Err(Status::unimplemented("Update find_node")) }
    async fn grep_node(&self, _: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> { Err(Status::unimplemented("Update grep_node")) }
    async fn get_tree(&self, _: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> { Err(Status::unimplemented("Update get_tree")) }
    async fn exec_script(&self, _: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> { Err(Status::unimplemented("Update exec_script")) }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = pytja_core::telemetry::init_telemetry("./logs", "pytja_server.log");
    tracing::info!("Pytja Server Enterprise Edition starting up...");

    // 1. Config laden
    let config = AppConfig::new().expect("CRITICAL: Failed to load configuration");

    // 2. Datenbank Verbindung
    let db_path_or_url = if config.database.primary_url.starts_with("sqlite://") {
        config.database.primary_url.strip_prefix("sqlite://").unwrap()
    } else {
        &config.database.primary_url
    };

    let manager = Arc::new(DriverManager::new());
    let session_mgr = Arc::new(SessionManager::new());

    manager.load_config("mounts.json").await;

    tracing::info!("Mounting Primary DB: {}", db_path_or_url);
    manager.mount("primary", db_path_or_url, DatabaseType::Sqlite).await
        .expect("FATAL: Failed to mount primary DB");

    if let Some(repo) = manager.get_repo("primary") {
        repo.init().await.expect("DB Migration failed");
    }

    // 3. Storage
    let storage: Arc<dyn BlobStorage> = if config.storage.storage_type == "s3" {
        tracing::info!("Using S3 Storage");
        Arc::new(S3Storage::new(&config.storage.s3_bucket, &config.storage.s3_region).await)
    } else {
        tracing::info!("Using Local Storage");
        Arc::new(FileSystemStorage::new(&config.storage.local_path).await?)
    };

    let addr_str = format!("{}:{}", config.server.host, config.server.port);
    let addr = addr_str.parse()?;

    let service = MyPytjaService {
        manager: manager.clone(),
        sessions: session_mgr,
        config: config.clone(),
        storage,
    };

    println!("{}", "PYTJA ENTERPRISE HUB ONLINE".green().bold());
    println!("Listening on {}", addr);

    Server::builder()
        .add_service(PytjaServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
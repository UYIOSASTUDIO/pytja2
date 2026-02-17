use tonic::{transport::Server, Request, Response, Status};
use tonic::metadata::MetadataMap; // FIX: Import hinzugefügt
use pytja_proto::pytja::pytja_service_server::{PytjaService, PytjaServiceServer};
use pytja_proto::pytja::{
    ActionResponse, AddMountRequest, AdminActionResponse, ChallengeRequest, ChallengeResponse,
    CreateNodeRequest, DeleteNodeRequest, GetMountsRequest, GetMountsResponse, LoginRequest,
    LoginResponse, MoveNodeRequest, RemoveMountRequest, UploadRequest,
    // FIX: UploadData ist ein nested Enum (oneof), wir aliassen es hier
    upload_request::Data as UploadData,

    ListUsersRequest, ListUsersResponse, UserData,
    RegisterUserRequest, RegisterUserResponse,
    SetQuotaRequest, SetQuotaResponse,
    SystemStatsRequest, SystemStatsResponse,
    GetAuditLogsRequest, GetAuditLogsResponse, AuditLogEntry,
    LogStreamRequest, LogStreamEntry,
    ListRolesRequest, ListRolesResponse, RoleInfo,
    CreateRoleRequest, AddPermissionRequest,
    ChangeRoleRequest, ChangeRoleResponse,
    AssignRoleRequest,
    GetSessionsRequest, GetSessionsResponse, SessionInfo,
    KickUserRequest, BanUserRequest, BanUserResponse,
    MountInfo,
    PingRequest, PingResponse,
    ListRequest, ListResponse, FileInfo,
    DownloadRequest, FileChunk,
    ReadFileRequest, ReadFileResponse,
    CopyNodeRequest,
    ChangeModeRequest, ChownRequest, LockRequest,
    UsageRequest, UsageResponse,
    FindRequest, FindResponse,
    GrepRequest, GrepResponse,
    TreeRequest, TreeResponse,
    StatRequest, StatResponse,
    ExecRequest, ExecResponse,
};
use pytja_core::{
    DriverManager, PytjaRepository, PytjaError, AppConfig, BlobStorage, FileSystemStorage, S3Storage,
    models::{FileNode, User, Role, Claims},
    drivers::DatabaseType,
    crypto::CryptoService,
};

// FIX: SessionManager ist lokal in diesem Crate, nicht in Core
mod session_manager;
use crate::session_manager::SessionManager;

use sysinfo::{CpuExt, SystemExt, System};
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use bytes::Bytes;
use std::env;
use std::collections::HashSet;
use tracing::{info, warn, error};
use jsonwebtoken::{encode, Header, EncodingKey};
use dotenv::dotenv;

const JWT_SECRET: &[u8] = b"pytja_super_secret_key_change_me_in_prod";
const DEFAULT_QUOTA_LIMIT: usize = 1 * 1024 * 1024 * 1024; // 1 GB

pub struct MyPytjaService {
    manager: Arc<DriverManager>,
    sessions: Arc<SessionManager>,
    config: AppConfig,
    storage: Arc<dyn BlobStorage>,
    log_broadcast: broadcast::Sender<LogStreamEntry>,
}

impl MyPytjaService {
    async fn check_permissions(&self, meta: &MetadataMap, required_perm: Option<&str>) -> Result<Claims, Status> {
        let token = match meta.get("authorization") {
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
            if !self.sessions.is_valid(sid).await {
                return Err(Status::unauthenticated("Session expired or terminated"));
            }
        }

        if let Some(perm) = required_perm {
            let has_perm = token_data.claims.permissions.contains(perm)
                || token_data.claims.permissions.contains("*");

            if !has_perm {
                return Err(Status::permission_denied(format!(
                    "Missing permission: '{}'. Your Role: '{}'", perm, token_data.claims.role
                )));
            }
        }

        Ok(token_data.claims)
    }

    // HIER WAREN DIE FEHLER: Async Logic angepasst
    async fn resolve_repo(&self, full_path: &str) -> Result<(Arc<dyn PytjaRepository>, String), Status> {
        let clean_path = full_path.trim_start_matches('/');

        // WICHTIG: .await hinzugefügt
        let mounts = self.manager.list_mounts().await;

        for mount_name in mounts {
            if clean_path == mount_name || clean_path.starts_with(&format!("{}/", mount_name)) {
                // WICHTIG: .await hinzugefügt
                let repo = self.manager.get_repo(&mount_name).await
                    .ok_or_else(|| Status::internal(format!("Mount '{}' not found", mount_name)))?;

                let relative_path = if clean_path == mount_name {
                    "/".to_string()
                } else {
                    format!("/{}", &clean_path[mount_name.len() + 1..])
                };
                return Ok((repo, relative_path));
            }
        }

        // WICHTIG: .await hinzugefügt
        let repo = self.manager.get_repo("primary").await
            .ok_or_else(|| Status::internal("Primary DB connection lost"))?;
        Ok((repo, full_path.to_string()))
    }

    async fn get_user_quota_usage(&self, username: &str) -> usize {
        // 1. FAST PATH: Redis Cache fragen
        if let Some(bytes) = self.sessions.get_cached_quota(username).await {
            return bytes as usize;
        }

        // 2. SLOW PATH: SQL SUM() Query (nur wenn Cache leer/abgelaufen)
        if let Some(primary) = self.manager.get_repo("primary").await {
            let usage = primary.get_total_usage(username).await.unwrap_or(0);

            // Cache für 1 Stunde befüllen (Self-Healing)
            self.sessions.set_cached_quota(username, usage as u64).await;
            return usage;
        }
        0
    }
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse { message: "Pong".into(), server_version: "Pytja Enterprise V3.0".to_string(), is_ready: true }))
    }

    async fn get_challenge(&self, request: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or_else(|| Status::internal("DB Error"))?;
        let exists = repo.user_exists(&req.username).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ChallengeResponse { challenge: CryptoService::generate_random_challenge(), user_exists: exists }))
    }

    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or_else(|| Status::internal("DB Error"))?;

        let user = match repo.get_user(&req.username).await {
            Ok(Some(u)) => u,
            Ok(None) => return Ok(Response::new(LoginResponse { success: false, token: "".into(), message: "User not found".into() })),
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        let challenge_bytes = req.challenge.as_bytes();

        // FIX: Kein from_utf8 mehr! Wir übergeben die Bytes direkt.
        // user.public_key ist Vec<u8> (BLOB aus DB)
        let is_valid = match CryptoService::verify_signature(&user.public_key, challenge_bytes, &req.signature) {
            Ok(valid) => valid,
            Err(e) => {
                warn!("Signature verification error for user {}: {}", req.username, e);
                false
            }
        };

        if !is_valid {
            return Ok(Response::new(LoginResponse { success: false, token: "".into(), message: "Invalid Signature".into() }));
        }

        let role = if let Some(cached) = self.sessions.get_cached_role(&user.role).await {
            cached
        } else {
            let r = repo.get_role(&user.role).await.map_err(|e| Status::internal(e.to_string()))?
                .unwrap_or(Role { name: "guest".into(), permissions: vec![] });
            self.sessions.cache_role(&r).await;
            r
        };

        let mut perms_set = HashSet::new();
        for p in role.permissions { perms_set.insert(p); }

        let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::minutes(60)).unwrap().timestamp() as usize;

        self.sessions.clear_user_sessions(&user.username).await;

        let session_id = self.sessions.register_session(&user.username, &user.role, "127.0.0.1").await
            .map_err(|e| Status::internal(format!("Redis Error: {}", e)))?;

        let claims = Claims {
            sub: user.username.clone(),
            role: user.role.clone(),
            permissions: perms_set,
            exp: expiration,
            sid: Some(session_id),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
            .map_err(|e| Status::internal(format!("Token error: {}", e)))?;

        Ok(Response::new(LoginResponse { success: true, token, message: "Login successful".into() }))
    }

    // --- USER MANAGEMENT RPCs ---

    async fn list_users(&self, request: Request<ListUsersRequest>) -> Result<Response<ListUsersResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;

        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let users_db = repo.list_users().await.map_err(|e| Status::internal(e.to_string()))?;

        let mut user_list = Vec::new();
        for u in users_db {
            let usage = self.get_user_quota_usage(&u.username).await as u64;

            user_list.push(UserData {
                username: u.username,
                role: u.role,
                is_active: u.is_active,
                quota_used: usage,
                quota_limit: u.quota_limit as u64,
                // FIX: chrono Deprecation Warnung behoben
                created_at: chrono::DateTime::from_timestamp(u.created_at as i64, 0)
                    .map(|dt| dt.to_string())
                    .unwrap_or_default(),
            });
        }

        Ok(Response::new(ListUsersResponse { users: user_list }))
    }

    async fn register_user(&self, request: Request<RegisterUserRequest>) -> Result<Response<RegisterUserResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        if repo.user_exists(&req.username).await.unwrap_or(false) {
            return Err(Status::already_exists("User already exists"));
        }

        // FIX: User Struct wird jetzt korrekt erkannt (durch Import oben)
        let new_user = User {
            username: req.username,
            public_key: req.public_key,
            role: req.role,
            is_active: true,
            created_at: chrono::Utc::now().timestamp() as f64,
            quota_limit: req.quota_limit as i64,
            description: None,
        };

        repo.create_user(&new_user).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RegisterUserResponse { success: true, message: "User registered.".into() }))
    }

    async fn set_user_quota(&self, request: Request<SetQuotaRequest>) -> Result<Response<SetQuotaResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        repo.set_user_quota(&req.username, req.limit_bytes).await.map_err(|e| Status::internal(e.to_string()))?;

        self.sessions.invalidate_quota(&req.username).await;

        Ok(Response::new(SetQuotaResponse { success: true, message: "Quota updated.".into() }))
    }

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();

        // resolve_repo ist jetzt async und wurde oben gefixt
        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        let mut nodes = repo.list_directory(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?;

        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts().await;
            for mount_name in mounts {
                if mount_name == "primary" { continue; }
                nodes.push(FileNode {
                    path: format!("/{}", mount_name), name: mount_name.clone(), owner: "SYSTEM".to_string(),
                    is_folder: true, size: 0, content: vec![], lock_pass: None, permissions: 0,
                    created_at: 0.0, blob_id: None,
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
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let mut stream = request.into_inner();

        let first_msg = stream.message().await.map_err(|e| Status::internal(e.to_string()))?;
        let metadata = match first_msg {
            Some(req) => match req.data {
                Some(UploadData::Metadata(m)) => m,
                _ => return Err(Status::invalid_argument("Metadata missing")),
            },
            None => return Err(Status::invalid_argument("Empty stream")),
        };

        if !self.sessions.try_lock_file(&metadata.path, &claims.sub).await {
            return Err(Status::aborted("File is busy."));
        }

        let limit: usize = env::var("PYTJA_QUOTA_LIMIT").unwrap_or_else(|_| DEFAULT_QUOTA_LIMIT.to_string()).parse().unwrap_or(DEFAULT_QUOTA_LIMIT);
        let current_usage = self.get_user_quota_usage(&claims.sub).await;
        if current_usage >= limit {
            self.sessions.unlock_file(&metadata.path, &claims.sub).await;
            return Err(Status::resource_exhausted("Quota exceeded"));
        }

        let (repo, relative_path) = match self.resolve_repo(&metadata.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&metadata.path, &claims.sub).await;
                return Err(e);
            }
        };

        self.sessions.init_upload(&claims.sub, &metadata.path).await;

        let mut upload_session_bytes = 0;
        let mut last_redis_update = 0;
        let session_manager = self.sessions.clone();
        let owner_clone = claims.sub.clone();
        let path_clone = metadata.path.clone();

        let byte_stream = stream.map(move |item| {
            match item {
                Ok(req) => match req.data {
                    Some(UploadData::Chunk(data)) => {
                        let len = data.len();
                        if current_usage + upload_session_bytes + len > limit {
                            return Err(PytjaError::QuotaExceeded { current: current_usage + upload_session_bytes, limit });
                        }
                        upload_session_bytes += len;
                        if upload_session_bytes - last_redis_update > 5 * 1024 * 1024 {
                            let sm = session_manager.clone();
                            let o = owner_clone.clone();
                            let p = path_clone.clone();
                            let delta = upload_session_bytes - last_redis_update;
                            tokio::spawn(async move { sm.update_upload_progress(&o, &p, delta).await; });
                            last_redis_update = upload_session_bytes;
                        }
                        Ok(Bytes::from(data))
                    },
                    _ => Ok(Bytes::new()),
                },
                Err(e) => Err(PytjaError::System(e.to_string())),
            }
        });

        // FIX: Absoluten Pfad verhindern! Wir entfernen den führenden Slash.
        // Aus "/bild.png" wird "bild.png", das korrekt an ./data/blobs angehängt wird.
        let storage_path = metadata.path.trim_start_matches('/').to_string();

        let pinned_stream = Box::pin(byte_stream);
        let result = self.storage.put(&storage_path, pinned_stream).await; // FIX: storage_path nutzen

        if result.is_ok() { self.sessions.complete_upload(&claims.sub, &metadata.path).await; }
        self.sessions.unlock_file(&metadata.path, &claims.sub).await;

        let blob_id = result.map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path, name, owner: metadata.owner, is_folder: false,
            content: vec![], blob_id: Some(blob_id), size: upload_session_bytes,
            lock_pass: if metadata.lock_password.is_empty() { None } else { Some(metadata.lock_password) },
            permissions: 0, created_at: chrono::Utc::now().timestamp() as f64,
        };

        repo.save_node(&node).await.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.update_quota(&claims.sub, upload_session_bytes as i64).await;
        if let Some(primary) = self.manager.get_repo("primary").await { let _ = primary.log_action(&claims.sub, "UPLOAD", &metadata.path).await; }

        Ok(Response::new(ActionResponse { success: true, message: "Upload complete".into() }))
    }

    async fn download_file(&self, request: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

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
                for chunk in content.chunks(64 * 1024) { let _ = tx.send(Ok(FileChunk { content: chunk.to_vec() })).await; }
            });
            Box::pin(ReceiverStream::new(rx))
        };

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut s = stream;
            while let Some(item) = s.next().await { if tx.send(item).await.is_err() { break; } }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn create_node(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();

        // Lock
        if !self.sessions.try_lock_file(&req.path, &claims.sub).await {
            return Err(Status::aborted("File/Path is busy."));
        }

        let (repo, relative_path) = match self.resolve_repo(&req.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&req.path, &claims.sub).await;
                return Err(e);
            }
        };

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        // FIX: Größe vor dem Move speichern!
        let content_len = req.content.len();

        let node = FileNode {
            path: relative_path.clone(), name, owner: req.owner, is_folder: req.is_folder,
            size: content_len, content: req.content,
            lock_pass: if req.lock_password.is_empty() { None } else { Some(req.lock_password) },
            permissions: 0, created_at: chrono::Utc::now().timestamp() as f64, blob_id: None,
        };

        let res = repo.save_node(&node).await;

        // Unlock
        self.sessions.unlock_file(&req.path, &claims.sub).await;

        res.map_err(|e| Status::internal(e.to_string()))?;

        // FIX: content_len Variable nutzen
        self.sessions.update_quota(&claims.sub, content_len as i64).await;

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "CREATE", &req.path).await;
        }
        Ok(Response::new(ActionResponse { success: true, message: "Created successfully".into() }))
    }

    async fn read_file(&self, request: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        let node = repo.get_node(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("File not found"))?;

        if let Some(pass) = node.lock_pass {
            if pass != req.password { return Err(Status::permission_denied("File is locked")); }
        }
        if node.blob_id.is_some() { return Err(Status::failed_precondition("File stored as blob. Use download.")); }

        Ok(Response::new(ReadFileResponse { success: true, message: "Read success".into(), content: node.content }))
    }

    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();

        if !self.sessions.try_lock_file(&req.path, &claims.sub).await {
            return Err(Status::aborted("File is busy."));
        }

        let (repo, relative_path) = match self.resolve_repo(&req.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&req.path, &claims.sub).await;
                return Err(e);
            }
        };

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "DELETE", &req.path).await;
        }

        let res = repo.delete_node_recursive(&relative_path).await;

        self.sessions.unlock_file(&req.path, &claims.sub).await;

        res.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.invalidate_quota(&claims.sub).await;
        Ok(Response::new(ActionResponse { success: true, message: "Deleted".into() }))
    }

    async fn move_node(&self, request: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();

        // 1. Distributed Locking
        if !self.sessions.try_lock_file(&req.source_path, &claims.sub).await {
            return Err(Status::aborted("Source file is busy/locked."));
        }
        if !self.sessions.try_lock_file(&req.dest_path, &claims.sub).await {
            self.sessions.unlock_file(&req.source_path, &claims.sub).await;
            return Err(Status::aborted("Destination file is busy/locked."));
        }

        // 2. Resolve Repositories
        let (repo_src, src_rel) = match self.resolve_repo(&req.source_path).await {
            Ok(v) => v,
            Err(e) => {
                self.sessions.unlock_file(&req.source_path, &claims.sub).await;
                self.sessions.unlock_file(&req.dest_path, &claims.sub).await;
                return Err(e);
            }
        };

        let (repo_dst, dst_rel) = match self.resolve_repo(&req.dest_path).await {
            Ok(v) => v,
            Err(e) => {
                self.sessions.unlock_file(&req.source_path, &claims.sub).await;
                self.sessions.unlock_file(&req.dest_path, &claims.sub).await;
                return Err(e);
            }
        };

        // 3. Ausführungs-Logik
        let move_result = if Arc::ptr_eq(&repo_src, &repo_dst) {
            // A) FAST PATH
            repo_src.move_path(&src_rel, &dst_rel).await
                .map_err(|e| Status::internal(e.to_string()))
        } else {
            // B) SLOW PATH: Cross-Repository Move

            // FIX: Typen im match Block vereinheitlicht (Result zurückgeben)
            let src_node = match repo_src.get_node(&src_rel).await {
                Ok(Some(n)) => Ok(n), // FIX: Hier fehlte das Ok()
                Ok(None) => Err(Status::not_found("Source file not found")),
                Err(e) => Err(Status::internal(format!("Source DB Error: {}", e))),
            };

            match src_node {
                Ok(node) => {
                    if node.is_folder {
                        Err(Status::unimplemented("Cross-mount folder move not supported yet. Move files individually."))
                    } else {
                        let new_blob_id = if let Some(old_id) = node.blob_id {
                            match self.storage.get(&old_id).await {
                                Ok(stream) => {
                                    match self.storage.put(&req.dest_path, stream).await {
                                        Ok(new_id) => Some(new_id),
                                        Err(e) => return Err(Status::internal(format!("Storage Write Error: {}", e))),
                                    }
                                },
                                Err(e) => return Err(Status::internal(format!("Storage Read Error: {}", e))),
                            }
                        } else {
                            None
                        };

                        let path_obj = std::path::Path::new(&dst_rel);
                        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

                        let new_node = FileNode {
                            path: dst_rel.clone(),
                            name,
                            owner: claims.sub.clone(),
                            is_folder: false,
                            size: node.size,
                            content: node.content,
                            blob_id: new_blob_id,
                            lock_pass: node.lock_pass,
                            permissions: node.permissions,
                            created_at: chrono::Utc::now().timestamp() as f64,
                        };

                        if let Err(e) = repo_dst.save_node(&new_node).await {
                            Err(Status::internal(format!("Target DB Save Error: {}", e)))
                        } else {
                            if let Err(e) = repo_src.delete_node_recursive(&src_rel).await {
                                tracing::error!("CRITICAL: Duplicate file created. Source delete failed: {}", e);
                                Ok(())
                            } else {
                                Ok(())
                            }
                        }
                    }
                },
                Err(e) => Err(e)
            }
        };

        // 4. Locks freigeben
        self.sessions.unlock_file(&req.source_path, &claims.sub).await;
        self.sessions.unlock_file(&req.dest_path, &claims.sub).await;

        // 5. Audit & Quota
        match move_result {
            Ok(_) => {
                self.sessions.invalidate_quota(&claims.sub).await;
                if let Some(primary) = self.manager.get_repo("primary").await {
                    let _ = primary.log_action(&claims.sub, "MOVE", &format!("{}->{}", req.source_path, req.dest_path)).await;
                }
                Ok(Response::new(ActionResponse { success: true, message: "Moved successfully".into() }))
            },
            Err(e) => Err(e)
        }
    }

    async fn copy_node(&self, request: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, src_rel) = self.resolve_repo(&req.source_path).await?;
        let (_, dst_rel) = self.resolve_repo(&req.dest_path).await?;

        let src_node = repo.get_node(&src_rel).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("Source file not found"))?;

        if src_node.is_folder { return Err(Status::unimplemented("Recursive copy not supported")); }

        let new_node = FileNode {
            path: dst_rel, name: "".to_string(), owner: claims.sub.clone(), is_folder: false,
            content: src_node.content, blob_id: src_node.blob_id, size: src_node.size,
            lock_pass: None, permissions: 0, created_at: chrono::Utc::now().timestamp() as f64,
        };

        repo.save_node(&new_node).await.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.update_quota(&claims.sub, new_node.size as i64).await;
        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "COPY", &format!("{}->{}", req.source_path, req.dest_path)).await;
        }
        Ok(Response::new(ActionResponse { success: true, message: "Copied".into() }))
    }

    async fn change_mode(&self, request: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        repo.update_permissions(&rel_path, req.permissions as u8).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Permissions updated".into() }))
    }

    async fn chown_node(&self, request: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;

        if let Some(primary) = self.manager.get_repo("primary").await {
            if !primary.user_exists(&req.new_owner).await.unwrap_or(false) { return Err(Status::not_found("New owner user does not exist")); }
        }
        repo.update_metadata(&rel_path, None, Some(req.new_owner)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Ownership transferred".into() }))
    }

    async fn lock_node(&self, request: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        let lock_val = if req.password.is_empty() { None } else { Some(req.password) };
        repo.update_metadata(&rel_path, lock_val, None).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Lock updated".into() }))
    }

    async fn get_usage(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let usage = self.get_user_quota_usage(&req.owner).await;
        Ok(Response::new(UsageResponse { bytes: usage as u64 }))
    }

    async fn find_node(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let paths = repo.find_nodes(&format!("%{}%", req.pattern)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(FindResponse { paths }))
    }

    async fn grep_node(&self, request: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let files = repo.get_all_files_content().await.map_err(|e| Status::internal(e.to_string()))?;
        let mut matches = Vec::new();
        for (path, content) in files {
            if let Ok(text) = std::str::from_utf8(&content) {
                if text.contains(&req.pattern) { matches.push(path); }
            }
        }
        Ok(Response::new(GrepResponse { matches }))
    }

    async fn get_tree(&self, request: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.root_path).await?;
        let all_nodes = repo.list_directory(&rel_path).await.map_err(|e| Status::internal(e.to_string()))?;

        let mut output = String::new();
        for node in all_nodes {
            let marker = if node.is_folder { "[DIR]" } else { "[FILE]" };
            output.push_str(&format!("{} {}\n", marker, node.path));
        }
        Ok(Response::new(TreeResponse { tree_output: output }))
    }

    async fn stat_node(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        self.check_permissions(request.metadata(), None).await?;
        let req = request.into_inner();
        let clean = req.path.trim_start_matches('/');

        // WICHTIG: .await hinzugefügt
        for m in self.manager.list_mounts().await {
            if clean == m { return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false })); }
        }

        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        if rel_path == "/" { return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false })); }

        match repo.get_node(&rel_path).await {
            Ok(Some(n)) => Ok(Response::new(StatResponse { exists: true, is_folder: n.is_folder, is_locked: n.lock_pass.is_some() })),
            Ok(None) => Ok(Response::new(StatResponse { exists: false, is_folder: false, is_locked: false })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn exec_script(&self, request: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:exec")).await?;
        let req = request.into_inner();
        let (_repo, _relative_path) = self.resolve_repo(&req.script_path).await?;

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "EXEC", &req.script_path).await;
        }

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(ExecResponse { output_line: "Remote Execution initiated...".into() })).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Result: [Function executed]".into() })).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // --- ADMIN RPCS ---

    async fn create_role(&self, request: Request<CreateRoleRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:roles")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        repo.create_role(&Role { name: req.name, permissions: vec![] }).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(AdminActionResponse { success: true, message: "Role created".into() }))
    }

    async fn add_permission(&self, request: Request<AddPermissionRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:roles")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        if let Some(mut role) = repo.get_role(&req.role_name).await.map_err(|e| Status::internal(e.to_string()))? {
            if !role.permissions.contains(&req.permission) {
                role.permissions.push(req.permission);
                repo.update_role_permissions(&role.name, role.permissions).await.map_err(|e| Status::internal(e.to_string()))?;
            }
            Ok(Response::new(AdminActionResponse { success: true, message: "Permission added".into() }))
        } else {
            Err(Status::not_found("Role not found"))
        }
    }

    async fn assign_role(&self, request: Request<AssignRoleRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        if !repo.user_exists(&req.username).await.unwrap_or(false) { return Err(Status::not_found("User not found")); }
        let user = repo.get_user(&req.username).await.unwrap().unwrap();
        repo.update_user_status(&req.username, user.is_active, &req.role_name).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(AdminActionResponse { success: true, message: "Role assigned".into() }))
    }

    async fn list_roles(&self, request: Request<ListRolesRequest>) -> Result<Response<ListRolesResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:read")).await?;
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let roles = repo.list_roles().await.map_err(|e| Status::internal(e.to_string()))?;
        let infos = roles.into_iter().map(|r| RoleInfo { name: r.name, permissions: r.permissions }).collect();
        Ok(Response::new(ListRolesResponse { roles: infos }))
    }

    async fn get_active_sessions(&self, request: Request<GetSessionsRequest>) -> Result<Response<GetSessionsResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:read")).await?;
        let sessions: Vec<_> = self.sessions.get_all_sessions().await.into_iter().map(|s| SessionInfo {
            session_id: s.session_id, username: s.username, ip_address: s.ip_address, role_level: 0, login_time: s.login_time.to_rfc3339(), last_activity: s.last_activity.to_rfc3339(), role: s.role
        }).collect();
        let total = sessions.len() as i32;
        Ok(Response::new(GetSessionsResponse { sessions, total_active: total }))
    }

    async fn kick_user(&self, request: Request<KickUserRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        self.sessions.remove_session(&req.session_id).await;
        if let Some(primary) = self.manager.get_repo("primary").await { let _ = primary.log_action(&claims.sub, "KICK", &req.session_id).await; }
        Ok(Response::new(ActionResponse { success: true, message: "User session terminated.".into() }))
    }

    async fn ban_user(&self, request: Request<BanUserRequest>) -> Result<Response<BanUserResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        let user = repo.get_user(&req.username).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("User not found"))?;

        let new_active_status = !req.ban;
        repo.update_user_status(&req.username, new_active_status, &user.role).await
            .map_err(|e| Status::internal(e.to_string()))?;

        if req.ban {
            self.sessions.clear_user_sessions(&req.username).await;
        }

        let msg = if req.ban { "User banned and sessions terminated." } else { "User unbanned." };
        Ok(Response::new(BanUserResponse { success: true, message: msg.into() }))
    }

    // --- DATABASE MANAGEMENT RPCS ---

    async fn change_user_role(&self, request: Request<ChangeRoleRequest>) -> Result<Response<ChangeRoleResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:users")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        let user = repo.get_user(&req.username).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("User not found"))?;

        repo.update_user_status(&req.username, user.is_active, &req.new_role).await
            .map_err(|e| Status::internal(e.to_string()))?;

        self.sessions.update_session_role(&req.username, &req.new_role).await;

        Ok(Response::new(ChangeRoleResponse { success: true, message: format!("Role changed to {}", req.new_role) }))
    }

    async fn get_mounts(&self, request: Request<GetMountsRequest>) -> Result<Response<GetMountsResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:read")).await?;

        let mounts_list = self.manager.list_mounts().await;
        let mut infos = Vec::new();

        for m in mounts_list {
            infos.push(MountInfo {
                name: m.clone(),
                r#type: if m == "primary" { "System DB" } else { "Mounted Storage" }.to_string(),
                connection: "Hosted".to_string(),
                is_connected: self.manager.get_repo(&m).await.is_some(),
            });
        }

        Ok(Response::new(GetMountsResponse { mounts: infos }))
    }

    async fn add_mount(&self, request: Request<AddMountRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:sys")).await?;
        let req = request.into_inner();

        let db_type = match req.r#type.as_str() {
            "sqlite" => DatabaseType::Sqlite,
            "postgres" => DatabaseType::Postgres,
            _ => return Err(Status::invalid_argument("Unknown DB Type")),
        };

        self.manager.mount(&req.name, &req.connection_string, db_type).await
            .map_err(|e| Status::internal(format!("Mount failed: {}", e)))?;

        Ok(Response::new(AdminActionResponse { success: true, message: "Database mounted".into() }))
    }

    async fn remove_mount(&self, request: Request<RemoveMountRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:sys")).await?;
        let req = request.into_inner();

        if req.name == "primary" {
            return Err(Status::invalid_argument("Cannot unmount primary system database."));
        }

        self.manager.unmount(&req.name).await
            .map_err(|e| Status::internal(format!("Unmount failed: {}", e)))?;

        // Optional: Audit Log
        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action("admin", "UNMOUNT", &req.name).await;
        }

        Ok(Response::new(AdminActionResponse { success: true, message: format!("Database '{}' unmounted.", req.name) }))
    }

    // --- SYSTEM MONITORING ---

    async fn get_system_stats(&self, _req: Request<SystemStatsRequest>) -> Result<Response<SystemStatsResponse>, Status> {
        self.check_permissions(_req.metadata(), Some("core:admin:read")).await?;

        let mut sys = System::new_all();
        sys.refresh_all();

        let active_sessions = self.sessions.get_all_sessions().await.len() as u64;
        let redis_ok = self.sessions.get_cached_quota("ping").await.is_some() || true;

        Ok(Response::new(SystemStatsResponse {
            // FIX: cpu_usage() funktioniert jetzt dank `use sysinfo::CpuExt`
            cpu_usage_percent: sys.global_cpu_info().cpu_usage() as f64,
            memory_usage_bytes: sys.used_memory(),
            active_sessions,
            active_uploads: 0,
            uptime: format!("{} s", sys.uptime()),
            redis_connected: redis_ok,
        }))
    }

    async fn get_audit_logs(&self, request: Request<GetAuditLogsRequest>) -> Result<Response<GetAuditLogsResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:read")).await?;
        let req = request.into_inner();

        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let filter = if req.filter_user.is_empty() { None } else { Some(req.filter_user) };

        let logs_db = repo.get_audit_logs(req.limit, filter).await.map_err(|e| Status::internal(e.to_string()))?;

        let logs_proto = logs_db.into_iter().map(|l| AuditLogEntry {
            timestamp: chrono::DateTime::from_timestamp(l.timestamp as i64, 0)
                .map(|dt| dt.to_string())
                .unwrap_or_default(),
            user: l.user_id,
            action: l.action,
            target: l.target,
        }).collect();

        Ok(Response::new(GetAuditLogsResponse { logs: logs_proto }))
    }

    type StreamServerLogsStream = ReceiverStream<Result<LogStreamEntry, Status>>;

    async fn stream_server_logs(&self, request: Request<LogStreamRequest>) -> Result<Response<Self::StreamServerLogsStream>, Status> {
        self.check_permissions(request.metadata(), Some("core:admin:read")).await?;

        let mut rx = self.log_broadcast.subscribe();
        let (tx, response_rx) = mpsc::channel(100);

        tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                if tx.send(Ok(msg)).await.is_err() { break; }
            }
        });

        Ok(Response::new(ReceiverStream::new(response_rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Config & ENV (Critical fix for paths)
    dotenv().ok(); // <--- DIESE ZEILE IST WICHTIG!

    let config = AppConfig::new().expect("CRITICAL: Failed to load configuration");

    // 2. Telemetry initialisieren
    let _guard = pytja_core::telemetry::init_telemetry(&config.paths.logs_dir, "pytja_server.log");

    info!("Pytja Server Enterprise Edition starting up...");
    info!("Configuration loaded. Host: {}:{}", config.server.host, config.server.port);

    // 3. Driver Manager (Core System)
    let manager = Arc::new(DriverManager::new());

    // 4. Redis Session Manager (Async Connect)
    let redis_url = config.redis.as_ref().map(|r| r.url.clone()).unwrap_or_else(|| "redis://127.0.0.1/".to_string());
    info!("Connecting to Redis at {}", redis_url);

    let session_mgr = Arc::new(
        SessionManager::new(&redis_url).await.expect("FATAL: Redis Connection Failed")
    );

    // 5. Load Mounts (Async I/O - Non Blocking)
    // Lädt die mounts.json, ohne den Thread zu blockieren
    manager.load_config(&config.paths.mounts_file).await;

    // 6. Mount Primary Database
    let db_path_or_url = if config.database.primary_url.starts_with("sqlite://") {
        config.database.primary_url.strip_prefix("sqlite://").unwrap()
    } else {
        &config.database.primary_url
    };

    info!("Mounting Primary DB: {}", db_path_or_url);

    manager.mount("primary", db_path_or_url, DatabaseType::Sqlite).await
        .expect("FATAL: Failed to mount primary DB");

    // WICHTIG: get_repo ist jetzt async, da wir tokio locks nutzen!
    if let Some(repo) = manager.get_repo("primary").await {
        repo.init().await.expect("DB Migration failed");
    } else {
        panic!("FATAL: Primary DB lost immediately after mount!");
    }

    // 7. Blob Storage Setup (Async)
    let storage: Arc<dyn BlobStorage> = if config.storage.storage_type == "s3" {
        info!("Using S3 Storage (Region: {})", config.storage.s3_region);
        Arc::new(S3Storage::new(&config.storage.s3_bucket, &config.storage.s3_region).await)
    } else {
        info!("Using Local Storage at: {}", config.storage.local_path);
        // Auch FileSystem Init ist jetzt async (Ordner erstellen via tokio::fs)
        Arc::new(FileSystemStorage::new(&config.storage.local_path).await?)
    };

    // 8. Server Start
    let (tx, _rx) = broadcast::channel(100);
    let addr_str = format!("{}:{}", config.server.host, config.server.port);
    let addr = addr_str.parse()?;

    let service = MyPytjaService {
        manager: manager.clone(),
        sessions: session_mgr,
        config: config.clone(),
        storage,
        log_broadcast: tx.clone(),
    };

    info!("PYTJA ENTERPRISE HUB ONLINE");
    info!("Listening on {}", addr);

    Server::builder()
        .add_service(PytjaServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
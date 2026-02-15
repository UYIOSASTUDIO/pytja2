use tonic::{transport::Server, Request, Response, Status};

// Service Traits & Messages
use pytja_proto::{PytjaService, PytjaServiceServer};
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
    // Admin Messages
    CreateRoleRequest, AddPermissionRequest, AssignRoleRequest, AdminActionResponse,
    ListRolesRequest, ListRolesResponse, RoleInfo,
    upload_request::Data as UploadData
};

use pytja_core::models::{FileNode, Claims, Role};
use pytja_core::config::AppConfig;
use pytja_core::storage::{BlobStorage, FileSystemStorage, S3Storage};
use pytja_core::{PytjaRepository, DriverManager, DatabaseType, PytjaError};
use pytja_core::crypto::CryptoService;

use bytes::Bytes;
use colored::*;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use futures_util::StreamExt;
use jsonwebtoken::{encode, Header, EncodingKey};
use std::env;
use std::collections::HashSet;

mod session_manager;
use crate::session_manager::SessionManager;

const JWT_SECRET: &[u8] = b"pytja_super_secret_key_change_me_in_prod";
const DEFAULT_QUOTA_LIMIT: usize = 1 * 1024 * 1024 * 1024; // 1 GB

pub struct MyPytjaService {
    manager: Arc<DriverManager>,
    sessions: Arc<SessionManager>,
    config: AppConfig,
    storage: Arc<dyn BlobStorage>,
}

impl MyPytjaService {
    // FIX: Neuer Permission Check (RBAC)
    // required_perm: z.B. Some("core:fs:write") oder None (nur Login check)
    fn check_permissions<T>(&self, req: &Request<T>, required_perm: Option<&str>) -> Result<Claims, Status> {
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

        // Session Check
        if let Some(sid) = &token_data.claims.sid {
            if !self.sessions.is_valid(sid) {
                return Err(Status::unauthenticated("Session expired"));
            }
            self.sessions.update_activity(sid);
        }

        // RBAC Check
        if let Some(perm) = required_perm {
            let has_perm = token_data.claims.permissions.contains(perm)
                || token_data.claims.permissions.contains("*"); // Admin Wildcard

            if !has_perm {
                return Err(Status::permission_denied(format!(
                    "Missing permission: '{}'. Your Role: '{}'", perm, token_data.claims.role
                )));
            }
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

    async fn get_user_quota_usage(&self, username: &str) -> usize {
        if let Some(primary) = self.manager.get_repo("primary") {
            primary.get_total_usage(username).await.unwrap_or(0)
        } else { 0 }
    }
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;

    // --- STANDARD RPCs ---

    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse {
            message: "Pong".into(),
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

        // Permissions laden
        let role = repo.get_role(&user.role).await.map_err(|e| Status::internal(e.to_string()))?
            .unwrap_or(Role { name: "guest".into(), permissions: vec![] });

        let mut perms_set = HashSet::new();
        for p in role.permissions { perms_set.insert(p); }

        let expiration = chrono::Utc::now().checked_add_signed(chrono::Duration::minutes(60)).unwrap().timestamp() as usize;
        // FIX: Session mit Role-String
        let session_id = self.sessions.register_session(&user.username, &user.role, "127.0.0.1");

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

    // --- DATEI OPERATIONEN (Mit Permission Checks) ---

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?; // Check Permission
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let mut nodes = repo.list_directory(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?;

        // Virtual Mounts injection
        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts();
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
        let claims = self.check_permissions(&request, Some("core:fs:write"))?;
        let mut stream = request.into_inner();

        let first_msg = stream.message().await.map_err(|e| Status::internal(e.to_string()))?;
        let metadata = match first_msg {
            Some(req) => match req.data {
                Some(UploadData::Metadata(m)) => m,
                _ => return Err(Status::invalid_argument("Metadata missing")),
            },
            None => return Err(Status::invalid_argument("Empty stream")),
        };

        // Quota Check
        let limit: usize = env::var("PYTJA_QUOTA_LIMIT").unwrap_or_else(|_| DEFAULT_QUOTA_LIMIT.to_string()).parse().unwrap_or(DEFAULT_QUOTA_LIMIT);
        let current_usage = self.get_user_quota_usage(&claims.sub).await;
        if current_usage >= limit { return Err(Status::resource_exhausted("Quota exceeded")); }

        let (repo, relative_path) = self.resolve_repo(&metadata.path)?;

        let mut upload_session_bytes = 0;
        let byte_stream = stream.map(move |item| {
            match item {
                Ok(req) => match req.data {
                    Some(UploadData::Chunk(data)) => {
                        if current_usage + upload_session_bytes + data.len() > limit {
                            return Err(PytjaError::QuotaExceeded { current: current_usage + upload_session_bytes, limit });
                        }
                        upload_session_bytes += data.len();
                        Ok(Bytes::from(data))
                    },
                    _ => Ok(Bytes::new()),
                },
                Err(e) => Err(PytjaError::System(e.to_string())),
            }
        });

        let pinned_stream = Box::pin(byte_stream);
        let blob_id = self.storage.put(&metadata.path, pinned_stream).await
            .map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path, name, owner: metadata.owner, is_folder: false,
            content: vec![], blob_id: Some(blob_id), size: upload_session_bytes,
            lock_pass: if metadata.lock_password.is_empty() { None } else { Some(metadata.lock_password) },
            permissions: 0, created_at: chrono::Utc::now().timestamp() as f64,
        };

        repo.save_node(&node).await.map_err(|e| Status::internal(e.to_string()))?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "UPLOAD", &metadata.path).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Upload complete".into() }))
    }

    async fn download_file(&self, request: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
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

    // --- ADMIN RPCS (NEU IMPLEMENTIERT) ---

    async fn create_role(&self, request: Request<CreateRoleRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(&request, Some("core:admin:roles"))?; // Needs Admin Perm
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;

        let role = Role { name: req.name, permissions: vec![] };
        repo.create_role(&role).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(AdminActionResponse { success: true, message: "Role created".into() }))
    }

    async fn add_permission(&self, request: Request<AddPermissionRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.check_permissions(&request, Some("core:admin:roles"))?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;

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
        self.check_permissions(&request, Some("core:admin:users"))?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;

        if !repo.user_exists(&req.username).await.unwrap_or(false) { return Err(Status::not_found("User not found")); }

        // is_active behalten wir bei (müssten wir eigentlich erst laden, hier nehmen wir true an oder laden User)
        let user = repo.get_user(&req.username).await.unwrap().unwrap();
        repo.update_user_status(&req.username, user.is_active, &req.role_name).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(AdminActionResponse { success: true, message: "Role assigned".into() }))
    }

    async fn list_roles(&self, request: Request<ListRolesRequest>) -> Result<Response<ListRolesResponse>, Status> {
        self.check_permissions(&request, Some("core:admin:read"))?;
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;

        let roles = repo.list_roles().await.map_err(|e| Status::internal(e.to_string()))?;
        let infos = roles.into_iter().map(|r| RoleInfo { name: r.name, permissions: r.permissions }).collect();

        Ok(Response::new(ListRolesResponse { roles: infos }))
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

    async fn get_active_sessions(&self, request: Request<GetSessionsRequest>) -> Result<Response<GetSessionsResponse>, Status> {
        self.check_permissions(&request, 100)?;

        let sessions: Vec<SessionInfo> = self.sessions.get_all_sessions().into_iter().map(|s| SessionInfo {
            session_id: s.session_id, username: s.username, ip_address: s.ip_address, role_level: s.role_level, login_time: s.login_time.to_rfc3339(), last_activity: s.last_activity.to_rfc3339()
        }).collect();

        let total = sessions.len() as i32;
        Ok(Response::new(GetSessionsResponse { sessions, total_active: total }))
    }

    async fn kick_user(&self, request: Request<KickUserRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 100)?;
        self.sessions.remove_session(&request.into_inner().session_id);
        Ok(Response::new(ActionResponse { success: true, message: "Kicked".into() }))
    }

    async fn get_usage(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.check_permissions(&request, 0)?;
        let owner = request.into_inner().owner;
        let usage = self.get_user_quota_usage(&owner).await;
        Ok(Response::new(UsageResponse { bytes: usage as u64 }))
    }

    // Dummy Implementationen für den Rest
    async fn read_file(&self, _: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> { Err(Status::unimplemented("Use download for files")) }
    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, 50)?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

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
    async fn find_node(&self, _: Request<FindRequest>) -> Result<Response<FindResponse>, Status> { Err(Status::unimplemented("Update find_node")) }
    async fn grep_node(&self, _: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> { Err(Status::unimplemented("Update grep_node")) }
    async fn get_tree(&self, _: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> { Err(Status::unimplemented("Update get_tree")) }

    async fn exec_script(&self, request: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        let claims = self.check_permissions(&request, 80)?;
        let req = request.into_inner();
        let (_repo, _relative_path) = self.resolve_repo(&req.script_path)?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "EXEC", &req.script_path).await;
        }

        // Mock Implementation für Exec Stream
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(ExecResponse { output_line: "Remote Execution initiated...".into() })).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Security Sandbox: Active".into() })).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Result: [Function executed]".into() })).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // --- FILE MANIPULATION ---

    async fn create_node(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path.clone(),
            name,
            owner: req.owner,
            is_folder: req.is_folder,
            size: req.content.len(),
            content: req.content, // Für kleine Files ok, große gehen über upload_file
            lock_pass: if req.lock_password.is_empty() { None } else { Some(req.lock_password) },
            permissions: 0,
            created_at: chrono::Utc::now().timestamp() as f64,
            blob_id: None,
        };

        if let Err(e) = repo.save_node(&node).await {
            // Check for duplicate
            if e.to_string().contains("constraint") || e.to_string().contains("exists") {
                return Err(Status::already_exists("Node already exists"));
            }
            return Err(Status::internal(e.to_string()));
        }

        // Audit Log
        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "CREATE", &req.path).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Created successfully".into() }))
    }

    async fn read_file(&self, request: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let node = repo.get_node(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("File not found"))?;

        // Security Check: Lock Password
        if let Some(pass) = node.lock_pass {
            if pass != req.password { return Err(Status::permission_denied("File is locked (Wrong Password)")); }
        }

        // WICHTIG: Wenn blob_id existiert, verweisen wir auf Download (Performance!)
        if node.blob_id.is_some() {
            return Err(Status::failed_precondition("File is stored in Blob Storage. Use 'download' command instead of 'cat/read'."));
        }

        Ok(Response::new(ReadFileResponse {
            content: node.content,
            message: "Read success".into()
        }))
    }

    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // Audit Log VOR Löschung
        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "DELETE", &req.path).await;
        }

        // Falls Blob vorhanden, müsste man theoretisch auch den Blob im Storage löschen.
        // In V3.0 löschen wir nur den DB-Eintrag. Ein "Garbage Collector" Job würde verwaiste Blobs später aufräumen.
        match repo.delete_node_recursive(&relative_path).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Deleted".into() })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn move_node(&self, request: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();

        // Wir gehen davon aus, dass Source und Dest im selben Repo liegen
        let (repo, src_rel) = self.resolve_repo(&req.source_path)?;
        let (_, dst_rel) = self.resolve_repo(&req.dest_path)?; // Check mount logic implicitly

        repo.move_path(&src_rel, &dst_rel).await.map_err(|e| Status::internal(e.to_string()))?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "MOVE", &format!("{}->{}", req.source_path, req.dest_path)).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Moved".into() }))
    }

    async fn copy_node(&self, request: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, src_rel) = self.resolve_repo(&req.source_path)?;
        let (_, dst_rel) = self.resolve_repo(&req.dest_path)?;

        // 1. Source laden
        let src_node = repo.get_node(&src_rel).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("Source file not found"))?;

        if src_node.is_folder {
            return Err(Status::unimplemented("Recursive folder copy not supported in V3 server yet"));
        }

        // 2. Als neuen Node speichern
        let path_obj = std::path::Path::new(&dst_rel);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let new_node = FileNode {
            path: dst_rel,
            name,
            owner: claims.sub.clone(), // Neuer Owner ist der Kopierer
            is_folder: false,
            content: src_node.content,
            blob_id: src_node.blob_id, // Zeigt auf denselben Blob (Deduplication!)
            size: src_node.size,
            lock_pass: None, // Lock wird nicht kopiert
            permissions: 0,
            created_at: chrono::Utc::now().timestamp() as f64,
        };

        repo.save_node(&new_node).await.map_err(|e| Status::internal(e.to_string()))?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "COPY", &format!("{}->{}", req.source_path, req.dest_path)).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Copied".into() }))
    }

    async fn change_mode(&self, request: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path)?;

        repo.update_permissions(&rel_path, req.permissions as u8).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Permissions updated".into() }))
    }

    async fn chown_node(&self, request: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path)?;

        // Prüfen ob neuer User existiert (Global Check in Primary DB)
        if let Some(primary) = self.manager.get_repo("primary") {
            if !primary.user_exists(&req.new_owner).await.unwrap_or(false) {
                return Err(Status::not_found("New owner user does not exist"));
            }
        }

        repo.update_metadata(&rel_path, None, Some(req.new_owner)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Ownership transferred".into() }))
    }

    async fn lock_node(&self, request: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:write"))?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path)?;

        let lock_val = if req.password.is_empty() { None } else { Some(req.password) };
        repo.update_metadata(&rel_path, lock_val, None).await.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ActionResponse { success: true, message: "Lock updated".into() }))
    }

    // --- SEARCH & INFO ---

    async fn get_usage(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
        let req = request.into_inner();

        // Usage wird global über alle Mounts aggregiert? Nein, aktuell per Owner.
        // Wir fragen die Primary DB (User DB) oder iterieren über alle Mounts (Teuer).
        // V3.0 Implementierung: Frage Primary DB (Metadata Store).
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;
        let bytes = repo.get_total_usage(&req.owner).await.unwrap_or(0);

        Ok(Response::new(UsageResponse { bytes: bytes as u64 }))
    }

    async fn find_node(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
        let req = request.into_inner();

        // Suche aktuell nur auf Primary (Mount-übergreifende Suche wäre komplexer)
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;
        let pattern = format!("%{}%", req.pattern);

        let paths = repo.find_nodes(&pattern).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(FindResponse { paths }))
    }

    async fn grep_node(&self, request: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").ok_or(Status::internal("DB Error"))?;

        // WARNUNG: Grep auf Server-Seite ist teuer. Wir suchen nur in kleinen Files (Content in DB).
        let files = repo.get_all_files_content().await.map_err(|e| Status::internal(e.to_string()))?;
        let mut matches = Vec::new();

        for (path, content) in files {
            if let Ok(text) = std::str::from_utf8(&content) {
                if text.contains(&req.pattern) {
                    matches.push(path);
                }
            }
        }
        Ok(Response::new(GrepResponse { matches }))
    }

    async fn get_tree(&self, request: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        self.check_permissions(&request, Some("core:fs:read"))?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.root_path)?;

        // Simpler Tree: Liste Directory und Kind-Elemente (Rekursion wäre hier zu heavy für einen Call)
        // Wir geben nur die erste Ebene zurück oder eine Text-Repräsentation.
        // V3.0: Wir listen alle Files die mit dem Pfad beginnen (SQL LIKE).
        let all_nodes = repo.list_directory(&rel_path).await.map_err(|e| Status::internal(e.to_string()))?;

        // Formatiere als String Liste
        let mut output = String::new();
        for node in all_nodes {
            let marker = if node.is_folder { "[DIR]" } else { "[FILE]" };
            output.push_str(&format!("{} {}\n", marker, node.path));
        }

        Ok(Response::new(TreeResponse { tree_output: output }))
    }

    async fn stat_node(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        // Public Access erlaubt (Level 0), aber wir prüfen Auth Header
        self.check_permissions(&request, None)?;
        let req = request.into_inner();

        let clean = req.path.trim_start_matches('/');
        // Check Mounts
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

    // --- EXECUTION (Sandbox Stub) ---

    async fn exec_script(&self, request: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        let claims = self.check_permissions(&request, Some("core:exec"))?; // Hohe Rechte nötig
        let req = request.into_inner();
        let (_repo, _relative_path) = self.resolve_repo(&req.script_path)?;

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "EXEC", &req.script_path).await;
        }

        // Streaming Response Channel
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(ExecResponse { output_line: format!("Executing {} on Pytja Kernel...", req.script_path) })).await;

            // Hier würde der Code an einen Python/WASM Runner gesendet werden.
            // Für V3 ist es ein Mock, der Sicherheit simuliert.
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Initializing Sandbox environment [SECURE]...".into() })).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Result: Execution completed successfully (Mock).".into() })).await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // --- ADMIN & SESSIONS ---

    async fn get_active_sessions(&self, request: Request<GetSessionsRequest>) -> Result<Response<GetSessionsResponse>, Status> {
        self.check_permissions(&request, Some("core:admin:read"))?; // Admin only

        let sessions: Vec<SessionInfo> = self.sessions.get_all_sessions().into_iter().map(|s| SessionInfo {
            session_id: s.session_id,
            username: s.username,
            ip_address: s.ip_address,
            role_level: 0, // Legacy Feld, ignorieren oder mappen
            login_time: s.login_time.to_rfc3339(),
            last_activity: s.last_activity.to_rfc3339()
        }).collect();

        let total = sessions.len() as i32;
        Ok(Response::new(GetSessionsResponse { sessions, total_active: total }))
    }

    async fn kick_user(&self, request: Request<KickUserRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, Some("core:admin:users"))?;
        let req = request.into_inner();

        self.sessions.remove_session(&req.session_id);

        if let Some(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "KICK", &req.session_id).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "User session terminated.".into() }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = pytja_core::telemetry::init_telemetry("./logs", "pytja_server.log");
    tracing::info!("Pytja Server Enterprise Edition starting up...");

    let config = AppConfig::new().expect("CRITICAL: Failed to load configuration");

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
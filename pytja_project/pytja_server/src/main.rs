use tonic::{transport::Server, Request, Response, Status};
use pytja_proto::pytja::pytja_service_server::{PytjaService, PytjaServiceServer};
use pytja_proto::pytja::*; // Alle Proto-Typen importieren
use pytja_core::{DriverManager, AppConfig, BlobStorage, FileSystemStorage, S3Storage, drivers::DatabaseType};
use std::sync::Arc;
use tokio::sync::{mpsc, broadcast};
use tokio_stream::wrappers::ReceiverStream;
use tracing::info;
use dotenv::dotenv;

// Module einbinden
mod session_manager;
mod handlers;

use crate::session_manager::SessionManager;
use crate::handlers::service::MyPytjaService;

// Implementierung des gRPC Traits (Delegation an die Handler)
#[tonic::async_trait]
impl PytjaService for MyPytjaService {
    // Stream Typen definieren
    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;
    type StreamServerLogsStream = ReceiverStream<Result<LogStreamEntry, Status>>;

    // --- AUTHENTICATION ---
    async fn ping(&self, r: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        self.ping_impl(r).await
    }
    async fn get_challenge(&self, r: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        self.get_challenge_impl(r).await
    }
    async fn login(&self, r: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        self.login_impl(r).await
    }

    // --- FILESYSTEM OPERATIONS ---
    async fn list_directory(&self, r: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.list_directory_impl(r).await
    }
    async fn get_tree(&self, r: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        self.get_tree_impl(r).await
    }
    async fn upload_file(&self, r: Request<tonic::Streaming<UploadRequest>>) -> Result<Response<ActionResponse>, Status> {
        self.upload_file_impl(r).await
    }
    async fn download_file(&self, r: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        self.download_file_impl(r).await
    }
    async fn create_node(&self, r: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.create_node_impl(r).await
    }
    async fn read_file(&self, r: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        self.read_file_impl(r).await
    }
    async fn delete_node(&self, r: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.delete_node_impl(r).await
    }
    async fn move_node(&self, r: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.move_node_impl(r).await
    }
    async fn copy_node(&self, r: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.copy_node_impl(r).await
    }
    async fn change_mode(&self, r: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.change_mode_impl(r).await
    }
    async fn chown_node(&self, r: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        self.chown_node_impl(r).await
    }
    async fn lock_node(&self, r: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        self.lock_node_impl(r).await
    }
    async fn get_usage(&self, r: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.get_usage_impl(r).await
    }
    async fn find_node(&self, r: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        self.find_node_impl(r).await
    }
    async fn grep_node(&self, r: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        self.grep_node_impl(r).await
    }
    async fn stat_node(&self, r: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        self.stat_node_impl(r).await
    }
    async fn exec_script(&self, r: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        self.exec_script_impl(r).await
    }

    // --- USER ADMINISTRATION ---
    async fn list_users(&self, r: Request<ListUsersRequest>) -> Result<Response<ListUsersResponse>, Status> {
        self.list_users_impl(r).await
    }
    async fn register_user(&self, r: Request<RegisterUserRequest>) -> Result<Response<RegisterUserResponse>, Status> {
        self.register_user_impl(r).await
    }
    async fn set_user_quota(&self, r: Request<SetQuotaRequest>) -> Result<Response<SetQuotaResponse>, Status> {
        self.set_user_quota_impl(r).await
    }
    async fn change_user_role(&self, r: Request<ChangeRoleRequest>) -> Result<Response<ChangeRoleResponse>, Status> {
        self.change_user_role_impl(r).await
    }
    async fn kick_user(&self, r: Request<KickUserRequest>) -> Result<Response<ActionResponse>, Status> {
        self.kick_user_impl(r).await
    }
    async fn ban_user(&self, r: Request<BanUserRequest>) -> Result<Response<BanUserResponse>, Status> {
        self.ban_user_impl(r).await
    }
    async fn get_active_sessions(&self, r: Request<GetSessionsRequest>) -> Result<Response<GetSessionsResponse>, Status> {
        self.get_active_sessions_impl(r).await
    }

    // --- RBAC ADMINISTRATION ---
    async fn create_role(&self, r: Request<CreateRoleRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.create_role_impl(r).await
    }
    async fn add_permission(&self, r: Request<AddPermissionRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.add_permission_impl(r).await
    }
    async fn assign_role(&self, r: Request<AssignRoleRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.assign_role_impl(r).await
    }
    async fn list_roles(&self, r: Request<ListRolesRequest>) -> Result<Response<ListRolesResponse>, Status> {
        self.list_roles_impl(r).await
    }

    // --- SYSTEM & MOUNTS ---
    async fn get_system_stats(&self, r: Request<SystemStatsRequest>) -> Result<Response<SystemStatsResponse>, Status> {
        self.get_system_stats_impl(r).await
    }
    async fn stream_server_logs(&self, r: Request<LogStreamRequest>) -> Result<Response<Self::StreamServerLogsStream>, Status> {
        self.stream_server_logs_impl(r).await
    }
    async fn get_audit_logs(&self, r: Request<GetAuditLogsRequest>) -> Result<Response<GetAuditLogsResponse>, Status> {
        self.get_audit_logs_impl(r).await
    }
    async fn get_mounts(&self, r: Request<GetMountsRequest>) -> Result<Response<GetMountsResponse>, Status> {
        self.get_mounts_impl(r).await
    }
    async fn add_mount(&self, r: Request<AddMountRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.add_mount_impl(r).await
    }
    async fn remove_mount(&self, r: Request<RemoveMountRequest>) -> Result<Response<AdminActionResponse>, Status> {
        self.remove_mount_impl(r).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load ENV & Config
    dotenv().ok();
    let config = AppConfig::new().expect("CRITICAL: Failed to load configuration");

    // 2. Init Telemetry
    let _guard = pytja_core::telemetry::init_telemetry(&config.paths.logs_dir, "pytja_server.log");
    info!("Pytja Server Enterprise Edition starting up...");
    info!("Configuration loaded. Host: {}:{}", config.server.host, config.server.port);

    // 3. Driver Manager (Core System)
    let manager = Arc::new(DriverManager::new());

    // 4. Redis Session Manager
    let redis_url = config.redis.as_ref().map(|r| r.url.clone()).unwrap_or_else(|| "redis://127.0.0.1/".to_string());
    info!("Connecting to Redis at {}", redis_url);
    let session_mgr = Arc::new(SessionManager::new(&redis_url).await.expect("FATAL: Redis Connection Failed"));

    // 5. Load Mounts
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

    if let Some(repo) = manager.get_repo("primary").await {
        repo.init().await.expect("DB Migration failed");
    } else {
        panic!("FATAL: Primary DB lost immediately after mount!");
    }

    // 7. Blob Storage Setup
    let storage: Arc<dyn BlobStorage> = if config.storage.storage_type == "s3" {
        info!("Using S3 Storage (Region: {})", config.storage.s3_region);
        Arc::new(S3Storage::new(&config.storage.s3_bucket, &config.storage.s3_region).await)
    } else {
        info!("Using Local Storage at: {}", config.storage.local_path);
        Arc::new(FileSystemStorage::new(&config.storage.local_path).await?)
    };

    // 8. Broadcast Channel for Logs
    let (tx, _rx) = broadcast::channel(100);

    // 9. Service Construction
    let service = MyPytjaService {
        manager: manager.clone(),
        sessions: session_mgr,
        config: config.clone(),
        storage,
        log_broadcast: tx.clone(),
    };

    // 10. Start gRPC Server
    let addr_str = format!("{}:{}", config.server.host, config.server.port);
    let addr = addr_str.parse()?;
    info!("PYTJA ENTERPRISE HUB ONLINE");
    info!("Listening on {}", addr);

    Server::builder()
        .add_service(PytjaServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
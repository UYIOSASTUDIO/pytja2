use tonic::{transport::Server, Request, Response, Status};
use pytja_proto::{
    PytjaService, PytjaServiceServer,
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
    UploadRequest, FileMetadata,
    DownloadRequest, FileChunk,
    ExecRequest, ExecResponse,
    ChallengeRequest, ChallengeResponse,
    LoginRequest, LoginResponse
};
use pytja_core::models::{FileNode, Claims};
use colored::*;
use std::sync::Arc;
use pytja_core::{PytjaRepository, ConnectionManager, DatabaseType};
use pytja_core::crypto::CryptoService;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use futures_util::StreamExt;
use pytja_proto::pytja::upload_request::Data as UploadData;
use jsonwebtoken::{encode, Header, EncodingKey};

const JWT_SECRET: &[u8] = b"pytja_super_secret_key_change_me_in_prod";

pub struct MyPytjaService {
    manager: Arc<ConnectionManager>,
}

impl MyPytjaService {
    /// Zentrale Berechtigungsprüfung
    /// Holt das Token aus den Metadaten, validiert es und prüft das Level.
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
            // Wir suchen nach Pfaden, die mit dem Mount-Namen beginnen (z.B. "archive" oder "archive/bild.jpg")
            if clean_path == mount_name || clean_path.starts_with(&format!("{}/", mount_name)) {

                let repo = self.manager.get_repo(&mount_name)
                    .map_err(|_| Status::internal(format!("Mount '{}' not found", mount_name)))?;

                // Pfad relativieren: "archive/bild.jpg" -> "/bild.jpg"
                let relative_path = if clean_path == mount_name {
                    "/".to_string()
                } else {
                    format!("/{}", &clean_path[mount_name.len() + 1..])
                };

                return Ok((repo, relative_path));
            }
        }

        // Fallback: Primary DB
        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("Primary DB connection lost"))?;

        Ok((repo, full_path.to_string()))
    }

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.check_permissions(&request, 0)?;
        let req = request.into_inner();

        // 1. Router fragen
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // 2. Echte Dateien laden
        let mut nodes = repo.list_directory(&relative_path).await
            .map_err(|e| Status::internal(format!("DB Error: {}", e)))?;

        // 3. VIRTUAL INJECTION: Wenn wir im Root sind, fügen wir die Mounts hinzu!
        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts();
            for mount_name in mounts {
                // Wir zeigen alle Mounts an (außer es ist ein interner Name)

                // Einen Fake-Ordner erstellen
                let virtual_folder = FileNode {
                    path: format!("/{}", mount_name),
                    name: mount_name.clone(),
                    owner: "SYSTEM".to_string(),
                    is_folder: true, // WICHTIG: Es ist ein Ordner
                    size: 0,
                    content: vec![],
                    lock_pass: None,
                    permissions: 0,
                    created_at: 0.0,
                };

                nodes.push(virtual_folder);
            }
        }

        // 4. Konvertieren für gRPC
        let proto_files: Vec<FileInfo> = nodes.into_iter().map(|node| {
            FileInfo {
                name: node.name,
                is_folder: node.is_folder,
                size: node.size as u64,
                owner: node.owner,
                permissions: node.permissions as u32,
                created_at: node.created_at,
            }
        }).collect();

        Ok(Response::new(ListResponse { files: proto_files }))
    }
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;

    // Öffentlich (Kein Login nötig)
    async fn ping(&self, _request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let mounts = self.manager.list_mounts();
        let mount_info = format!("Active Mounts: {:?}", mounts);

        let reply = PingResponse {
            message: format!("Pong! Hub Status: {}", mount_info),
            server_version: "Pytja Hub V3.0 (Enterprise)".to_string(),
            is_ready: true,
        };
        Ok(Response::new(reply))
    }

    // Öffentlich (Authentifizierungs-Schritt 1)
    async fn get_challenge(&self, request: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("DB Error"))?;

        let exists = repo.user_exists(&req.username).await
            .map_err(|e| Status::internal(e.to_string()))?;

        let challenge = CryptoService::generate_random_challenge();

        Ok(Response::new(ChallengeResponse {
            challenge,
            user_exists: exists,
        }))
    }

    // Öffentlich (Authentifizierungs-Schritt 2)
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("DB Error"))?;

        // 1. User laden
        let user = match repo.get_user(&req.username).await {
            Ok(Some(u)) => u,
            Ok(None) => return Ok(Response::new(LoginResponse {
                success: false, token: "".into(), message: "User not found".into()
            })),
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        // 2. Signatur prüfen
        let challenge_bytes = req.challenge.as_bytes();
        let is_valid = match CryptoService::verify_signature(&user.public_key, challenge_bytes, &req.signature) {
            Ok(valid) => valid,
            Err(e) => {
                println!("Signature verification error: {}", e);
                false
            }
        };

        if !is_valid {
            return Ok(Response::new(LoginResponse {
                success: false, token: "".into(), message: "Invalid Signature".into()
            }));
        }

        // 3. Token erstellen (Mit echtem Level aus DB!)
        let expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(60))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: user.username.clone(),
            role_level: user.role_level, // WICHTIG: Das echte Level!
            exp: expiration,
        };

        let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)) {
            Ok(t) => t,
            Err(e) => return Err(Status::internal(format!("Token creation failed: {}", e))),
        };

        Ok(Response::new(LoginResponse {
            success: true,
            token,
            message: "Login successful".into(),
        }))
    }

    // --- LEVEL 0: GUEST (Nur gucken) ---

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        self.check_permissions(&request, 0)?; // Level 0 (Guest) darf listen
        let req = request.into_inner();

        // 1. Router fragen: Welche DB ist zuständig?
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // 2. Echte Dateien aus der zuständigen DB laden
        // Hinweis: Wir nutzen 'relative_path', damit die DB nicht verwirrt ist ("/" statt "/archive")
        let mut nodes = repo.list_directory(&relative_path).await
            .map_err(|e| Status::internal(format!("DB Error: {}", e)))?;

        // 3. SPEZIALFALL: Wenn wir im ROOT ("/") sind, müssen wir die Mounts hinzufügen!
        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts();
            for mount_name in mounts {
                if mount_name == "primary" { continue; } // Primary ist ja schon "hier"

                // Wir faken einen Ordner-Eintrag für den Mount
                nodes.push(pytja_core::models::FileNode {
                    path: format!("/{}", mount_name),
                    name: mount_name, // z.B. "archive"
                    owner: "SYSTEM".to_string(),
                    is_folder: true, // Wichtig: Wird als Ordner angezeigt
                    size: 0,
                    content: vec![],
                    lock_pass: None,
                    permissions: 0,
                    created_at: 0.0,
                });
            }
        }

        // 4. Mapping für Proto Response
        let proto_files: Vec<FileInfo> = nodes.into_iter().map(|node| {
            FileInfo {
                name: node.name,
                is_folder: node.is_folder,
                size: node.size as u64,
                owner: node.owner,
                permissions: node.permissions as u32,
                created_at: node.created_at,
            }
        }).collect();

        Ok(Response::new(ListResponse { files: proto_files }))
    }

    async fn stat_node(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        self.check_permissions(&request, 0)?;
        let req = request.into_inner();

        // LOGGING: Was kommt rein?
        tracing::info!("STAT CHECK: '{}'", req.path);

        // 1. Mount-Point Check (Direkter Vergleich)
        let clean_path = req.path.trim_start_matches('/').trim_end_matches('/'); // FIX: Auch hinten trimmen!
        let mounts = self.manager.list_mounts();

        tracing::info!(" -> Clean path: '{}', Mounts: {:?}", clean_path, mounts);

        for mount_name in mounts {
            if clean_path == mount_name {
                tracing::info!(" -> MATCH! Found mount '{}'", mount_name);
                return Ok(Response::new(StatResponse {
                    exists: true, is_folder: true, is_locked: false,
                }));
            }
        }

        // 2. Router fragen
        tracing::info!(" -> No direct match, asking Router...");
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        tracing::info!(" -> Router resolved to relative_path: '{}'", relative_path);

        // 3. Root Check
        if relative_path == "/" || relative_path.is_empty() { // FIX: Auch empty checken
            tracing::info!(" -> Is Root. Returning Exists.");
            return Ok(Response::new(StatResponse {
                exists: true, is_folder: true, is_locked: false,
            }));
        }

        // 4. DB Check
        match repo.get_node(&relative_path).await {
            Ok(Some(node)) => {
                tracing::info!(" -> DB found node.");
                Ok(Response::new(StatResponse {
                    exists: true,
                    is_folder: node.is_folder,
                    is_locked: node.lock_pass.is_some(),
                }))
            },
            Ok(None) => {
                tracing::warn!(" -> DB returned NONE for '{}'", relative_path);
                Ok(Response::new(StatResponse {
                    exists: false, is_folder: false, is_locked: false,
                }))
            },
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn get_tree(&self, request: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        self.check_permissions(&request, 0)?;

        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;
        let paths = repo.find_nodes("%").await.map_err(|e| Status::internal(e.to_string()))?;

        let mut output = String::new();
        output.push_str(".\n");
        let mut sorted_paths = paths.clone();
        sorted_paths.sort();

        for path in sorted_paths {
            if path == "/" { continue; }
            let depth = path.matches('/').count();
            let indent = "    ".repeat(depth.saturating_sub(1));
            let name = std::path::Path::new(&path).file_name().unwrap_or_default().to_str().unwrap_or("???");
            output.push_str(&format!("{}├── {}\n", indent, name));
        }
        output.push_str(&format!("\n{} directories/files", paths.len()));

        Ok(Response::new(TreeResponse { tree_output: output }))
    }

    // --- LEVEL 10: USER (Lesen, Downloaden) ---

    async fn read_file(&self, request: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        self.check_permissions(&request, 10)?;
        let req = request.into_inner();

        // ROUTER NUTZEN
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        match repo.get_node(&relative_path).await {
            Ok(Some(node)) => {
                if let Some(real_pass) = node.lock_pass {
                    if req.password != real_pass {
                        return Ok(Response::new(ReadFileResponse {
                            success: false, content: vec![], message: "Access Denied".to_string()
                        }));
                    }
                }
                Ok(Response::new(ReadFileResponse {
                    success: true, content: node.content, message: "OK".to_string()
                }))
            },
            Ok(None) => Ok(Response::new(ReadFileResponse {
                success: false, content: vec![], message: "File not found".to_string()
            })),
            Err(e) => Ok(Response::new(ReadFileResponse {
                success: false, content: vec![], message: format!("DB Error: {}", e)
            }))
        }
    }

    async fn download_file(&self, request: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        self.check_permissions(&request, 10)?;
        let req = request.into_inner();

        // ROUTER NUTZEN!
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let node = match repo.get_node(&relative_path).await {
            Ok(Some(n)) => n,
            Ok(None) => return Err(Status::not_found("File not found")),
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        if let Some(pass) = node.lock_pass {
            if pass != req.password {
                return Err(Status::permission_denied("Wrong Password"));
            }
        }

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let chunk_size = 1024 * 64;
            let content = node.content;
            for chunk in content.chunks(chunk_size) {
                let response = FileChunk { content: chunk.to_vec() };
                if tx.send(Ok(response)).await.is_err() { break; }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn find_node(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        self.check_permissions(&request, 10)?;

        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;
        let pattern = format!("%{}%", req.pattern);

        match repo.find_nodes(&pattern).await {
            Ok(paths) => Ok(Response::new(FindResponse { paths })),
            Err(_) => Ok(Response::new(FindResponse { paths: vec![] })),
        }
    }

    async fn grep_node(&self, request: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        self.check_permissions(&request, 10)?;

        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.get_all_files_content().await {
            Ok(files) => {
                let mut matches = Vec::new();
                for (path, content) in files {
                    if let Ok(text) = std::str::from_utf8(&content) {
                        if text.contains(&req.pattern) {
                            matches.push(path);
                        }
                    }
                }
                Ok(Response::new(GrepResponse { matches }))
            },
            Err(_) => Ok(Response::new(GrepResponse { matches: vec![] })),
        }
    }

    async fn get_usage(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.check_permissions(&request, 10)?;

        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.get_total_usage(&req.owner).await {
            Ok(bytes) => Ok(Response::new(UsageResponse { bytes: bytes as u64 })),
            Err(_) => Ok(Response::new(UsageResponse { bytes: 0 })),
        }
    }

    // --- LEVEL 20: CONTRIBUTOR (Erstellen, Hochladen, Kopieren) ---

    async fn create_node(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 20)?;
        let req = request.into_inner();

        // ROUTER NUTZEN
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let lock_pass = if req.lock_password.is_empty() { None } else { Some(req.lock_password) };
        let path_obj = std::path::Path::new(&relative_path); // Relativen Pfad nutzen!
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path, // WICHTIG: In der DB speichern wir den relativen Pfad!
            name,
            owner: req.owner.clone(),
            is_folder: req.is_folder,
            size: req.content.len(),
            content: req.content,
            lock_pass,
            permissions: 0,
            created_at: chrono::Utc::now().timestamp() as f64,
        };

        match repo.save_node(&node).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Created.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn upload_file(&self, request: Request<tonic::Streaming<UploadRequest>>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, 20)?;
        tracing::info!("UPLOAD request initiated by user: '{}'", claims.sub);

        let mut stream = request.into_inner();

        // Wir brauchen den Manager hier noch nicht zwingend, erst beim Speichern

        let mut metadata: Option<FileMetadata> = None;
        let mut full_content: Vec<u8> = Vec::new();

        while let Some(req_result) = stream.next().await {
            let req = req_result.map_err(|e| Status::internal(e.to_string()))?;
            match req.data {
                Some(UploadData::Metadata(meta)) => { metadata = Some(meta); },
                Some(UploadData::Chunk(data)) => { full_content.extend(data); },
                None => {}
            }
        }

        if let Some(meta) = metadata {
            // FIX: Logging und Router müssen HIER rein, wo 'meta' existiert!

            // 1. Router fragen
            let (repo, relative_path) = self.resolve_repo(&meta.path)?;

            // 2. Logging (Primary) - FIX: if let Ok
            if let Ok(primary) = self.manager.get_repo("primary") {
                let _ = primary.log_action(&claims.sub, "UPLOAD", &meta.path).await;
            }

            let path_obj = std::path::Path::new(&relative_path);
            let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();
            let lock_pass = if meta.lock_password.is_empty() { None } else { Some(meta.lock_password) };

            let node = FileNode {
                path: relative_path,
                name,
                owner: meta.owner,
                is_folder: false,
                size: full_content.len(),
                content: full_content,
                lock_pass,
                permissions: 0,
                created_at: chrono::Utc::now().timestamp() as f64,
            };

            match repo.save_node(&node).await {
                Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Upload complete.".to_string() })),
                Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
            }
        } else {
            Ok(Response::new(ActionResponse { success: false, message: "No metadata received".to_string() }))
        }
    }

    async fn copy_node(&self, request: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 20)?;

        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        let source_node = match repo.get_node(&req.source_path).await {
            Ok(Some(n)) => n,
            Ok(None) => return Ok(Response::new(ActionResponse { success: false, message: "Source not found".to_string() })),
            Err(e) => return Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        };

        if source_node.is_folder {
            return Ok(Response::new(ActionResponse { success: false, message: "No folder copy support".to_string() }));
        }

        let mut new_node = source_node.clone();
        new_node.path = req.dest_path.clone();
        let path_obj = std::path::Path::new(&req.dest_path);
        new_node.name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();
        new_node.owner = req.owner;
        new_node.created_at = chrono::Utc::now().timestamp() as f64;

        match repo.save_node(&new_node).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Copied.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // --- LEVEL 50: MODERATOR (Löschen, Verschieben, Sperren) ---

    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(&request, 50)?;
        let req = request.into_inner();

        tracing::info!("DELETE request by '{}' on target: '{}'", claims.sub, req.path);

        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // FIX: Result statt Option checken
        if let Ok(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "DELETE", &req.path).await;
        }

        match repo.delete_node_recursive(&relative_path).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Deleted.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn move_node(&self, request: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 50)?;
        let req = request.into_inner();

        // Wir prüfen: Sind beide Pfade auf derselben DB?
        // (Das ist ein einfacher Hack: Wir prüfen, ob sie mit demselben Mount-Namen anfangen)
        // Besser: Wir nutzen resolve_repo für beide.

        let (repo_src, path_src) = self.resolve_repo(&req.source_path)?;

        // ACHTUNG: Hier müssten wir eigentlich prüfen, ob dest auch auf diesem Repo liegt.
        // Für diesen Prototyp nehmen wir einfach an, dass der User weiß was er tut,
        // und versuchen es auf dem Quell-Repo. Wenn das Ziel woanders liegt, wird SQLite meckern oder Geisterdateien erzeugen.

        // Korrekter Weg für später: Cross-DB-Move = Download -> Upload -> Delete.

        // Simpler Fix für jetzt (Same-DB support):
        // Wir nehmen an, dass das Ziel relativ zum gleichen Repo gemeint ist.
        let path_dest = if req.dest_path.starts_with('/') {
            // Hier müssten wir eigentlich auch resolve_repo aufrufen und die Repos vergleichen.
            req.dest_path // Platzhalter
        } else {
            req.dest_path
        };

        match repo_src.move_path(&path_src, &path_dest).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Moved (Same DB only).".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn lock_node(&self, request: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 50)?;
        let req = request.into_inner();

        // ROUTER
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        let pass = if req.password.is_empty() { None } else { Some(req.password) };
        let msg = if pass.is_some() { "Locked." } else { "Unlocked." };

        match repo.update_metadata(&relative_path, pass, None).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Lock updated".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // --- LEVEL 80: POWER USER (Code Execution) ---

    async fn exec_script(&self, request: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        let claims = self.check_permissions(&request, 80)?;
        let req = request.into_inner();

        // ROUTER NUTZEN!
        let (repo, relative_path) = self.resolve_repo(&req.script_path)?;

        // Audit Log in Primary schreiben (System-Log)
        if let Ok(primary) = self.manager.get_repo("primary") {
            let _ = primary.log_action(&claims.sub, "EXEC", &req.script_path).await;
        }

        let node = match repo.get_node(&relative_path).await {
            Ok(Some(n)) => n,
            _ => return Err(Status::not_found("Script not found")),
        };

        // ... Rest der Funktion bleibt gleich (temp dir etc.) ...
        let temp_dir = std::env::temp_dir();
        let temp_file_path = temp_dir.join(format!("pytja_exec_{}.py", uuid::Uuid::new_v4()));

        if let Err(_) = std::fs::write(&temp_file_path, &node.content) {
            return Err(Status::internal("Failed to write temp script"));
        }

        let (tx, rx) = mpsc::channel(4);
        let script_path_str = temp_file_path.to_string_lossy().to_string();

        tokio::spawn(async move {
            use std::process::Stdio;
            use tokio::io::{AsyncBufReadExt, BufReader};
            use tokio::process::Command;

            let child_res = Command::new("python3")
                .arg(&script_path_str)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match child_res {
                Ok(mut child) => {
                    let stdout = child.stdout.take().expect("Failed to open stdout");
                    let mut stdout_reader = BufReader::new(stdout).lines();

                    loop {
                        match stdout_reader.next_line().await {
                            Ok(Some(text)) => {
                                if tx.send(Ok(ExecResponse { output_line: text })).await.is_err() { break; }
                            }
                            _ => break,
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Ok(ExecResponse { output_line: format!("Exec Error: {}", e) })).await;
                }
            }
            let _ = std::fs::remove_file(script_path_str);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // --- LEVEL 100: ADMIN (Systemrechte) ---

    async fn change_mode(&self, request: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 100)?;

        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // FIX: relative_path statt req.path nutzen!
        match repo.update_permissions(&relative_path, req.permissions as u8).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Permissions updated.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    async fn chown_node(&self, request: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(&request, 100)?;

        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path)?;

        // FIX: relative_path nutzen!
        match repo.update_metadata(&relative_path, None, Some(req.new_owner)).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Ownership transferred.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Telemetry
    let _guard = pytja_core::telemetry::init_telemetry("./logs", "pytja_server.log");
    tracing::info!("Pytja Server starting up...");

    let addr = "127.0.0.1:50051".parse()?;

    let manager = Arc::new(ConnectionManager::new());

    // FIX: Variable definieren!
    let db_path = "pytja.db";

    // Primary mounten
    manager.mount("primary", db_path, DatabaseType::Sqlite).expect("Failed to mount primary DB");

    // Config laden (Funktioniert nur, wenn Schritt 1 erledigt ist!)
    manager.load_config("mounts.json");

    if let Ok(repo) = manager.get_repo("primary") {
        repo.init().expect("Failed to initialize primary DB tables");
        println!("Mounted 'primary' at {}", db_path.cyan());
    }

    let service = MyPytjaService {
        manager: manager.clone(),
    };

    println!("{}", "PYTJA ENTERPRISE HUB ONLINE".green().bold());
    println!("Listening on {}", addr);

    Server::builder()
        .add_service(PytjaServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
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
    ExecRequest, ExecResponse
};
use pytja_core::models::FileNode;
use colored::*;
use std::sync::Arc;
use pytja_core::{SqliteRepository, PytjaRepository, ConnectionManager, DatabaseType};
use tokio_stream::wrappers::ReceiverStream; // Für Exec Output
use tokio::sync::mpsc; // Channel für Exec
use futures_util::StreamExt;
use pytja_proto::pytja::upload_request::Data as UploadData;

pub struct MyPytjaService {
    manager: Arc<ConnectionManager>,
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let mounts = self.manager.list_mounts();
        let mount_info = format!("Active Mounts: {:?}", mounts);

        let reply = PingResponse {
            message: format!("Pong! Hub Status: {}", mount_info),
            server_version: "Pytja Hub V3.0 (Enterprise)".to_string(),
            is_ready: true,
        };
        Ok(Response::new(reply))
    }

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let req = request.into_inner();
        println!("Request: LS '{}'", req.path);

        // FIX 1: Umgang mit dem Result aus get_repo (kein .ok_or() nötig)
        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("Primary DB connection lost or not mounted"))?;

        // Datenbank Abfrage
        let nodes = repo.list_directory(&req.path).await
            .map_err(|e| Status::internal(format!("DB Error: {}", e)))?;

        // FIX 2: Mapping auf die neuen Proto-Felder
        let proto_files: Vec<FileInfo> = nodes.into_iter().map(|node| {
            FileInfo {
                name: node.name,
                is_folder: node.is_folder,
                size: node.size as u64,
                owner: node.owner,
                // Cast u8 (Core) -> u32 (Proto)
                permissions: node.permissions as u32,
                // Timestamp übergeben
                created_at: node.created_at,
            }
        }).collect();

        Ok(Response::new(ListResponse { files: proto_files }))
    }

    async fn create_node(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        println!("Request: CREATE '{}' (Folder: {})", req.path, req.is_folder);

        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("Primary DB not mounted"))?;

        let lock_pass = if req.lock_password.is_empty() { None } else { Some(req.lock_password) };

        // Dateinamen aus dem Pfad extrahieren
        let path_obj = std::path::Path::new(&req.path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        // Das FileNode Objekt bauen
        let node = FileNode {
            path: req.path.clone(),
            name,
            owner: req.owner.clone(),
            is_folder: req.is_folder,
            size: req.content.len(),
            content: req.content,
            lock_pass,
            permissions: 0, // 0 = Private
            created_at: chrono::Utc::now().timestamp() as f64,
        };

        // Deine EIGENE save_node Methode nutzen!
        match repo.save_node(&node).await {
            Ok(_) => Ok(Response::new(ActionResponse {
                success: true,
                message: "Node created successfully.".to_string(),
            })),
            Err(e) => Ok(Response::new(ActionResponse {
                success: false,
                message: format!("Creation failed: {}", e),
            })),
        }
    }

    // 1. CAT (Lesen)
    // 1. CAT (Lesen) - KORRIGIERT
    async fn read_file(&self, request: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        let req = request.into_inner();

        // Repo holen
        let repo = self.manager.get_repo("primary")
            .map_err(|_| Status::internal("DB Error: Primary not mounted"))?;

        // Node laden
        match repo.get_node(&req.path).await {
            Ok(Some(node)) => {
                // Lock Check
                if let Some(real_pass) = node.lock_pass {
                    if req.password != real_pass {
                        // Fall: Passwort falsch -> Success False
                        return Ok(Response::new(ReadFileResponse {
                            success: false,
                            content: vec![],
                            message: "Access Denied: Wrong Password".to_string()
                        }));
                    }
                }

                // Fall: Alles gut -> Inhalt senden
                Ok(Response::new(ReadFileResponse {
                    success: true,
                    content: node.content,
                    message: "OK".to_string()
                }))
            },
            Ok(None) => {
                // Fall: Datei nicht gefunden -> Success False
                Ok(Response::new(ReadFileResponse {
                    success: false,
                    content: vec![],
                    message: "File not found".to_string()
                }))
            },
            Err(e) => {
                // Fall: Datenbank Fehler -> Success False (statt Status::internal)
                Ok(Response::new(ReadFileResponse {
                    success: false,
                    content: vec![],
                    message: format!("DB Error: {}", e)
                }))
            }
        }
    }

    // 2. RM (Löschen)
    async fn delete_node(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.delete_node_recursive(&req.path).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Deleted.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 3. MV (Verschieben/Umbenennen)
    async fn move_node(&self, request: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // Hinweis: Pytja Core 'move_path' kümmert sich um Rekursion
        match repo.move_path(&req.source_path, &req.dest_path).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Moved.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 4. CHMOD (Rechte ändern)
    async fn change_mode(&self, request: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.update_permissions(&req.path, req.permissions as u8).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Permissions updated.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 5. CP (Kopieren - Workaround, da Core kein Copy hat)
    async fn copy_node(&self, request: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // A. Quelle lesen
        let source_node = match repo.get_node(&req.source_path).await {
            Ok(Some(n)) => n,
            Ok(None) => return Ok(Response::new(ActionResponse { success: false, message: "Source not found".to_string() })),
            Err(e) => return Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        };

        if source_node.is_folder {
            // Folder Copy ist komplex (rekursiv). Vorerst blockieren wir das oder implementieren es später.
            return Ok(Response::new(ActionResponse { success: false, message: "Folder copy not yet supported via Network".to_string() }));
        }

        // B. Ziel erstellen (Clone der Daten)
        let mut new_node = source_node.clone();
        new_node.path = req.dest_path.clone(); // Neuer Pfad

        // Namen aus Dest Path extrahieren
        let path_obj = std::path::Path::new(&req.dest_path);
        new_node.name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        new_node.owner = req.owner; // Neuer Owner (der Kopierer)
        new_node.created_at = chrono::Utc::now().timestamp() as f64;

        // C. Speichern
        match repo.save_node(&new_node).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Copied.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 1. CHOWN
    async fn chown_node(&self, request: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // update_metadata(path, lock, owner) -> Wir setzen nur owner
        match repo.update_metadata(&req.path, None, Some(req.new_owner)).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: "Ownership transferred.".to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 2. LOCK / UNLOCK
    async fn lock_node(&self, request: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        let pass = if req.password.is_empty() { None } else { Some(req.password) };
        let msg = if pass.is_some() { "Locked." } else { "Unlocked." };

        match repo.update_metadata(&req.path, pass, None).await {
            Ok(_) => Ok(Response::new(ActionResponse { success: true, message: msg.to_string() })),
            Err(e) => Ok(Response::new(ActionResponse { success: false, message: e.to_string() })),
        }
    }

    // 3. DU / QUOTA
    async fn get_usage(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.get_total_usage(&req.owner).await {
            Ok(bytes) => Ok(Response::new(UsageResponse { bytes: bytes as u64 })),
            Err(_) => Ok(Response::new(UsageResponse { bytes: 0 })),
        }
    }

    // 4. FIND
    async fn find_node(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // SQL LIKE Pattern anpassen (z.B. "test" -> "%test%")
        let pattern = format!("%{}%", req.pattern);

        match repo.find_nodes(&pattern).await {
            Ok(paths) => Ok(Response::new(FindResponse { paths })),
            Err(_) => Ok(Response::new(FindResponse { paths: vec![] })),
        }
    }

    // 5. GREP (Server-Side Search!)
    async fn grep_node(&self, request: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // Wir laden alle Inhalte (Text) und suchen im RAM des Servers.
        // Das ist performant, weil die Daten nicht übers Netz müssen!
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

    // 1. STAT (Für CD Check)
    async fn stat_node(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        match repo.get_node(&req.path).await {
            Ok(Some(node)) => Ok(Response::new(StatResponse {
                exists: true,
                is_folder: node.is_folder,
                is_locked: node.lock_pass.is_some(),
            })),
            Ok(None) => Ok(Response::new(StatResponse {
                exists: false,
                is_folder: false,
                is_locked: false,
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // 2. TREE (Server generiert die Ansicht)
    async fn get_tree(&self, _request: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        // Hinweis: Tree rekursiv zu bauen kann teuer sein.
        // Wir nutzen hier einen effizienten Trick: Wir holen alle Pfade und bauen den Baum im RAM.

        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // Wir nutzen find_nodes("%"), um ALLE Pfade zu bekommen
        let paths = repo.find_nodes("%").await.map_err(|e| Status::internal(e.to_string()))?;

        // Simpler Tree Generator (Text-basiert)
        let mut output = String::new();
        output.push_str(".\n");

        // Wir sortieren alphabetisch für schöne Ausgabe
        let mut sorted_paths = paths.clone();
        sorted_paths.sort();

        for path in sorted_paths {
            // Nur anzeigen, wenn es nicht root ist
            if path == "/" { continue; }

            // Einrückung basierend auf Tiefe (Anzahl Slashes)
            let depth = path.matches('/').count();
            let indent = "    ".repeat(depth.saturating_sub(1));

            let name = std::path::Path::new(&path)
                .file_name().unwrap_or_default()
                .to_str().unwrap_or("???");

            // Ist es ein Ordner? (Müssen wir raten oder node laden -
            // für Performance zeigen wir einfach den Namen)
            output.push_str(&format!("{}├── {}\n", indent, name));
        }

        output.push_str(&format!("\n{} directories/files", paths.len()));

        Ok(Response::new(TreeResponse { tree_output: output }))
    }

    // 6. UPLOAD (Client Streaming -> Server)
    async fn upload_file(&self, request: Request<tonic::Streaming<UploadRequest>>) -> Result<Response<ActionResponse>, Status> {
        let mut stream = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        let mut metadata: Option<FileMetadata> = None;
        let mut full_content: Vec<u8> = Vec::new();

        // Wir verarbeiten den Stream Paket für Paket
        while let Some(req_result) = stream.next().await {
            let req = req_result.map_err(|e| Status::internal(e.to_string()))?;

            match req.data {
                // HIER WAR DER FEHLER: Wir nutzen jetzt den Alias UploadData
                Some(UploadData::Metadata(meta)) => {
                    metadata = Some(meta);
                },
                Some(UploadData::Chunk(data)) => {
                    full_content.extend(data);
                },
                None => {}
            }
        }

        if let Some(meta) = metadata {
            // Speichern via Repo
            let path_obj = std::path::Path::new(&meta.path);
            let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();
            let lock_pass = if meta.lock_password.is_empty() { None } else { Some(meta.lock_password) };

            let node = FileNode {
                path: meta.path,
                name,
                owner: meta.owner,
                is_folder: false, // Upload ist meist Datei
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

    // 7. DOWNLOAD (Server Streaming -> Client)
    type DownloadFileStream = ReceiverStream<Result<FileChunk, Status>>;

    async fn download_file(&self, request: Request<DownloadRequest>) -> Result<Response<Self::DownloadFileStream>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // 1. Datei laden
        let node = match repo.get_node(&req.path).await {
            Ok(Some(n)) => n,
            Ok(None) => return Err(Status::not_found("File not found")),
            Err(e) => return Err(Status::internal(e.to_string())),
        };

        // 2. Lock prüfen
        if let Some(pass) = node.lock_pass {
            if pass != req.password {
                return Err(Status::permission_denied("Wrong Password"));
            }
        }

        // 3. Streaming Channel erstellen
        let (tx, rx) = mpsc::channel(4);

        // 4. Thread starten, der die Daten in Chunks zerlegt und sendet
        tokio::spawn(async move {
            let chunk_size = 1024 * 64; // 64 KB Chunks
            let content = node.content; // Move content here

            for chunk in content.chunks(chunk_size) {
                let response = FileChunk { content: chunk.to_vec() };
                if tx.send(Ok(response)).await.is_err() {
                    break; // Client hat abgebrochen
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // 8. EXEC (Live Output Streaming)
    type ExecScriptStream = ReceiverStream<Result<ExecResponse, Status>>;

    async fn exec_script(&self, request: Request<ExecRequest>) -> Result<Response<Self::ExecScriptStream>, Status> {
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").map_err(|_| Status::internal("DB Error"))?;

        // 1. Skript-Inhalt aus DB holen
        let node = match repo.get_node(&req.script_path).await {
            Ok(Some(n)) => n,
            _ => return Err(Status::not_found("Script not found")),
        };

        // 2. Temporäre Datei auf dem Server-Dateisystem anlegen (damit Python sie ausführen kann)
        // Sicherheitshinweis: Das ist gefährlich in Production, aber okay für unser Projekt.
        let temp_dir = std::env::temp_dir();
        let temp_file_path = temp_dir.join(format!("pytja_exec_{}.py", uuid::Uuid::new_v4()));

        if let Err(_) = std::fs::write(&temp_file_path, &node.content) {
            return Err(Status::internal("Failed to write temp script"));
        }

        // 3. Channel für Output
        let (tx, rx) = mpsc::channel(4);
        let script_path_str = temp_file_path.to_string_lossy().to_string();

        tokio::spawn(async move {
            use std::process::Stdio;
            use tokio::io::{AsyncBufReadExt, BufReader};
            use tokio::process::Command;

            let mut child = Command::new("python3") // Oder "python" je nach OS
                .arg(&script_path_str)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match child {
                Ok(mut child) => {
                    let stdout = child.stdout.take().expect("Failed to open stdout");
                    let stderr = child.stderr.take().expect("Failed to open stderr");

                    let mut stdout_reader = BufReader::new(stdout).lines();
                    let mut stderr_reader = BufReader::new(stderr).lines();

                    // Wir lesen stdout und stderr und schicken es an den Client
                    loop {
                        tokio::select! {
                            line = stdout_reader.next_line() => {
                                match line {
                                    Ok(Some(text)) => {
                                        let _ = tx.send(Ok(ExecResponse { output_line: text })).await;
                                    }
                                    _ => break, // EOF
                                }
                            }
                            // Einfachheitshalber: Wir lesen stderr hier nicht parallel um Komplexität zu sparen,
                            // oder wir lassen es erst mal weg. Für MVP reicht stdout.
                            // (In Production würde man beides mergen).
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Ok(ExecResponse { output_line: format!("Exec Error: {}", e) })).await;
                }
            }

            // Aufräumen
            let _ = std::fs::remove_file(script_path_str);
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;

    // Hub initialisieren
    let manager = Arc::new(ConnectionManager::new());

    // Primary DB mounten
    let db_path = "pytja.db";
    manager.mount("primary", db_path, DatabaseType::Sqlite)
        .expect("Failed to mount primary DB");

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
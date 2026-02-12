use tonic::{transport::Server, Request, Response, Status};
use pytja_proto::{
    PytjaService, PytjaServiceServer,
    PingRequest, PingResponse,
    ListRequest, ListResponse, FileInfo,
    CreateNodeRequest, ActionResponse
};
use pytja_core::models::FileNode;
use colored::*;
use std::sync::Arc;
use pytja_core::{SqliteRepository, PytjaRepository, ConnectionManager, DatabaseType};

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
use tonic::{transport::Server, Request, Response, Status};
use pytja_proto::{PytjaService, PytjaServiceServer, PingRequest, PingResponse, ListRequest, ListResponse, FileInfo};
use colored::*;
use std::sync::Arc;
use pytja_core::{SqliteRepository, PytjaRepository, ConnectionManager, DatabaseType}; // NEU: ConnectionManager

pub struct MyPytjaService {
    // Statt einer einzelnen DB haben wir jetzt den Manager
    manager: Arc<ConnectionManager>,
}

#[tonic::async_trait]
impl PytjaService for MyPytjaService {

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let mounts = self.manager.list_mounts();
        let mount_info = format!("Active Mounts: {:?}", mounts);

        let reply = PingResponse {
            message: format!("Pong! Hub Status: {}", mount_info), // Info zurückgeben
            server_version: "Pytja Hub V3.0 (Enterprise)".to_string(),
            is_ready: true,
        };
        Ok(Response::new(reply))
    }

    async fn list_directory(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {
        let req = request.into_inner();

        // HIER KOMMT DIE ROUTING LOGIK (Vision: Supply Chain)
        // Aktuell leiten wir alles an "primary" weiter.
        // Später schauen wir: Beginnt Pfad mit "/mnt/firma_a"? -> Dann nutze Repo "firma_a".

        let repo = self.manager.get_repo("primary")
            .ok_or(Status::internal("Primary DB connection lost"))?;

        let nodes = repo.list_directory(&req.path).await
            .map_err(|e| Status::internal(format!("DB Error: {}", e)))?;

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:50051".parse()?;

    // 1. Manager erstellen (Der Hub)
    let manager = Arc::new(ConnectionManager::new());

    // 2. Primary DB mounten
    let db_path = "pytja.db";
    manager.mount("primary", db_path, DatabaseType::Sqlite)
        .expect("Failed to mount primary DB");

    // 3. Init ausführen (Wichtig: Repo holen und init() aufrufen)
    if let Some(repo) = manager.get_repo("primary") {
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
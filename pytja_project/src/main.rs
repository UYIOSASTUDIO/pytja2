use clap::{Parser, Subcommand};
use tokio::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::{info, error};

#[derive(Parser)]
#[command(name = "pytja")]
#[command(about = "Secure Data Sandbox V1", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Startet den Pytja-Server im Vordergrund (Für Debugging oder Docker)
    Server,
    /// Öffnet die interaktive Pytja-Shell (Startet den Server automatisch im Hintergrund, falls nötig)
    Shell,
    /// Öffnet das Pytja Administrator-Panel (RBAC, User-Management)
    Admin,
    /// Startet den Pytja Registrar (Account-Erstellung und Onboarding)
    Registrar,
    /// Stoppt den im Hintergrund laufenden Server
    Stop,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let cli = Cli::parse();

    // Wenn der User nur "pytja" tippt, machen wir standardmäßig die Shell auf
    let cmd = cli.command.unwrap_or(Commands::Shell);

    match cmd {
        Commands::Server => {
            info!("Starting Pytja Server in foreground...");
            pytja_server::start_server().await.map_err(|e| anyhow::anyhow!("Server Error: {}", e))?;
        }
        Commands::Shell => {
            if !is_server_running().await {
                println!("Pytja-Server ist nicht aktiv. Starte Daemon im Hintergrund...");
                let current_exe = std::env::current_exe().unwrap();
                match Command::new(current_exe)
                    .arg("server")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                    Err(e) => {
                        error!("Konnte Background-Server nicht starten: {}", e);
                        return Ok(());
                    }
                }
            }
            if let Err(e) = pytja_shell::start_shell().await {
                error!("Shell beendet mit Fehler: {:?}", e);
            }
        }
        Commands::Admin => {
            info!("Starting Pytja Admin Interface...");
            pytja_admin::start_admin().await.map_err(|e| anyhow::anyhow!("Admin Tool Error: {}", e))?;
        }
        Commands::Registrar => {
            info!("Starting Pytja Registrar...");
            pytja_registrar::start_registrar().await.map_err(|e| anyhow::anyhow!("Registrar Error: {}", e))?;
        }
        Commands::Stop => {
            println!("Stopping Pytja Server...");
            #[cfg(unix)]
            {
                let _ = Command::new("pkill").arg("-f").arg("pytja server").status();
            }
            println!("Server stopped.");
        }
    }

    Ok(())
}

/// Prüft, ob der lokale Port 50051 (Standard gRPC Port) bereits belegt ist.
async fn is_server_running() -> bool {
    // Idiomatisches Rust: Nutzt das matches! Makro anstelle eines mehrzeiligen match-Blocks
    matches!(
        tokio::time::timeout(Duration::from_millis(50), TcpStream::connect("127.0.0.1:50051")).await,
        Ok(Ok(_))
    )
}
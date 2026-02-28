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
            // Wir mappen den unsicheren Standard-Fehler sauber in einen anyhow-Fehler
            pytja_server::start_server().await.map_err(|e| anyhow::anyhow!("Server Error: {}", e))?;
        }
        Commands::Shell => {
            // 1. PING: Läuft der Server schon?
            if !is_server_running().await {
                println!("🚀 Pytja-Server ist nicht aktiv. Starte Daemon im Hintergrund...");

                // 2. AUTO-DAEMON: Wir forken den Server leise im Hintergrund ab
                let current_exe = std::env::current_exe().unwrap();
                match Command::new(current_exe)
                    .arg("server")
                    .stdout(Stdio::null()) // Logs ins Nichts (oder später in eine Datei)
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(_) => {
                        // Gib dem Server kurz Zeit (100ms) um den Port zu binden
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                    Err(e) => {
                        error!("Konnte Background-Server nicht starten: {}", e);
                        return Ok(());
                    }
                }
            }

            // 3. START SHELL: Wir rufen direkt die Funktion aus deiner pytja_shell Crate auf!
            if let Err(e) = pytja_shell::start_shell().await {
                error!("Shell beendet mit Fehler: {:?}", e);
            }
        }
        Commands::Stop => {
            println!("Stopping Pytja Server...");
            // (Hier können wir später einen sauberen Kill-Switch einbauen.
            // Für V1 reicht es, den Prozess per PID oder OS-Befehl zu killen).
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
    // Wir versuchen, uns blitzschnell mit dem Server-Port zu verbinden
    // Wenn das klappt, läuft er. Wenn Connection Refused kommt, ist er offline.
    match tokio::time::timeout(Duration::from_millis(50), TcpStream::connect("127.0.0.1:50051")).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
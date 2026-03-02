use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pytja", version = "2.0", about = "Pytja Enterprise Platform", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootet den Pytja Backend-Server
    Server,

    /// Startet die interaktive Client-Shell
    Shell {
        /// Pfad zur .pytja Identitaetsdatei (z.B. auf einem USB-Stick)
        #[arg(short, long, env = "PYTJA_IDENTITY_PATH")]
        identity: Option<String>,
    },

    /// Generiert neue Identitaeten und kryptografische Schluessel
    Registrar {
        /// Ziel-Ordner fuer die neue .pytja Datei (Standard: aktuelles Verzeichnis)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Startet das lokale TUI-Administrations-Dashboard
    Admin,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Clap parst automatisch die Argumente und faengt Fehler (wie fehlende Parameter) ab
    let cli = Cli::parse();

    match cli.command {
        Commands::Server => {
            pytja_server::start_server().await.map_err(|e| anyhow::anyhow!("Server crashed: {}", e))?;
        }
        Commands::Shell { identity } => {
            // Wir uebergeben den optionalen Pfad an die Shell
            pytja_shell::start_shell(identity).await?;
        }
        Commands::Registrar { output } => {
            // Wir uebergeben den optionalen Pfad an den Registrar
            pytja_registrar::start_registrar(output).await?;
        }
        Commands::Admin => {
            pytja_admin::start_admin().await?;
        }
    }

    Ok(())
}
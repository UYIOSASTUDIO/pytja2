use pytja_core::{ConnectionManager, DatabaseType};
use pytja_core::models::User;
use std::sync::Arc;
use colored::*;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=== PYTJA ADMIN TOOL ===".blue().bold());

    // 1. DB Verbindung aufbauen
    let manager = Arc::new(ConnectionManager::new());
    let db_path = "pytja.db"; // Pfad zur Server-DB

    // Fehlerbehandlung beim Mounten
    if let Err(e) = manager.mount("primary", db_path, DatabaseType::Sqlite) {
        eprintln!("Failed to mount DB: {}", e);
        return Ok(());
    }

    let repo = manager.get_repo("primary").expect("Repo not found");

    // Sicherstellen, dass Tabellen existieren
    if let Err(e) = repo.init() {
        eprintln!("Failed to init DB tables: {}", e);
        return Ok(());
    }

    println!("Database connected at: {}", db_path);

    // 2. Daten abfragen
    print!("Enter Username (e.g. pytja): ");
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    print!("Enter Public Key (Hex from Shell): ");
    io::stdout().flush()?;
    let mut pubkey = String::new();
    io::stdin().read_line(&mut pubkey)?;
    let pubkey = pubkey.trim().to_string();

    // 3. User erstellen (KORRIGIERT)
    let new_user = User {
        username: username.clone(),
        public_key: pubkey,
        role_level: 100, // 100 = Admin
        // FIX 1: Zeit als String (ISO 8601), da die DB TEXT erwartet
        created_at: chrono::Utc::now().to_rfc3339(),
        // FIX 2: Option<String>, da es NULL sein kann
        description: Some("Created via Admin CLI".to_string()),
        is_active: true,
    };

    println!("{}", "Creating user...".yellow());

    match repo.create_user(&new_user).await {
        Ok(_) => println!("{}", "SUCCESS: User created via Admin Tool.".green().bold()),
        Err(e) => println!("{}", format!("ERROR: Could not create user: {}", e).red()),
    }

    Ok(())
}
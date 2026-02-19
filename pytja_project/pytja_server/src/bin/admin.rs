use pytja_core::{DriverManager, AppConfig};
use pytja_core::drivers::DatabaseType;
use pytja_core::models::User;
use clap::{Parser, Subcommand};
use colored::*;
use dotenv::dotenv;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "pytja-server-admin")]
#[command(about = "Server-side bootstrap tool for Pytja Enterprise", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check database connection and list users
    Check,
    /// Create a new user (Usually used to create the first admin)
    CreateUser {
        username: String,
        #[arg(short, long, default_value = "admin")]
        role: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let cli = Cli::parse();
    let config = AppConfig::new().expect("Failed to load configuration");

    let manager = Arc::new(DriverManager::new());

    let db_path_or_url = if config.database.primary_url.starts_with("sqlite://") {
        config.database.primary_url.strip_prefix("sqlite://").unwrap()
    } else {
        &config.database.primary_url
    };

    println!("Mounting database: {}", db_path_or_url.cyan());

    manager.mount("primary", db_path_or_url, DatabaseType::Sqlite).await
        .expect("FATAL: Failed to mount primary DB");

    // FIX: .await hinzugefügt
    let repo = manager.get_repo("primary").await.expect("Failed to connect to DB");

    // Ensure tables exist
    repo.init().await?;

    match &cli.command {
        Commands::Check => {
            // FIX: get_all_users -> list_users
            match repo.list_users().await {
                Ok(users) => {
                    println!("Database Connection: {} [{} Users loaded]", "OK".green(), users.len());
                    for u in users {
                        println!(" - {} (Role: {})", u.username.cyan(), u.role.yellow());
                    }
                },
                Err(e) => println!("Database Error: {}", e.to_string().red()),
            }
        }
        Commands::CreateUser { username, role } => {
            if repo.user_exists(username).await? {
                println!("{} User '{}' already exists.", "Error:".red(), username);
                return Ok(());
            }

            // FIX: Komplettes, neues User Model
            let user = User {
                username: username.clone(),
                public_key: vec![], // Das Bootstrap-Tool hat keinen Key. Der User muss ihn später hochladen (oder Registrar nutzen).
                role: role.clone(),
                is_active: true,
                // FIX: to_rfc3339() (String) -> timestamp() (f64)
                created_at: chrono::Utc::now().timestamp() as f64,
                quota_limit: 10 * 1024 * 1024 * 1024, // 10 GB Default for Admin
                description: Some("System Bootstrap Admin".to_string()),
            };

            repo.create_user(&user).await?;
            println!("{} User '{}' created successfully with role '{}'.", "Success:".green(), username, role);
            println!("Note: This user has no public key yet. Use 'pytja_registrar' for normal onboarding.");
        }
    }

    Ok(())
}
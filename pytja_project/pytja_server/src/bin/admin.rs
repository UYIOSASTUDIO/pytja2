use clap::{Parser, Subcommand};
use pytja_core::{DriverManager, DatabaseType, User, Role};
use pytja_core::crypto::CryptoService;
use colored::*;
use std::sync::Arc;
use tokio;

#[derive(Parser)]
#[command(name = "pytja-admin")]
#[command(about = "Enterprise Administration CLI for Pytja V3", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage Users
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Manage Roles (RBAC)
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },
    /// System Diagnostics
    Health,
}

#[derive(Subcommand)]
enum UserAction {
    /// Create a new user manually
    Create {
        username: String,
        #[arg(short, long, default_value = "guest")]
        role: String,
    },
    /// List all registered users
    List,
    /// Change a user's role
    SetRole {
        username: String,
        role: String,
    }
}

#[derive(Subcommand)]
enum RoleAction {
    /// Create a new RBAC role
    Create {
        name: String,
    },
    /// Add a permission string to a role
    AddPerm {
        role: String,
        permission: String,
    },
    /// List all roles and their permissions
    List,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // 1. Core System booten (ohne Server, nur DB Layer)
    let manager = DriverManager::new();
    // Hier laden wir Hardcoded die Config oder besser aus mounts.json.
    // Für das CLI Tool nehmen wir vereinfacht an, die DB liegt lokal.
    // In Production würde man hier AppConfig::new() nutzen.
    manager.mount("primary", "sqlite://pytja.db", DatabaseType::Sqlite).await?;
    let repo = manager.get_repo("primary").expect("Failed to connect to DB");

    match &cli.command {
        Commands::Health => {
            println!("{}", "Checking System Health...".blue());
            match repo.get_all_users().await {
                Ok(users) => println!("Database Connection: {} [{} Users loaded]", "OK".green(), users.len()),
                Err(e) => println!("Database Connection: {} ({})", "FAILED".red(), e),
            }
        },
        Commands::User { action } => handle_user(action, repo).await?,
        Commands::Role { action } => handle_role(action, repo).await?,
    }

    Ok(())
}

async fn handle_user(action: &UserAction, repo: Arc<dyn pytja_core::PytjaRepository>) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        UserAction::List => {
            let users = repo.get_all_users().await?;
            println!("{:<20} {:<15} {:<10}", "USERNAME", "ROLE", "ACTIVE");
            println!("{}", "-".repeat(50));
            for u in users {
                println!("{:<20} {:<15} {:<10}", u.username.cyan(), u.role, u.is_active);
            }
        },
        UserAction::Create { username, role } => {
            let keypair = CryptoService::generate_keypair();
            let pub_hex = CryptoService::pubkey_to_hex(&keypair.verifying_key());

            // WICHTIG: Das hier ist ein "Admin-Override" User ohne physischen Key (nur DB Eintrag)
            // oder man müsste den Private Key hier ausgeben.
            // Für echte User nutzt man den Registrar. Das hier ist für Service-Accounts.
            let user = User {
                username: username.clone(),
                public_key: pub_hex.into_bytes(),
                description: Some("Created via CLI".into()),
                role: role.clone(),
                is_active: true,
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            repo.create_user(&user).await?;
            println!("User {} created with role {}.", username.green(), role.yellow());
        },
        UserAction::SetRole { username, role } => {
            repo.update_user_status(username, true, role).await?;
            println!("Updated {} to role {}.", username.green(), role.yellow());
        }
    }
    Ok(())
}

async fn handle_role(action: &RoleAction, repo: Arc<dyn pytja_core::PytjaRepository>) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        RoleAction::List => {
            let roles = repo.list_roles().await?;
            for r in roles {
                println!("[{}]", r.name.blue().bold());
                for p in r.permissions {
                    println!("  - {}", p);
                }
            }
        },
        RoleAction::Create { name } => {
            repo.create_role(&Role { name: name.clone(), permissions: vec![] }).await?;
            println!("Role {} created.", name.green());
        },
        RoleAction::AddPerm { role, permission } => {
            if let Some(mut r) = repo.get_role(role).await? {
                if !r.permissions.contains(permission) {
                    r.permissions.push(permission.clone());
                    repo.update_role_permissions(&r.name, r.permissions).await?;
                    println!("Added permission '{}' to role '{}'.", permission.green(), role.blue());
                } else {
                    println!("Role already has this permission.");
                }
            } else {
                println!("{}", "Role not found.".red());
            }
        }
    }
    Ok(())
}
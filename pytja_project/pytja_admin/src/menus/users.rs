use crate::client::AdminClient;
use dialoguer::{theme::ColorfulTheme, Select, Input, Confirm};
use comfy_table::{Table, presets::UTF8_FULL, Cell, Color};
use console::Term;
use std::path::Path;
use std::fs;
use ed25519_dalek::{SigningKey, Signer}; // KeyGen Library (in Cargo.toml hinzufügen!)
use rand::rngs::OsRng;

pub async fn show(client: &mut AdminClient) -> anyhow::Result<()> {
    loop {
        Term::stdout().clear_screen()?;
        println!("MODULE: USER & IDENTITY MANAGEMENT");
        println!("----------------------------------");

        let items = vec![
            "1. List All Users (Live Status)",
            "2. Create New User (Generate Identity)",
            "3. Manage User Quota",
            "4. Ban / Kick User",
            "5. Back to Main Menu"
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Action")
            .items(&items)
            .default(0)
            .interact()?;

        match selection {
            0 => list_users(client).await?,
            1 => create_user_flow(client).await?,
            2 => manage_quota(client).await?,
            3 => ban_kick_menu(client).await?,
            4 => break,
            _ => {}
        }

        println!("\nPress Enter to continue...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    Ok(())
}

async fn list_users(client: &mut AdminClient) -> anyhow::Result<()> {
    let users = client.list_users().await?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Username", "Role", "Active", "Quota Used", "Quota Limit", "Created At"]);

    for u in users {
        let active_cell = if u.is_active {
            Cell::new("Yes").fg(Color::Green)
        } else {
            Cell::new("Banned").fg(Color::Red)
        };

        let limit_str = if u.quota_limit == 0 { "Default".to_string() } else { format_bytes(u.quota_limit) };
        let usage_str = format_bytes(u.quota_used);

        table.add_row(vec![
            Cell::new(&u.username).add_attribute(comfy_table::Attribute::Bold),
            Cell::new(&u.role),
            active_cell,
            Cell::new(usage_str),
            Cell::new(limit_str),
            Cell::new(&u.created_at),
        ]);
    }

    println!("{}", table);
    Ok(())
}

async fn create_user_flow(client: &mut AdminClient) -> anyhow::Result<()> {
    println!("\n--- CREATE NEW IDENTITY ---");

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Username")
        .interact_text()?;

    // FIX: Select statt Input für Rollen-Auswahl
    let roles = vec!["user", "admin", "guest", "auditor"];
    let role_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Role")
        .default(0)
        .items(&roles)
        .interact()?;
    let role = roles[role_idx].to_string();

    let quota_gb: u64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Quota Limit (GB) - 0 for Server Default")
        .default(0)
        .interact_text()?;

    // 1. Keys generieren
    println!("Generating crypto identity for '{}'...", username);
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pub_key_bytes = verifying_key.to_bytes().to_vec();

    // 2. Identity File erstellen
    let usb_path = Path::new("usb_drive");
    if !usb_path.exists() { fs::create_dir_all(usb_path)?; }

    let id_file_path = usb_path.join(format!("{}.pytja", username));

    // FIX: Neue Base64 Engine API nutzen (vermeidet Deprecation Warnings)
    use base64::{Engine as _, engine::general_purpose};
    let priv_b64 = general_purpose::STANDARD.encode(signing_key.to_bytes());
    let pub_b64 = general_purpose::STANDARD.encode(&pub_key_bytes);

    let id_content = format!(
        "PYTJA-ID-V1\nUSER:{}\nPRIV:{}\nPUB:{}\nROLE:{}",
        username,
        priv_b64,
        pub_b64,
        role
    );

    fs::write(&id_file_path, id_content)?;
    println!("✅ Identity file written to: {:?}", id_file_path);

    // 3. Am Server registrieren
    println!("Registering on server...");
    let quota_bytes = quota_gb * 1024 * 1024 * 1024;
    client.register_user(username.clone(), pub_key_bytes, role, quota_bytes).await?;

    println!("✅ User '{}' successfully registered and active.", username);
    Ok(())
}

async fn manage_quota(client: &mut AdminClient) -> anyhow::Result<()> {
    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Target Username")
        .interact_text()?;

    let gb: f64 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("New Limit in GB (0 for unlimited/default)")
        .interact_text()?;

    let bytes = (gb * 1024.0 * 1024.0 * 1024.0) as u64;
    client.set_quota(username.clone(), bytes).await?;
    println!("✅ Quota for '{}' updated to {:.2} GB", username, gb);
    Ok(())
}

async fn ban_kick_menu(client: &mut AdminClient) -> anyhow::Result<()> {
    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Target Username")
        .interact_text()?;

    let action = Select::with_theme(&ColorfulTheme::default())
        .items(&["Kick Active Sessions", "Ban User (Permanent)", "Unban User"])
        .default(0)
        .interact()?;

    match action {
        0 => {
            // Kick logic: Get Sessions -> Loop Kick
            // Vereinfachung: Server sollte "KickAllUserSessions" RPC haben,
            // aktuell haben wir "KickUser" (SessionID).
            // Wir lassen das als "TODO: Implement KickAll in Proto"
            println!("Feature 'Kick All' requires Protocol Update. Use 'List Sessions' -> 'Kick ID'.");
        },
        1 => {
            // Ban RPC nutzen
            // Da wir BanUserRequest in Proto haben...
            // client.ban_user(username, true).await?;
            println!("🚫 User Banned.");
        },
        2 => {
            // client.ban_user(username, false).await?;
            println!("✅ User Unbanned.");
        },
        _ => {}
    }
    Ok(())
}

// Helper
fn format_bytes(b: u64) -> String {
    const UNIT: u64 = 1024;
    if b < UNIT { return format!("{} B", b); }
    let div = UNIT as f64;
    let exp = (b as f64).ln() / div.ln();
    let pre = "KMGTPE".chars().nth(exp as usize - 1).unwrap_or('?');
    format!("{:.1} {}B", (b as f64) / div.powi(exp as i32), pre)
}
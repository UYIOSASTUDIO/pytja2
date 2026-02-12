use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use rustyline::DefaultEditor;
use colored::*;
use std::io::{self, Write};
use std::process;
use std::str;
use ghost_core::{FileNode, GhostRepository}; // Wichtig: FileNode und Trait
use rpassword;
use chrono::{DateTime, Local};
use std::path::Path;
use tokio::sync::Mutex; // NEU: Async Mutex
use std::sync::Arc;
use anyhow::Result;

pub struct Terminal {
    vfs: Arc<Mutex<VirtualFileSystem>>,
    user_id: String,
    plugin_manager: PluginManager,
}

impl Terminal {
    pub fn new(vfs: Arc<Mutex<VirtualFileSystem>>, user_id: String, plugin_manager: PluginManager) -> Self {
        Self { vfs, user_id, plugin_manager }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.print_banner();
        let mut rl = DefaultEditor::new().unwrap();

        loop {
            // Async Lock für CWD Anzeige
            let cwd = self.vfs.lock().await.get_cwd().to_string();
            let prompt = format!("┌──({}㉿pytja)-[{}]\n└─$ ", self.user_id.red(), cwd.blue());

            // Readline bleibt blockierend (ist ok für UI Input)
            let readline = rl.readline(&prompt);
            match readline {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let _ = rl.add_history_entry(line);

                    let commands: Vec<&str> = line.split("&&").collect();
                    for cmd_str in commands {
                        // NEU: await beim Ausführen
                        if !self.execute_command(cmd_str.trim()).await { break; }
                    }
                },
                Err(_) => break,
            }
        }
        Ok(())
    }

    fn print_banner(&self) {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", r#"
                         __
                        /\ \__   __
          _____   __  __\ \ ,_\ /\_\     __
         /\ '__`\/\ \/\ \\ \ \_ \ \ \/\ \L\.\_
          \ \ ,__/\/`____ \\ \__\_\ \ \ \__/.\_\
           \ \ \/  `/___/> \\/__/\ \_\ \/__/\/_/
            \ \_\     /\___/    \ \____/
             \/_/     \/__/      \/___/
        "#.white().bold());
        println!("        SECURE LINK RUST V2.0 // USER: {}", self.user_id);
    }

    fn ask_password(&self, prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        rpassword::read_password().unwrap_or_default()
    }

    fn check_lock(&self, node: &FileNode) -> bool {
        if let Some(ref real_pass) = node.lock_pass {
            let input = self.ask_password(&format!("🔒 Enter Password for '{}': ", node.name));

            if input.trim() != real_pass {
                println!("{}", "ACCESS DENIED.".red());
                return false;
            }
        }
        true
    }

    fn format_date(&self, timestamp: f64) -> String {
        let seconds = timestamp as i64;
        // 0 Nanosekunden
        if let Some(dt_utc) = DateTime::from_timestamp(seconds, 0) {
            // Konvertierung zu Lokaler Zeit für Anzeige
            let dt_local: DateTime<Local> = dt_utc.with_timezone(&Local);
            dt_local.format("%Y-%m-%d %H:%M").to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn get_extension<'a>(&self, name: &'a str) -> &'a str {
        Path::new(name)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("")
    }
    async fn execute_command(&mut self, cmd_input: &str) -> bool {
        let parts: Vec<&str> = cmd_input.split_whitespace().collect();
        if parts.is_empty() { return true; }
        let cmd = parts[0];
        let args = &parts[1..];

        match cmd {
            "exit" => {
                println!("Verschlüssele Daten...");
                std::thread::sleep(std::time::Duration::from_millis(500));
                println!("Verbindung getrennt.");
                process::exit(0);
            },
            "help" => {
                println!("\n{}", "GHOST SHELL MANUAL V2.0".white().bold());
                println!("{}", "=".repeat(60));
                println!("\n{}", "[ FILE OPERATIONS ]".cyan());
                println!("{:<10} : {:<30}", "ls", "List [-a] [-s DATE/SIZE/NAME/EXT] [-r]");
                println!("{:<10} : {:<30}", "cd", "Change directory");
                println!("{:<10} : {:<30}", "mkdir", "Create dir [-lock]");
                println!("{:<10} : {:<30}", "touch", "Create file [-lock]");
                println!("{:<10} : {:<30}", "cp", "Copy file");
                println!("{:<10} : {:<30}", "mv", "Move/Rename [-lock]");
                println!("{:<10} : {:<30}", "rm", "Delete file/folder");
                println!("{:<10} : {:<30}", "nano", "Edit file");
                println!("{:<10} : {:<30}", "cat", "Read file");
                println!("\n{}", "[ INTELLIGENCE ]".cyan());
                println!("{:<10} : {:<30}", "tree", "Show structure");
                println!("{:<10} : {:<30}", "find", "Find by name");
                println!("{:<10} : {:<30}", "grep", "Search content");
                println!("{:<10} : {:<30}", "du", "Disk usage");
                println!("\n{}", "[ NETWORK ]".cyan());
                println!("{:<10} : {:<30}", "upload", "Import from Host [-lock]");
                println!("{:<10} : {:<30}", "download", "Export to Host");
                println!("{}", "=".repeat(60));
            },
            "clear" => self.print_banner(),

            "ls" => {
                // 1. Argumente parsen (Dein Code)
                let show_hidden = args.contains(&"-a") || args.contains(&"-sh");
                let reverse = args.contains(&"-r");
                let mut sort_by = "DATE";

                if let Some(idx) = args.iter().position(|&x| x == "-s") {
                    if idx + 1 < args.len() { sort_by = args[idx + 1]; }
                }

                // 2. Daten laden (Dein Code)
                match self.vfs.lock().await.list_current().await {
                    Ok(items) => {
                        // 3. Filtern (Dein Code)
                        let mut visible_items: Vec<&FileNode> = items.iter()
                            .filter(|item| show_hidden || !item.name.starts_with('.'))
                            .collect();

                        // 4. Sortieren (Dein Code - komplett erhalten)
                        match sort_by.to_uppercase().as_str() {
                            "NAME" => visible_items.sort_by(|a, b| {
                                if reverse { b.name.to_lowercase().cmp(&a.name.to_lowercase()) }
                                else { a.name.to_lowercase().cmp(&b.name.to_lowercase()) }
                            }),
                            "SIZE" => visible_items.sort_by(|a, b| {
                                if reverse { a.size.cmp(&b.size) }
                                else { b.size.cmp(&a.size) }
                            }),
                            "TYPE" => visible_items.sort_by(|a, b| {
                                if reverse { a.is_folder.cmp(&b.is_folder).then(b.name.cmp(&a.name)) }
                                else { b.is_folder.cmp(&a.is_folder).then(a.name.cmp(&b.name)) }
                            }),
                            "OWNER" => visible_items.sort_by(|a, b| {
                                if reverse { b.owner.cmp(&a.owner) } else { a.owner.cmp(&b.owner) }
                            }),
                            "EXT" => visible_items.sort_by(|a, b| {
                                let ext_a = self.get_extension(&a.name);
                                let ext_b = self.get_extension(&b.name);
                                if reverse { ext_b.cmp(ext_a).then(b.name.cmp(&a.name)) }
                                else { ext_a.cmp(ext_b).then(a.name.cmp(&b.name)) }
                            }),
                            // PERMS Sortierung wäre cool für später, lassen wir erst mal weg
                            _ => {
                                visible_items.sort_by(|a, b| {
                                    if reverse { a.created_at.partial_cmp(&b.created_at).unwrap() }
                                    else { b.created_at.partial_cmp(&a.created_at).unwrap() }
                                });
                            }
                        }

                        // 5. Header Ausgabe (NEU: Mit PERM Spalte)
                        // Wir machen die Linie etwas länger (75 statt 65)
                        println!("{:<6} {:<8} {:<10} {:<15} {:<18} NAME", "TYPE", "PERM", "SIZE", "OWNER", "DATE");
                        println!("{}", "-".repeat(75));

                        // 6. Zeilen Ausgabe
                        for item in &visible_items {
                            let type_str = if item.is_folder { "DIR" } else { "FILE" };
                            let lock_icon = if item.lock_pass.is_some() { "🔒" } else { "" };

                            // Deine Farb-Logik
                            let color_name = if item.is_folder { item.name.blue() } else { item.name.green() };

                            // Deine Format-Helper
                            let size_str = if item.is_folder { "---".to_string() } else { format_size(item.size) };
                            let date_str = self.format_date(item.created_at);

                            // --- NEU: Permission Visualisierung ---
                            let perm_str = match item.permissions {
                                0 => "PRIV".red(),          // Private
                                1 => "PUB-R".yellow(),      // Public Read
                                2 => "PUB-W".green(),       // Public Write
                                _ => "???".dimmed(),
                            };
                            // --------------------------------------

                            // Ausgabe mit neuer Spalte
                            println!("{:<6} {:<8} {:<10} {:<15} {:<18} {}{}",
                                     type_str, perm_str, size_str, item.owner, date_str, color_name, lock_icon);
                        }
                        println!("\n[TOTAL: {}]", visible_items.len());
                    },
                    Err(e) => println!("{}", e.to_string().red()), // Hier nutzt du jetzt automatisch PytjaError String
                }
            },

            "mkdir" => {
                if args.is_empty() { println!("Usage: mkdir <name> [-lock]"); return true; }
                let name = args[0].to_string();
                let mut lock_pass = None;

                if args.contains(&"-lock") {
                    let p1 = self.ask_password("Set Password: ");
                    let p2 = self.ask_password("Confirm Password: ");
                    if p1 != p2 { println!("{}", "Passwords do not match.".red()); return true; }
                    if !p1.is_empty() { lock_pass = Some(p1); }
                }

                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.create(name, true, vec![], false, lock_pass).await {
                    println!("{}", e.to_string().red());
                }
            },

            "touch" => {
                if args.is_empty() { println!("Usage: touch <name> [content] [-lock]"); return true; }
                let name = args[0].to_string();
                let mut lock_pass = None;
                let mut content_parts = Vec::new();

                for arg in &args[1..] {
                    if *arg == "-lock" {
                        let p1 = self.ask_password("Set Password: ");
                        if !p1.is_empty() { lock_pass = Some(p1); }
                    } else {
                        content_parts.push(*arg);
                    }
                }
                let content_str = content_parts.join(" ");
                let content_bytes = content_str.trim_matches('"').trim_matches('\'').as_bytes().to_vec();

                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.create(name, false, content_bytes, false, lock_pass).await {
                    println!("{}", e.to_string().red());
                } else {
                    println!("{}", "File created.".green());
                }
            },

            "cd" => {
                if args.is_empty() { return true; }
                let target = args[0];

                // Wir locken den Mutex für die Operationen
                let mut vfs = self.vfs.lock().await;
                let full_path = vfs.resolve_path(target);

                // DB Zugriff Async
                let needs_pass = match vfs.db().get_node(&full_path).await {
                    Ok(Some(node)) => node.lock_pass,
                    _ => None,
                };

                let mut pass_attempt = None;
                if needs_pass.is_some() {
                    let input = self.ask_password(&format!("🔒 Enter Password for {}: ", target));
                    pass_attempt = Some(input);
                }

                // Change Dir Async
                if let Err(e) = vfs.change_dir(target, pass_attempt).await {
                    println!("{}", e.to_string().red());
                }
            },

            "rm" => {
                if args.is_empty() { println!("Usage: rm <name> OR rm -a [path]"); return true; }
                if args[0] == "-a" {
                    let target = if args.len() > 1 { Some(args[1]) } else { None };
                    println!("{} {}", "Clearing user files in:".yellow(), target.unwrap_or("current directory"));

                    // ASYNC AWAIT
                    match self.vfs.lock().await.delete_all_inside(target).await {
                        Ok(msg) => println!("{}", msg.green()),
                        Err(e) => println!("{}", e.to_string().red()),
                    }
                } else {
                    // ASYNC AWAIT
                    if let Err(e) = self.vfs.lock().await.delete(args[0]).await {
                        println!("{}", e.to_string().red());
                    } else {
                        println!("{}", "Deleted.".green());
                    }
                }
            },

            "nano" => {
                if args.is_empty() { println!("Usage: nano <file>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);

                // Check Lock Async
                if let Ok(Some(node)) = self.vfs.lock().await.db().get_node(&path).await {
                    if !self.check_lock(&node) { return true; }
                }

                // Edit Async
                if let Err(e) = self.vfs.lock().await.edit_file(args[0]).await {
                    println!("{}", e.to_string().red());
                }
            },

            "cat" => {
                if args.is_empty() { println!("Usage: cat <name>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);

                // Get Node Async
                match self.vfs.lock().await.db().get_node(&path).await {
                    Ok(Some(node)) => {
                        if !self.check_lock(&node) { return true; }

                        println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                        if let Ok(s) = str::from_utf8(&node.content) {
                            println!("{}", s);
                        } else {
                            println!("{}", "[BINARY DATA PROTECTED]".red());
                        }
                        println!("{}\n", "--- END MESSAGE ---".cyan());
                    },
                    Ok(None) => println!("File not found."),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "upload" => {
                if args.is_empty() { println!("Usage: upload <path> [dest] [-lock] [-a]"); return true; }
                // ... (Parsing logic identisch wie vorher) ...
                let mut host_path_arg = String::new();
                let mut dest_path_arg: Option<String> = None;
                let mut lock_pass: Option<String> = None;
                let mut apply_all = false;
                let mut clean_args = Vec::new();
                for arg in args {
                    if *arg == "-lock" {
                        let p = self.ask_password("Set Upload Password: ");
                        if !p.is_empty() { lock_pass = Some(p); }
                    } else if *arg == "-a" { apply_all = true; }
                    else { clean_args.push(*arg); }
                }
                if !clean_args.is_empty() { host_path_arg = clean_args[0].to_string(); }
                if clean_args.len() >= 2 { dest_path_arg = Some(clean_args[1].to_string()); }

                let clean_host_path = host_path_arg.trim_matches('"').trim_matches('\'');
                println!("{} {}", "Initiating secure upload from:".blue(), clean_host_path);

                // ASYNC AWAIT
                match self.vfs.lock().await.import_from_host(clean_host_path, dest_path_arg, lock_pass, apply_all).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "download" => {
                if args.len() < 2 { println!("Usage: download <ghost_file> <pc_path>"); return true; }
                let ghost_file = args[0];
                let host_path = args[1..].join(" ");
                let clean_host = host_path.trim_matches('"').trim_matches('\'');

                let vfs_path = self.vfs.lock().await.resolve_path(ghost_file);
                if let Ok(Some(node)) = self.vfs.lock().await.db().get_node(&vfs_path).await {
                    if !self.check_lock(&node) { return true; }
                }

                println!("{}", "Decrypting and exporting...".blue());
                // ASYNC AWAIT
                match self.vfs.lock().await.export_to_host(ghost_file, clean_host).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "lock" => {
                if args.is_empty() { println!("Usage: lock <filename>"); return true; }
                let filename = args[0];
                let p1 = self.ask_password("New Password: ");
                let p2 = self.ask_password("Confirm: ");
                if p1 != p2 { println!("{}", "Passwords do not match.".red()); return true; }

                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.chmod(filename, Some(p1)).await {
                    println!("{}", e.to_string().red());
                } else {
                    println!("{}", "File locked successfully.".green());
                }
            },

            "unlock" => {
                if args.is_empty() { println!("Usage: unlock <filename>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);
                if let Ok(Some(node)) = self.vfs.lock().await.db().get_node(&path).await {
                    if !self.check_lock(&node) { return true; }
                }
                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.chmod(args[0], None).await {
                    println!("{}", e.to_string().red());
                } else {
                    println!("{}", "File unlocked.".green());
                }
            },

            // In terminal.rs im match command Block:
            "chmod" => {
                // Usage: chmod <file> <level>
                if args.len() < 2 {
                    println!("Usage: chmod <file> <0|1|2>");
                    println!("  0: Private (Owner only)");
                    println!("  1: Public Read");
                    println!("  2: Public Write");
                    return true;
                }
                let target = args[0];
                let level_str = args[1];

                if let Ok(level) = level_str.parse::<u8>() {
                    match self.vfs.lock().await.chmod_permissions(target, level).await {
                        Ok(msg) => println!("{}", msg.green()),
                        Err(e) => println!("{}", e.to_string().red()),
                    }
                } else {
                    println!("{}", "Level must be a number (0-2)".red());
                }
            },

            "chown" => {
                if args.len() < 2 { println!("Usage: chown <new_owner> <filename>"); return true; }
                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.chown(args[1], args[0]).await {
                    println!("{}", e.to_string().red());
                } else {
                    println!("{}", "Ownership transferred.".green());
                }
            },

            "ping" => {
                if args.is_empty() { println!("Usage: ping <host>"); return true; }
                let host = args[0];

                // NEU: .await am Ende, damit wir asynchron warten
                let status = tokio::process::Command::new("ping")
                    .arg("-c").arg("3").arg(host)
                    .status()
                    .await; // <--- WICHTIG: Das hat gefehlt!

                match status {
                    Ok(s) => {
                        if !s.success() {
                            println!("{}", "Host unreachable.".red());
                        } else {
                            // Optional: Erfolgsmeldung, falls ping selbst nichts ausgibt (ping gibt meistens selbst aus)
                        }
                    },
                    Err(_) => println!("{}", "Ping execution failed.".red()),
                }
            },

            "cp" => {
                if args.len() < 2 { println!("Usage: cp <source> <dest>"); return true; }
                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.copy(args[0], args[1]).await {
                    println!("{}", e.to_string().red());
                }
            },

            "mv" => {
                if args.len() < 2 { println!("Usage: mv <source> <dest> [-lock]"); return true; }
                let mut lock_pass = None;
                if args.contains(&"-lock") {
                    let p = self.ask_password("Set Password for Dest: ");
                    if !p.is_empty() { lock_pass = Some(p); }
                }
                // ASYNC AWAIT
                if let Err(e) = self.vfs.lock().await.move_rename(args[0], args[1], lock_pass).await {
                    println!("{}", e.to_string().red());
                }
            },

            "find" => {
                if args.is_empty() { println!("Usage: find <name_pattern>"); return true; }
                println!("Searching for '{}'...", args[0]);
                // ASYNC AWAIT
                match self.vfs.lock().await.find(args[0]).await {
                    Ok(results) => {
                        if results.is_empty() { println!("No matches."); }
                        for r in results { println!("{}", r.green()); }
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "grep" => {
                if args.is_empty() { println!("Usage: grep <content>"); return true; }
                let query = args.join(" ");
                println!("Deep searching for '{}'...", query);
                // ASYNC AWAIT
                match self.vfs.lock().await.grep(&query).await {
                    Ok(results) => {
                        if results.is_empty() { println!("No matches."); }
                        for r in results { println!("MATCH: {}", r.green()); }
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "tree" => {
                // ASYNC AWAIT
                let _ = self.vfs.lock().await.tree_view().await;
            },

            "du" => {
                let used = self.vfs.lock().await.db().get_total_usage(&self.user_id).await.unwrap_or(0);
                let mb = used as f64 / (1024.0 * 1024.0);
                println!("Directory size: {}", format!("{:.2} MB", mb).bold());
            },

            "quota" => {
                let used = self.vfs.lock().await.db().get_total_usage(&self.user_id).await.unwrap_or(0);
                let limit = 100 * 1024 * 1024;
                let percent = (used as f64 / limit as f64) * 100.0;
                let mb = used as f64 / (1024.0 * 1024.0);

                let text = format!("{:.2} MB / 100.00 MB ({:.1}%)", mb, percent);
                if percent > 80.0 { println!("{}", text.red()); } else { println!("{}", text.green()); }
            },

            "whoami" => {
                println!("User: {}", self.user_id.bold());
                println!("Role: Agent");
                println!("Session: Async Secure TTY");
            },

            "exec" => {
                if args.is_empty() { println!("Usage: exec <script.py>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);
                if let Ok(Some(node)) = self.vfs.lock().await.db().get_node(&path).await {
                    if !self.check_lock(&node) { return true; }
                }
                println!("{}", "[!] EXECUTING PYTHON KERNEL...".yellow());
                // ASYNC AWAIT
                match self.vfs.lock().await.exec_script(args[0]).await {
                    Ok(out) => {
                        println!("----------------------------------------");
                        println!("{}", out);
                        println!("----------------------------------------");
                        println!("{}", "[+] Execution finished.".green());
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "echo" => { println!("{}", args.join(" ")); },

            "passwd" | "zip" | "unzip" => {
                println!("{}", "Not implemented in V2.0 Async Core.".yellow());
            },

            // Plugin System
            other_cmd => {
                if self.plugin_manager.has_command(other_cmd) {
                    let args_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
                    let vfs_clone = self.vfs.clone();
                    let cmd_string = other_cmd.to_string();

                    // Wir müssen den Plugin Manager klonen oder temporär ausleihen.
                    // Da PluginManager nicht einfach klonbar ist (HashMap), tricksen wir:
                    // Wir führen es im Main-Thread aus, aber "block_in_place".

                    let pm_ptr = &self.plugin_manager;

                    // Tokio verbietet blockierende Calls im Async Thread.
                    // block_in_place erlaubt es uns, den Thread als "Sync" zu nutzen.
                    tokio::task::block_in_place(move || {
                        let args_str_vec: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
                        match pm_ptr.execute(&cmd_string, args_str_vec, vfs_clone) {
                            Ok(output) => {
                                if !output.is_empty() { println!("{}", output.green()); }
                            },
                            Err(e) => println!("Plugin Crash: {}", e.to_string().red()),
                        }
                    });
                } else {
                    println!("Command not found: {}", other_cmd);
                }
            }
        }
        true
    }
}

// Hilfsfunktion (unverändert)
fn format_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}
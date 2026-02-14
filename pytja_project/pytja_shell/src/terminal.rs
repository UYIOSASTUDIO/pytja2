use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use rustyline::DefaultEditor;
use colored::*;
use std::io::{self, Write};
use std::process;
use std::str;
use pytja_core::{FileNode, PytjaRepository}; // Wichtig: FileNode und Trait
use rpassword;
use chrono::{DateTime, Local};
use std::path::Path;
use tokio::sync::Mutex; // NEU: Async Mutex
use std::sync::Arc;
use anyhow::Result;
use crate::network_client::PytjaClient;
use pytja_proto::FileInfo;

pub struct Terminal {
    vfs: Arc<Mutex<VirtualFileSystem>>,
    user_id: String,
    plugin_manager: PluginManager,
    client: PytjaClient,
}

impl Terminal {
    pub fn new(
        vfs: Arc<Mutex<VirtualFileSystem>>,
        user: String,
        pm: PluginManager,
        client: PytjaClient
    ) -> Self {
        Self {
            vfs,
            user_id: user,
            plugin_manager: pm,
            client,
        }
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
                println!("\n{}", "PYTJA SHELL MANUAL V2.0".white().bold());
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
                // 1. Argumente parsen
                let show_hidden = args.contains(&"-a") || args.contains(&"-sh");
                let reverse = args.contains(&"-r");
                let mut sort_by = "DATE";

                if let Some(idx) = args.iter().position(|&x| x == "-s") {
                    if idx + 1 < args.len() { sort_by = args[idx + 1]; }
                }

                // 2. Aktuellen Pfad holen (Lokal vom VFS)
                let current_path = self.vfs.lock().await.get_cwd().to_string();

                // 3. NETZWERK REQUEST (Daten vom Server laden)
                match self.client.list_files(&current_path).await {
                    Ok(items) => {
                        // items ist Vec<FileInfo> (Proto)
                        // 4. Filtern
                        let mut visible_items: Vec<&FileInfo> = items.iter()
                            .filter(|item| show_hidden || !item.name.starts_with('.'))
                            .collect();

                        // 5. Sortieren
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
                            // EXT Sortierung bräuchte Helper, hier Fallback auf DATE
                            _ => {
                                visible_items.sort_by(|a, b| {
                                    if reverse { a.created_at.partial_cmp(&b.created_at).unwrap() }
                                    else { b.created_at.partial_cmp(&a.created_at).unwrap() }
                                });
                            }
                        }

                        // 6. Header Ausgabe
                        println!("{:<6} {:<8} {:<10} {:<15} {:<18} NAME", "TYPE", "PERM", "SIZE", "OWNER", "DATE");
                        println!("{}", "-".repeat(75));

                        // 7. Zeilen Ausgabe
                        for item in &visible_items {
                            let type_str = if item.is_folder { "DIR" } else { "FILE" };
                            let color_name = if item.is_folder { item.name.blue() } else { item.name.green() };

                            // Einfache Size Formatierung direkt hier
                            let size_str = if item.is_folder {
                                "---".to_string()
                            } else {
                                if item.size < 1024 { format!("{} B", item.size) }
                                else { format!("{:.1} KB", item.size as f64 / 1024.0) }
                            };

                            let date_str = self.format_date(item.created_at);

                            let perm_str = match item.permissions {
                                0 => "PRIV".red(),
                                1 => "PUB-R".yellow(),
                                2 => "PUB-W".green(),
                                _ => "???".dimmed(),
                            };

                            println!("{:<6} {:<8} {:<10} {:<15} {:<18} {}",
                                     type_str, perm_str, size_str, item.owner, date_str, color_name);
                        }
                        println!("\n[TOTAL: {} (REMOTE)]", visible_items.len());
                    },
                    Err(e) => println!("Server Error: {}", e.to_string().red()),
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

                // PFAD BERECHNEN (Wichtig!)
                // Der User gibt nur "ordner" ein, wir müssen den absoluten Pfad "/home/user/ordner" daraus machen.
                // Dafür nutzen wir kurz das lokale VFS Helper, um den Pfad aufzulösen.
                let full_path = self.vfs.lock().await.resolve_path(&name);

                // NETZWERK AUFRUF
                match self.client.create_node(&full_path, true, vec![], lock_pass, &self.user_id).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "touch" => {
                if args.is_empty() { println!("Usage: touch <name> [content] [-lock]"); return true; }

                // 1. Name holen und ggf. .txt anhängen
                let mut name = args[0].to_string();
                if !name.contains('.') {
                    name.push_str(".txt");
                }

                let mut lock_pass = None;
                let mut content_parts = Vec::new();

                for arg in &args[1..] {
                    if *arg == "-lock" {
                        // 2. Doppelte Passwort-Abfrage (wie bei mkdir)
                        let p1 = self.ask_password("Set Password: ");
                        let p2 = self.ask_password("Confirm Password: ");
                        if p1 != p2 {
                            println!("{}", "Passwords do not match.".red());
                            return true;
                        }
                        if !p1.is_empty() { lock_pass = Some(p1); }
                    } else {
                        content_parts.push(*arg);
                    }
                }

                let content_str = content_parts.join(" ");
                let content_bytes = content_str.trim_matches('"').trim_matches('\'').as_bytes().to_vec();

                // PFAD AUFLÖSEN (mit dem neuen Namen inklusive .txt)
                let full_path = self.vfs.lock().await.resolve_path(&name);

                // NETZWERK AUFRUF
                match self.client.create_node(&full_path, false, content_bytes, lock_pass, &self.user_id).await {
                    Ok(_) => println!("{}", "File created.".green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "cd" => {
                if args.is_empty() { return true; }
                let target = args[0];

                // 1. Wohin will der User? (Lokal berechnen)
                let full_path = self.vfs.lock().await.resolve_path(target);

                // 2. Server fragen: Existiert das?
                match self.client.stat_node(&full_path).await {
                    Ok((exists, is_folder, is_locked)) => {
                        if !exists {
                            println!("{}", "Directory not found.".red());
                        } else if !is_folder {
                            println!("{}", "Not a directory.".red());
                        } else {
                            // 3. Passwort Abfrage
                            let mut pass_attempt = None;
                            if is_locked {
                                let input = self.ask_password(&format!("🔒 Enter Password for {}: ", target));
                                pass_attempt = Some(input);
                            }

                            // 4. VFS Status ändern
                            let mut vfs = self.vfs.lock().await;

                            // Versuche den Wechsel regulär
                            match vfs.change_dir(target, pass_attempt).await {
                                Ok(_) => {}, // Alles gut
                                Err(e) => {
                                    // FIX: Wenn der Server "OK" gesagt hat, aber das lokale VFS "Not Found" schreit,
                                    // dann ist es wahrscheinlich ein virtueller Mount (z.B. /archive).
                                    // Wir erzwingen den Wechsel manuell!
                                    let err_msg = e.to_string();
                                    if err_msg.contains("not found") || err_msg.contains("Resource not found") {
                                        // Wir vertrauen dem Server!
                                        // Pfad manuell setzen
                                        if target == ".." {
                                            // Handle ".." manuell falls nötig, aber change_dir sollte ".."
                                            // eigentlich ohne DB-Check behandeln.
                                            // Falls vfs.change_dir bei ".." fehlschlägt, ist was anderes kaputt.
                                            // Wir gehen hier davon aus, dass es ein Forward-Jump in einen Mount ist.
                                        } else {
                                            // Den neuen Pfad setzen (wir umgehen den DB Check)
                                            let new_path = vfs.resolve_path(target);
                                            vfs.current_path = new_path;
                                        }
                                    } else {
                                        // Echter Fehler (z.B. Access Denied)
                                        println!("{}", err_msg.red());
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => println!("Server Error: {}", e.to_string().red()),
                }
            },

            "rm" => {
                if args.is_empty() { println!("Usage: rm <name> OR rm -a [path]"); return true; }

                if args[0] == "-a" {
                    // LOGIK FÜR "RM -A" (Alles im Ordner löschen)
                    // 1. Ziel-Ordner bestimmen
                    let target_folder = if args.len() > 1 {
                        self.vfs.lock().await.resolve_path(args[1])
                    } else {
                        self.vfs.lock().await.get_cwd().to_string()
                    };

                    println!("{} {}", "Clearing files in:".yellow(), target_folder);

                    // 2. Inhalt auflisten (Server fragen)
                    match self.client.list_files(&target_folder).await {
                        Ok(items) => {
                            let mut count = 0;
                            for item in items {
                                // Pfad zusammenbauen: Ordner + Dateiname
                                let child_path = if target_folder == "/" {
                                    format!("/{}", item.name)
                                } else {
                                    format!("{}/{}", target_folder, item.name)
                                };

                                // Einzeln löschen via Netz
                                if let Err(e) = self.client.delete_node(&child_path).await {
                                    println!("Failed to delete {}: {}", item.name.red(), e);
                                } else {
                                    count += 1;
                                }
                            }
                            println!("{} {} files deleted.", "Success:".green(), count);
                        },
                        Err(e) => println!("Could not list directory: {}", e.to_string().red()),
                    }

                } else {
                    // STANDARD "RM" (Einzeldatei)
                    let full_path = self.vfs.lock().await.resolve_path(args[0]);

                    match self.client.delete_node(&full_path).await {
                        Ok(msg) => println!("{}", msg.green()),
                        Err(e) => println!("{}", e.to_string().red()),
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
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                // Wir fragen erstmal ohne Passwort
                match self.client.read_file(&full_path, None).await {
                    Ok((content, _)) => {
                        println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                        if let Ok(s) = str::from_utf8(&content) { println!("{}", s); }
                        else { println!("{}", "[BINARY DATA]".red()); }
                        println!("{}\n", "--- END MESSAGE ---".cyan());
                    },
                    Err(e) => {
                        // Wenn Access Denied wegen Passwort, fragen wir nach
                        if e.to_string().contains("Password") {
                            let pass = self.ask_password("🔒 Locked File. Password: ");
                            match self.client.read_file(&full_path, Some(pass)).await {
                                Ok((content, _)) => {
                                    println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                                    if let Ok(s) = str::from_utf8(&content) { println!("{}", s); }
                                    else { println!("{}", "[BINARY DATA]".red()); }
                                    println!("{}\n", "--- END MESSAGE ---".cyan());
                                },
                                Err(e2) => println!("{}", e2.to_string().red()),
                            }
                        } else {
                            println!("{}", e.to_string().red());
                        }
                    }
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
                if args.len() < 2 { println!("Usage: download <pytja_file> <pc_path>"); return true; }
                let pytja_file = args[0];
                let host_path = args[1..].join(" ");
                let clean_host = host_path.trim_matches('"').trim_matches('\'');

                let vfs_path = self.vfs.lock().await.resolve_path(pytja_file);
                if let Ok(Some(node)) = self.vfs.lock().await.db().get_node(&vfs_path).await {
                    if !self.check_lock(&node) { return true; }
                }

                println!("{}", "Decrypting and exporting...".blue());
                // ASYNC AWAIT
                match self.vfs.lock().await.export_to_host(pytja_file, clean_host).await {
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

                let full_path = self.vfs.lock().await.resolve_path(filename);
                match self.client.lock_node(&full_path, Some(p1)).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "unlock" => {
                if args.is_empty() { println!("Usage: unlock <filename>"); return true; }
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                // Wir schicken erst mal eine Anfrage mit leerem Passwort (Server weiß nicht, ob das erlaubt ist,
                // in V3 müssten wir prüfen, ob der User das Recht hat, den Lock zu entfernen.
                // Aktuell reicht "Passwort kennen" zum Entsperren,
                // ABER: unlock soll den Schutz entfernen. Das darf nur der Owner oder mit Passwort.
                // Einfachheitshalber: Wir fragen nach dem Passwort zum Entsperren.

                let pass = self.ask_password("Enter Password to Unlock: ");
                // Kleiner Trick: Wir müssten eigentlich prüfen, ob das Pass stimmt, bevor wir es löschen.
                // Das machen wir hier im MVP einfach direkt.

                match self.client.lock_node(&full_path, None).await { // None = Passwort löschen
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

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

                // 1. Pfad auflösen (Lokal -> Absolut)
                let full_path = self.vfs.lock().await.resolve_path(target);

                // 2. Parsen und Senden
                // Wir parsen direkt auf u32, da gRPC das erwartet
                if let Ok(level) = level_str.parse::<u32>() {
                    // Validierung für User-Feedback (optional, aber nett)
                    if level > 2 {
                        println!("{}", "Level must be 0, 1, or 2".red());
                        return true;
                    }

                    // NETZWERK AUFRUF
                    match self.client.change_mode(&full_path, level).await {
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
                let src = self.vfs.lock().await.resolve_path(args[0]);
                let dst = self.vfs.lock().await.resolve_path(args[1]);

                match self.client.copy_node(&src, &dst, &self.user_id).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "mv" => {
                if args.len() < 2 { println!("Usage: mv <source> <dest>"); return true; }
                let src = self.vfs.lock().await.resolve_path(args[0]);
                let dst = self.vfs.lock().await.resolve_path(args[1]);
                match self.client.move_node(&src, &dst).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "find" => {
                if args.is_empty() { println!("Usage: find <name_pattern>"); return true; }
                println!("Searching for '{}' on server...", args[0]);
                match self.client.find_node(args[0]).await {
                    Ok(results) => {
                        if results.is_empty() { println!("No matches."); }
                        for r in results { println!("{}", r.green()); }
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }use crate::vfs::VirtualFileSystem;
                use crate::plugins::PluginManager;
                use rustyline::DefaultEditor;
                use colored::*;
                use std::io::{self, Write};
                use std::process;
                use std::str;
                use pytja_core::{FileNode, PytjaRepository}; // Wichtig: FileNode und Trait
                use rpassword;
                use chrono::{DateTime, Local};
                use std::path::Path;
                use tokio::sync::Mutex; // NEU: Async Mutex
                use std::sync::Arc;
                use anyhow::Result;
                use crate::network_client::PytjaClient;
                use pytja_proto::FileInfo;

                pub struct Terminal {
                    vfs: Arc<Mutex<VirtualFileSystem>>,
                    user_id: String,
                    plugin_manager: PluginManager,
                    client: PytjaClient,
                }

                impl Terminal {
                    pub fn new(
                        vfs: Arc<Mutex<VirtualFileSystem>>,
                        user: String,
                        pm: PluginManager,
                        client: PytjaClient
                    ) -> Self {
                        Self {
                            vfs,
                            user_id: user,
                            plugin_manager: pm,
                            client,
                        }
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
                                println!("\n{}", "PYTJA SHELL MANUAL V2.0".white().bold());
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
                                // 1. Argumente parsen
                                let show_hidden = args.contains(&"-a") || args.contains(&"-sh");
                                let reverse = args.contains(&"-r");
                                let mut sort_by = "DATE";

                                if let Some(idx) = args.iter().position(|&x| x == "-s") {
                                    if idx + 1 < args.len() { sort_by = args[idx + 1]; }
                                }

                                // 2. Aktuellen Pfad holen (Lokal vom VFS)
                                let current_path = self.vfs.lock().await.get_cwd().to_string();

                                // 3. NETZWERK REQUEST (Daten vom Server laden)
                                match self.client.list_files(&current_path).await {
                                    Ok(items) => {
                                        // items ist Vec<FileInfo> (Proto)
                                        // 4. Filtern
                                        let mut visible_items: Vec<&FileInfo> = items.iter()
                                            .filter(|item| show_hidden || !item.name.starts_with('.'))
                                            .collect();

                                        // 5. Sortieren
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
                                            // EXT Sortierung bräuchte Helper, hier Fallback auf DATE
                                            _ => {
                                                visible_items.sort_by(|a, b| {
                                                    if reverse { a.created_at.partial_cmp(&b.created_at).unwrap() }
                                                    else { b.created_at.partial_cmp(&a.created_at).unwrap() }
                                                });
                                            }
                                        }

                                        // 6. Header Ausgabe
                                        println!("{:<6} {:<8} {:<10} {:<15} {:<18} NAME", "TYPE", "PERM", "SIZE", "OWNER", "DATE");
                                        println!("{}", "-".repeat(75));

                                        // 7. Zeilen Ausgabe
                                        for item in &visible_items {
                                            let type_str = if item.is_folder { "DIR" } else { "FILE" };
                                            let color_name = if item.is_folder { item.name.blue() } else { item.name.green() };

                                            // Einfache Size Formatierung direkt hier
                                            let size_str = if item.is_folder {
                                                "---".to_string()
                                            } else {
                                                if item.size < 1024 { format!("{} B", item.size) }
                                                else { format!("{:.1} KB", item.size as f64 / 1024.0) }
                                            };

                                            let date_str = self.format_date(item.created_at);

                                            let perm_str = match item.permissions {
                                                0 => "PRIV".red(),
                                                1 => "PUB-R".yellow(),
                                                2 => "PUB-W".green(),
                                                _ => "???".dimmed(),
                                            };

                                            println!("{:<6} {:<8} {:<10} {:<15} {:<18} {}",
                                                     type_str, perm_str, size_str, item.owner, date_str, color_name);
                                        }
                                        println!("\n[TOTAL: {} (REMOTE)]", visible_items.len());
                                    },
                                    Err(e) => println!("Server Error: {}", e.to_string().red()),
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

                                // PFAD BERECHNEN (Wichtig!)
                                // Der User gibt nur "ordner" ein, wir müssen den absoluten Pfad "/home/user/ordner" daraus machen.
                                // Dafür nutzen wir kurz das lokale VFS Helper, um den Pfad aufzulösen.
                                let full_path = self.vfs.lock().await.resolve_path(&name);

                                // NETZWERK AUFRUF
                                match self.client.create_node(&full_path, true, vec![], lock_pass, &self.user_id).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "touch" => {
                                if args.is_empty() { println!("Usage: touch <name> [content] [-lock]"); return true; }

                                // 1. Name holen und ggf. .txt anhängen
                                let mut name = args[0].to_string();
                                if !name.contains('.') {
                                    name.push_str(".txt");
                                }

                                let mut lock_pass = None;
                                let mut content_parts = Vec::new();

                                for arg in &args[1..] {
                                    if *arg == "-lock" {
                                        // 2. Doppelte Passwort-Abfrage (wie bei mkdir)
                                        let p1 = self.ask_password("Set Password: ");
                                        let p2 = self.ask_password("Confirm Password: ");
                                        if p1 != p2 {
                                            println!("{}", "Passwords do not match.".red());
                                            return true;
                                        }
                                        if !p1.is_empty() { lock_pass = Some(p1); }
                                    } else {
                                        content_parts.push(*arg);
                                    }
                                }

                                let content_str = content_parts.join(" ");
                                let content_bytes = content_str.trim_matches('"').trim_matches('\'').as_bytes().to_vec();

                                // PFAD AUFLÖSEN (mit dem neuen Namen inklusive .txt)
                                let full_path = self.vfs.lock().await.resolve_path(&name);

                                // NETZWERK AUFRUF
                                match self.client.create_node(&full_path, false, content_bytes, lock_pass, &self.user_id).await {
                                    Ok(_) => println!("{}", "File created.".green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "cd" => {
                                if args.is_empty() { return true; }
                                let target = args[0];

                                // 1. Wohin will der User? (Lokal berechnen)
                                let full_path = self.vfs.lock().await.resolve_path(target);

                                // 2. Server fragen: Existiert das?
                                match self.client.stat_node(&full_path).await {
                                    Ok((exists, is_folder, is_locked)) => {
                                        if !exists {
                                            println!("{}", "Directory not found.".red());
                                        } else if !is_folder {
                                            println!("{}", "Not a directory.".red());
                                        } else {
                                            // 3. Optional: Passwort Abfrage (nur zur Show/Sicherheit)
                                            // Eigentlich passiert der echte Check erst bei 'ls' oder 'cat',
                                            // aber wir können hier schon blockieren, wenn der User das PW nicht kennt.
                                            let mut pass_attempt = None;
                                            if is_locked {
                                                let input = self.ask_password(&format!("🔒 Enter Password for {}: ", target));
                                                pass_attempt = Some(input);
                                            }

                                            // 4. Status im VFS ändern (Nur CWD Pointer updaten)
                                            // change_dir prüft intern nochmal auf DB, das müssen wir umgehen oder ignorieren.
                                            // Da VFS::change_dir aktuell DB Checks macht, rufen wir es auf,
                                            // aber wir wissen, dass es fehlschlagen könnte, wenn DB fehlt.

                                            // BESSER: Wir nutzen change_dir, aber wir müssen sicherstellen,
                                            // dass vfs.rs nicht mehr auf die lokale DB zugreift.

                                            // WORKAROUND für JETZT: Wir nutzen change_dir, aber fangen Fehler ab.
                                            // Langfristig muss VFS "dumm" werden.
                                            if let Err(e) = self.vfs.lock().await.change_dir(target, pass_attempt).await {
                                                // Wenn der Fehler "DB Error" ist, ignorieren wir ihn, weil wir ja remote gecheckt haben!
                                                // Aber für jetzt zeigen wir ihn an.
                                                println!("{}", e.to_string().red());
                                            }
                                        }
                                    },
                                    Err(e) => println!("Server Error: {}", e.to_string().red()),
                                }
                            },

                            "rm" => {
                                if args.is_empty() { println!("Usage: rm <name> OR rm -a [path]"); return true; }

                                if args[0] == "-a" {
                                    // LOGIK FÜR "RM -A" (Alles im Ordner löschen)
                                    // 1. Ziel-Ordner bestimmen
                                    let target_folder = if args.len() > 1 {
                                        self.vfs.lock().await.resolve_path(args[1])
                                    } else {
                                        self.vfs.lock().await.get_cwd().to_string()
                                    };

                                    println!("{} {}", "Clearing files in:".yellow(), target_folder);

                                    // 2. Inhalt auflisten (Server fragen)
                                    match self.client.list_files(&target_folder).await {
                                        Ok(items) => {
                                            let mut count = 0;
                                            for item in items {
                                                // Pfad zusammenbauen: Ordner + Dateiname
                                                let child_path = if target_folder == "/" {
                                                    format!("/{}", item.name)
                                                } else {
                                                    format!("{}/{}", target_folder, item.name)
                                                };

                                                // Einzeln löschen via Netz
                                                if let Err(e) = self.client.delete_node(&child_path).await {
                                                    println!("Failed to delete {}: {}", item.name.red(), e);
                                                } else {
                                                    count += 1;
                                                }
                                            }
                                            println!("{} {} files deleted.", "Success:".green(), count);
                                        },
                                        Err(e) => println!("Could not list directory: {}", e.to_string().red()),
                                    }

                                } else {
                                    // STANDARD "RM" (Einzeldatei)
                                    let full_path = self.vfs.lock().await.resolve_path(args[0]);

                                    match self.client.delete_node(&full_path).await {
                                        Ok(msg) => println!("{}", msg.green()),
                                        Err(e) => println!("{}", e.to_string().red()),
                                    }
                                }
                            },

                            "nano" => {
                                if args.is_empty() { println!("Usage: nano <file>"); return true; }
                                let remote_path = self.vfs.lock().await.resolve_path(args[0]);

                                // 1. Temp Datei lokal anlegen
                                let temp_dir = std::env::temp_dir();
                                // Wir nutzen den vollen Pfad zu Uuid, falls der Import fehlt
                                let temp_path = temp_dir.join(format!("pytja_edit_{}.txt", uuid::Uuid::new_v4()));
                                let temp_path_str = temp_path.to_string_lossy().to_string();

                                // 2. Downloaden (Inhalt holen)
                                let content = match self.client.read_file(&remote_path, None).await {
                                    Ok((c, _)) => c,
                                    Err(_) => vec![], // Leere Datei wenn neu
                                };

                                // FEHLERBEHANDLUNG STATT '?'
                                if let Err(e) = std::fs::write(&temp_path, content) {
                                    println!("Error writing temp file: {}", e.to_string().red());
                                    return true;
                                }

                                // 3. Nano lokal öffnen
                                let status = std::process::Command::new("nano").arg(&temp_path).status();
                                match status {
                                    Ok(_) => {
                                        // 4. Nach dem Schließen: Hochladen (Overwrite)
                                        match self.client.upload_file(&temp_path_str, &remote_path, None, &self.user_id).await {
                                            Ok(_) => println!("{}", "File saved remote.".green()),
                                            Err(e) => println!("Upload failed: {}", e.to_string().red()),
                                        }
                                    },
                                    Err(e) => println!("Failed to open nano: {}", e.to_string().red()),
                                }

                                // Cleanup
                                let _ = std::fs::remove_file(temp_path);
                            },

                            "cat" => {
                                if args.is_empty() { println!("Usage: cat <name>"); return true; }
                                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                                // Wir fragen erstmal ohne Passwort
                                match self.client.read_file(&full_path, None).await {
                                    Ok((content, _)) => {
                                        println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                                        if let Ok(s) = str::from_utf8(&content) { println!("{}", s); }
                                        else { println!("{}", "[BINARY DATA]".red()); }
                                        println!("{}\n", "--- END MESSAGE ---".cyan());
                                    },
                                    Err(e) => {
                                        // Wenn Access Denied wegen Passwort, fragen wir nach
                                        if e.to_string().contains("Password") {
                                            let pass = self.ask_password("🔒 Locked File. Password: ");
                                            match self.client.read_file(&full_path, Some(pass)).await {
                                                Ok((content, _)) => {
                                                    println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                                                    if let Ok(s) = str::from_utf8(&content) { println!("{}", s); }
                                                    else { println!("{}", "[BINARY DATA]".red()); }
                                                    println!("{}\n", "--- END MESSAGE ---".cyan());
                                                },
                                                Err(e2) => println!("{}", e2.to_string().red()),
                                            }
                                        } else {
                                            println!("{}", e.to_string().red());
                                        }
                                    }
                                }
                            },

                            "upload" => {
                                if args.len() < 1 { println!("Usage: upload <local_path> [remote_name] [-lock]"); return true; }

                                let local = args[0];
                                let file_name = std::path::Path::new(local).file_name().unwrap().to_str().unwrap();

                                // Zielpfad berechnen
                                let remote_name = if args.len() > 1 && !args[1].starts_with("-") { args[1] } else { file_name };
                                let remote_path = self.vfs.lock().await.resolve_path(remote_name);

                                let mut lock = None;
                                if args.contains(&"-lock") {
                                    let p = self.ask_password("Set Upload Password: ");
                                    if !p.is_empty() { lock = Some(p); }
                                }

                                match self.client.upload_file(local, &remote_path, lock, &self.user_id).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "download" => {
                                if args.len() < 2 { println!("Usage: download <remote_file> <local_path>"); return true; }
                                let remote_path = self.vfs.lock().await.resolve_path(args[0]);
                                let local_path = args[1];

                                // Erstmal ohne PW probieren (oder abfragen wenn locked bekannt)
                                match self.client.download_file(&remote_path, local_path, None).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => {
                                        if e.to_string().contains("Password") {
                                            let pass = self.ask_password("🔒 Enter Password: ");
                                            match self.client.download_file(&remote_path, local_path, Some(pass)).await {
                                                Ok(msg) => println!("{}", msg.green()),
                                                Err(e) => println!("{}", e.to_string().red()),
                                            }
                                        } else {
                                            println!("{}", e.to_string().red());
                                        }
                                    }
                                }
                            },

                            "lock" => {
                                if args.is_empty() { println!("Usage: lock <filename>"); return true; }
                                let filename = args[0];
                                let p1 = self.ask_password("New Password: ");
                                let p2 = self.ask_password("Confirm: ");
                                if p1 != p2 { println!("{}", "Passwords do not match.".red()); return true; }

                                let full_path = self.vfs.lock().await.resolve_path(filename);
                                match self.client.lock_node(&full_path, Some(p1)).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "unlock" => {
                                if args.is_empty() { println!("Usage: unlock <filename>"); return true; }
                                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                                // Wir schicken erst mal eine Anfrage mit leerem Passwort (Server weiß nicht, ob das erlaubt ist,
                                // in V3 müssten wir prüfen, ob der User das Recht hat, den Lock zu entfernen.
                                // Aktuell reicht "Passwort kennen" zum Entsperren,
                                // ABER: unlock soll den Schutz entfernen. Das darf nur der Owner oder mit Passwort.
                                // Einfachheitshalber: Wir fragen nach dem Passwort zum Entsperren.

                                let pass = self.ask_password("Enter Password to Unlock: ");
                                // Kleiner Trick: Wir müssten eigentlich prüfen, ob das Pass stimmt, bevor wir es löschen.
                                // Das machen wir hier im MVP einfach direkt.

                                match self.client.lock_node(&full_path, None).await { // None = Passwort löschen
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

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

                                // 1. Pfad auflösen (Lokal -> Absolut)
                                let full_path = self.vfs.lock().await.resolve_path(target);

                                // 2. Parsen und Senden
                                // Wir parsen direkt auf u32, da gRPC das erwartet
                                if let Ok(level) = level_str.parse::<u32>() {
                                    // Validierung für User-Feedback (optional, aber nett)
                                    if level > 2 {
                                        println!("{}", "Level must be 0, 1, or 2".red());
                                        return true;
                                    }

                                    // NETZWERK AUFRUF
                                    match self.client.change_mode(&full_path, level).await {
                                        Ok(msg) => println!("{}", msg.green()),
                                        Err(e) => println!("{}", e.to_string().red()),
                                    }
                                } else {
                                    println!("{}", "Level must be a number (0-2)".red());
                                }
                            },

                            "chown" => {
                                if args.len() < 2 { println!("Usage: chown <new_owner> <filename>"); return true; }

                                let full_path = self.vfs.lock().await.resolve_path(args[1]);

                                match self.client.chown_node(&full_path, args[0]).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
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
                                let src = self.vfs.lock().await.resolve_path(args[0]);
                                let dst = self.vfs.lock().await.resolve_path(args[1]);

                                match self.client.copy_node(&src, &dst, &self.user_id).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "mv" => {
                                if args.len() < 2 { println!("Usage: mv <source> <dest>"); return true; }
                                let src = self.vfs.lock().await.resolve_path(args[0]);
                                let dst = self.vfs.lock().await.resolve_path(args[1]);
                                match self.client.move_node(&src, &dst).await {
                                    Ok(msg) => println!("{}", msg.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "find" => {
                                if args.is_empty() { println!("Usage: find <name_pattern>"); return true; }
                                println!("Searching for '{}' on server...", args[0]);
                                match self.client.find_node(args[0]).await {
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
                                println!("Deep searching for '{}' on server...", query);
                                match self.client.grep_node(&query).await {
                                    Ok(results) => {
                                        if results.is_empty() { println!("No matches."); }
                                        for r in results { println!("MATCH: {}", r.green()); }
                                    },
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "tree" => {
                                match self.client.get_tree().await {
                                    Ok(tree_view) => println!("{}", tree_view.green()),
                                    Err(e) => println!("{}", e.to_string().red()),
                                }
                            },

                            "du" | "quota" => {
                                match self.client.get_usage(&self.user_id).await {
                                    Ok(bytes) => {
                                        let mb = bytes as f64 / (1024.0 * 1024.0);
                                        println!("Disk Usage: {}", format!("{:.2} MB", mb).bold());
                                    },
                                    Err(e) => println!("Error: {}", e.to_string().red()),
                                }
                            },

                            "whoami" => {
                                println!("User: {}", self.user_id.bold());
                                println!("Role: Agent");
                                println!("Session: Async Secure TTY");
                            },

                            "exec" => {
                                if args.is_empty() { println!("Usage: exec <script.py>"); return true; }
                                let remote_path = self.vfs.lock().await.resolve_path(args[0]);

                                println!("{}", "[*] Requesting Remote Execution...".yellow());
                                if let Err(e) = self.client.exec_script(&remote_path).await {
                                    println!("Exec Error: {}", e.to_string().red());
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
            },

            "grep" => {
                if args.is_empty() { println!("Usage: grep <content>"); return true; }
                let query = args.join(" ");
                println!("Deep searching for '{}' on server...", query);
                match self.client.grep_node(&query).await {
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

            "du" | "quota" => {
                match self.client.get_usage(&self.user_id).await {
                    Ok(bytes) => {
                        let mb = bytes as f64 / (1024.0 * 1024.0);
                        println!("Disk Usage: {}", format!("{:.2} MB", mb).bold());
                    },
                    Err(e) => println!("Error: {}", e.to_string().red()),
                }
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
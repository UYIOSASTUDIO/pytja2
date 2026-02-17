use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::PytjaClient;
use rustyline::DefaultEditor;
use colored::*;
use std::io::{self, Write};
use std::process;
use std::str;
use pytja_core::{FileNode, PytjaRepository}; // Wichtig: PytjaRepository für Trait-Methoden
use rpassword;
use chrono::{DateTime, Local};
use tokio::sync::Mutex;
use std::sync::Arc;
use pytja_proto::FileInfo;
use indicatif::{ProgressBar, ProgressStyle}; // NEU: Für Ladebalken
use directories::ProjectDirs; // NEU: Für Speicherpfade
use rustyline::error::ReadlineError;

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
        let mut rl = DefaultEditor::new()?;

        // 1. History laden (Enterprise Standard)
        let history_path = if let Some(proj_dirs) = ProjectDirs::from("com", "pytja", "shell") {
            let data_dir = proj_dirs.data_dir();
            std::fs::create_dir_all(data_dir).ok(); // Ordner erstellen falls nicht existent
            Some(data_dir.join("history.txt"))
        } else {
            None
        };

        if let Some(ref path) = history_path {
            if rl.load_history(path).is_err() {
                // Keine History vorhanden oder Fehler, ignorieren wir beim ersten Start
            }
        }

        loop {
            let cwd = self.vfs.lock().await.get_cwd().to_string();
            let prompt = format!("┌──({}㉿pytja)-[{}]\n└─$ ", self.user_id.red(), cwd.blue());

            let readline = rl.readline(&prompt);
            match readline {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let _ = rl.add_history_entry(line);

                    // Support für verkettete Befehle (cmd1 && cmd2)
                    let commands: Vec<&str> = line.split("&&").collect();
                    for cmd_str in commands {
                        if !self.execute_command(cmd_str.trim()).await {
                            // Wenn 'exit' aufgerufen wurde, brechen wir den Loop ab
                            break;
                        }
                    }
                },
                Err(ReadlineError::Interrupted) => {
                    println!("CTRL-C");
                    break;
                },
                Err(ReadlineError::Eof) => {
                    println!("CTRL-D");
                    break;
                },
                Err(err) => {
                    println!("Error: {:?}", err);
                    break;
                }
            }
        }

        // 2. History speichern beim Exit
        if let Some(ref path) = history_path {
            let _ = rl.save_history(path);
        }

        Ok(())
    }

    fn format_size(&self, size: u64) -> String {
        const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut size = size as f64;
        let mut unit_idx = 0;

        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_idx])
    }

    fn print_banner(&self) {
        print!("\x1B[2J\x1B[1;1H");
        println!("{}", r#"
                          __
                         /\ \__   __
          _____   __  __ \ \ ,_\ /\_\   ____
         /\ '__`\/\ \/\  \\ \ \_ \ \ \/\ \L\.\_
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
        if let Some(dt_utc) = DateTime::from_timestamp(seconds, 0) {
            let dt_local: DateTime<Local> = dt_utc.with_timezone(&Local);
            dt_local.format("%Y-%m-%d %H:%M").to_string()
        } else {
            "Unknown".to_string()
        }
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
                println!("{:<10} : {:<30}", "ls", "List [-a] [-s DATE/SIZE/NAME] [-r]");
                println!("{:<10} : {:<30}", "cd", "Change directory");
                println!("{:<10} : {:<30}", "mkdir", "Create dir [-lock]");
                println!("{:<10} : {:<30}", "touch", "Create file [-lock]");
                println!("{:<10} : {:<30}", "cp", "Copy file <src> <dst>");
                println!("{:<10} : {:<30}", "mv", "Move/Rename <src> <dst>");
                println!("{:<10} : {:<30}", "rm", "Delete file/folder");
                println!("{:<10} : {:<30}", "nano", "Edit file");
                println!("{:<10} : {:<30}", "cat", "Read file");
                println!("\n{}", "[ SECURITY & PERMISSIONS ]".cyan());
                println!("{:<10} : {:<30}", "chmod", "Change Mode <0|1|2> <file>");
                println!("{:<10} : {:<30}", "chown", "Change Owner <user> <file>");
                println!("{:<10} : {:<30}", "lock", "Set/Change Password <file>");
                println!("\n{}", "[ INTELLIGENCE ]".cyan());
                println!("{:<10} : {:<30}", "tree", "Show structure [path]");
                println!("{:<10} : {:<30}", "stat", "Show node details <file>");
                println!("{:<10} : {:<30}", "find", "Find by name <pattern>");
                println!("{:<10} : {:<30}", "grep", "Search content <pattern>");
                println!("{:<10} : {:<30}", "du", "Disk usage / Quota");
                println!("\n{}", "[ NETWORK ]".cyan());
                println!("{:<10} : {:<30}", "upload", "Import from Host [-lock]");
                println!("{:<10} : {:<30}", "download", "Export to Host");
                println!("{}", "=".repeat(60));
            },
            "clear" => self.print_banner(),
            "whoami" => println!("{}", self.user_id.green().bold()),

            "ls" => {
                let show_hidden = args.contains(&"-a") || args.contains(&"-sh");
                let reverse = args.contains(&"-r");
                let mut sort_by = "DATE";

                if let Some(idx) = args.iter().position(|&x| x == "-s") {
                    if idx + 1 < args.len() { sort_by = args[idx + 1]; }
                }

                let current_path = self.vfs.lock().await.get_cwd().to_string();

                match self.client.list_files(&current_path).await {
                    Ok(items) => {
                        let mut visible_items: Vec<&FileInfo> = items.iter()
                            .filter(|item| show_hidden || !item.name.starts_with('.'))
                            .collect();

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
                            _ => {
                                visible_items.sort_by(|a, b| {
                                    if reverse { a.created_at.partial_cmp(&b.created_at).unwrap() }
                                    else { b.created_at.partial_cmp(&a.created_at).unwrap() }
                                });
                            }
                        }

                        println!("{:<6} {:<8} {:<10} {:<15} {:<18} NAME", "TYPE", "PERM", "SIZE", "OWNER", "DATE");
                        println!("{}", "-".repeat(75));

                        for item in &visible_items {
                            let type_str = if item.is_folder { "DIR" } else { "FILE" };
                            let color_name = if item.is_folder { item.name.blue() } else { item.name.green() };

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

                let full_path = self.vfs.lock().await.resolve_path(&name);

                match self.client.create_node(&full_path, true, vec![], lock_pass, &self.user_id).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "touch" => {
                if args.is_empty() { println!("Usage: touch <name> [content] [-lock]"); return true; }

                let mut name = args[0].to_string();
                if !name.contains('.') {
                    name.push_str(".txt");
                }

                let mut lock_pass = None;
                let mut content_parts = Vec::new();

                for arg in &args[1..] {
                    if *arg == "-lock" {
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

                let full_path = self.vfs.lock().await.resolve_path(&name);

                match self.client.create_node(&full_path, false, content_bytes, lock_pass, &self.user_id).await {
                    Ok(_) => println!("{}", "File created.".green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "cd" => {
                if args.is_empty() { return true; }
                let target = args[0];

                // CD ist eine lokale VFS Operation (Navigation im virtuellen Baum)
                let full_path = self.vfs.lock().await.resolve_path(target);

                // Wir prüfen gegen den Server, ob der Pfad existiert
                match self.client.stat_node(&full_path).await {
                    Ok((exists, is_folder, is_locked)) => {
                        if !exists {
                            println!("{}", "Directory not found.".red());
                        } else if !is_folder {
                            println!("{}", "Not a directory.".red());
                        } else {
                            let mut pass_attempt = None;
                            if is_locked {
                                let input = self.ask_password(&format!("🔒 Enter Password for {}: ", target));
                                pass_attempt = Some(input);
                            }

                            let mut vfs = self.vfs.lock().await;

                            // WICHTIG: update_cwd Logic lokal im VFS oder hier simulieren.
                            // Da VFS jetzt local cache ist, nutzen wir einfach change_dir logic mit Mock oder DB
                            // Hier ist der Fix: Wir setzen den Pfad einfach, da der Server-Check OK war.
                            if target == ".." {
                                let current = vfs.get_cwd();
                                let parent = std::path::Path::new(current).parent().unwrap_or(std::path::Path::new("/"));
                                vfs.current_path = parent.to_string_lossy().into_owned();
                                if vfs.current_path.is_empty() { vfs.current_path = "/".to_string(); }
                            } else {
                                vfs.current_path = full_path;
                            }
                        }
                    },
                    Err(e) => println!("Server Error: {}", e.to_string().red()),
                }
            },

            "cp" => {
                if args.len() < 2 { println!("Usage: cp <source> <dest>"); return true; }
                let src_path = self.vfs.lock().await.resolve_path(args[0]);
                let dst_path = self.vfs.lock().await.resolve_path(args[1]);

                // FIX: self.user_id als 3. Argument hinzugefügt
                match self.client.copy_node(&src_path, &dst_path, &self.user_id).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "mv" => {
                if args.len() < 2 { println!("Usage: mv <source> <dest>"); return true; }
                let src_path = self.vfs.lock().await.resolve_path(args[0]);
                let dst_path = self.vfs.lock().await.resolve_path(args[1]);

                match self.client.move_node(&src_path, &dst_path).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "rm" => {
                if args.is_empty() { println!("Usage: rm <name>"); return true; }
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                match self.client.delete_node(&full_path).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "nano" => {
                if args.is_empty() { println!("Usage: nano <file>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);

                // WICHTIG: Async DB check
                let vfs_guard = self.vfs.lock().await;

                // FIX: get_db() ist async, also erst .await, dann das Option prüfen
                if let Some(db) = vfs_guard.get_db().await {
                    if let Ok(Some(node)) = db.get_node(&path).await {
                        if !self.check_lock(&node) { return true; }
                    }
                }
                drop(vfs_guard); // Mutex freigeben für edit_file

                // edit_file ist jetzt auch async
                if let Err(e) = self.vfs.lock().await.edit_file(args[0]).await {
                    println!("{}", e.to_string().red());
                }
            },

            "cat" => {
                if args.is_empty() { println!("Usage: cat <name>"); return true; }
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                match self.client.read_file(&full_path, None).await {
                    Ok((content, _)) => {
                        println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
                        if let Ok(s) = str::from_utf8(&content) { println!("{}", s); }
                        else { println!("{}", "[BINARY DATA]".red()); }
                        println!("{}\n", "--- END MESSAGE ---".cyan());
                    },
                    Err(e) => {
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
                // Argument Parsing (gleich wie vorher)
                let mut host_path_arg = String::new();
                let mut dest_path_arg: Option<String> = None;
                let mut lock_pass = None;
                let mut clean_args = Vec::new();
                for arg in args {
                    if *arg == "-lock" {
                        let p = self.ask_password("Set Upload Password: ");
                        if !p.is_empty() { lock_pass = Some(p); }
                    } else if *arg == "-a" { /* ignored */ }
                    else { clean_args.push(*arg); }
                }
                if !clean_args.is_empty() { host_path_arg = clean_args[0].to_string(); }
                if clean_args.len() >= 2 { dest_path_arg = Some(clean_args[1].to_string()); }

                let clean_host_path = host_path_arg.trim_matches('"').trim_matches('\'');
                let target_path = if let Some(dp) = dest_path_arg {
                    self.vfs.lock().await.resolve_path(&dp)
                } else {
                    let fname = std::path::Path::new(clean_host_path).file_name().unwrap_or_default().to_string_lossy();
                    self.vfs.lock().await.resolve_path(&fname)
                };

                // NEU: Dateigröße ermitteln für Progress Bar
                let file_size = std::fs::metadata(clean_host_path).map(|m| m.len()).unwrap_or(0);

                println!("{} {} -> {}", "Initiating Upload:".blue(), clean_host_path, target_path);

                // Spinner starten (da wir Upload noch nicht in Chunks im Client exposed haben)
                // Für echte Enterprise-Lösungen müssten wir den 'upload_file' Stream hier manuell steuern.
                // Vorerst nutzen wir einen Spinner, der "Busy" anzeigt.
                let pb = ProgressBar::new_spinner();
                pb.set_style(ProgressStyle::default_spinner()
                    .template("{spinner:.green} [{elapsed_precise}] {msg}")
                    .unwrap());
                pb.set_message(format!("Uploading {}...", clean_host_path));
                pb.enable_steady_tick(std::time::Duration::from_millis(100));

                let start = std::time::Instant::now();
                match self.client.upload_file(clean_host_path, &target_path, lock_pass, &self.user_id).await {
                    Ok(msg) => {
                        pb.finish_and_clear();
                        let duration = start.elapsed();
                        let speed = if duration.as_secs_f64() > 0.0 {
                            (file_size as f64 / 1024.0 / 1024.0) / duration.as_secs_f64()
                        } else { 0.0 };

                        println!("{} ({}) in {:.2}s ({:.2} MB/s)", msg.green(), self.format_size(file_size), duration.as_secs_f64(), speed);
                    },
                    Err(e) => {
                        pb.finish_with_message("Failed");
                        println!("{}", e.to_string().red());
                    }
                }
            },

            "download" => {
                if args.len() < 2 { println!("Usage: download <remote_path> <local_path>"); return true; }
                let remote_arg = args[0];
                let local_arg = args[1];
                let clean_local = local_arg.trim_matches('"').trim_matches('\'');

                let full_remote = self.vfs.lock().await.resolve_path(remote_arg);

                // 1. UX Feedback start
                println!("{} {} -> {}", "Downloading:".blue(), full_remote, clean_local);

                let pb = ProgressBar::new_spinner();
                pb.set_style(ProgressStyle::default_spinner()
                    .template("{spinner:.cyan} [{elapsed_precise}] {msg}")
                    .unwrap());
                pb.set_message(format!("Receiving {}...", full_remote));
                pb.enable_steady_tick(std::time::Duration::from_millis(100));
                let start = std::time::Instant::now();

                // 2. Action
                // Wir versuchen es erst ohne Passwort
                match self.client.download_file(&full_remote, clean_local, None).await {
                    Ok(msg) => {
                        pb.finish_and_clear();
                        let duration = start.elapsed().as_secs_f64();
                        println!("{} in {:.2}s", msg.green(), duration);
                    },
                    Err(e) => {
                        // Check auf Passwort-Schutz
                        if e.to_string().contains("Password") || e.to_string().contains("locked") {
                            pb.finish_and_clear(); // Spinner stoppen für Eingabe
                            let pass = self.ask_password("🔒 Enter Password for Download: ");

                            // Spinner Neustart für 2. Versuch
                            let pb2 = ProgressBar::new_spinner();
                            pb2.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan} {msg}").unwrap());
                            pb2.set_message("Decrypting & Downloading...");
                            pb2.enable_steady_tick(std::time::Duration::from_millis(100));

                            match self.client.download_file(&full_remote, clean_local, Some(pass)).await {
                                Ok(msg) => {
                                    pb2.finish_and_clear();
                                    println!("{} (Decrypted)", msg.green());
                                },
                                Err(e2) => {
                                    pb2.finish_with_message("Failed");
                                    println!("{}", e2.to_string().red());
                                }
                            }
                        } else {
                            pb.finish_with_message("Failed");
                            println!("{}", e.to_string().red());
                        }
                    }
                }
            },

            "exec" => {
                if args.is_empty() { println!("Usage: exec <script.py>"); return true; }
                let path = self.vfs.lock().await.resolve_path(args[0]);

                println!("{}", "[!] EXECUTING REMOTE KERNEL...".yellow());
                if let Err(e) = self.client.exec_script(&path).await {
                    println!("{}", e.to_string().red());
                }
            },

            // --- SECURITY & PERMISSIONS ---

            "chmod" => {
                if args.len() < 2 { println!("Usage: chmod <0|1|2> <file>\n0=Private, 1=PubRead, 2=PubWrite"); return true; }
                let perm_val: i32 = args[0].parse().unwrap_or(-1);
                if perm_val < 0 || perm_val > 2 { println!("Invalid mode. Use 0, 1 or 2."); return true; }

                let full_path = self.vfs.lock().await.resolve_path(args[1]);
                // FIX: 'as u32' Cast hinzugefügt
                match self.client.change_mode(&full_path, perm_val as u32).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "chown" => {
                if args.len() < 2 { println!("Usage: chown <new_owner> <file>"); return true; }
                let new_owner = args[0];
                let full_path = self.vfs.lock().await.resolve_path(args[1]);

                match self.client.chown_node(&full_path, new_owner).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "lock" => {
                if args.is_empty() { println!("Usage: lock <file>"); return true; }
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                let p1 = self.ask_password("Enter new Password (leave empty to unlock): ");
                if !p1.is_empty() {
                    let p2 = self.ask_password("Confirm Password: ");
                    if p1 != p2 { println!("{}", "Passwords do not match.".red()); return true; }
                }

                // FIX: Logik für Option<String>
                let password_opt = if p1.is_empty() { None } else { Some(p1) };

                match self.client.lock_node(&full_path, password_opt).await {
                    Ok(msg) => println!("{}", msg.green()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            // --- INTELLIGENCE ---

            "tree" => {
                let path = if args.is_empty() { "." } else { args[0] };
                let full_path = self.vfs.lock().await.resolve_path(path);

                match self.client.get_tree(&full_path).await {
                    Ok(tree_str) => println!("{}", tree_str.cyan()),
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "stat" => {
                if args.is_empty() { println!("Usage: stat <file>"); return true; }
                let full_path = self.vfs.lock().await.resolve_path(args[0]);

                match self.client.stat_node(&full_path).await {
                    Ok((exists, is_folder, is_locked)) => {
                        println!("{}", "--- NODE STATUS ---".yellow());
                        println!("Path:   {}", full_path);
                        println!("Exists: {}", exists);
                        println!("Type:   {}", if is_folder { "Directory" } else { "File" });
                        println!("Locked: {}", if is_locked { "YES (Encrypted)" } else { "NO" });
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "find" => {
                if args.is_empty() { println!("Usage: find <pattern>"); return true; }
                let pattern = args[0];

                match self.client.find_node(pattern).await {
                    Ok(paths) => {
                        println!("Found {} matches:", paths.len());
                        for p in paths { println!(" - {}", p.cyan()); }
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "grep" => {
                if args.is_empty() { println!("Usage: grep <content_pattern>"); return true; }
                let pattern = args[0];

                match self.client.grep_node(pattern).await {
                    Ok(matches) => {
                        println!("Found content in {} files:", matches.len());
                        for m in matches { println!(" - {}", m.green()); }
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            "du" => {
                // Disk Usage / Quota für den aktuellen User
                match self.client.get_usage(&self.user_id).await {
                    Ok(bytes) => {
                        let mb = bytes as f64 / 1024.0 / 1024.0;
                        let gb = mb / 1024.0;
                        println!("Disk Usage for {}:", self.user_id.yellow());
                        println!("  {:.2} MB", mb);
                        println!("  {:.4} GB", gb);
                    },
                    Err(e) => println!("{}", e.to_string().red()),
                }
            },

            _ => {
                // Einfache Plugin-Unterstützung
                if self.plugin_manager.has_command(cmd) {
                    println!("Executing Plugin: {}", cmd);
                    if let Err(e) = self.plugin_manager.execute(cmd, args.iter().map(|s| *s).collect(), self.vfs.clone()) {
                        println!("Plugin Error: {}", e);
                    }
                } else {
                    println!("Command not found: {}", cmd);
                }
            }
        }
        true
    }
}
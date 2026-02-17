use crate::vfs::VirtualFileSystem;
use crate::plugins::PluginManager;
use crate::network_client::PytjaClient;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use colored::*;
use std::io::{self, Write};
use std::process;
use std::str;
use pytja_core::{FileNode, PytjaRepository};
use rpassword;
use chrono::{DateTime, Local};
use tokio::sync::Mutex;
use std::sync::Arc;
use pytja_proto::FileInfo;
use indicatif::{ProgressBar, ProgressStyle};
use directories::ProjectDirs;
use walkdir::WalkDir;
use std::path::Path;

pub struct Terminal {
    vfs: Arc<Mutex<VirtualFileSystem>>,
    user_id: String,
    plugin_manager: PluginManager,
    client: PytjaClient,
    current_path: String, // Cache für CWD um DB-Locks zu minimieren
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
            current_path: "/".to_string(),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.print_banner();
        let mut rl = DefaultEditor::new()?;

        // 1. History laden
        let history_path = if let Some(proj_dirs) = ProjectDirs::from("com", "pytja", "shell") {
            let data_dir = proj_dirs.data_dir();
            std::fs::create_dir_all(data_dir).ok();
            Some(data_dir.join("history.txt"))
        } else {
            None
        };

        if let Some(ref path) = history_path {
            let _ = rl.load_history(path);
        }

        // Init CWD from VFS
        self.current_path = self.vfs.lock().await.get_cwd().to_string();

        loop {
            let prompt = format!("┌──({}㉿pytja)-[{}]\n└─$ ", self.user_id.red(), self.current_path.blue());

            let readline = rl.readline(&prompt);
            match readline {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let _ = rl.add_history_entry(line);

                    // Support für verkettete Befehle
                    let commands: Vec<&str> = line.split("&&").collect();
                    for cmd_str in commands {
                        if !self.dispatch_command(cmd_str.trim()).await {
                            // Exit signal received
                            if let Some(ref path) = history_path {
                                let _ = rl.save_history(path);
                            }
                            return Ok(());
                        }
                    }
                },
                Err(ReadlineError::Interrupted) => { println!("CTRL-C"); break; },
                Err(ReadlineError::Eof) => { println!("CTRL-D"); break; },
                Err(err) => { println!("Error: {:?}", err); break; }
            }
        }

        if let Some(ref path) = history_path {
            let _ = rl.save_history(path);
        }
        Ok(())
    }

    // Zentrale Verteiler-Funktion
    async fn dispatch_command(&mut self, cmd_input: &str) -> bool {
        let parts: Vec<&str> = cmd_input.split_whitespace().collect();
        if parts.is_empty() { return true; }
        let cmd = parts[0];
        let args = parts[1..].to_vec(); // Als Vec<&str> übergeben

        match cmd {
            "exit" => self.handle_exit(),
            "help" => self.handle_help(),
            "clear" => self.print_banner(),
            "whoami" => println!("{}", self.user_id.green().bold()),

            "ls" | "ll" => self.handle_ls(args).await,
            "cd" => self.handle_cd(args).await,
            "mkdir" => self.handle_mkdir(args).await,
            "touch" => self.handle_touch(args).await,
            "cp" => self.handle_cp(args).await,
            "mv" => self.handle_mv(args).await,
            "rm" => self.handle_rm(args).await,
            "nano" => self.handle_nano(args).await,
            "cat" => self.handle_cat(args).await,

            "upload" => self.handle_upload(args).await,
            "download" => self.handle_download(args).await,
            "exec" => self.handle_exec(args).await,

            "chmod" => self.handle_chmod(args).await,
            "chown" => self.handle_chown(args).await,
            "lock" => self.handle_lock(args).await,

            "tree" => self.handle_tree(args).await,
            "stat" => self.handle_stat(args).await,
            "find" => self.handle_find(args).await,
            "grep" => self.handle_grep(args).await,
            "du" => self.handle_du(args).await,

            _ => {
                if self.plugin_manager.has_command(cmd) {
                    println!("Executing Plugin: {}", cmd);
                    if let Err(e) = self.plugin_manager.execute(cmd, args, self.vfs.clone()) {
                        println!("Plugin Error: {}", e);
                    }
                } else {
                    println!("Command not found: {}", cmd);
                }
            }
        }

        if cmd == "exit" { false } else { true }
    }

    // --- COMMAND HANDLERS ---

    fn handle_exit(&self) -> bool {
        println!("Verschlüssele Daten...");
        std::thread::sleep(std::time::Duration::from_millis(500));
        println!("Verbindung getrennt.");
        false // Signal to stop loop
    }

    fn handle_help(&self) {
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
    }

    async fn handle_ls(&self, args: Vec<&str>) {
        let show_hidden = args.contains(&"-a") || args.contains(&"-sh");
        let reverse = args.contains(&"-r");
        let mut sort_by = "DATE";

        if let Some(idx) = args.iter().position(|&x| x == "-s") {
            if idx + 1 < args.len() { sort_by = args[idx + 1]; }
        }

        let current_path = self.current_path.clone();

        match self.client.list_files(&current_path).await {
            Ok(items) => {
                let mut visible_items: Vec<&FileInfo> = items.iter()
                    .filter(|item| show_hidden || !item.name.starts_with('.'))
                    .collect();

                match sort_by.to_uppercase().as_str() {
                    "NAME" => visible_items.sort_by(|a, b| if reverse { b.name.to_lowercase().cmp(&a.name.to_lowercase()) } else { a.name.to_lowercase().cmp(&b.name.to_lowercase()) }),
                    "SIZE" => visible_items.sort_by(|a, b| if reverse { a.size.cmp(&b.size) } else { b.size.cmp(&a.size) }),
                    "TYPE" => visible_items.sort_by(|a, b| if reverse { a.is_folder.cmp(&b.is_folder).then(b.name.cmp(&a.name)) } else { b.is_folder.cmp(&a.is_folder).then(a.name.cmp(&b.name)) }),
                    "OWNER" => visible_items.sort_by(|a, b| if reverse { b.owner.cmp(&a.owner) } else { a.owner.cmp(&b.owner) }),
                    _ => visible_items.sort_by(|a, b| if reverse { a.created_at.partial_cmp(&b.created_at).unwrap() } else { b.created_at.partial_cmp(&a.created_at).unwrap() }),
                }

                println!("{:<6} {:<8} {:<10} {:<15} {:<18} NAME", "TYPE", "PERM", "SIZE", "OWNER", "DATE");
                println!("{}", "-".repeat(75));

                for item in &visible_items {
                    let type_str = if item.is_folder { "DIR" } else { "FILE" };
                    let color_name = if item.is_folder { item.name.blue() } else { item.name.green() };
                    let size_str = if item.is_folder { "---".to_string() } else { self.format_size(item.size) };
                    let date_str = self.format_date(item.created_at);
                    let perm_str = match item.permissions {
                        0 => "PRIV".red(),
                        1 => "PUB-R".yellow(),
                        2 => "PUB-W".green(),
                        _ => "???".dimmed(),
                    };
                    println!("{:<6} {:<8} {:<10} {:<15} {:<18} {}", type_str, perm_str, size_str, item.owner, date_str, color_name);
                }
                println!("\n[TOTAL: {} (REMOTE)]", visible_items.len());
            },
            Err(e) => println!("Server Error: {}", e.to_string().red()),
        }
    }

    async fn handle_cd(&mut self, args: Vec<&str>) {
        if args.is_empty() { return; }
        let target = args[0];

        // 1. Pfad berechnen
        let new_path = if target == ".." {
            if self.current_path == "/" {
                "/".to_string()
            } else {
                let path = Path::new(&self.current_path);
                path.parent().unwrap_or(Path::new("/")).to_string_lossy().to_string()
            }
        } else if target.starts_with('/') {
            target.to_string()
        } else {
            if self.current_path == "/" {
                format!("/{}", target)
            } else {
                format!("{}/{}", self.current_path, target)
            }
        };

        // 2. Check: Existiert der Ordner? Ist er gelockt?
        match self.client.stat_node(&new_path).await {
            Ok(stat) => {
                if !stat.exists {
                    println!("{} Directory not found.", "Error:".red());
                    return;
                }
                if !stat.is_folder {
                    println!("{} Not a directory.", "Error:".red());
                    return;
                }
                if stat.is_locked {
                    let _ = self.ask_password("Locked Directory. Enter Password (optional check): ");
                }
                // Update local state and VFS
                self.current_path = new_path.clone();
                self.vfs.lock().await.current_path = new_path;
            },
            Err(e) => println!("{} {}", "Server Error:".red(), e),
        }
    }

    async fn handle_mkdir(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: mkdir <name> [-lock]"); return; }
        let name = args[0];
        let mut lock_pass = None;

        if args.contains(&"-lock") {
            let p1 = self.ask_password("Set Password: ");
            let p2 = self.ask_password("Confirm Password: ");
            if p1 != p2 { println!("{}", "Passwords do not match.".red()); return; }
            if !p1.is_empty() { lock_pass = Some(p1); }
        }

        let full_path = self.resolve_path(name).await;
        match self.client.create_node(&full_path, true, vec![], lock_pass, &self.user_id).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_touch(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: touch <name> [content] [-lock]"); return; }
        let mut name = args[0].to_string();
        if !name.contains('.') { name.push_str(".txt"); }

        let mut lock_pass = None;
        let mut content_parts = Vec::new();

        for arg in &args[1..] {
            if *arg == "-lock" {
                let p1 = self.ask_password("Set Password: ");
                let p2 = self.ask_password("Confirm Password: ");
                if p1 != p2 { println!("{}", "Passwords do not match.".red()); return; }
                if !p1.is_empty() { lock_pass = Some(p1); }
            } else { content_parts.push(*arg); }
        }

        let content_str = content_parts.join(" ");
        let content_bytes = content_str.trim_matches('"').trim_matches('\'').as_bytes().to_vec();
        let full_path = self.resolve_path(&name).await;

        match self.client.create_node(&full_path, false, content_bytes, lock_pass, &self.user_id).await {
            Ok(_) => println!("{}", "File created.".green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_cp(&self, args: Vec<&str>) {
        if args.len() < 2 { println!("Usage: cp <source> <dest>"); return; }
        let src_path = self.resolve_path(args[0]).await;
        let dst_path = self.resolve_path(args[1]).await;

        match self.client.copy_node(&src_path, &dst_path, &self.user_id).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_mv(&self, args: Vec<&str>) {
        if args.len() < 2 { println!("Usage: mv <source> <dest>"); return; }
        let src_path = self.resolve_path(args[0]).await;
        let dst_path = self.resolve_path(args[1]).await;

        match self.client.move_node(&src_path, &dst_path).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_rm(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: rm <name>"); return; }
        let full_path = self.resolve_path(args[0]).await;

        match self.client.delete_node(&full_path).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_nano(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: nano <file>"); return; }
        let path = self.resolve_path(args[0]).await;

        // Check Lock via VFS cache
        let vfs_guard = self.vfs.lock().await;
        if let Some(db) = vfs_guard.get_db().await {
            if let Ok(Some(node)) = db.get_node(&path).await {
                if !self.check_lock(&node) { return; }
            }
        }
        drop(vfs_guard);

        if let Err(e) = self.vfs.lock().await.edit_file(args[0]).await {
            println!("{}", e.to_string().red());
        }
    }

    async fn handle_cat(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: cat <name>"); return; }
        let full_path = self.resolve_path(args[0]).await;

        match self.client.read_file(&full_path, None).await {
            Ok((content, _)) => self.print_file_content(&content),
            Err(e) => {
                if e.to_string().contains("Password") {
                    let pass = self.ask_password("🔒 Locked File. Password: ");
                    match self.client.read_file(&full_path, Some(pass)).await {
                        Ok((content, _)) => self.print_file_content(&content),
                        Err(e2) => println!("{}", e2.to_string().red()),
                    }
                } else {
                    println!("{}", e.to_string().red());
                }
            }
        }
    }

    async fn handle_upload(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: upload <local_path> [remote_path]"); return; }
        let local_path_str = args[0];
        let local_path = Path::new(local_path_str);

        if !local_path.exists() {
            println!("{} Local path does not exist.", "Error:".red());
            return;
        }

        let remote_base = if args.len() > 1 {
            args[1].to_string()
        } else {
            let name = local_path.file_name().unwrap().to_string_lossy();
            if self.current_path == "/" { format!("/{}", name) } else { format!("{}/{}", self.current_path, name) }
        };

        if local_path.is_dir() {
            println!("Initiating Recursive Upload: {} -> {}", local_path_str, remote_base);
            let _ = self.client.create_node(&remote_base, true, vec![], None, &self.user_id).await; // Mkdir remote root

            let walker = WalkDir::new(local_path);
            let mut count = 0;

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path == local_path { continue; } // Skip root dir itself

                let relative = path.strip_prefix(local_path).unwrap();
                let remote_target = format!("{}/{}", remote_base, relative.to_string_lossy()).replace("//", "/");

                if path.is_dir() {
                    let _ = self.client.create_node(&remote_target, true, vec![], None, &self.user_id).await;
                } else {
                    print!("Uploading {}... ", relative.to_string_lossy());
                    match self.client.upload_file(path.to_str().unwrap(), &remote_target, None, &self.user_id).await {
                        Ok(_) => println!("{}", "OK".green()),
                        Err(e) => println!("{} {}", "FAIL".red(), e),
                    }
                    count += 1;
                }
            }
            println!("Recursive upload finished. {} files processed.", count);
        } else {
            println!("Uploading: {} -> {}", local_path_str, remote_base);
            // Lock handling for upload command
            let mut lock_pass = None;
            if args.contains(&"-lock") {
                let p = self.ask_password("Set Upload Password: ");
                if !p.is_empty() { lock_pass = Some(p); }
            }

            match self.client.upload_file(local_path_str, &remote_base, lock_pass, &self.user_id).await {
                Ok(_) => println!("{}", "Upload complete.".green()),
                Err(e) => println!("{} {}", "Upload failed:".red(), e),
            }
        }
    }

    async fn handle_download(&self, args: Vec<&str>) {
        if args.len() < 2 { println!("Usage: download <remote_path> <local_path>"); return; }
        let remote_path = args[0];
        let local_path_str = args[1];
        let local_path = Path::new(local_path_str);

        // Resolve absolute remote path
        let full_remote = self.resolve_path(remote_path).await;

        match self.client.stat_node(&full_remote).await {
            Ok(stat) => {
                if !stat.exists {
                    println!("{} Remote path not found.", "Error:".red());
                    return;
                }

                if stat.is_folder {
                    println!("Initiating Recursive Download: {} -> {}", full_remote, local_path_str);
                    let mut stack = vec![(full_remote.clone(), local_path.to_path_buf())];
                    std::fs::create_dir_all(local_path).unwrap_or(());

                    let mut count = 0;
                    while let Some((r_curr, l_curr)) = stack.pop() {
                        match self.client.list_files(&r_curr).await {
                            Ok(files) => {
                                for file in files {
                                    let child_remote = if r_curr == "/" { format!("/{}", file.name) } else { format!("{}/{}", r_curr, file.name) };
                                    let child_local = l_curr.join(&file.name);

                                    if file.is_folder {
                                        std::fs::create_dir_all(&child_local).unwrap_or(());
                                        stack.push((child_remote, child_local));
                                    } else {
                                        print!("Downloading {}... ", file.name);
                                        match self.client.download_file(&child_remote, child_local.to_str().unwrap(), None).await {
                                            Ok(_) => println!("{}", "OK".green()),
                                            Err(_) => println!("{}", "FAIL".red()), // Simplified
                                        }
                                        count += 1;
                                    }
                                }
                            },
                            Err(e) => println!("Failed to list {}: {}", r_curr, e),
                        }
                    }
                    println!("Finished. {} files.", count);
                } else {
                    println!("Downloading: {} -> {}", full_remote, local_path_str);
                    match self.client.download_file(&full_remote, local_path_str, None).await {
                        Ok(msg) => println!("{}", msg.green()),
                        Err(e) => println!("{} {}", "Download Error:".red(), e),
                    }
                }
            },
            Err(e) => println!("{} {}", "Stat Error:".red(), e),
        }
    }

    async fn handle_exec(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: exec <script.py>"); return; }
        let path = self.resolve_path(args[0]).await;
        println!("{}", "[!] EXECUTING REMOTE KERNEL...".yellow());
        if let Err(e) = self.client.exec_script(&path).await {
            println!("{}", e.to_string().red());
        }
    }

    // --- SECURITY ---

    async fn handle_chmod(&self, args: Vec<&str>) {
        if args.len() < 2 { println!("Usage: chmod <0|1|2> <file>"); return; }
        let perm_val: i32 = args[0].parse().unwrap_or(-1);
        let path = self.resolve_path(args[1]).await;
        if perm_val < 0 || perm_val > 2 { println!("Invalid mode."); return; }
        match self.client.change_mode(&path, perm_val as u32).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_chown(&self, args: Vec<&str>) {
        if args.len() < 2 { println!("Usage: chown <new_owner> <file>"); return; }
        let path = self.resolve_path(args[1]).await;
        match self.client.chown_node(&path, args[0]).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_lock(&self, args: Vec<&str>) {
        if args.is_empty() { println!("Usage: lock <file>"); return; }
        let path = self.resolve_path(args[0]).await;
        let p1 = self.ask_password("Enter new Password (empty to unlock): ");
        if !p1.is_empty() {
            let p2 = self.ask_password("Confirm: ");
            if p1 != p2 { println!("Mismatch."); return; }
        }
        let password_opt = if p1.is_empty() { None } else { Some(p1) };
        match self.client.lock_node(&path, password_opt).await {
            Ok(msg) => println!("{}", msg.green()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    // --- INTELLIGENCE ---

    async fn handle_tree(&self, args: Vec<&str>) {
        let path = if args.is_empty() { "." } else { args[0] };
        let full_path = self.resolve_path(path).await;
        match self.client.get_tree(&full_path).await {
            Ok(tree) => println!("{}", tree.cyan()),
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_stat(&self, args: Vec<&str>) {
        if args.is_empty() { return; }
        let full_path = self.resolve_path(args[0]).await;
        match self.client.stat_node(&full_path).await {
            Ok((exists, is_folder, is_locked)) => {
                println!("{}", "--- NODE STATUS ---".yellow());
                println!("Path:   {}", full_path);
                println!("Exists: {}", exists);
                println!("Type:   {}", if is_folder { "Directory" } else { "File" });
                println!("Locked: {}", if is_locked { "YES" } else { "NO" });
            },
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_find(&self, args: Vec<&str>) {
        if args.is_empty() { return; }
        match self.client.find_node(args[0]).await {
            Ok(paths) => {
                println!("Found {} matches:", paths.len());
                for p in paths { println!(" - {}", p.cyan()); }
            },
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_grep(&self, args: Vec<&str>) {
        if args.is_empty() { return; }
        match self.client.grep_node(args[0]).await {
            Ok(matches) => {
                println!("Found content in {} files:", matches.len());
                for m in matches { println!(" - {}", m.green()); }
            },
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    async fn handle_du(&self, _args: Vec<&str>) {
        match self.client.get_usage(&self.user_id).await {
            Ok(bytes) => {
                let mb = bytes as f64 / 1024.0 / 1024.0;
                println!("Usage: {:.2} MB", mb);
            },
            Err(e) => println!("{}", e.to_string().red()),
        }
    }

    // --- UTILS ---

    async fn resolve_path(&self, input: &str) -> String {
        self.vfs.lock().await.resolve_path(input)
    }

    fn print_file_content(&self, content: &[u8]) {
        println!("\n{}", "--- BEGIN MESSAGE ---".cyan());
        if let Ok(s) = str::from_utf8(content) { println!("{}", s); }
        else { println!("{}", "[BINARY DATA]".red()); }
        println!("{}\n", "--- END MESSAGE ---".cyan());
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
         _____   __  __\ \ ,_\ /\_\     __
        /\ '__`\/\ \/\ \\ \ \/ \/\ \  /'__`\
        \ \ \L\ \ \ \_\ \\ \ \_ \ \ \/\ \L\.\_
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
}
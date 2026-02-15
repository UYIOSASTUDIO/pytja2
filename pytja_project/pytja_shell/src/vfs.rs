use pytja_core::{
    PytjaRepository, DriverManager, DatabaseType, FileNode, PytjaError
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Write, Read};
use std::fs;
use colored::*;
use std::sync::Arc;

const DEFAULT_QUOTA: usize = 100 * 1024 * 1024;
const ALLOWED_TEXT_EXTENSIONS: &[&str] = &[
    ".txt", ".md", ".log", ".json", ".xml", ".yaml", ".csv", ".conf", ".ini",
    ".py", ".js", ".html", ".css", ".c", ".cpp", ".h", ".java", ".go", ".rs", ".php", ".sh", ".rb", ".sql"
];

pub struct VirtualFileSystem {
    pub connection_manager: DriverManager,
    pub active_mount: String,
    pub user_id: String,
    pub current_path: String,
}

pub enum AccessType { Read, Write, Execute }

impl VirtualFileSystem {
    pub async fn new(user_id: String, db_path: &str) -> Self {
        let manager = DriverManager::new();

        // Versuche zu mounten, Warnung statt Panic wenn es fehlschlägt
        if let Err(e) = manager.mount("primary", db_path, DatabaseType::Sqlite).await {
            eprintln!("Warning: Failed to mount local DB: {}", e);
        }

        Self {
            connection_manager: manager,
            active_mount: "primary".to_string(),
            user_id,
            current_path: "/".to_string(),
        }
    }

    pub fn get_cwd(&self) -> &str {
        &self.current_path
    }

    pub fn db(&self) -> Option<Arc<dyn PytjaRepository>> {
        self.connection_manager.get_repo(&self.active_mount)
    }

    // Helper: Garantiert Zugriff oder Error
    // Löst das Problem mit "no method named ... found for enum Option"
    fn get_db(&self) -> Result<Arc<dyn PytjaRepository>, PytjaError> {
        self.db().ok_or_else(|| PytjaError::System("Local database disconnected".to_string()))
    }

    pub fn resolve_path(&self, name: &str) -> String {
        if name == "/" { return "/".to_string(); }
        if name.starts_with("/") { return name.to_string(); }
        if self.current_path == "/" { format!("/{}", name) } else { format!("{}/{}", self.current_path, name) }
    }

    async fn check_quota_availability(&self, size_needed: usize) -> Result<(), PytjaError> {
        let used = self.get_db()?.get_total_usage(&self.user_id).await.unwrap_or(0);
        if used + size_needed > DEFAULT_QUOTA {
            return Err(PytjaError::QuotaExceeded { current: used, limit: DEFAULT_QUOTA });
        }
        Ok(())
    }

    // --- ASYNC CORE OPERATIONS ---

    pub async fn create(&mut self, mut name: String, is_folder: bool, content: Vec<u8>, system_override: bool, lock_pass: Option<String>) -> Result<String, PytjaError> {
        if !system_override {
            if !is_folder {
                let has_valid_ext = ALLOWED_TEXT_EXTENSIONS.iter().any(|&ext| name.ends_with(ext));
                if !has_valid_ext && !name.contains('.') { name.push_str(".txt"); }
            }
            self.check_quota_availability(content.len()).await?;
        }

        let full_path = self.resolve_path(&name);
        let db = self.get_db()?;

        if db.get_node(&full_path).await?.is_some() {
            return Err(PytjaError::AlreadyExists(full_path));
        }

        let node = FileNode {
            path: full_path.clone(),
            name: name.clone(),
            owner: self.user_id.clone(),
            is_folder,
            size: content.len(),
            content,
            lock_pass,
            permissions: 0,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            blob_id: None, // FIX: blob_id initialisieren
        };

        db.save_node(&node).await?;
        let _ = db.log_action(&self.user_id, "CREATE", &full_path).await;
        Ok(format!("Created: {}", name))
    }

    pub async fn list_current(&self) -> Result<Vec<FileNode>, PytjaError> {
        self.get_db()?.list_directory(&self.current_path).await
    }

    pub async fn change_dir(&mut self, target: &str, password_attempt: Option<String>) -> Result<(), PytjaError> {
        if target == ".." {
            if self.current_path == "/" { return Ok(()); }
            let parent = Path::new(&self.current_path).parent().unwrap();
            self.current_path = parent.to_str().unwrap().to_string();
            if self.current_path.is_empty() { self.current_path = "/".to_string(); }
            return Ok(());
        }

        let potential_path = self.resolve_path(target);
        let db = self.get_db()?;

        if let Some(node) = db.get_node(&potential_path).await? {
            if !node.is_folder { return Err(PytjaError::System("Not a directory".to_string())); }
            self.check_access(&node, AccessType::Read)?;
            if let Some(real_pass) = node.lock_pass {
                if password_attempt.unwrap_or_default() != real_pass {
                    return Err(PytjaError::AccessDenied("Locked Directory".to_string()));
                }
            }
            self.current_path = potential_path;
            Ok(())
        } else {
            Err(PytjaError::NotFound(target.to_string()))
        }
    }

    pub async fn delete(&mut self, name: &str) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound(name.to_string()))?;

        if node.owner != self.user_id { return Err(PytjaError::AccessDenied("Permission denied".to_string())); }

        db.delete_node_recursive(&full_path).await?;
        let _ = db.log_action(&self.user_id, "DELETE", &full_path).await;
        Ok(format!("Deleted: {}", name))
    }

    pub async fn delete_all_inside(&mut self, target_path_opt: Option<&str>) -> Result<String, PytjaError> {
        let dir_path = match target_path_opt {
            Some(p) => self.resolve_path(p),
            None => self.current_path.clone(),
        };
        let db = self.get_db()?;

        if let Some(node) = db.get_node(&dir_path).await? {
            if node.owner != self.user_id { return Err(PytjaError::AccessDenied("Permission denied".to_string())); }
        }

        let items = db.list_directory(&dir_path).await?;
        if items.is_empty() { return Ok("Directory is already empty.".to_string()); }

        let mut count = 0;
        for item in items {
            if item.owner == self.user_id {
                db.delete_node_recursive(&item.path).await?;
                count += 1;
            }
        }
        Ok(format!("Deleted {} items in {}", count, dir_path))
    }

    pub async fn chmod(&mut self, name: &str, lock_pass: Option<String>) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound(name.to_string()))?;

        if node.owner != self.user_id { return Err(PytjaError::AccessDenied("Permission denied".to_string())); }
        db.update_metadata(&full_path, lock_pass, None).await?;
        Ok("Lock updated.".to_string())
    }

    pub async fn chmod_permissions(&mut self, name: &str, level: u8) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound(name.to_string()))?;

        if node.owner != self.user_id { return Err(PytjaError::AccessDenied("Only owner can change permissions.".to_string())); }
        if level > 2 { return Err(PytjaError::System("Invalid permission level (0-2).".to_string())); }

        db.update_permissions(&full_path, level).await?;
        Ok(format!("Permissions for {} set to {}", name, level))
    }

    pub async fn chown(&mut self, name: &str, new_owner: &str) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound(name.to_string()))?;

        if node.owner != self.user_id { return Err(PytjaError::AccessDenied("Only owner can transfer file".to_string())); }
        db.update_metadata(&full_path, None, Some(new_owner.to_string())).await?;
        Ok(format!("Owner changed to {}", new_owner))
    }

    pub async fn edit_file(&mut self, name: &str) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = if let Some(n) = db.get_node(&full_path).await? {
            n
        } else {
            let try_txt = if !name.contains(".") { format!("{}.txt", name) } else { name.to_string() };
            self.create(try_txt.clone(), false, vec![], false, None).await?;
            db.get_node(&self.resolve_path(&try_txt)).await?.ok_or_else(|| PytjaError::NotFound("Created file lost".into()))?
        };

        self.check_access(&node, AccessType::Write)?;

        let mut temp_file = tempfile::NamedTempFile::new().map_err(|e| PytjaError::IoError(e))?;
        temp_file.write_all(&node.content).map_err(|e| PytjaError::IoError(e))?;
        let temp_path = temp_file.path().to_str().unwrap().to_string();

        let status = std::process::Command::new("nano").arg(&temp_path).status().map_err(|e| PytjaError::IoError(e))?;
        if !status.success() { return Err(PytjaError::System("Editor exited with error".to_string())); }

        let mut new_content = Vec::new();
        let mut file = std::fs::File::open(&temp_path).map_err(|e| PytjaError::IoError(e))?;
        file.read_to_end(&mut new_content).map_err(|e| PytjaError::IoError(e))?;

        let diff = new_content.len() as i64 - node.size as i64;
        if diff > 0 {
            let used = db.get_total_usage(&self.user_id).await.unwrap_or(0);
            if used + diff as usize > DEFAULT_QUOTA { return Err(PytjaError::QuotaExceeded { current: used, limit: DEFAULT_QUOTA }); }
        }

        let mut new_node = node.clone();
        new_node.content = new_content;
        new_node.size = new_node.content.len();

        db.save_node(&new_node).await?;
        let _ = db.log_action(&self.user_id, "EDIT", &full_path).await;
        Ok("File saved.".to_string())
    }

    pub async fn exec_script(&self, name: &str) -> Result<String, PytjaError> {
        use tokio::process::Command;
        let full_path = self.resolve_path(name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound(name.to_string()))?;

        self.check_access(&node, AccessType::Read)?;
        let script_content = String::from_utf8(node.content.clone())
            .map_err(|_| PytjaError::System("Binary file cannot be executed".to_string()))?;

        let output = Command::new("python3").arg("-c").arg(&script_content).output().await.map_err(|e| PytjaError::IoError(e))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(format!("{}\n{}", stdout, stderr.red()))
    }

    pub async fn copy(&mut self, source: &str, dest: &str) -> Result<String, PytjaError> {
        let old_path = self.resolve_path(source);
        let dest_path_raw = self.resolve_path(dest);
        let db = self.get_db()?;

        let src_node = db.get_node(&old_path).await?
            .ok_or_else(|| PytjaError::NotFound("Source not found".to_string()))?;

        if src_node.is_folder { return Err(PytjaError::System("Folder copy not supported yet.".to_string())); }
        self.check_access(&src_node, AccessType::Read)?;
        self.check_quota_availability(src_node.size).await?;

        let mut new_path_str = dest_path_raw.clone();
        if new_path_str == "/" {
            let src_name = Path::new(&old_path).file_name().unwrap().to_str().unwrap();
            new_path_str = format!("/{}", src_name);
        } else if let Ok(Some(node)) = db.get_node(&new_path_str).await {
            if node.is_folder {
                let src_name = Path::new(&old_path).file_name().unwrap().to_str().unwrap();
                new_path_str = format!("{}/{}", new_path_str, src_name);
            }
        }

        if db.get_node(&new_path_str).await?.is_some() {
            return Err(PytjaError::AlreadyExists(new_path_str));
        }

        let mut new_node = src_node.clone();
        new_node.path = new_path_str.clone();
        new_node.name = Path::new(&new_path_str).file_name().unwrap().to_str().unwrap().to_string();
        new_node.permissions = 0;
        new_node.owner = self.user_id.clone();
        new_node.created_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        // new_node.blob_id bleibt gleich, da wir lokal arbeiten und blob_id None ist

        db.save_node(&new_node).await?;
        Ok(format!("Copied to {}", new_path_str))
    }

    pub async fn move_rename(&mut self, source: &str, dest: &str, lock_pass: Option<String>) -> Result<String, PytjaError> {
        let old_path = self.resolve_path(source);
        let dest_path_raw = self.resolve_path(dest);
        let db = self.get_db()?;

        let node = db.get_node(&old_path).await?
            .ok_or_else(|| PytjaError::NotFound("Source not found".to_string()))?;

        self.check_access(&node, AccessType::Write)?;

        let mut new_path_str = dest_path_raw.clone();
        if let Ok(Some(dest_node)) = db.get_node(&new_path_str).await {
            if dest_node.is_folder {
                let src_name = Path::new(&old_path).file_name().unwrap().to_str().unwrap();
                new_path_str = format!("{}/{}", new_path_str, src_name);
            }
        }

        db.move_path(&old_path, &new_path_str).await?;

        if let Some(pass) = lock_pass {
            db.update_metadata(&new_path_str, Some(pass), None).await?;
            Ok(format!("Moved to {} and locked.", new_path_str))
        } else {
            Ok(format!("Moved/Renamed to {}", new_path_str))
        }
    }

    pub async fn import_from_host(&mut self, host_path_str: &str, _target_vfs_path: Option<String>, lock_pass: Option<String>, recursive_lock: bool) -> Result<String, PytjaError> {
        let host_path = Path::new(host_path_str);
        if !host_path.exists() { return Err(PytjaError::NotFound("Host path not found".to_string())); }

        let name = host_path.file_name().ok_or(PytjaError::System("Invalid path".to_string()))?.to_str().unwrap().to_string();

        if host_path.is_dir() {
            println!("Starting recursive import of '{}'...", name);
            match self.create(name.clone(), true, vec![], false, lock_pass.clone()).await {
                Ok(_) => {}, Err(PytjaError::AlreadyExists(_)) => {}, Err(e) => return Err(e),
            }
            let target_root = if self.current_path == "/" { format!("/{}", name) } else { format!("{}/{}", self.current_path, name) };
            self.import_recursive(host_path.to_path_buf(), target_root, lock_pass, recursive_lock).await?;
            return Ok(format!("Imported directory structure: {}", name));
        } else {
            let content = fs::read(host_path).map_err(|e| PytjaError::IoError(e))?;
            let current_pass = if recursive_lock { lock_pass } else { None };
            self.create(name.clone(), false, content, true, current_pass).await?;
            return Ok(format!("Imported file: {}", name));
        }
    }

    fn import_recursive<'a>(&'a mut self, host_path: std::path::PathBuf, vfs_parent: String, lock_pass: Option<String>, rec_lock: bool)
                            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PytjaError>> + Send + 'a>> {
        Box::pin(async move {
            let entries = fs::read_dir(&host_path).map_err(|e| PytjaError::IoError(e))?;
            let db = self.get_db()?;

            for entry in entries {
                let entry = entry.map_err(|e| PytjaError::IoError(e))?;
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let vfs_path = if vfs_parent == "/" { format!("/{}", name) } else { format!("{}/{}", vfs_parent, name) };
                let current_pass = if rec_lock { lock_pass.clone() } else { None };

                if path.is_dir() {
                    let node = FileNode {
                        path: vfs_path.clone(), name: name.clone(), owner: self.user_id.clone(),
                        is_folder: true, size: 0, content: vec![], lock_pass: current_pass.clone(),
                        permissions: 0, created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                        blob_id: None,
                    };
                    let _ = db.save_node(&node).await;
                    self.import_recursive(path, vfs_path, lock_pass.clone(), rec_lock).await?;
                } else {
                    if let Ok(content) = fs::read(&path) {
                        let node = FileNode {
                            path: vfs_path, name, owner: self.user_id.clone(),
                            is_folder: false, size: content.len(), content, lock_pass: current_pass,
                            permissions: 0, created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                            blob_id: None,
                        };
                        let _ = db.save_node(&node).await;
                    }
                }
            }
            Ok(())
        })
    }

    pub async fn export_to_host(&self, vfs_name: &str, host_path: &str) -> Result<String, PytjaError> {
        let full_path = self.resolve_path(vfs_name);
        let db = self.get_db()?;

        let node = db.get_node(&full_path).await?
            .ok_or_else(|| PytjaError::NotFound("File not found".to_string()))?;

        self.check_access(&node, AccessType::Read)?;
        if node.is_folder { return Err(PytjaError::System("Folder export not supported.".to_string())); }

        let target_path = Path::new(host_path).join(&node.name);
        fs::write(&target_path, &node.content).map_err(|e| PytjaError::IoError(e))?;
        Ok(format!("Exported to {:?}", target_path))
    }

    pub async fn find(&self, query: &str) -> Result<Vec<String>, PytjaError> {
        let pattern = format!("%{}%", query);
        self.get_db()?.find_nodes(&pattern).await
    }

    pub async fn grep(&self, query: &str) -> Result<Vec<String>, PytjaError> {
        let mut matches = Vec::new();
        let all_files = self.get_db()?.get_all_files_content().await?;

        for (path, content) in all_files {
            if let Ok(text) = std::str::from_utf8(&content) {
                if text.contains(query) {
                    matches.push(format!("Found in {}: ...{}...", path, query));
                }
            }
        }
        Ok(matches)
    }

    pub async fn tree_view(&self) -> Result<(), PytjaError> {
        let root_name = if self.current_path == "/" { "/" } else { Path::new(&self.current_path).file_name().unwrap().to_str().unwrap() };
        println!("{}", root_name.blue().bold());
        self.print_tree_recursive(self.current_path.clone(), "".to_string()).await
    }

    fn print_tree_recursive(&self, path: String, prefix: String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), PytjaError>> + Send + '_>> {
        Box::pin(async move {
            let items = self.get_db()?.list_directory(&path).await?;
            let mut sorted_items = items;
            sorted_items.sort_by(|a, b| b.is_folder.cmp(&a.is_folder).then(a.name.cmp(&b.name)));

            let count = sorted_items.len();
            for (i, item) in sorted_items.iter().enumerate() {
                let is_last = i == count - 1;
                let connector = if is_last { "└── " } else { "├── " };
                let name_display = if item.is_folder { item.name.blue().bold() } else {
                    let lock = if item.lock_pass.is_some() { "🔒" } else { "" };
                    format!("{}{}", item.name, lock).white()
                };
                println!("{}{}{}", prefix, connector, name_display);
                if item.is_folder {
                    let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
                    self.print_tree_recursive(item.path.clone(), child_prefix).await?;
                }
            }
            Ok(())
        })
    }

    fn check_access(&self, node: &FileNode, access: AccessType) -> Result<(), PytjaError> {
        if node.owner == self.user_id { return Ok(()); }
        match access {
            AccessType::Read => if node.permissions >= 1 { return Ok(()); },
            AccessType::Write => if node.permissions >= 2 { return Ok(()); },
            _ => {}
        }
        Err(PytjaError::AccessDenied(format!("You do not have permission to access '{}'", node.name)))
    }
}
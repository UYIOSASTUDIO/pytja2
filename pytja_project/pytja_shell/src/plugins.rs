use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::instrument;
use wasmer_wasix::WasiEnv;
use serde::{Deserialize, Serialize};
use colored::*;
use dialoguer::{Confirm, theme::ColorfulTheme};
use wasmer::{Module, Store, Engine};

// --- DATA STRUCTURES ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Permission {
    #[serde(rename = "fs_read")]
    FsRead,
    #[serde(rename = "fs_write")]
    FsWrite,
    #[serde(rename = "network")]
    Network,
    #[serde(rename = "env")]
    Env,
    #[serde(rename = "admin")]
    Admin,
}

impl Permission {
    fn is_high_risk(&self) -> bool {
        matches!(self, Permission::Admin | Permission::Network | Permission::FsWrite)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PermissionDb {
    pub granted: HashMap<String, HashSet<Permission>>,
}

// --- MANAGER (Serverless Edge Architecture) ---

pub struct PluginManager {
    plugin_dir: PathBuf,
    manifests: HashMap<String, PluginManifest>,
    modules: HashMap<String, Module>,
    engine: Engine,
    db_path: PathBuf,
    permissions_db: PermissionDb,
}

impl PluginManager {
    pub fn new<P: AsRef<Path>>(plugin_dir: P, data_dir: P) -> Self {
        let db_path = data_dir.as_ref().join("plugin_permissions.json");

        let permissions_db = if db_path.exists() {
            let content = fs::read_to_string(&db_path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            PermissionDb::default()
        };

        Self {
            plugin_dir: plugin_dir.as_ref().to_path_buf(),
            manifests: HashMap::new(),
            modules: HashMap::new(),
            engine: Engine::default(),
            db_path,
            permissions_db,
        }
    }

    pub fn load_and_verify_plugins(&mut self) -> Result<()> {
        if !self.plugin_dir.exists() {
            fs::create_dir_all(&self.plugin_dir)?;
        }

        let mut new_plugins: Vec<PluginManifest> = Vec::new();

        for entry in fs::read_dir(&self.plugin_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "wasm") {
                let stem = path.file_stem().unwrap().to_string_lossy().to_string();
                let manifest_path = path.with_extension("json");

                let manifest: PluginManifest = if manifest_path.exists() {
                    let content = fs::read_to_string(&manifest_path)?;
                    serde_json::from_str(&content).context(format!("Invalid manifest for {}", stem))?
                } else {
                    PluginManifest {
                        name: stem.clone(),
                        version: "0.0.0".into(),
                        description: "No manifest provided".into(),
                        permissions: vec![],
                    }
                };

                let wasm_bytes = fs::read(&path).context("Failed to read wasm file")?;
                let module = Module::new(&self.engine, &wasm_bytes).context("Failed to compile WASM")?;
                self.modules.insert(stem.clone(), module);

                if !self.permissions_db.granted.contains_key(&manifest.name) {
                    new_plugins.push(manifest.clone());
                } else {
                    let granted = self.permissions_db.granted.get(&manifest.name).unwrap();
                    let has_new_perms = manifest.permissions.iter().any(|p| !granted.contains(p));
                    if has_new_perms {
                        new_plugins.push(manifest.clone());
                    }
                }
                self.manifests.insert(manifest.name.clone(), manifest);
            }
        }

        if !new_plugins.is_empty() {
            self.interactive_permission_grant(new_plugins)?;
        }

        Ok(())
    }

    fn interactive_permission_grant(&mut self, plugins: Vec<PluginManifest>) -> Result<()> {
        println!("\n{}", "[SECURITY ALERT] NEW PLUGINS DETECTED".yellow().bold());
        println!("The following plugins are requesting permissions. Review them carefully.\n");

        let mut low_risk = Vec::new();
        let mut high_risk = Vec::new();

        for p in plugins {
            if p.permissions.iter().any(|perm| perm.is_high_risk()) {
                high_risk.push(p);
            } else {
                low_risk.push(p);
            }
        }

        if !low_risk.is_empty() {
            println!("{}", "--- Standard Plugins (Safe to verify) ---".cyan());
            for p in &low_risk {
                let perms_str = if p.permissions.is_empty() { "None".to_string() } else { format!("{:?}", p.permissions) };
                println!("* {} (v{}): {}", p.name.bold(), p.version, perms_str.dimmed());
            }

            if Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Grant permissions to these standard plugins?")
                .default(true)
                .interact()?
            {
                for p in low_risk {
                    let set: HashSet<Permission> = p.permissions.iter().cloned().collect();
                    self.permissions_db.granted.insert(p.name.clone(), set);
                }
            } else {
                println!("{}", "[WARNING] Plugins denied. They may not function correctly.".red());
                for p in low_risk {
                    self.permissions_db.granted.insert(p.name.clone(), HashSet::new());
                }
            }
        }

        if !high_risk.is_empty() {
            println!("\n{}", "--- [ELEVATED PRIVILEGES REQUESTED (ADMIN/ROOT)] ---".red().bold());
            println!("These plugins requested full system access or network control.");

            for p in &high_risk {
                println!("\nPlugin: {}", p.name.bold().red());
                println!("Description: {}", p.description);
                println!("Requested: {:?}", p.permissions);

                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt(format!("AUTHORIZE '{}' with Admin Rights?", p.name))
                    .default(false)
                    .interact()?
                {
                    let set: HashSet<Permission> = p.permissions.iter().cloned().collect();
                    self.permissions_db.granted.insert(p.name.clone(), set);
                    println!("[OK] Authorized.");
                } else {
                    println!("[DENIED] Action aborted.");
                    self.permissions_db.granted.insert(p.name.clone(), HashSet::new());
                }
            }
        }

        let json = serde_json::to_string_pretty(&self.permissions_db)?;
        fs::write(&self.db_path, json)?;
        println!("\nSecurity Policy updated.\n");

        Ok(())
    }

    #[allow(dead_code)]
    pub fn list_functions(&self) -> Vec<String> {
        self.manifests.keys().cloned().collect()
    }

    #[instrument(skip(self, client))]
    pub async fn execute(
        &mut self,
        cmd: &str,
        args: Vec<&str>,
        client: &mut crate::network_client::PytjaClient,
        current_path: &str,
    ) -> Result<()> {
        let module = match self.modules.get(cmd) {
            Some(m) => m.clone(),
            None => {
                eprintln!("{}", format!("[ERROR] Plugin '{}' not found in memory cache.", cmd).red());
                return Ok(());
            }
        };

        let permissions = self.permissions_db.granted.get(cmd).cloned().unwrap_or_default();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let cmd_string = cmd.to_string();

        // --- 1. ENTERPRISE SANDBOX SETUP ---
        let mut sandbox_path = None;

        if permissions.contains(&Permission::FsRead) || permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {

            // THE ULTIMATE MACOS FIX:
            // Wir umgehen /tmp, /var und /private komplett, um Wasmers Symlink-Paranoia zu besiegen.
            // Wir umgehen ./data, damit dein eigenes Pytja VFS den Ordner nicht löscht.
            // Wir nutzen stattdessen einen versteckten Ordner in deinem Mac-Home-Verzeichnis!
            let home_dir = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let session_id = uuid::Uuid::new_v4().to_string();
            let temp_path = PathBuf::from(home_dir).join(".pytja").join("sandboxes").join(session_id);

            std::fs::create_dir_all(&temp_path).context("Failed to create secure sandbox directory")?;

            // Kein Canonicalize mehr nötig, da der Home-Pfad absolut und real ist!
            sandbox_path = Some(temp_path.clone());

            let mut i = 0;
            while i < args.len() {
                if args[i] == "--input" && i + 1 < args.len() {
                    let remote_path = args[i + 1];

                    let absolute_remote = if remote_path.starts_with('/') {
                        remote_path.to_string()
                    } else if current_path == "/" {
                        format!("/{}", remote_path)
                    } else {
                        format!("{}/{}", current_path, remote_path)
                    };

                    let file_name = std::path::Path::new(&absolute_remote).file_name().unwrap_or_default();
                    let local_dest = temp_path.join(file_name);

                    println!("[INFO] Mounting input file '{}' into Sandbox...", absolute_remote);
                    if let Err(e) = client.download_file(&absolute_remote, local_dest.to_str().unwrap(), None).await {
                        eprintln!("[ERROR] Failed to mount {}: {}", absolute_remote, e);
                        let _ = std::fs::remove_dir_all(&temp_path);
                        return Err(anyhow::anyhow!("Sandbox Mount aborted."));
                    }
                }
                i += 1;
            }
        }

        // --- 2. JIT EXECUTION (Synchronous Enterprise Pattern) ---
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message(format!("Executing {} in secure enclave...", cmd.cyan()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        // Wir bleiben auf dem synchronen Haupt-Thread. Das ist die sicherste Variante für macOS
        // und verhindert zu 100% Tokio-Context Verluste.
        let sp_clone = sandbox_path.clone();

        let execution_result = (|| -> Result<String> {
            let mut store = Store::default();
            let mut builder = WasiEnv::builder(&cmd_string);
            builder = builder.args(&args_owned);

            if let Some(ref sp) = sp_clone {
                let absolute_sp = sp.to_string_lossy().to_string();
                builder = builder.map_dir("/workspace", &absolute_sp).context("Sandbox mapping failed")?;
                builder = builder.current_dir("/workspace");
            }

            if permissions.contains(&Permission::Env) || permissions.contains(&Permission::Admin) {
                for (k, v) in std::env::vars() { builder = builder.env(k, v); }
            } else {
                builder = builder.env("SANDBOXED", "true");
            }

            let (instance, _env) = builder.instantiate(module, &mut store).context("WASI instantiation failed")?;
            let start = instance.exports.get_function("_start").context("Missing _start")?;

            start.call(&mut store, &[]).context("Plugin crashed")?;

            Ok(format!("Execution of {} completed.", cmd_string))
        })();

        let execution_successful = match execution_result {
            Ok(msg) => { pb.finish_and_clear(); println!("{} {}", "[OK]".green(), msg); true },
            Err(e) => { pb.finish_and_clear(); eprintln!("{} {:?}", "[ERROR] Plugin error:".red(), e); false }
        };

        // --- 3. SERVER SYNC (UPLOAD) ---
        if execution_successful {
            if let Some(ref tp) = sandbox_path {
                if permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
                    let mut synced_files = 0;
                    for entry in walkdir::WalkDir::new(tp).into_iter().filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() && !path.to_string_lossy().ends_with(".meta.json") {
                            let rel_path = path.strip_prefix(tp).unwrap().to_string_lossy().to_string();
                            let remote_path = if current_path == "/" { format!("/{}", rel_path) } else { format!("{}/{}", current_path, rel_path) };
                            let local_str = path.to_string_lossy().to_string();

                            match client.upload_file(&local_str, &remote_path, None, &client.username, None).await {
                                Ok(_) => synced_files += 1,
                                Err(e) => eprintln!("{} Failed to upload plugin output '{}': {}", "[ERROR]".red(), rel_path, e),
                            }
                        }
                    }
                    if synced_files > 0 {
                        println!("{} Synced {} output files directly to Pytja Server.", "[OK]".green(), synced_files);
                    }
                }
            }
        }

        // --- 4. ENTERPRISE CLEANUP ---
        if let Some(tp) = sandbox_path {
            let _ = std::fs::remove_dir_all(tp);
        }

        Ok(())
    }

    pub fn has_command(&self, cmd: &str) -> bool {
        self.modules.contains_key(cmd)
    }

    pub fn list_plugins(&self) -> Vec<(PluginManifest, std::collections::HashSet<Permission>)> {
        let mut result = Vec::new();

        for (name, manifest) in &self.manifests {
            let granted = self.permissions_db.granted.get(name).cloned().unwrap_or_default();
            result.push((manifest.clone(), granted));
        }

        result.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        result
    }
}
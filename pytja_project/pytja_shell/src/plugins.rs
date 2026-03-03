use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, instrument};
use wasmer_wasix::WasiEnv;
use serde::{Deserialize, Serialize};
use colored::*;
use dialoguer::{Confirm, theme::ColorfulTheme};
use wasmer::{Module, Store};
use tokio::sync::{mpsc, oneshot};

// --- ASYNC MESSAGE SYSTEM ---
#[derive(Debug)]
pub enum PluginMessage {
    ExecuteCommand {
        args: Vec<String>,
        sandbox_path: Option<PathBuf>,
        responder: oneshot::Sender<anyhow::Result<String>>,
    },
    Shutdown,
}

// --- DATA STRUCTURES ---
// (Dein bestehender Code für Permission, PluginManifest, PermissionDb bleibt exakt gleich!)

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
    Admin, // "Root" Zugriff
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

// --- MANAGER ---

// --- MANAGER ---

pub struct PluginManager {
    plugin_dir: PathBuf,
    manifests: HashMap<String, PluginManifest>,
    db_path: PathBuf,
    permissions_db: PermissionDb,
    active_daemons: HashMap<String, mpsc::Sender<PluginMessage>>,
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
            db_path,
            permissions_db,
            active_daemons: HashMap::new(),
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

    pub fn boot_daemon(&mut self, cmd_name: &str) -> Result<()> {
        let permissions = self.permissions_db.granted.get(cmd_name).cloned().unwrap_or_default();
        let plugin_path = self.plugin_dir.join(format!("{}.wasm", cmd_name));
        let wasm_bytes = fs::read(&plugin_path).context("Failed to read plugin binary.")?;
        let cmd_string = cmd_name.to_string();

        let (tx, mut rx) = mpsc::channel::<PluginMessage>(32);
        self.active_daemons.insert(cmd_string.clone(), tx);

        // NEU: Tokio Handle sichern, um ihn an den isolierten Thread zu übergeben
        let handle = tokio::runtime::Handle::current();

        tokio::spawn(async move {
            info!("Daemon '{}' is now running in background.", cmd_string);

            while let Some(msg) = rx.recv().await {
                match msg {
                    PluginMessage::ExecuteCommand { args, sandbox_path, responder } => {
                        let thread_permissions = permissions.clone();
                        let bytes_clone = wasm_bytes.clone();
                        let cmd_clone = cmd_string.clone();
                        let handle_clone = handle.clone();

                        let res = tokio::task::spawn_blocking(move || -> Result<String> {
                            // ENTERPRISE FIX 1: Den Tokio-Kontext im synchronen Thread wiederherstellen!
                            let _guard = handle_clone.enter();

                            let mut store = Store::default();
                            let module = Module::new(&store, bytes_clone)?;

                            let mut builder = WasiEnv::builder(&cmd_clone);
                            builder = builder.args(&args);

                            if let Some(sp) = sandbox_path {
                                builder = builder.map_dir("/workspace", sp)
                                    .context("Sandbox-Directory mapping failed")?;
                                builder = builder.current_dir("/workspace");
                            }

                            if thread_permissions.contains(&Permission::Env) || thread_permissions.contains(&Permission::Admin) {
                                for (k, v) in std::env::vars() { builder = builder.env(k, v); }
                            } else {
                                builder = builder.env("SANDBOXED", "true");
                            }

                            // Wir fangen das Instantiate jetzt mit vollem Kontext ab
                            let (instance, _env) = builder.instantiate(module, &mut store)
                                .context("WASI instantiation failed")?;

                            let start = instance.exports.get_function("_start")
                                .context("Missing _start function in WASM module")?;

                            start.call(&mut store, &[]).context("Plugin crashed during execution")?;
                            Ok(format!("Execution of {} completed.", cmd_clone))
                        }).await;

                        let final_result = match res {
                            Ok(Ok(success_msg)) => Ok(success_msg),
                            Ok(Err(e)) => Err(e),
                            Err(e) => Err(anyhow::anyhow!("Thread panic: {}", e)),
                        };
                        let _ = responder.send(final_result);
                    }
                    PluginMessage::Shutdown => {
                        info!("Daemon '{}' shutting down.", cmd_string);
                        break;
                    }
                }
            }
        });

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
        let sender = match self.active_daemons.get(cmd) {
            Some(s) => s,
            None => {
                eprintln!("{}", format!("[ERROR] Plugin Daemon '{}' is not running.", cmd).red());
                return Ok(());
            }
        };

        let permissions = self.permissions_db.granted.get(cmd).cloned().unwrap_or_default();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        // --- 1. SANDBOX SETUP & DOWNLOAD ---
        let mut _temp_dir = None;
        let mut sandbox_path = None;

        if permissions.contains(&Permission::FsRead) || permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
            let td = tempfile::tempdir().context("Failed to create secure sandbox directory")?;

            // ENTERPRISE FIX: Mac/Linux Symlinks auflösen, damit WASI den echten Pfad sieht!
            let temp_path = std::fs::canonicalize(td.path()).unwrap_or_else(|_| td.path().to_path_buf());
            sandbox_path = Some(temp_path.clone());

            let mut i = 0;
            while i < args.len() {
                if args[i] == "--input" && i + 1 < args.len() {
                    let remote_path = args[i + 1];

                    // RESOLVE PATH: Wandelt relative Pfade in absolute VFS-Pfade um
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
                        return Err(anyhow::anyhow!("Sandbox Mount aborted."));
                    }
                }
                i += 1;
            }
            _temp_dir = Some(td); // Hält den temporären Ordner am Leben!
        }

        // --- 2. ASYNC DAEMON KOMMUNIKATION ---
        let (resp_tx, resp_rx) = oneshot::channel();
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
        pb.set_message(format!("Sending command to {} daemon...", cmd.cyan()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        sender.send(PluginMessage::ExecuteCommand {
            args: args_owned,
            sandbox_path: sandbox_path.clone(),
            responder: resp_tx,
        }).await.context("Failed to communicate with plugin daemon")?;

        let execution_successful = match resp_rx.await {
            Ok(Ok(msg)) => { pb.finish_and_clear(); println!("{} {}", "[OK]".green(), msg); true },
            Ok(Err(e)) => { pb.finish_and_clear(); eprintln!("{} {:?}", "[ERROR] Plugin error:".red(), e); false },
            Err(_) => { pb.finish_and_clear(); eprintln!("{}", "[FATAL] Daemon disconnected.".red()); false }
        };

        // --- 3. SERVER SYNC (UPLOAD) ---
        if execution_successful {
            if let Some(tp) = sandbox_path {
                if permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
                    let mut synced_files = 0;
                    for entry in walkdir::WalkDir::new(&tp).into_iter().filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_file() && !path.to_string_lossy().ends_with(".meta.json") {
                            let rel_path = path.strip_prefix(&tp).unwrap().to_string_lossy().to_string();
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

        Ok(())
    }

    pub fn has_command(&self, cmd: &str) -> bool {
        self.active_daemons.contains_key(cmd) || self.manifests.contains_key(cmd)
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

    pub async fn shutdown_all(&mut self) {
        for (name, sender) in self.active_daemons.drain() {
            let _ = sender.send(PluginMessage::Shutdown).await;
            info!("Sent shutdown signal to daemon '{}'", name);
        }
    }
}
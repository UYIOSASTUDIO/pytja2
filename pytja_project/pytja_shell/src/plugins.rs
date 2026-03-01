use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, error, instrument};
use wasmer_wasix::WasiEnv; // Umstellung auf WASIX
use serde::{Deserialize, Serialize};
use colored::*;
use dialoguer::{Confirm, theme::ColorfulTheme};
use wasmer::{Module, Store};

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

pub struct PluginManager {
    plugin_dir: PathBuf,
    modules: HashMap<String, Module>,
    manifests: HashMap<String, PluginManifest>,
    store: Store,
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
            modules: HashMap::new(),
            manifests: HashMap::new(),
            store: Store::default(),
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

                match self.compile_module(&path) {
                    Ok(module) => {
                        self.modules.insert(manifest.name.clone(), module);

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
                    },
                    Err(e) => error!("Failed to compile {}: {}", stem, e),
                }
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

    fn compile_module(&self, path: &Path) -> Result<Module> {
        let wasm_bytes = fs::read(path).context("Failed to read wasm file")?;
        let module = Module::new(&self.store, wasm_bytes)?;
        Ok(module)
    }

    pub fn has_command(&self, cmd: &str) -> bool {
        self.modules.contains_key(cmd)
    }

    #[allow(dead_code)]
    pub fn list_functions(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }

    #[instrument(skip(self, client))]
    pub async fn execute(
        &mut self,
        cmd: &str,
        args: Vec<&str>,
        client: &mut crate::network_client::PytjaClient,
        current_path: &str,
    ) -> Result<()> {
        let permissions = self.permissions_db.granted.get(cmd)
            .cloned().unwrap_or_default();

        info!("Executing Plugin '{}' with rights: {:?}", cmd, permissions);

        let cmd_string = cmd.to_string();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let plugin_path = self.plugin_dir.join(format!("{}.wasm", cmd));
        let wasm_bytes = fs::read(&plugin_path).context("Failed to read plugin binary. Is it installed?")?;

        let mut _temp_dir = None;
        let mut temp_path_clone = None;
        let mut sandbox_path = None;

        if permissions.contains(&Permission::FsRead) || permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
            let td = tempfile::tempdir().context("Failed to create secure sandbox directory")?;
            let temp_path = td.path().to_path_buf();

            temp_path_clone = Some(temp_path.clone());
            sandbox_path = Some(temp_path.clone());
            _temp_dir = Some(td);

            let mut i = 0;
            while i < args.len() {
                if args[i] == "--input" && i + 1 < args.len() {
                    let remote_path = args[i + 1];
                    let file_name = std::path::Path::new(remote_path).file_name().unwrap_or_default();
                    let local_dest = temp_path.join(file_name);

                    println!("[INFO] Mounting input file '{}' into Sandbox...", remote_path);
                    if let Err(e) = client.download_file(remote_path, local_dest.to_str().unwrap(), None).await {
                        eprintln!("[ERROR] Failed to mount {}: {}", remote_path, e);
                        return Err(anyhow::anyhow!("Sandbox Mount aborted due to download error."));
                    }
                }
                i += 1;
            }
        }

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")?);
        pb.set_message(format!("{} is running in secure WASIX sandbox...", cmd.cyan()));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        let thread_permissions = permissions.clone();

        // Asynchrone WASIX Ausführung
        let execution_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut store = Store::default();
            let module = Module::new(&store, wasm_bytes)?;

            // WASIX Environment Builder (Consuming Builder Pattern)
            let mut builder = WasiEnv::builder(&cmd_string);

            // Neu: Wir weisen das Ergebnis wieder builder zu
            builder = builder.args(&args_owned);

            if let Some(sp) = sandbox_path {
                // map_dir gibt ein Result zurück, daher das ? am Ende
                builder = builder.map_dir("/", sp)?;
            }

            if thread_permissions.contains(&Permission::Env) || thread_permissions.contains(&Permission::Admin) {
                for (k, v) in std::env::vars() {
                    builder = builder.env(k, v);
                }
            } else {
                builder = builder.env("SANDBOXED", "true");
            }

            // WASIX Instanziierung (Kapselt WasiFunctionEnv)
            let (instance, _env) = builder.instantiate(module, &mut store)?;

            let memory = instance.exports.get_memory("memory")?;
            let _initial_size = memory.view(&store).size().bytes().0;

            let start = instance.exports.get_function("_start").context("Plugin is missing a _start (main) function")?;
            start.call(&mut store, &[]).context("Plugin crashed during execution (Possible Out-of-Memory or Segfault)")?;

            Ok(())
        });

        let timeout_duration = tokio::time::Duration::from_secs(300);

        tokio::select! {
            res = execution_task => {
                pb.finish_and_clear();
                match res {
                    Ok(Ok(_)) => println!("{}", "[OK] Plugin execution completed.".green()),
                    Ok(Err(e)) => eprintln!("{} {}", "[ERROR] Plugin error:".red(), e),
                    Err(e) => eprintln!("{} {}", "[FATAL] Thread panic:".red(), e),
                }
            }
            _ = tokio::time::sleep(timeout_duration) => {
                pb.finish_and_clear();
                eprintln!("{}", "[TIMEOUT] Execution killed! Plugin exceeded maximum runtime of 5 minutes.".red().bold());
                return Ok(());
            }
            _ = tokio::signal::ctrl_c() => {
                pb.finish_and_clear();
                eprintln!("{}", "[INTERRUPT] Execution forcefully interrupted by user (SIGINT).".yellow().bold());
                return Ok(());
            }
        }

        if let Some(tp) = temp_path_clone {
            if permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
                let mut synced_files = 0;

                for entry in walkdir::WalkDir::new(&tp).into_iter().filter_map(|e| e.ok()) {
                    let path = entry.path();

                    if path.is_file() && !path.to_string_lossy().ends_with(".meta.json") {
                        let rel_path = path.strip_prefix(&tp).unwrap().to_string_lossy().to_string();
                        let remote_path = if current_path == "/" { format!("/{}", rel_path) } else { format!("{}/{}", current_path, rel_path) };

                        let meta_path = std::path::PathBuf::from(format!("{}.meta.json", path.display()));
                        let metadata = if meta_path.exists() {
                            std::fs::read_to_string(&meta_path).ok()
                        } else {
                            None
                        };

                        let local_str = path.to_string_lossy().to_string();

                        match client.upload_file(&local_str, &remote_path, None, &client.username, metadata).await {
                            Ok(_) => synced_files += 1,
                            Err(e) => eprintln!("{} Failed to upload plugin output '{}': {}", "[ERROR]".red(), rel_path, e),
                        }
                    }
                }

                if synced_files > 0 {
                    println!("{} Synced {} output files (with metadata) directly to Pytja Server.", "[OK]".green(), synced_files);
                }
            }
        }

        Ok(())
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
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn, error, instrument};
use wasmer::{Module, Store, Instance};
use wasmer_wasi::WasiState;
use serde::{Deserialize, Serialize};
use colored::*;
use dialoguer::{Confirm, theme::ColorfulTheme};

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

            if path.extension().map_or(false, |ext| ext == "wasm") {
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
        println!("\n{}", "🔒 SECURITY ALERT: NEW PLUGINS DETECTED".yellow().bold());
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
                println!("• {} (v{}): {}", p.name.bold(), p.version, perms_str.dimmed());
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
                println!("{}", "⚠️  Plugins denied. They may not function correctly.".red());
                for p in low_risk {
                    self.permissions_db.granted.insert(p.name.clone(), HashSet::new());
                }
            }
        }

        if !high_risk.is_empty() {
            println!("\n{}", "--- 🛡️  ELEVATED PRIVILEGES REQUESTED (ADMIN/ROOT) ---".red().bold());
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
                    println!("✅ Authorized.");
                } else {
                    println!("❌ Denied.");
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

    pub fn list_functions(&self) -> Vec<String> {
        self.modules.keys().cloned().collect()
    }

    #[instrument(skip(self, client))]
    pub async fn execute(
        &mut self,
        cmd: &str,
        args: Vec<&str>,
        client: &mut crate::network_client::PytjaClient, // KORREKT: Der Netzwerk-Client!
        current_path: &str, // KORREKT: Der aktuelle Pfad!
    ) -> Result<()> {
        let module = self.modules.get(cmd).context("Plugin not found")?;
        let permissions = self.permissions_db.granted.get(cmd)
            .cloned().unwrap_or_default();

        info!("Executing Plugin '{}' with rights: {:?}", cmd, permissions);

        let mut builder = WasiState::new(cmd);
        builder.args(&args);

        let mut _temp_dir = None;
        let mut temp_path_clone = None;

        if permissions.contains(&Permission::FsRead) || permissions.contains(&Permission::FsWrite) || permissions.contains(&Permission::Admin) {
            let td = tempfile::tempdir().context("Failed to create secure sandbox directory")?;
            let temp_path = td.path().to_path_buf();

            builder.map_dir("/", temp_path.clone())?;
            builder.preopen_dir(temp_path.clone())?;

            temp_path_clone = Some(temp_path);
            _temp_dir = Some(td);
        }

        if permissions.contains(&Permission::Env) || permissions.contains(&Permission::Admin) {
            builder.envs(std::env::vars());
        } else {
            builder.env("SANDBOXED", "true");
        }

        let mut wasi_env = builder.finalize(&mut self.store)?;
        let import_object = wasi_env.import_object(&mut self.store, &module)?;

        // 1. PLUGIN INITIALISIEREN
        let instance = Instance::new(&mut self.store, &module, &import_object)?;
        wasi_env.initialize(&mut self.store, &instance)?;

        // DEN START-KNOPF DRÜCKEN
        let start = instance.exports.get_function("_start").context("Plugin is missing a _start (main) function")?;
        start.call(&mut self.store, &[]).context("Plugin crashed during execution")?;

        // 2. POST-EXECUTION SYNC (Direkt über gRPC zum Server)
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

                        // UPLOAD: Wir pushen die Datei direkt live in die entfernte Datenbank
                        if client.upload_file(&local_str, &remote_path, None, "plugin_system", metadata).await.is_ok() {
                            synced_files += 1;
                        } else {
                            eprintln!("{} Failed to upload {}", "❌".red(), rel_path);
                        }
                    }
                }

                if synced_files > 0 {
                    println!("{} Synced {} output files (with metadata) to Pytja VFS.", "✔".green(), synced_files);
                }
            }
        }

        Ok(())
    }
}
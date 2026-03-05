use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, instrument};
use wasmer::{Engine, Module, Store, Function, Instance, Exports};
use wasmer_wasix::WasiEnv;
use wasmer_wasix::virtual_fs::{FileSystem, TmpFileSystem};
use tokio::io::AsyncWriteExt;
use crate::network_client::PytjaClient;

use tokio::sync::mpsc;
use super::models::{PluginManifest, RadarPermission};

pub struct DaemonContext {
    pub monitor_task: tokio::task::JoinHandle<()>,
    pub tx: mpsc::Sender<String>,
}

pub struct RadarEngine {
    wasm_engine: Engine,
    module_cache: HashMap<String, Module>,
    manifests: HashMap<String, PluginManifest>,
    active_daemons: HashMap<String, DaemonContext>,
}

impl RadarEngine {
    pub fn new() -> Result<Self> {
        Ok(Self {
            wasm_engine: Engine::default(),
            module_cache: HashMap::new(),
            manifests: HashMap::new(),
            active_daemons: HashMap::new(),
        })
    }

    #[instrument(skip(self, wasm_bytes))]
    pub fn register_plugin(&mut self, manifest: PluginManifest, wasm_bytes: &[u8]) -> Result<()> {
        info!("Compiling plugin '{}' into Radar memory cache...", manifest.name);

        let module = Module::new(&self.wasm_engine, wasm_bytes)
            .context(format!("AOT Compilation failed for plugin: {}", manifest.name))?;

        self.module_cache.insert(manifest.name.clone(), module);
        self.manifests.insert(manifest.name.clone(), manifest);

        Ok(())
    }

    // --- DAEMON LIFECYCLE MANAGEMENT ---

    pub fn start_daemon(&mut self, plugin_name: &str, args: Vec<String>, client: PytjaClient) -> Result<()> {
        if self.active_daemons.contains_key(plugin_name) {
            anyhow::bail!("Daemon '{}' is already running.", plugin_name);
        }

        let module = self.module_cache.get(plugin_name)
            .context(format!("Plugin '{}' not found in Radar cache", plugin_name))?
            .clone();

        let plugin_name_owned = plugin_name.to_string();
        let handle = tokio::runtime::Handle::current();

        // --- ZERO TRUST: Berechtigungen für diesen Prozess isolieren ---
        let manifest = self.manifests.get(plugin_name).cloned().unwrap_or_else(|| PluginManifest {
            name: plugin_name.to_string(),
            version: "UNKNOWN".into(),
            description: "Unverified Daemon".into(),
            permissions: vec![],
            autostart: false,
        });
        let process_permissions = manifest.permissions;

        // --- THE C2 EVENT BUS ---
        let (tx, mut rx) = mpsc::channel::<String>(32);
        let mem_fs = TmpFileSystem::new();
        let mem_fs_inbox = mem_fs.clone();

        // Hintergrund-Relay: Leitet asynchrone Channel-Nachrichten in den RAM des Plugins
        // Hintergrund-Relay: Leitet asynchrone Channel-Nachrichten in den RAM des Plugins
        let inbox_handle = handle.clone();
        inbox_handle.spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(msg) = rx.recv().await {
                // THE ENTERPRISE FIX: Das OpenOptions-Objekt VOR dem .await sofort droppen
                let open_result = mem_fs_inbox
                    .new_open_options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(std::path::Path::new("/workspace/.radar_inbox"));

                if let Ok(mut file) = open_result {
                    let _ = file.write_all(msg.as_bytes()).await;
                }
            }
        });

        // 1. Die Sandbox im Hintergrund aufbauen
        let daemon_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let _guard = handle.enter();

            let mut store = Store::default();
            let mem_fs = TmpFileSystem::new();

            // FIX: Klone das FS für die ABI, BEVOR es vom Builder konsumiert wird
            let mem_fs_abi = mem_fs.clone();

            let mut builder = WasiEnv::builder(&plugin_name_owned)
                .args(&args)
                .sandbox_fs(mem_fs);

            builder = builder.env("RADAR_MODE", "DAEMON");

            // THE ENTERPRISE FIX: Dem Daemon den Schlüssel zum RAM-Ordner übergeben
            builder = builder.preopen_dir("/workspace")?;
            builder = builder.current_dir("/workspace");

            let mut wasi_env = builder.finalize(&mut store)?;
            let mut import_object = wasi_env.import_object(&mut store, &module)?;

            // Radar ABI aufbauen
            let mut radar_exports = Exports::new();

            radar_exports.insert("host_log_status", Function::new_typed(&mut store, |code: i32| {
                println!("\n[DAEMON EVENT] Process reported status: {}", code);
            }));

            let handle_abi = handle.clone();
            let client_abi = client.clone();
            let perms_abi = process_permissions.clone(); // Die Security-Tokens für den Router

            // THE ENTERPRISE FIX: Unified IPC Router mit Zero Trust PEP
            radar_exports.insert("host_ipc_request", Function::new_typed(&mut store, move || -> i32 {
                let fs = mem_fs_abi.clone();
                let client_req = client_abi.clone();
                let allowed_perms = perms_abi.clone();

                handle_abi.block_on(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};

                    let mut req_content = String::new();
                    if let Ok(mut file) = fs.new_open_options().read(true).open(std::path::Path::new("/workspace/.radar_req")) {
                        let _ = file.read_to_string(&mut req_content).await;
                    }

                    let response_json = match serde_json::from_str::<serde_json::Value>(&req_content) {
                        Ok(req) => {
                            let module = req["module"].as_str().unwrap_or("");
                            let method = req["method"].as_str().unwrap_or("");

                            // --- ROUTE: VFS MODULE ---
                            if module == "vfs" {
                                // SECURITY CHECK: FsRead (angepasst an dein neues Modell)
                                if !allowed_perms.contains(&RadarPermission::FsRead) {
                                    r#"{"status": "error", "message": "403 Forbidden: Missing fs_read permission"}"#.to_string()
                                } else if method == "list_dir" {
                                    let target_path = req["params"]["path"].as_str().unwrap_or("/");

                                    match client_req.list_files(target_path).await {
                                        Ok(items) => {
                                            let json_items: Vec<String> = items.iter().map(|i| {
                                                format!(r#"{{"name": "{}", "is_folder": {}, "size": {}}}"#, i.name, i.is_folder, i.size)
                                            }).collect();
                                            format!(r#"{{"status": "success", "data": {{"items": [{}]}}}}"#, json_items.join(", "))
                                        },
                                        Err(e) => {
                                            let safe_err = e.to_string().replace("\"", "\\\"");
                                            format!(r#"{{"status": "error", "message": "{}"}}"#, safe_err)
                                        }
                                    }
                                } else {
                                    r#"{"status": "error", "message": "Method not implemented in VFS module"}"#.to_string()
                                }
                            }
                            // --- ROUTE: NETWORK MODULE ---
                            else if module == "network" {
                                // SECURITY CHECK: NetworkTcp
                                if !allowed_perms.contains(&RadarPermission::NetworkTcp) {
                                    r#"{"status": "error", "message": "403 Forbidden: Missing network_tcp permission"}"#.to_string()
                                } else {
                                    let url = req["params"]["url"].as_str().unwrap_or("");
                                    let method_http = req["params"]["method"].as_str().unwrap_or("GET");
                                    let body_opt = req["params"]["body"].as_str();

                                    let client_http = reqwest::Client::new();
                                    let mut request_builder = match method_http {
                                        "POST" => client_http.post(url),
                                        "PUT" => client_http.put(url),
                                        _ => client_http.get(url),
                                    };

                                    if let Some(b) = body_opt {
                                        request_builder = request_builder.body(b.to_string());
                                    }

                                    match request_builder.send().await {
                                        Ok(resp) => {
                                            let status_code = resp.status().as_u16();
                                            let body_text = resp.text().await.unwrap_or_default();

                                            let res_json = serde_json::json!({
                                                "status": "success",
                                                "data": {
                                                    "status_code": status_code,
                                                    "body": body_text
                                                }
                                            });
                                            res_json.to_string()
                                        },
                                        Err(e) => {
                                            let res_json = serde_json::json!({
                                                "status": "error",
                                                "message": e.to_string()
                                            });
                                            res_json.to_string()
                                        }
                                    }
                                }
                            }
                            else {
                                r#"{"status": "error", "message": "Unknown IPC module"}"#.to_string()
                            }
                        },
                        Err(_) => r#"{"status": "error", "message": "Invalid IPC JSON payload"}"#.to_string()
                    };

                    if let Ok(mut file) = fs.new_open_options().write(true).create(true).truncate(true).open(std::path::Path::new("/workspace/.radar_res")) {
                        let _ = file.write_all(response_json.as_bytes()).await;
                    }
                });

                200
            }));

            import_object.register_namespace("radar_abi", radar_exports);

            let instance = Instance::new(&mut store, &module, &import_object)?;
            wasi_env.initialize(&mut store, instance.clone())?;

            let start = instance.exports.get_function("_start")?;
            start.call(&mut store, &[])?;

            Ok(())
        });

        let monitor_name = plugin_name.to_string();
        let monitor_task = tokio::spawn(async move {
            match daemon_task.await {
                Ok(Ok(_)) => println!("\n[RADAR] Daemon '{}' exited cleanly.", monitor_name),
                Ok(Err(e)) => println!("\n[RADAR] Daemon '{}' crashed: {}", monitor_name, e),
                Err(_) => println!("\n[RADAR] Daemon '{}' was forcefully terminated.", monitor_name),
            }
        });

        self.active_daemons.insert(plugin_name.to_string(), DaemonContext {
            monitor_task,
            tx,
        });
        Ok(())
    }

    pub fn stop_daemon(&mut self, plugin_name: &str) -> Result<()> {
        if let Some(ctx) = self.active_daemons.remove(plugin_name) {
            ctx.monitor_task.abort();
            Ok(())
        } else {
            anyhow::bail!("Daemon '{}' is not currently running.", plugin_name);
        }
    }

    pub async fn send_to_daemon(&self, plugin_name: &str, message: String) -> Result<()> {
        if let Some(ctx) = self.active_daemons.get(plugin_name) {
            ctx.tx.send(message).await.context("Failed to dispatch IPC message")?;
            Ok(())
        } else {
            anyhow::bail!("Daemon '{}' is not currently running.", plugin_name);
        }
    }

    pub fn list_daemons(&self) -> Vec<String> {
        self.active_daemons.keys().cloned().collect()
    }

    // --- STANDARD PLUGIN MANAGEMENT ---

    pub fn load_plugins(&mut self, plugin_dir: impl AsRef<std::path::Path>) -> Result<()> {
        let dir = plugin_dir.as_ref();
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "wasm") {
                let stem = path.file_stem().unwrap().to_string_lossy().to_string();
                let manifest_path = path.with_extension("json");

                let manifest: PluginManifest = if manifest_path.exists() {
                    let content = std::fs::read_to_string(&manifest_path)?;
                    serde_json::from_str(&content).unwrap_or_else(|_| PluginManifest {
                        name: stem.clone(),
                        version: "0.0.0".into(),
                        description: "Invalid manifest".into(),
                        permissions: vec![],
                        autostart: false,
                    })
                } else {
                    PluginManifest {
                        name: stem.clone(),
                        version: "0.0.0".into(),
                        description: "No manifest".into(),
                        permissions: vec![],
                        autostart: false,
                    }
                };

                let wasm_bytes = std::fs::read(&path).context("Failed to read WASM file")?;
                if let Err(e) = self.register_plugin(manifest, &wasm_bytes) {
                    tracing::error!("Failed to register plugin {}: {}", stem, e);
                }
            }
        }
        Ok(())
    }

    pub fn has_plugin(&self, name: &str) -> bool {
        self.module_cache.contains_key(name)
    }

    pub fn get_manifests(&self) -> Vec<PluginManifest> {
        let mut manifests: Vec<_> = self.manifests.values().cloned().collect();
        manifests.sort_by(|a, b| a.name.cmp(&b.name));
        manifests
    }

    // --- EPHEMERAL EXECUTION ---

    #[instrument(skip(self, input_data))]
    pub async fn execute_ephemeral(
        &self,
        plugin_name: &str,
        args: Vec<String>,
        input_data: Option<(String, Vec<u8>)>,
    ) -> Result<(String, Vec<(String, Vec<u8>)>)> {
        let module = self.module_cache.get(plugin_name)
            .context(format!("Plugin '{}' not found in Radar cache", plugin_name))?
            .clone();

        let plugin_name_owned = plugin_name.to_string();
        let input_filename = input_data.as_ref().map(|(name, _)| name.clone()).unwrap_or_default();

        let mem_fs = TmpFileSystem::new();
        let mem_fs_clone = mem_fs.clone();

        // FIX: Auch hier das FS klonen, BEVOR es vom Builder konsumiert wird!
        let mem_fs_abi = mem_fs.clone();

        if let Some((filename, data)) = input_data {
            let filepath = format!("/workspace/{}", filename);
            mem_fs.create_dir(std::path::Path::new("/workspace")).ok();

            let mut file = mem_fs.new_open_options()
                .write(true)
                .create(true)
                .open(std::path::Path::new(&filepath))
                .context("Failed to create file in MemFS")?;

            file.write_all(&data).await.context("Failed to write data to MemFS")?;
        }

        let handle = tokio::runtime::Handle::current();

        let execution_result = tokio::task::spawn_blocking(move || -> Result<String> {
            let _guard = handle.enter();

            let mut store = Store::default();
            let mut builder = WasiEnv::builder(&plugin_name_owned)
                .args(&args)
                .sandbox_fs(mem_fs);

            builder = builder.preopen_dir("/workspace").context("Failed to preopen workspace in MemFS")?;
            builder = builder.current_dir("/workspace");
            builder = builder.env("RADAR_ENGINE", "v3.0");

            let mut wasi_env = builder.finalize(&mut store).context("Failed to finalize WASI env")?;
            let mut import_object = wasi_env.import_object(&mut store, &module).context("Failed to create WASI imports")?;

            // Radar ABI aufbauen
            let mut radar_exports = Exports::new();

            radar_exports.insert("host_log_status", Function::new_typed(&mut store, |code: i32| {
                println!("\n[DAEMON EVENT] Process reported status: {}", code);
            }));

            let handle_abi = handle.clone();

            radar_exports.insert("host_vfs_execute", Function::new_typed(&mut store, move || -> i32 {
                let fs = mem_fs_abi.clone();

                handle_abi.block_on(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};

                    let mut req_content = String::new();
                    if let Ok(mut file) = fs.new_open_options().read(true).open(std::path::Path::new("/workspace/.radar_req")) {
                        let _ = file.read_to_string(&mut req_content).await;
                    }

                    let response = format!(
                        "{{\"status\": \"success\", \"action\": \"{}\", \"items\": [\"geheim_1.txt\", \"system.log\"]}}",
                        req_content.trim()
                    );

                    if let Ok(mut file) = fs.new_open_options().write(true).create(true).truncate(true).open(std::path::Path::new("/workspace/.radar_res")) {
                        let _ = file.write_all(response.as_bytes()).await;
                    }
                });

                200
            }));

            import_object.register_namespace("radar_abi", radar_exports);

            let instance = Instance::new(&mut store, &module, &import_object)
                .context("Failed to instantiate WASM with Radar ABI")?;

            wasi_env.initialize(&mut store, instance.clone()).context("Failed to initialize WASI env")?;

            let start = instance.exports.get_function("_start")
                .context("Invalid WASM: Missing _start function")?;

            start.call(&mut store, &[]).context("Plugin crashed during execution")?;

            Ok(format!("Execution of {} completed successfully in MemFS.", plugin_name_owned))
        }).await.context("Thread Panic")??;

        // --- THE OUTPUT SYNC ---
        let mut output_files = Vec::new();
        use tokio::io::AsyncReadExt;

        if let Ok(entries) = mem_fs_clone.read_dir(std::path::Path::new("/workspace")) {
            for entry_res in entries {
                if let Ok(entry) = entry_res {
                    let path = entry.path;
                    let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                    if file_name == input_filename || file_name.starts_with('.') {
                        continue;
                    }

                    if let Ok(mut file) = mem_fs_clone.new_open_options().read(true).open(&path) {
                        let mut buf = Vec::new();
                        if file.read_to_end(&mut buf).await.is_ok() {
                            output_files.push((file_name, buf));
                        }
                    }
                }
            }
        }

        Ok((execution_result, output_files))
    }
}
use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, instrument};
use wasmer::{Engine, Module, Store, Function, Instance, Exports, FunctionEnv, FunctionEnvMut};
use wasmer_wasix::WasiEnv;
use wasmer_wasix::virtual_fs::{FileSystem, TmpFileSystem};
use tokio::io::AsyncWriteExt;
use crate::network_client::PytjaClient;

use std::sync::Arc;
use tokio::sync::mpsc;
use super::models::PluginManifest;

pub struct DaemonContext {
    pub monitor_task: tokio::task::JoinHandle<()>,
    pub tx: mpsc::Sender<String>,
    pub mem_fs: TmpFileSystem, // NEU: Referenz auf das RAM-Laufwerk des Daemons
}

pub struct RadarEngine {
    wasm_engine: Engine,
    module_cache: HashMap<String, Module>,
    manifests: HashMap<String, PluginManifest>,
    active_daemons: HashMap<String, DaemonContext>,
    pub ui_registry: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    pub alarm_tx: tokio::sync::mpsc::Sender<String>, // NEU: Der Alarm-Kanal
}

impl RadarEngine {
    pub fn new(alarm_tx: tokio::sync::mpsc::Sender<String>) -> Result<Self> {
        let ui_registry = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let ui_reg_clone = ui_registry.clone();
        tokio::spawn(async move {
            crate::radar::display::run_ui_server(ui_reg_clone).await;
        });

        Ok(Self {
            wasm_engine: Engine::default(),
            module_cache: HashMap::new(),
            manifests: HashMap::new(),
            active_daemons: HashMap::new(),
            ui_registry,
            alarm_tx, // NEU
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

        let manifest = self.manifests.get(plugin_name).cloned().unwrap_or_else(|| PluginManifest {
            name: plugin_name.to_string(),
            version: "UNKNOWN".into(),
            description: "Unverified Daemon".into(),
            permissions: vec![],
            autostart: false,
        });
        let process_permissions = manifest.permissions;

        let (tx, mut rx) = mpsc::channel::<String>(32);
        let active_sockets: Arc<tokio::sync::Mutex<std::collections::HashMap<String, mpsc::Sender<String>>>> = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let mem_fs = TmpFileSystem::new();
        let _ = mem_fs.create_dir(std::path::Path::new("/workspace"));

        let mem_fs_inbox = mem_fs.clone();
        let mem_fs_sandbox = mem_fs.clone();
        let mem_fs_context = mem_fs.clone();

        let inbox_handle = handle.clone();
        inbox_handle.spawn(async move {
            use tokio::io::AsyncWriteExt;
            while let Some(msg) = rx.recv().await {
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

        let tx_for_daemon = tx.clone();
        let ui_registry_for_daemon = self.ui_registry.clone();
        let alarm_tx_for_daemon = self.alarm_tx.clone();

        let daemon_task = tokio::task::spawn_blocking(move || -> Result<()> {
            let _guard = handle.enter();
            let mut store = Store::default();
            let mem_fs_abi = mem_fs_sandbox.clone();

            // --- ENTERPRISE FIX: DIRECT MEMORY ACCESS (DMA) ENVIRONMENT ---
            #[derive(Clone)]
            struct RadarEnv { memory: Option<wasmer::Memory> }
            let radar_env = FunctionEnv::new(&mut store, RadarEnv { memory: None });

            let mut builder = WasiEnv::builder(&plugin_name_owned)
                .args(&args)
                .sandbox_fs(mem_fs_sandbox);

            builder = builder.env("RADAR_MODE", "DAEMON");
            builder = builder.preopen_dir("/workspace")?;
            builder = builder.current_dir("/workspace");

            if let Ok(log_out) = mem_fs_abi.new_open_options().write(true).create(true).append(true).open(std::path::Path::new("/workspace/daemon.log")) {
                builder = builder.stdout(log_out);
            }
            if let Ok(log_err) = mem_fs_abi.new_open_options().write(true).create(true).append(true).open(std::path::Path::new("/workspace/daemon.log")) {
                builder = builder.stderr(log_err);
            }

            let mut wasi_env = builder.finalize(&mut store)?;
            let mut import_object = wasi_env.import_object(&mut store, &module)?;

            let mut radar_exports = Exports::new();

            radar_exports.insert("host_log_status", Function::new_typed(&mut store, |code: i32| {
                println!("\n[DAEMON EVENT] Process reported status: {}", code);
            }));

            let handle_abi = handle.clone();
            let client_abi = client.clone();
            let perms_abi = process_permissions.clone();
            let plugin_owner_id = format!("radar_{}", plugin_name_owned);
            let ui_registry_abi = ui_registry_for_daemon;
            let plugin_tx_abi = tx_for_daemon.clone();
            let sockets_abi = active_sockets.clone();
            let alarm_tx_for_daemon_inner = alarm_tx_for_daemon.clone();

            // --- THE ENTERPRISE FIX: POINTER ABI (ZERO-COPY) ---
            radar_exports.insert("host_ipc_request", Function::new_typed_with_env(&mut store, &radar_env, move |mut env: FunctionEnvMut<RadarEnv>, req_ptr: i32, req_len: i32, res_ptr: i32, res_cap: i32| -> i32 {

                // 1. Memory abrufen
                let memory = env.data().memory.as_ref().unwrap().clone();

                // 2. Request direkt über Pointers aus dem Plugin-RAM lesen
                let mut req_bytes = vec![0u8; req_len as usize];
                {
                    let view = memory.view(&env);
                    if view.read(req_ptr as u64, &mut req_bytes).is_err() {
                        return -1;
                    }
                }

                let req_content = String::from_utf8_lossy(&req_bytes).to_string();

                let client_req = client_abi.clone();
                let allowed_perms = perms_abi.clone();
                let owner_id = plugin_owner_id.clone();
                let ui_inner = ui_registry_abi.clone();
                let tx_inner = plugin_tx_abi.clone();
                let sockets_inner = sockets_abi.clone();
                let alarm_inner = alarm_tx_for_daemon_inner.clone();

                // 3. Routing (synchrones Warten blockiert nur diesen einen Thread)
                let response_json = handle_abi.block_on(async move {
                    match serde_json::from_str::<serde_json::Value>(&req_content) {
                        Ok(req) => {
                            let module = req["module"].as_str().unwrap_or("");
                            let method = req["method"].as_str().unwrap_or("");

                            if module == "vfs" {
                                crate::radar::vfs::handle_vfs_request(&req, &client_req, &allowed_perms, &owner_id).await
                            } else if module == "network" {
                                crate::radar::network::handle_network_request(&req, &allowed_perms, tx_inner, sockets_inner).await
                            } else if module == "display" {
                                crate::radar::display::handle_display_request(&req, &allowed_perms, &owner_id.replace("radar_", ""), ui_inner).await
                            } else if module == "host" {
                                if method == "alarm" {
                                    if let Some(msg) = req["params"]["message"].as_str() {
                                        let plugin_id = owner_id.replace("radar_", "").to_uppercase();
                                        let _ = alarm_inner.try_send(format!("[{}] {}", plugin_id, msg));
                                    }
                                    r#"{"status": "success"}"#.to_string()
                                } else {
                                    r#"{"status": "error", "message": "Unknown host method"}"#.to_string()
                                }
                            } else {
                                r#"{"status": "error", "message": "Unknown IPC module"}"#.to_string()
                            }
                        },
                        Err(_) => r#"{"status": "error", "message": "Invalid IPC JSON payload"}"#.to_string()
                    }
                });

                // 4. Response prüfen und direkt in den Plugin-RAM zurückschreiben
                let res_bytes = response_json.as_bytes();
                let res_len = res_bytes.len() as i32;

                if res_len > res_cap {
                    return -res_len; // Puffer im Plugin ist zu klein!
                }

                {
                    let view = memory.view(&env);
                    if view.write(res_ptr as u64, res_bytes).is_err() {
                        return -1;
                    }
                }

                res_len // Erfolgreich: Wir geben die echte Länge zurück
            }));

            import_object.register_namespace("radar_abi", radar_exports);

            let instance = Instance::new(&mut store, &module, &import_object)?;

            // --- ENTERPRISE FIX: Memory an das RadarEnv binden! ---
            if let Ok(memory) = instance.exports.get_memory("memory") {
                radar_env.as_mut(&mut store).memory = Some(memory.clone());
            }

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
            mem_fs: mem_fs_context,
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

    pub async fn get_daemon_logs(&self, plugin_name: &str) -> Result<String> {
        if let Some(ctx) = self.active_daemons.get(plugin_name) {
            let mut content = String::new();
            // Liest die versteckte Log-Datei aus dem RAM des Daemons
            if let Ok(mut file) = ctx.mem_fs.new_open_options().read(true).open(std::path::Path::new("/workspace/daemon.log")) {
                use tokio::io::AsyncReadExt;
                let _ = file.read_to_string(&mut content).await;
            }
            if content.is_empty() {
                Ok("[No logs generated by this daemon yet]".to_string())
            } else {
                Ok(content)
            }
        } else {
            anyhow::bail!("Daemon '{}' is not currently running.", plugin_name);
        }
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
use extism::{Plugin, Manifest, Wasm, Function, ValType, UserData, Val};
use anyhow::{Result, anyhow};
use std::path::Path;
use std::fs;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex; // Tokio Mutex!
use crate::vfs::VirtualFileSystem;
use serde_json::Value;
use pytja_core::PytjaRepository;

pub struct PluginManager {
    loaded_plugins: HashMap<String, Vec<u8>>,
    plugin_dir: String,
}

impl PluginManager {
    pub fn new(plugin_dir: &str) -> Self {
        if !Path::new(plugin_dir).exists() { let _ = fs::create_dir_all(plugin_dir); }
        Self {
            loaded_plugins: HashMap::new(),
            plugin_dir: plugin_dir.to_string(),
        }
    }

    pub fn scan_and_load(&mut self) -> Result<String> {
        let mut count = 0;
        self.loaded_plugins.clear();
        for entry in fs::read_dir(&self.plugin_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                let cmd_name = path.file_stem().unwrap().to_str().unwrap().to_string();
                self.loaded_plugins.insert(cmd_name, fs::read(&path)?);
                count += 1;
            }
        }
        Ok(format!("Loaded {} plugins.", count))
    }

    pub fn has_command(&self, cmd: &str) -> bool {
        self.loaded_plugins.contains_key(cmd)
    }

    // WICHTIG: Hier kommt der "Bridge" Code
    pub fn execute(&self, cmd: &str, args: Vec<&str>, vfs_arc: Arc<Mutex<VirtualFileSystem>>) -> Result<String> {
        let wasm_bytes = self.loaded_plugins.get(cmd).ok_or(anyhow!("Plugin not found"))?;
        let manifest = Manifest::new([Wasm::data(wasm_bytes.clone())]);

        // HOST 1: PRINT (Synchron, einfach)
        let f_print = Function::new("host_print", [ValType::I64], [], UserData::new(()),
                                    move |plugin, inputs, _, _| {
                                        let msg = plugin.memory_get_val::<String>(&inputs[0])?;
                                        println!("{}", msg);
                                        Ok(())
                                    },
        );

        // HOST 2: GET FILE (Muss Async DB rufen -> Bridge nötig!)
        let vfs_clone_read = vfs_arc.clone();
        let f_get_file = Function::new("host_get_file", [ValType::I64, ValType::I64], [ValType::I64], UserData::new(()),
                                       move |plugin, inputs, outputs, _| {
                                           let filename = plugin.memory_get_val::<String>(&inputs[0])?;

                                           let result_json = tokio::runtime::Handle::current().block_on(async {
                                               let vfs = vfs_clone_read.lock().await;
                                               let full_path = vfs.resolve_path(&filename);

                                               match vfs.db().get_node(&full_path).await {
                                                   Ok(Some(mut node)) => {
                                                       node.content = vec![];
                                                       serde_json::to_string(&node).unwrap_or("{}".to_string())
                                                   },
                                                   _ => "{}".to_string()
                                               }
                                           });

                                           let bytes = result_json.as_bytes();
                                           let memory_handle = plugin.memory_alloc(bytes.len() as u64)?;
                                           let dest_slice = plugin.memory_bytes_mut(memory_handle)?;
                                           dest_slice.copy_from_slice(bytes);
                                           outputs[0] = Val::I64(memory_handle.offset() as i64);
                                           Ok(())
                                       }
        );

        // HOST 3: UPDATE (Auch Async Bridge)
        let vfs_clone_write = vfs_arc.clone();
        let f_update = Function::new("host_update_file", [ValType::I64, ValType::I64], [], UserData::new(()),
                                     move |plugin, inputs, _, _| {
                                         let filename = plugin.memory_get_val::<String>(&inputs[0])?;
                                         let json_data = plugin.memory_get_val::<String>(&inputs[1])?;

                                         tokio::runtime::Handle::current().block_on(async {
                                             let vfs = vfs_clone_write.lock().await;
                                             let full_path = vfs.resolve_path(&filename);

                                             if let Ok(Some(node)) = vfs.db().get_node(&full_path).await {
                                                 if node.owner != vfs.user_id {
                                                     println!("Security Block: Plugin tried to edit file owned by {}", node.owner);
                                                     return;
                                                 }
                                                 if let Ok(new_vals) = serde_json::from_str::<Value>(&json_data) {
                                                     let lock_pass = new_vals["lock_pass"].as_str().map(|s| s.to_string());
                                                     if lock_pass.is_some() {
                                                         let _ = vfs.db().update_metadata(&full_path, lock_pass, None).await;
                                                     }
                                                 }
                                             }
                                         });
                                         Ok(())
                                     }
        );

        let mut plugin = Plugin::new(&manifest, [f_print, f_get_file, f_update], true)?;
        let args_json = serde_json::to_string(&args)?;
        let result = plugin.call::<&str, String>("run", &args_json)?;
        Ok(result)
    }
}
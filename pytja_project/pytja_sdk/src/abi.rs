use serde::Serialize;
use serde_json::Value;

// Der Import der rohen RADAR Engine Schnittstellen
#[link(wasm_import_module = "radar_abi")]
extern "C" {
    fn host_ipc_request(req_ptr: *const u8, req_len: i32, res_ptr: *mut u8, res_cap: i32) -> i32;
    pub fn host_log_status(code: i32);
    pub fn host_heartbeat();
}

/// Die zentrale, sichere Brücke zum Host.
/// Versteckt Pointer-Arithmetik, JSON-Serialisierung und Memory-Management.
pub fn send_ipc<T: Serialize>(module: &str, method: &str, params: T) -> Result<Value, String> {
    // 1. Sichere Serialisierung
    let req = serde_json::json!({
        "module": module,
        "method": method,
        "params": params
    });

    let req_str = req.to_string();
    let req_bytes = req_str.as_bytes();

    // 2. RAM-Puffer für die Antwort des Hosts reservieren (64 KB)
    let mut res_buf = vec![0u8; 65536];

    // 3. Pointer-Übergabe (Der einzige unsafe-Block im gesamten SDK!)
    let res_len = unsafe {
        host_ipc_request(
            req_bytes.as_ptr(),
            req_bytes.len() as i32,
            res_buf.as_mut_ptr(),
            res_buf.len() as i32,
        )
    };

    if res_len < 0 {
        return Err("Fatal: IPC request failed at host memory level".to_string());
    }

    // 4. Speicher auslesen und typsicher zurückgeben
    let res_str = std::str::from_utf8(&res_buf[..res_len as usize]).unwrap_or("{}");
    let res_json: Value = serde_json::from_str(res_str).unwrap_or(serde_json::json!({}));

    if res_json["status"] == "success" {
        Ok(res_json)
    } else {
        Err(res_json["message"].as_str().unwrap_or("Unknown Host Error").to_string())
    }
}

/// Informiert den Host-Watchdog, dass dieses Plugin noch lebt (Verhindert Auto-Kill).
pub fn ping_watchdog() {
    unsafe { host_heartbeat(); }
}
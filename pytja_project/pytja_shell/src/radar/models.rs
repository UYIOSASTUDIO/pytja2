use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RadarPermission {
    #[serde(rename = "fs_read")]
    FsRead,
    #[serde(rename = "fs_write")]
    FsWrite,
    #[serde(rename = "network_tcp")]
    NetworkTcp,
    #[serde(rename = "radar_ipc")]
    RadarIpc,
    #[serde(rename = "admin")]
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<RadarPermission>,
    // THE ENTERPRISE FIX: Abwärtskompatibler Autostart-Flag
    #[serde(default)]
    pub autostart: bool,
}
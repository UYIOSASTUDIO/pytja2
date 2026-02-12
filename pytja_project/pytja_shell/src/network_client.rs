use pytja_proto::{PytjaServiceClient, PingRequest, ListRequest, FileInfo};
use pytja_proto::{CreateNodeRequest, ActionResponse};
use colored::*;
use anyhow::Result;

pub struct PytjaClient {
    // Später speichern wir hier den Client für Wiederverwendung
    url: String,
}

impl PytjaClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn check_uplink(&self) -> Result<bool> {
        println!("{}", "[*] Establishing Uplink to Pytja Core...".yellow());

        // Verbindung aufbauen (Lazy: Er verbindet erst beim ersten Request richtig)
        // Wir müssen die URL parsen, tonic braucht "http://" davor
        let dst = format!("http://{}", self.url);

        // Timeout wäre hier gut, aber für den Anfang reicht connect
        let mut client: PytjaServiceClient<tonic::transport::Channel> = match PytjaServiceClient::connect(dst).await {
            Ok(c) => c,
            Err(e) => {
                println!(" [!] Connection Failed: {}", e.to_string().red());
                return Ok(false);
            }
        };

        // Den Ping-Befehl senden (definiert in pytja.proto)
        let request = tonic::Request::new(PingRequest {
            message: "Shell Uplink Request".into(),
        });

        match client.ping(request).await {
            Ok(response) => {
                let resp = response.into_inner();
                println!(" [+] Uplink Established: {}", "SECURE".green().bold());
                println!("     Server: {}", resp.server_version.cyan());
                println!("     Message: {}", resp.message.dimmed());
                Ok(true)
            },
            Err(status) => {
                println!(" [!] Server Error: {}", status.message().red());
                Ok(false)
            }
        }
    }

    pub async fn list_files(&self, path: &str) -> Result<Vec<FileInfo>> {
        let dst = format!("http://{}", self.url);
        let mut client = PytjaServiceClient::connect(dst).await?;

        let request = tonic::Request::new(ListRequest {
            path: path.to_string(),
            auth_token: "TODO_SECURE_TOKEN".to_string(),
        });

        let response = client.list_directory(request).await?;
        Ok(response.into_inner().files)
    }

    pub async fn create_node(&self, path: &str, is_folder: bool, content: Vec<u8>, lock_pass: Option<String>, owner: &str) -> Result<String> {
        let dst = format!("http://{}", self.url);
        let mut client = PytjaServiceClient::connect(dst).await?;

        let request = tonic::Request::new(CreateNodeRequest {
            path: path.to_string(),
            is_folder,
            content,
            lock_password: lock_pass.unwrap_or_default(), // Option -> String
            owner: owner.to_string(),
        });

        let response = client.create_node(request).await?.into_inner();

        if response.success {
            Ok(response.message)
        } else {
            // Wir geben den Fehlertext vom Server als Error zurück
            Err(anyhow::anyhow!(response.message))
        }
    }
}
use pytja_proto::{PytjaServiceClient, PingRequest, ListRequest, FileInfo};
use pytja_proto::{CreateNodeRequest, ActionResponse,
                  ReadFileRequest, DeleteNodeRequest, MoveNodeRequest,
                  CopyNodeRequest, ChangeModeRequest,
                  ChownRequest, LockRequest, UsageRequest,
                  FindRequest, GrepRequest,
                  StatRequest, TreeRequest,
                  UploadRequest, FileMetadata, DownloadRequest, ExecRequest
};
use colored::*;
use anyhow::Result;
use pytja_proto::pytja::upload_request::Data;
use futures_util::StreamExt;

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

    pub async fn read_file(&self, path: &str, password: Option<String>) -> Result<(Vec<u8>, String)> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.read_file(ReadFileRequest {
            path: path.to_string(),
            password: password.unwrap_or_default(),
        }).await?.into_inner();

        if resp.success {
            Ok((resp.content, resp.message))
        } else {
            Err(anyhow::anyhow!(resp.message))
        }
    }

    pub async fn delete_node(&self, path: &str) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.delete_node(DeleteNodeRequest { path: path.to_string() }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn move_node(&self, src: &str, dst: &str) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.move_node(MoveNodeRequest { source_path: src.to_string(), dest_path: dst.to_string() }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn copy_node(&self, src: &str, dst: &str, owner: &str) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.copy_node(CopyNodeRequest {
            source_path: src.to_string(),
            dest_path: dst.to_string(),
            owner: owner.to_string()
        }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn change_mode(&self, path: &str, perms: u32) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.change_mode(ChangeModeRequest { path: path.to_string(), permissions: perms }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn chown_node(&self, path: &str, owner: &str) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.chown_node(ChownRequest { path: path.to_string(), new_owner: owner.to_string() }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn lock_node(&self, path: &str, password: Option<String>) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.lock_node(LockRequest {
            path: path.to_string(),
            password: password.unwrap_or_default()
        }).await?.into_inner();
        if resp.success { Ok(resp.message) } else { Err(anyhow::anyhow!(resp.message)) }
    }

    pub async fn get_usage(&self, owner: &str) -> Result<u64> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.get_usage(UsageRequest { owner: owner.to_string() }).await?.into_inner();
        Ok(resp.bytes)
    }

    pub async fn find_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.find_node(FindRequest { pattern: pattern.to_string() }).await?.into_inner();
        Ok(resp.paths)
    }

    pub async fn grep_node(&self, pattern: &str) -> Result<Vec<String>> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.grep_node(GrepRequest { pattern: pattern.to_string() }).await?.into_inner();
        Ok(resp.matches)
    }

    pub async fn stat_node(&self, path: &str) -> Result<(bool, bool, bool)> { // exists, is_folder, is_locked
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.stat_node(StatRequest { path: path.to_string() }).await?.into_inner();
        Ok((resp.exists, resp.is_folder, resp.is_locked))
    }

    pub async fn get_tree(&self) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;
        let resp = client.get_tree(TreeRequest { root_path: "/".to_string() }).await?.into_inner();
        Ok(resp.tree_output)
    }

    // UPLOAD
    pub async fn upload_file(&self, local_path: &str, remote_path: &str, lock: Option<String>, owner: &str) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;

        // 1. Datei lokal lesen (Chunked Stream wäre besser, hier MVP Load-all)
        // Wir simulieren Streaming durch Iteration über Chunks
        let content = std::fs::read(local_path)?;

        let meta = FileMetadata {
            path: remote_path.to_string(),
            lock_password: lock.unwrap_or_default(),
            owner: owner.to_string(),
            is_folder: false,
        };

        // Stream bauen: Erst Metadata, dann Chunks
        let chunk_size = 1024 * 64;
        let outbound = async_stream::stream! {
            // Paket 1: Meta
            yield UploadRequest { data: Some(Data::Metadata(meta)) };

            // Pakete 2..n: Content
            for chunk in content.chunks(chunk_size) {
                yield UploadRequest { data: Some(Data::Chunk(chunk.to_vec())) };
            }
        };

        let response = client.upload_file(outbound).await?.into_inner();
        if response.success { Ok(response.message) } else { Err(anyhow::anyhow!(response.message)) }
    }

    // DOWNLOAD
    pub async fn download_file(&self, remote_path: &str, local_path: &str, password: Option<String>) -> Result<String> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;

        let request = DownloadRequest {
            path: remote_path.to_string(),
            password: password.unwrap_or_default(),
        };

        let mut stream = client.download_file(request).await?.into_inner();
        let mut full_content = Vec::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;
            full_content.extend(chunk.content);
        }

        std::fs::write(local_path, full_content)?;
        Ok(format!("Downloaded to {}", local_path))
    }

    // EXEC
    pub async fn exec_script(&self, path: &str) -> Result<()> {
        let mut client = PytjaServiceClient::connect(format!("http://{}", self.url)).await?;

        let request = ExecRequest {
            script_path: path.to_string(),
            args: vec![],
        };

        let mut stream = client.exec_script(request).await?.into_inner();

        println!("{}", "--- REMOTE OUTPUT START ---".cyan());
        while let Some(resp_result) = stream.next().await {
            let resp = resp_result?;
            println!("{}", resp.output_line);
        }
        println!("{}", "--- REMOTE OUTPUT END ---".cyan());
        Ok(())
    }
}
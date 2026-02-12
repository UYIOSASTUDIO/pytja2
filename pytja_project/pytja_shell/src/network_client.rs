use pytja_proto::PytjaServiceClient;
use pytja_proto::PingRequest;
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
}
// Hier importieren wir den generierten Code
pub mod pytja {
    tonic::include_proto!("pytja");
}

// Re-Exports für einfacheren Zugriff
pub use pytja::pytja_service_server::{PytjaService, PytjaServiceServer};
pub use pytja::pytja_service_client::PytjaServiceClient;
pub use pytja::{PingRequest, PingResponse, ListRequest, ListResponse, FileInfo};
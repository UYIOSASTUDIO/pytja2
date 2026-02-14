pub mod fs;
pub mod s3;

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;
use crate::error::PytjaError;
use std::sync::Arc;

// Ein generischer Stream von Bytes (für Uploads/Downloads ohne RAM-Limit)
pub type ByteStream = BoxStream<'static, Result<Bytes, PytjaError>>;

#[async_trait]
pub trait BlobStorage: Send + Sync {
    /// Speichert einen Stream von Daten und gibt eine ID (Key) zurück
    async fn put(&self, file_name: &str, stream: ByteStream) -> Result<String, PytjaError>;

    /// Liest eine Datei als Stream
    async fn get(&self, key: &str) -> Result<ByteStream, PytjaError>;

    /// Löscht eine Datei
    async fn delete(&self, key: &str) -> Result<(), PytjaError>;
}

// Factory für Storage
pub enum StorageType {
    FileSystem { base_path: String },
    S3 { bucket: String, region: String },
}
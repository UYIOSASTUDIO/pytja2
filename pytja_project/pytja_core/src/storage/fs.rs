use super::{BlobStorage, ByteStream};
use crate::error::PytjaError;
use async_trait::async_trait;
use futures::StreamExt;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt; // AsyncReadExt entfernt
use tokio_util::io::ReaderStream;
use std::path::PathBuf;
use uuid::Uuid;
use tracing::info;

pub struct FileSystemStorage {
    base_path: PathBuf,
}

impl FileSystemStorage {
    pub async fn new(path: &str) -> Result<Self, PytjaError> {
        fs::create_dir_all(path).await.map_err(|e| PytjaError::System(e.to_string()))?;
        Ok(Self { base_path: PathBuf::from(path) })
    }
}

#[async_trait]
impl BlobStorage for FileSystemStorage {
    async fn put(&self, _name: &str, mut stream: ByteStream) -> Result<String, PytjaError> {
        let blob_id = Uuid::new_v4().to_string();
        let file_path = self.base_path.join(&blob_id);

        let mut file = File::create(&file_path).await.map_err(|e| PytjaError::IoError(e))?;

        let mut total_bytes = 0;
        while let Some(chunk) = stream.next().await {
            let data = chunk?;
            total_bytes += data.len();
            file.write_all(&data).await.map_err(|e| PytjaError::IoError(e))?;
        }

        info!("Stored blob {} ({} bytes) on disk", blob_id, total_bytes);
        Ok(blob_id)
    }

    async fn get(&self, key: &str) -> Result<ByteStream, PytjaError> {
        let file_path = self.base_path.join(key);
        if !file_path.exists() { return Err(PytjaError::NotFound("Blob not found".into())); }

        let file = File::open(file_path).await.map_err(|e| PytjaError::IoError(e))?;
        let stream = ReaderStream::new(file).map(|r| r.map_err(|e| PytjaError::IoError(e)));

        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<(), PytjaError> {
        let path = self.base_path.join(key);
        if path.exists() { fs::remove_file(path).await.map_err(|e| PytjaError::IoError(e))?; }
        Ok(())
    }
}
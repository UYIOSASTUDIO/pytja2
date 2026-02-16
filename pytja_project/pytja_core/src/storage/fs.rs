use crate::storage::BlobStorage;
use crate::error::PytjaError;
use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use tokio::fs; // ASYNC FS
use tokio::io::AsyncWriteExt; // Traits für Async Write
use std::path::Path;
use bytes::Bytes;

pub struct FileSystemStorage {
    base_path: String,
}

impl FileSystemStorage {
    pub async fn new(path: &str) -> Result<Self, PytjaError> {
        fs::create_dir_all(path).await.map_err(|e| PytjaError::System(e.to_string()))?;
        Ok(Self { base_path: path.to_string() })
    }
}

#[async_trait]
impl BlobStorage for FileSystemStorage {
    async fn put(&self, path: &str, mut stream: BoxStream<'static, Result<Bytes, PytjaError>>) -> Result<String, PytjaError> {
        let full_path = Path::new(&self.base_path).join(path);

        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| PytjaError::System(e.to_string()))?;
        }

        let mut file = fs::File::create(&full_path).await.map_err(|e| PytjaError::System(e.to_string()))?;

        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            file.write_all(&chunk).await.map_err(|e| PytjaError::System(e.to_string()))?;
        }

        file.flush().await.map_err(|e| PytjaError::System(e.to_string()))?;

        Ok(path.to_string())
    }

    async fn get(&self, blob_id: &str) -> Result<BoxStream<'static, Result<Bytes, PytjaError>>, PytjaError> {
        let full_path = Path::new(&self.base_path).join(blob_id);

        // Datei öffnen (Async)
        let file = fs::File::open(full_path).await.map_err(|e| PytjaError::System(e.to_string()))?;

        // In Stream verwandeln (Tokio util)
        let stream = tokio_util::io::ReaderStream::new(file);

        let s = stream.map(|res| {
            res.map_err(|e| PytjaError::System(e.to_string()))
                .map(Bytes::from)
        });

        Ok(Box::pin(s))
    }

    async fn delete(&self, blob_id: &str) -> Result<(), PytjaError> {
        let full_path = Path::new(&self.base_path).join(blob_id);
        fs::remove_file(full_path).await.map_err(|e| PytjaError::System(e.to_string()))
    }
}
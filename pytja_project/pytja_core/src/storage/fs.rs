use super::{BlobStorage, ByteStream};
use crate::error::PytjaError;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use tokio::fs::{self, File};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio_util::io::ReaderStream;
use std::path::PathBuf;
use uuid::Uuid;

pub struct FileSystemStorage {
    base_path: PathBuf,
}

impl FileSystemStorage {
    pub async fn new(path: &str) -> Result<Self, PytjaError> {
        fs::create_dir_all(path).await?;
        Ok(Self {
            base_path: PathBuf::from(path),
        })
    }
}

#[async_trait]
impl BlobStorage for FileSystemStorage {
    async fn put(&self, _name: &str, mut stream: ByteStream) -> Result<String, PytjaError> {
        // Wir generieren eine zufällige ID, um Kollisionen zu vermeiden
        let blob_id = Uuid::new_v4().to_string();
        let file_path = self.base_path.join(&blob_id);

        let mut file = File::create(&file_path).await?;

        // Wir schreiben den Stream direkt auf die Platte (geringer RAM Verbrauch!)
        while let Some(chunk) = stream.next().await {
            let data = chunk?;
            file.write_all(&data).await?;
        }

        Ok(blob_id)
    }

    async fn get(&self, key: &str) -> Result<ByteStream, PytjaError> {
        let file_path = self.base_path.join(key);

        if !file_path.exists() {
            return Err(PytjaError::NotFound(format!("Blob {} not found", key)));
        }

        let file = File::open(file_path).await?;
        // Wandelt File-Reader in Stream um
        let stream = ReaderStream::new(file)
            .map_err(|e| PytjaError::IoError(e));

        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<(), PytjaError> {
        let file_path = self.base_path.join(key);
        if file_path.exists() {
            fs::remove_file(file_path).await?;
        }
        Ok(())
    }
}
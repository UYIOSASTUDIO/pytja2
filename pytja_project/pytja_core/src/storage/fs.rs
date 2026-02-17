use crate::storage::BlobStorage;
use crate::error::PytjaError;
use async_trait::async_trait;
use futures::stream::{BoxStream, StreamExt};
use tokio::fs;
use tokio::io::AsyncWriteExt;
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

    // Helper: Macht Pfade sicher (entfernt /, ./, ..)
    fn sanitize_path(&self, path: &str) -> Result<std::path::PathBuf, PytjaError> {
        let clean_path = path
            .trim_start_matches('/')
            .trim_start_matches("./")
            .trim_start_matches('\\'); // Windows support

        if clean_path.is_empty() {
            return Err(PytjaError::System("Invalid Path: Filename is empty".into()));
        }

        // Verhindert Directory Traversal (einfache Prüfung)
        if clean_path.contains("..") {
            return Err(PytjaError::System("Invalid Path: Directory traversal detected".into()));
        }

        Ok(Path::new(&self.base_path).join(clean_path))
    }
}

#[async_trait]
impl BlobStorage for FileSystemStorage {
    async fn put(&self, path: &str, mut stream: BoxStream<'static, Result<Bytes, PytjaError>>) -> Result<String, PytjaError> {
        // 1. Pfad sichern
        let full_path = self.sanitize_path(path)?;

        // 2. Ordner erstellen
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| PytjaError::System(e.to_string()))?;
        }

        // 3. Datei schreiben (Verhindert "Is a directory" Fehler, da wir create nutzen)
        let mut file = fs::File::create(&full_path).await.map_err(|e| PytjaError::System(e.to_string()))?;

        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            file.write_all(&chunk).await.map_err(|e| PytjaError::System(e.to_string()))?;
        }

        file.flush().await.map_err(|e| PytjaError::System(e.to_string()))?;

        // Wir geben den gesäuberten relativen Pfad zurück (wichtig für DB!)
        let relative_path = full_path.strip_prefix(&self.base_path)
            .unwrap_or(&full_path)
            .to_string_lossy()
            .to_string();

        Ok(relative_path)
    }

    async fn get(&self, blob_id: &str) -> Result<BoxStream<'static, Result<Bytes, PytjaError>>, PytjaError> {
        // 1. Pfad sichern
        let full_path = self.sanitize_path(blob_id)?;

        // Check ob es ein Verzeichnis ist (verhindert os error 21)
        if full_path.is_dir() {
            return Err(PytjaError::System("Storage Error: Target is a directory".into()));
        }

        // 2. Datei öffnen
        let file = fs::File::open(full_path).await.map_err(|e| PytjaError::System(e.to_string()))?;

        let stream = tokio_util::io::ReaderStream::new(file);
        let s = stream.map(|res| {
            res.map_err(|e| PytjaError::System(e.to_string()))
                .map(Bytes::from)
        });

        Ok(Box::pin(s))
    }

    async fn delete(&self, blob_id: &str) -> Result<(), PytjaError> {
        let full_path = self.sanitize_path(blob_id)?;
        if full_path.exists() {
            fs::remove_file(full_path).await.map_err(|e| PytjaError::System(e.to_string()))?;
        }
        Ok(())
    }
}
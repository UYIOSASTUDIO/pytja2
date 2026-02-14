use super::{BlobStorage, ByteStream};
use crate::error::PytjaError;
use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream as S3ByteStream;
use bytes::Bytes;
use futures::TryStreamExt;
use uuid::Uuid;

pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    pub async fn new(bucket: &str, _region: &str) -> Self {
        // Lädt Credentials automatisch aus Environment (AWS_ACCESS_KEY_ID etc.)
        let config = aws_config::load_from_env().await;
        let client = Client::new(&config);

        Self {
            client,
            bucket: bucket.to_string(),
        }
    }
}

#[async_trait]
impl BlobStorage for S3Storage {
    async fn put(&self, _name: &str, stream: ByteStream) -> Result<String, PytjaError> {
        let blob_id = Uuid::new_v4().to_string();

        // AWS SDK erwartet ein eigenes Body Format. Wir müssen unseren Stream konvertieren.
        // Hinweis: S3 PutObject braucht oft die Länge im Voraus oder Multipart Upload.
        // Für dieses Beispiel laden wir den Stream in den Speicher (Buffer),
        // für echte Big-Data wäre "Multipart Upload" der nächste Schritt.

        // Simpler Ansatz (Memory Buffer):
        let body_bytes = stream.try_collect::<Vec<Bytes>>().await?
            .concat(); // Das ist noch nicht 100% Streaming, aber S3 SDK ist tricky.

        let body = S3ByteStream::from(body_bytes);

        self.client.put_object()
            .bucket(&self.bucket)
            .key(&blob_id)
            .body(body)
            .send()
            .await
            .map_err(|e| PytjaError::System(format!("S3 Upload Error: {}", e)))?;

        Ok(blob_id)
    }

    async fn get(&self, key: &str) -> Result<ByteStream, PytjaError> {
        let resp = self.client.get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| PytjaError::NotFound(format!("S3 Download Error: {}", e)))?;

        // Der S3 Stream muss in unseren generischen Stream gewandelt werden
        let stream = resp.body
            .map_err(|e| PytjaError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)));

        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<(), PytjaError> {
        self.client.delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| PytjaError::System(format!("S3 Delete Error: {}", e)))?;
        Ok(())
    }
}
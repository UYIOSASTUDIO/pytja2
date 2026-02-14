use super::{BlobStorage, ByteStream};
use crate::error::PytjaError;
use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream as S3ByteStream;
use bytes::Bytes;
use futures::TryStreamExt;
use uuid::Uuid;
use tracing::info;
use tokio_util::io::ReaderStream;

pub struct S3Storage {
    client: Client,
    bucket: String,
}

impl S3Storage {
    pub async fn new(bucket: &str, _region: &str) -> Self {
        // FIX: Neue AWS Config Syntax (BehaviorVersion::latest)
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = Client::new(&config);
        Self { client, bucket: bucket.to_string() }
    }
}

#[async_trait]
impl BlobStorage for S3Storage {
    async fn put(&self, _name: &str, stream: ByteStream) -> Result<String, PytjaError> {
        let blob_id = Uuid::new_v4().to_string();

        let body_bytes = stream.try_collect::<Vec<Bytes>>().await
            .map_err(|e| PytjaError::System(format!("Stream error: {}", e)))?
            .concat();

        let body = S3ByteStream::from(body_bytes);

        self.client.put_object()
            .bucket(&self.bucket)
            .key(&blob_id)
            .body(body)
            .send()
            .await
            .map_err(|e| PytjaError::System(format!("S3 Upload Error: {}", e)))?;

        info!("Stored blob {} on S3", blob_id);
        Ok(blob_id)
    }

    async fn get(&self, key: &str) -> Result<ByteStream, PytjaError> {
        let resp = self.client.get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| PytjaError::NotFound(format!("S3 Download Error: {}", e)))?;

        let reader = resp.body.into_async_read();
        let stream = ReaderStream::new(reader)
            .map_err(|e| PytjaError::IoError(e));

        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<(), PytjaError> {
        self.client.delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| PytjaError::System(e.to_string()))?;
        Ok(())
    }
}
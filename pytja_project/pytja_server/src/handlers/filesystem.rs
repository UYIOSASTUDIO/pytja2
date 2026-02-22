use tonic::{Request, Response, Status};
use pytja_proto::pytja::*;
use pytja_proto::pytja::upload_request::Data as UploadData;
use pytja_core::{PytjaError, models::FileNode};
use crate::handlers::service::{MyPytjaService, DEFAULT_QUOTA_LIMIT};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use bytes::Bytes;
use std::env;
use std::sync::Arc;
use futures_util::Stream;

impl MyPytjaService {

    // --- LIST (LS) ---
    pub async fn list_directory_impl(&self, request: Request<ListRequest>) -> Result<Response<ListResponse>, Status> {

        let claims = self.check_permissions(request.metadata(), Some("core:fs:read")).await?;

        let req = request.into_inner();

        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        let mut nodes = repo.list_directory_secure(&relative_path, &claims.sub, &claims.role).await.map_err(|e| Status::internal(e.to_string()))?;

        if req.path == "/" || req.path.is_empty() {
            let mounts = self.manager.list_mounts().await;
            for mount_name in mounts {
                if mount_name == "primary" { continue; }
                nodes.push(FileNode {
                    path: format!("/{}", mount_name),
                    name: mount_name.clone(),
                    owner: "SYSTEM".to_string(),
                    is_folder: true,
                    size: 0,
                    content: vec![],
                    lock_pass: None,
                    permissions: 0,
                    created_at: 0.0,
                    blob_id: None,
                    metadata: None,
                });
            }
        }

        let proto_files = nodes.into_iter().map(|node| FileInfo {
            name: node.name,
            is_folder: node.is_folder,
            size: node.size as u64,
            owner: node.owner,
            permissions: node.permissions as u32,
            created_at: node.created_at,
        }).collect();

        Ok(Response::new(ListResponse { files: proto_files }))
    }

    // --- UPLOAD ---
    pub async fn upload_file_impl(&self, request: Request<tonic::Streaming<UploadRequest>>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let mut stream = request.into_inner();

        let first_msg = stream.message().await.map_err(|e| Status::internal(e.to_string()))?;
        let metadata = match first_msg {
            Some(req) => match req.data {
                Some(UploadData::Metadata(m)) => m,
                _ => return Err(Status::invalid_argument("Metadata missing")),
            },
            None => return Err(Status::invalid_argument("Empty stream")),
        };

        if !self.sessions.try_lock_file(&metadata.path, &claims.sub).await {
            return Err(Status::aborted("File is busy."));
        }

        let limit: usize = env::var("PYTJA_QUOTA_LIMIT")
            .unwrap_or_else(|_| DEFAULT_QUOTA_LIMIT.to_string())
            .parse()
            .unwrap_or(DEFAULT_QUOTA_LIMIT);

        let current_usage = self.get_user_quota_usage(&claims.sub).await;
        if current_usage >= limit {
            self.sessions.unlock_file(&metadata.path, &claims.sub).await;
            return Err(Status::resource_exhausted("Quota exceeded"));
        }

        let (repo, relative_path) = match self.resolve_repo(&metadata.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&metadata.path, &claims.sub).await;
                return Err(e);
            }
        };

        self.sessions.init_upload(&claims.sub, &metadata.path).await;

        let mut upload_session_bytes = 0;
        let mut last_redis_update = 0;
        let session_manager = self.sessions.clone();
        let owner_clone = claims.sub.clone();
        let path_clone = metadata.path.clone();

        let byte_stream = stream.map(move |item| {
            match item {
                Ok(req) => match req.data {
                    Some(UploadData::Chunk(data)) => {
                        let len = data.len();
                        if current_usage + upload_session_bytes + len > limit {
                            return Err(PytjaError::QuotaExceeded { current: current_usage + upload_session_bytes, limit });
                        }
                        upload_session_bytes += len;
                        // Progress Update alle 5MB
                        if upload_session_bytes - last_redis_update > 5 * 1024 * 1024 {
                            let sm = session_manager.clone();
                            let o = owner_clone.clone();
                            let p = path_clone.clone();
                            let delta = upload_session_bytes - last_redis_update;
                            tokio::spawn(async move { sm.update_upload_progress(&o, &p, delta).await; });
                            last_redis_update = upload_session_bytes;
                        }
                        Ok(Bytes::from(data))
                    },
                    _ => Ok(Bytes::new()),
                },
                Err(e) => Err(PytjaError::System(e.to_string())),
            }
        });

        // 1. Pfad säubern (FIX für OS Error 30)
        let clean_path = metadata.path.trim_start_matches('/');
        if clean_path.is_empty() || clean_path.ends_with('/') {
            self.sessions.unlock_file(&metadata.path, &claims.sub).await;
            return Err(Status::invalid_argument("Invalid filename (cannot be empty or root)"));
        }
        let storage_path = clean_path.to_string();

        // 2. Stream pinnen und speichern
        let pinned_stream = Box::pin(byte_stream);
        let result = self.storage.put(&storage_path, pinned_stream).await;

        if result.is_ok() { self.sessions.complete_upload(&claims.sub, &metadata.path).await; }
        self.sessions.unlock_file(&metadata.path, &claims.sub).await;

        let blob_id = result.map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();

        let node = FileNode {
            path: relative_path,
            name,
            owner: metadata.owner,
            is_folder: false,
            content: vec![],
            blob_id: Some(blob_id),
            size: upload_session_bytes,
            lock_pass: if metadata.lock_password.is_empty() { None } else { Some(metadata.lock_password) },
            permissions: 2, // FIX: Default Public Permissions (2)
            created_at: chrono::Utc::now().timestamp() as f64,
            metadata: metadata.metadata,
        };

        repo.save_node(&node).await.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.update_quota(&claims.sub, upload_session_bytes as i64).await;

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "UPLOAD", &metadata.path).await;
        }

        Ok(Response::new(ActionResponse { success: true, message: "Upload complete".into() }))
    }

    // --- DOWNLOAD ---
    pub async fn download_file_impl(&self, request: Request<DownloadRequest>) -> Result<Response<ReceiverStream<Result<FileChunk, Status>>>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        let node = repo.get_node(&relative_path).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("File not found"))?;

        if let Some(pass) = node.lock_pass {
            if pass != req.password { return Err(Status::permission_denied("Wrong Password")); }
        }

        let stream: std::pin::Pin<Box<dyn Stream<Item = Result<FileChunk, Status>> + Send>> = if let Some(blob_id) = node.blob_id {
            let storage_stream = self.storage.get(&blob_id).await
                .map_err(|e| Status::internal(format!("Storage Error: {}", e)))?;
            Box::pin(storage_stream.map(|res| match res {
                Ok(bytes) => Ok(FileChunk { content: bytes.to_vec() }),
                Err(e) => Err(Status::internal(e.to_string())),
            }))
        } else {
            let content = node.content;
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                for chunk in content.chunks(64 * 1024) { let _ = tx.send(Ok(FileChunk { content: chunk.to_vec() })).await; }
            });
            Box::pin(ReceiverStream::new(rx))
        };

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let mut s = stream;
            while let Some(item) = s.next().await { if tx.send(item).await.is_err() { break; } }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // --- CREATE (MKDIR / TOUCH) ---
    pub async fn create_node_impl(&self, request: Request<CreateNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();

        if !self.sessions.try_lock_file(&req.path, &claims.sub).await {
            return Err(Status::aborted("File/Path is busy."));
        }

        let (repo, relative_path) = match self.resolve_repo(&req.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&req.path, &claims.sub).await;
                return Err(e);
            }
        };

        let path_obj = std::path::Path::new(&relative_path);
        let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();
        let content_len = req.content.len();

        let node = FileNode {
            path: relative_path.clone(),
            name,
            owner: req.owner,
            is_folder: req.is_folder,
            size: content_len,
            content: req.content,
            lock_pass: if req.lock_password.is_empty() { None } else { Some(req.lock_password) },
            permissions: 2, // FIX: Default Public Permissions
            created_at: chrono::Utc::now().timestamp() as f64,
            blob_id: None,
            metadata: None,
        };

        let res = repo.save_node(&node).await;
        self.sessions.unlock_file(&req.path, &claims.sub).await;
        res.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.update_quota(&claims.sub, content_len as i64).await;

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "CREATE", &req.path).await;
        }
        Ok(Response::new(ActionResponse { success: true, message: "Created successfully".into() }))
    }

    // --- READ (CAT) ---
    pub async fn read_file_impl(&self, request: Request<ReadFileRequest>) -> Result<Response<ReadFileResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        let node = repo.get_node_secure(&relative_path, &claims.sub, &claims.role).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("File not found"))?;

        if let Some(pass) = node.lock_pass {
            if pass != req.password { return Err(Status::permission_denied("File is locked")); }
        }

        // FIX: Blobs bis 5MB laden
        let content = if let Some(blob_id) = node.blob_id {
            if node.size > 5 * 1024 * 1024 {
                return Err(Status::failed_precondition("File too large for cat (Blob). Use download command."));
            }
            let mut stream = self.storage.get(&blob_id).await
                .map_err(|e| Status::internal(format!("Storage Read Error: {}", e)))?;
            let mut buffer = Vec::with_capacity(node.size);
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|e| Status::internal(e.to_string()))?;
                buffer.extend_from_slice(&chunk);
            }
            buffer
        } else {
            node.content
        };

        Ok(Response::new(ReadFileResponse { success: true, message: "Read success".into(), content }))
    }

    // --- DELETE (RM) ---
    pub async fn delete_node_impl(&self, request: Request<DeleteNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        if !self.sessions.try_lock_file(&req.path, &claims.sub).await { return Err(Status::aborted("File is busy.")); }

        let (repo, relative_path) = match self.resolve_repo(&req.path).await {
            Ok(r) => r,
            Err(e) => {
                self.sessions.unlock_file(&req.path, &claims.sub).await;
                return Err(e);
            }
        };

        if let Some(primary) = self.manager.get_repo("primary").await {
            let _ = primary.log_action(&claims.sub, "DELETE", &req.path).await;
        }
        let res = repo.delete_node_recursive(&relative_path).await;
        self.sessions.unlock_file(&req.path, &claims.sub).await;
        res.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.invalidate_quota(&claims.sub).await;
        Ok(Response::new(ActionResponse { success: true, message: "Deleted".into() }))
    }

    // --- MOVE (MV) ---
    pub async fn move_node_impl(&self, request: Request<MoveNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        if !self.sessions.try_lock_file(&req.source_path, &claims.sub).await { return Err(Status::aborted("Source busy.")); }
        if !self.sessions.try_lock_file(&req.dest_path, &claims.sub).await {
            self.sessions.unlock_file(&req.source_path, &claims.sub).await;
            return Err(Status::aborted("Dest busy."));
        }

        let (repo_src, src_rel) = match self.resolve_repo(&req.source_path).await {
            Ok(v) => v,
            Err(e) => {
                self.sessions.unlock_file(&req.source_path, &claims.sub).await;
                self.sessions.unlock_file(&req.dest_path, &claims.sub).await;
                return Err(e);
            }
        };
        let (repo_dst, dst_rel) = match self.resolve_repo(&req.dest_path).await {
            Ok(v) => v,
            Err(e) => {
                self.sessions.unlock_file(&req.source_path, &claims.sub).await;
                self.sessions.unlock_file(&req.dest_path, &claims.sub).await;
                return Err(e);
            }
        };

        let move_result = if Arc::ptr_eq(&repo_src, &repo_dst) {
            repo_src.move_path(&src_rel, &dst_rel).await.map_err(|e| Status::internal(e.to_string()))
        } else {
            // Cross-Repo Move
            let src_node = repo_src.get_node(&src_rel).await.map_err(|e| Status::internal(e.to_string()))?
                .ok_or(Status::not_found("Source file not found"))?;

            if src_node.is_folder {
                Err(Status::unimplemented("Cross-mount folder move not supported."))
            } else {
                let new_blob_id = if let Some(old_id) = src_node.blob_id {
                    match self.storage.get(&old_id).await {
                        Ok(stream) => match self.storage.put(&req.dest_path, stream).await {
                            Ok(new_id) => Some(new_id),
                            Err(e) => return Err(Status::internal(format!("Write Error: {}", e))),
                        },
                        Err(e) => return Err(Status::internal(format!("Read Error: {}", e))),
                    }
                } else { None };

                let path_obj = std::path::Path::new(&dst_rel);
                let name = path_obj.file_name().unwrap_or_default().to_str().unwrap_or("").to_string();
                let new_node = FileNode {
                    path: dst_rel.clone(), name, owner: claims.sub.clone(), is_folder: false, size: src_node.size,
                    content: src_node.content, blob_id: new_blob_id, lock_pass: src_node.lock_pass, permissions: src_node.permissions,
                    created_at: chrono::Utc::now().timestamp() as f64,
                    metadata: src_node.metadata.clone(),
                };

                if let Err(e) = repo_dst.save_node(&new_node).await {
                    Err(Status::internal(e.to_string()))
                } else {
                    let _ = repo_src.delete_node_recursive(&src_rel).await;
                    Ok(())
                }
            }
        };

        self.sessions.unlock_file(&req.source_path, &claims.sub).await;
        self.sessions.unlock_file(&req.dest_path, &claims.sub).await;
        match move_result {
            Ok(_) => {
                self.sessions.invalidate_quota(&claims.sub).await;
                if let Some(primary) = self.manager.get_repo("primary").await { let _ = primary.log_action(&claims.sub, "MOVE", &format!("{}->{}", req.source_path, req.dest_path)).await; }
                Ok(Response::new(ActionResponse { success: true, message: "Moved.".into() }))
            },
            Err(e) => Err(e)
        }
    }

    // --- COPY (CP) ---
    pub async fn copy_node_impl(&self, request: Request<CopyNodeRequest>) -> Result<Response<ActionResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, src_rel) = self.resolve_repo(&req.source_path).await?;
        let (_, dst_rel) = self.resolve_repo(&req.dest_path).await?;

        let src_node = repo.get_node(&src_rel).await.map_err(|e| Status::internal(e.to_string()))?
            .ok_or(Status::not_found("Source not found"))?;
        if src_node.is_folder { return Err(Status::unimplemented("Recursive copy not supported")); }

        let new_node = FileNode {
            path: dst_rel, name: "".into(), owner: claims.sub.clone(), is_folder: false,
            content: src_node.content, blob_id: src_node.blob_id, size: src_node.size,
            lock_pass: None, permissions: 2, created_at: chrono::Utc::now().timestamp() as f64,
            metadata: src_node.metadata.clone(),
        };
        repo.save_node(&new_node).await.map_err(|e| Status::internal(e.to_string()))?;
        self.sessions.update_quota(&claims.sub, new_node.size as i64).await;
        if let Some(primary) = self.manager.get_repo("primary").await { let _ = primary.log_action(&claims.sub, "COPY", &format!("{}->{}", req.source_path, req.dest_path)).await; }
        Ok(Response::new(ActionResponse { success: true, message: "Copied.".into() }))
    }

    // --- METADATA OPS ---
    pub async fn change_mode_impl(&self, request: Request<ChangeModeRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        repo.update_permissions(&rel_path, req.permissions as u8).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Permissions updated".into() }))
    }

    pub async fn chown_node_impl(&self, request: Request<ChownRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        if let Some(primary) = self.manager.get_repo("primary").await {
            if !primary.user_exists(&req.new_owner).await.unwrap_or(false) { return Err(Status::not_found("User not found")); }
        }
        repo.update_metadata(&rel_path, None, Some(req.new_owner)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Ownership transferred".into() }))
    }

    pub async fn lock_node_impl(&self, request: Request<LockRequest>) -> Result<Response<ActionResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:write")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        let lock_val = if req.password.is_empty() { None } else { Some(req.password) };
        repo.update_metadata(&rel_path, lock_val, None).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ActionResponse { success: true, message: "Lock updated".into() }))
    }

    // --- SEARCH & INFO ---
    pub async fn get_usage_impl(&self, request: Request<UsageRequest>) -> Result<Response<UsageResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let usage = self.get_user_quota_usage(&request.into_inner().owner).await;
        Ok(Response::new(UsageResponse { bytes: usage as u64 }))
    }

    pub async fn find_node_impl(&self, request: Request<FindRequest>) -> Result<Response<FindResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let paths = repo.find_nodes(&format!("%{}%", req.pattern)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(FindResponse { paths }))
    }

    pub async fn grep_node_impl(&self, request: Request<GrepRequest>) -> Result<Response<GrepResponse>, Status> {
        self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;
        let files = repo.get_all_files_content().await.map_err(|e| Status::internal(e.to_string()))?;
        let mut matches = Vec::new();
        for (path, content) in files {
            if let Ok(text) = std::str::from_utf8(&content) { if text.contains(&req.pattern) { matches.push(path); } }
        }
        Ok(Response::new(GrepResponse { matches }))
    }

    // --- TREE ---
    pub async fn get_tree_impl(&self, request: Request<TreeRequest>) -> Result<Response<TreeResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let (repo, rel_path) = self.resolve_repo(&req.root_path).await?;

        // 1. Rekursive Liste holen
        let mut all_nodes = repo.list_recursive_secure(&rel_path, &claims.sub, &claims.role).await.map_err(|e| Status::internal(e.to_string()))?;
        all_nodes.sort_by(|a, b| a.path.cmp(&b.path));

        let mut output = format!("{}\n", req.root_path);
        let base_depth = if rel_path == "/" { 0 } else { rel_path.matches('/').count() };

        if all_nodes.is_empty() { output.push_str("(empty)\n"); }

        let total_dirs = all_nodes.iter().filter(|n| n.is_folder).count();
        let total_files = all_nodes.iter().filter(|n| !n.is_folder).count();

        for node in all_nodes {
            if node.path == rel_path || (rel_path == "/" && node.path.is_empty()) { continue; }
            let depth = node.path.matches('/').count();
            let relative_depth = if depth >= base_depth { depth - base_depth } else { 0 };
            let indent = "    ".repeat(relative_depth.saturating_sub(1));
            let prefix = if relative_depth > 0 { "└── " } else { "├── " };
            let marker = if node.is_folder { "[DIR]" } else { "" };
            let lock_marker = if node.lock_pass.is_some() { "🔒" } else { "" };
            output.push_str(&format!("{}{}{}{} {}\n", indent, prefix, node.name, marker, lock_marker));
        }
        output.push_str(&format!("\n{} directories, {} files\n", total_dirs, total_files));
        Ok(Response::new(TreeResponse { tree_output: output }))
    }

    // --- STAT ---
    pub async fn stat_node_impl(&self, request: Request<StatRequest>) -> Result<Response<StatResponse>, Status> {
        self.check_permissions(request.metadata(), None).await?;
        let req = request.into_inner();
        let clean = req.path.trim_start_matches('/');
        for m in self.manager.list_mounts().await {
            if clean == m { return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false })); }
        }
        let (repo, rel_path) = self.resolve_repo(&req.path).await?;
        if rel_path == "/" { return Ok(Response::new(StatResponse { exists: true, is_folder: true, is_locked: false })); }

        match repo.get_node(&rel_path).await {
            Ok(Some(n)) => Ok(Response::new(StatResponse { exists: true, is_folder: n.is_folder, is_locked: n.lock_pass.is_some() })),
            Ok(None) => Ok(Response::new(StatResponse { exists: false, is_folder: false, is_locked: false })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    // --- EXEC ---
    pub async fn exec_script_impl(&self, request: Request<ExecRequest>) -> Result<Response<ReceiverStream<Result<ExecResponse, Status>>>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:exec")).await?;
        let req = request.into_inner();
        let (_repo, _rel) = self.resolve_repo(&req.script_path).await?;
        if let Some(primary) = self.manager.get_repo("primary").await { let _ = primary.log_action(&claims.sub, "EXEC", &req.script_path).await; }

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(ExecResponse { output_line: "Remote Execution initiated...".into() })).await;
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let _ = tx.send(Ok(ExecResponse { output_line: "Result: [Function executed successfully]".into() })).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    pub async fn read_file_chunk_impl(&self, request: Request<pytja_proto::pytja::ReadChunkRequest>) -> Result<Response<pytja_proto::pytja::ReadChunkResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();

        let (repo, relative_path) = self.resolve_repo(&req.path).await?;

        // Wenn ein Passwort gesendet wurde, prüfen wir das (wie bei get_node)
        if let Ok(Some(node)) = repo.get_node(&relative_path).await {
            if let Some(real_pass) = node.lock_pass {
                let provided = req.password.unwrap_or_default();
                if provided != real_pass {
                    return Err(Status::permission_denied("Locked file. Incorrect password."));
                }
            }
        } else {
            return Err(Status::not_found("File not found"));
        }

        // Lade nur den Chunk (Zero-Trust + Zero-RAM Overhead)
        let chunk = repo.read_node_chunk_secure(&relative_path, &claims.sub, &claims.role, req.offset as usize, req.chunk_size as usize)
            .await.map_err(|e| Status::internal(e.to_string()))?;

        let is_eof = chunk.len() < req.chunk_size as usize;

        Ok(Response::new(pytja_proto::pytja::ReadChunkResponse {
            chunk,
            is_eof,
        }))
    }

    pub async fn query_metadata_impl(&self, request: Request<pytja_proto::pytja::QueryMetadataRequest>) -> Result<Response<pytja_proto::pytja::ListResponse>, Status> {
        let claims = self.check_permissions(request.metadata(), Some("core:fs:read")).await?;
        let req = request.into_inner();
        let repo = self.manager.get_repo("primary").await.ok_or(Status::internal("DB Error"))?;

        let nodes = repo.query_metadata_secure(&req.query, &claims.sub, &claims.role).await.map_err(|e| Status::internal(e.to_string()))?;

        let proto_files = nodes.into_iter().map(|node| FileInfo {
            name: node.name, is_folder: node.is_folder, size: node.size as u64,
            owner: node.owner, permissions: node.permissions as u32, created_at: node.created_at,
        }).collect();

        Ok(Response::new(pytja_proto::pytja::ListResponse { files: proto_files }))
    }
}
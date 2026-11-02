//! Object bytes: single-request put/get, multipart uploads and downloads, and the file and
//! directory helpers built on them.

use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::model::*;
use super::Esm;
use crate::http::Response;
use crate::service::CallOptions;
use crate::{Error, Result};

/// Attempts per part (and per create/complete call) before giving up.
const MAX_PART_ATTEMPTS: u32 = 4;
/// Back-off between attempts, multiplied by the attempt number.
const PART_RETRY_BASE_DELAY: Duration = Duration::from_millis(500);
/// `get-object`'s answer for an object too large to come back inline.
const PAYLOAD_TOO_LARGE: u16 = 413;
const OCTET_STREAM: &str = "application/octet-stream";

impl Esm {
    /// Options for a request carrying object bytes: bearer token, octet-stream, transfer timeout.
    fn binary_options(&self, headers: Vec<(String, String)>) -> CallOptions {
        CallOptions {
            timeout: Some(self.transfer_timeout),
            bearer_only: true,
            content_type: Some(OCTET_STREAM),
            headers,
        }
    }

    /// Sends a request, retrying a 5xx answer or a failed connection up to
    /// [`MAX_PART_ATTEMPTS`] times with linear back-off. A 4xx is the request itself being wrong
    /// and is not retried. Returns the successful response, or the last failure.
    async fn send_with_retry<F, Fut>(&self, action: &str, mut attempt: F) -> Result<Response>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Response>>,
    {
        for n in 1..=MAX_PART_ATTEMPTS {
            let last = n == MAX_PART_ATTEMPTS;
            match attempt().await {
                Ok(response) if response.is_success() => return Ok(response),
                Ok(response) if response.status < 500 || last => {
                    return Err(Error::service("esm", action, response.status, response.text()))
                }
                Ok(_) => {}
                Err(e @ Error::Http(_)) if !last => drop(e),
                Err(e) => return Err(e),
            }
            tokio::time::sleep(PART_RETRY_BASE_DELAY * n).await;
        }
        unreachable!("the last attempt always returns")
    }

    /// A signed JSON call retried like a part: used for the create/complete calls of a transfer,
    /// where failing would throw away every part already moved.
    async fn json_with_retry(
        &self,
        action: &str,
        body: &serde_json::Value,
        headers: Vec<(String, String)>,
    ) -> Result<Response> {
        let body = serde_json::to_vec(body)?;
        let options = CallOptions {
            headers,
            ..Default::default()
        };
        self.send_with_retry(action, || self.client.send(action, body.clone(), &options))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Single-request objects
    // -----------------------------------------------------------------------------------------

    /// Writes an object in a single request. Fine for small objects; use
    /// [`upload_file`](Self::upload_file) for large ones.
    pub async fn put_object(
        &self,
        bucket_ern: &str,
        key: &str,
        data: impl Into<Vec<u8>>,
    ) -> Result<CompleteUploadResponse> {
        self.put_object_with(bucket_ern, key, data, &Attributes::new(), &Attributes::new())
            .await
    }

    /// [`put_object`](Self::put_object) with attributes, sent as `x-euclid-attributes` and
    /// `x-euclid-system-attributes`.
    pub async fn put_object_with(
        &self,
        bucket_ern: &str,
        key: &str,
        data: impl Into<Vec<u8>>,
        attributes: &Attributes,
        system_attributes: &Attributes,
    ) -> Result<CompleteUploadResponse> {
        let mut headers = vec![
            ("x-euclid-bucket-ern".to_owned(), bucket_ern.to_owned()),
            ("x-euclid-key".to_owned(), key.to_owned()),
        ];
        push_attribute_headers(&mut headers, attributes, system_attributes)?;
        let response = self
            .client
            .send_ok("put-object", data.into(), &self.binary_options(headers))
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Reads an object whole. The server answers 413 (as [`Error::Service`]) for an object larger
    /// than `max_inline_size`; [`download_file`](Self::download_file) handles that case.
    pub async fn get_object(&self, bucket_ern: &str, key: &str, max_inline_size: u64) -> Result<Vec<u8>> {
        let response = self.get_object_response(bucket_ern, key, max_inline_size).await?;
        if !response.is_success() {
            return Err(Error::service("esm", "get-object", response.status, response.text()));
        }
        Ok(response.body)
    }

    async fn get_object_response(&self, bucket_ern: &str, key: &str, max_inline_size: u64) -> Result<Response> {
        let headers = vec![
            ("x-euclid-bucket-ern".to_owned(), bucket_ern.to_owned()),
            ("x-euclid-key".to_owned(), key.to_owned()),
            ("x-euclid-part-size".to_owned(), max_inline_size.to_string()),
        ];
        self.client
            .send("get-object", Vec::new(), &self.binary_options(headers))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Multipart upload
    // -----------------------------------------------------------------------------------------

    /// Starts a multipart upload. `expected_concurrency` is sent as
    /// `x-euclid-expected-concurrency` so the gateway can scale storage toward it. Retried on 5xx:
    /// the object row the server seeds is upserted on bucket and key.
    pub async fn create_upload(
        &self,
        bucket_ern: &str,
        key: &str,
        expected_concurrency: usize,
    ) -> Result<CreateUploadResponse> {
        let headers = vec![(
            "x-euclid-expected-concurrency".to_owned(),
            expected_concurrency.to_string(),
        )];
        let response = self
            .json_with_retry(
                "create-upload",
                &json!({ "bucketErn": bucket_ern, "key": key }),
                headers,
            )
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Uploads one part (numbered from 1) as a raw body with the bearer token. Retried on 5xx and
    /// on a failed connection.
    pub async fn upload_part(&self, upload_id: &str, part_number: u64, data: Vec<u8>) -> Result<()> {
        let headers = vec![
            ("x-euclid-upload-id".to_owned(), upload_id.to_owned()),
            ("x-euclid-part-number".to_owned(), part_number.to_string()),
        ];
        let options = self.binary_options(headers);
        self.send_with_retry("upload-part", || {
            self.client.send("upload-part", data.clone(), &options)
        })
        .await
        .map(|_| ())
    }

    /// Assembles the uploaded parts into the object. Attributes must travel here rather than be
    /// set afterwards: the object row the server's assembly pass writes is built from this call,
    /// and replaces any attribute added in the meantime.
    pub async fn complete_upload(
        &self,
        upload_id: &str,
        attributes: &Attributes,
        system_attributes: &Attributes,
    ) -> Result<CompleteUploadResponse> {
        let mut headers = Vec::new();
        push_attribute_headers(&mut headers, attributes, system_attributes)?;
        let response = self
            .json_with_retry("complete-upload", &json!({ "uploadId": upload_id }), headers)
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Abandons a multipart upload and its staged parts.
    pub async fn abort_upload(&self, upload_id: &str) -> Result<AbortUploadResponse> {
        self.client
            .call("abort-upload", &json!({ "uploadId": upload_id }))
            .await
    }

    // -----------------------------------------------------------------------------------------
    // Multipart download
    // -----------------------------------------------------------------------------------------

    /// Opens a multipart download session; the answer carries the object's size.
    pub async fn create_download(
        &self,
        bucket_ern: &str,
        key: &str,
        expected_concurrency: usize,
    ) -> Result<CreateDownloadResponse> {
        let headers = vec![(
            "x-euclid-expected-concurrency".to_owned(),
            expected_concurrency.to_string(),
        )];
        let response = self
            .json_with_retry(
                "create-download",
                &json!({ "bucketErn": bucket_ern, "key": key }),
                headers,
            )
            .await?;
        Ok(serde_json::from_slice(&response.body)?)
    }

    /// Reads part `part_number` (from 1) of `part_size` bytes. Retried on 5xx and on a failed
    /// connection.
    pub async fn download_part(&self, download_id: &str, part_number: u64, part_size: usize) -> Result<Vec<u8>> {
        let headers = vec![
            ("x-euclid-download-id".to_owned(), download_id.to_owned()),
            ("x-euclid-part-number".to_owned(), part_number.to_string()),
            ("x-euclid-part-size".to_owned(), part_size.to_string()),
        ];
        let options = self.binary_options(headers);
        self.send_with_retry("download-part", || {
            self.client.send("download-part", Vec::new(), &options)
        })
        .await
        .map(|r| r.body)
    }

    /// Releases a download session's server-side state.
    pub async fn complete_download(&self, download_id: &str) -> Result<()> {
        self.json_with_retry("complete-download", &json!({ "downloadId": download_id }), Vec::new())
            .await
            .map(|_| ())
    }

    // -----------------------------------------------------------------------------------------
    // Files and directories
    // -----------------------------------------------------------------------------------------

    /// Uploads a file. One smaller than `options.part_size` goes up whole in a single
    /// `put-object`; a larger one as a multipart upload with up to `options.concurrency` parts in
    /// flight, read from disk only as fast as parts go out. If a part fails for good, the upload
    /// is aborted and the error returned.
    pub async fn upload_file(
        &self,
        bucket_ern: &str,
        key: &str,
        file: impl AsRef<Path>,
        options: &TransferOptions,
    ) -> Result<CompleteUploadResponse> {
        let file = file.as_ref();
        let part_size = options.part_size.max(1);
        let concurrency = options.concurrency.max(1);

        if tokio::fs::metadata(file).await?.len() < part_size as u64 {
            let data = tokio::fs::read(file).await?;
            return self
                .put_object_with(bucket_ern, key, data, &options.attributes, &options.system_attributes)
                .await;
        }

        let upload_id = self
            .create_upload(bucket_ern, key, concurrency)
            .await?
            .upload_id
            .unwrap_or_default();

        let handle = tokio::fs::File::open(file).await?;
        let parts = stream::try_unfold((handle, 1u64), move |(mut handle, number)| async move {
            let mut buffer = Vec::with_capacity(part_size);
            (&mut handle).take(part_size as u64).read_to_end(&mut buffer).await?;
            if buffer.is_empty() {
                return Ok::<_, Error>(None);
            }
            Ok(Some(((number, buffer), (handle, number + 1))))
        });
        let uploaded = parts
            .map_ok(|(number, data)| self.upload_part(&upload_id, number, data))
            .try_buffer_unordered(concurrency)
            .try_collect::<Vec<()>>()
            .await;
        if let Err(e) = uploaded {
            let _ = self.abort_upload(&upload_id).await;
            return Err(e);
        }

        self.complete_upload(&upload_id, &options.attributes, &options.system_attributes)
            .await
    }

    /// Downloads an object to a file, creating its directory, and returns the bytes written. An
    /// object up to `options.part_size` comes back in one `get-object`; a larger one in parts,
    /// `options.concurrency` at a time, each written at its own offset.
    pub async fn download_file(
        &self,
        bucket_ern: &str,
        key: &str,
        file: impl AsRef<Path>,
        options: &TransferOptions,
    ) -> Result<u64> {
        let file = file.as_ref();
        let part_size = options.part_size.max(1);
        let concurrency = options.concurrency.max(1);
        if let Some(parent) = file.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }

        let inline = self.get_object_response(bucket_ern, key, part_size as u64).await?;
        if inline.status != PAYLOAD_TOO_LARGE {
            if !inline.is_success() {
                return Err(Error::service("esm", "get-object", inline.status, inline.text()));
            }
            tokio::fs::write(file, &inline.body).await?;
            return Ok(inline.body.len() as u64);
        }

        let created = self.create_download(bucket_ern, key, concurrency).await?;
        let download_id = created.download_id.unwrap_or_default();
        let total = created.size;
        // Pre-size the file so each part can be written at its offset in whatever order parts
        // finish.
        tokio::fs::File::create(file).await?.set_len(total).await?;

        let part_count = total.div_ceil(part_size as u64);
        stream::iter(1..=part_count)
            .map(|number| {
                let download_id = &download_id;
                async move {
                    let data = self.download_part(download_id, number, part_size).await?;
                    let mut out = tokio::fs::OpenOptions::new().write(true).open(file).await?;
                    out.seek(std::io::SeekFrom::Start((number - 1) * part_size as u64))
                        .await?;
                    out.write_all(&data).await?;
                    out.flush().await?;
                    Ok::<_, Error>(())
                }
            })
            .buffer_unordered(concurrency)
            .try_collect::<Vec<()>>()
            .await?;

        self.complete_download(&download_id).await?;
        Ok(total)
    }

    /// Uploads every regular file in `directory` (and below it, if `recursive`), in path order,
    /// under the key `prefix` + its path relative to `directory` with `/` separators.
    pub async fn upload_directory(
        &self,
        bucket_ern: &str,
        directory: impl AsRef<Path>,
        prefix: &str,
        recursive: bool,
        options: &TransferOptions,
    ) -> Result<Vec<CompleteUploadResponse>> {
        let directory = directory.as_ref();
        if !directory.is_dir() {
            return Err(Error::invalid(format!("not a directory: {}", directory.display())));
        }
        let mut files = Vec::new();
        collect_files(directory, recursive, &mut files)?;
        files.sort();

        let mut uploads = Vec::with_capacity(files.len());
        for file in files {
            let relative = file.strip_prefix(directory).unwrap_or(&file);
            let relative: Vec<String> = relative
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let key = format!("{prefix}{}", relative.join("/"));
            uploads.push(self.upload_file(bucket_ern, &key, &file, options).await?);
        }
        Ok(uploads)
    }

    /// Downloads every object under `prefix` into `directory`, at its key with the prefix
    /// removed. Without `recursive`, only objects directly under the prefix (no further `/`).
    /// A key whose path would escape `directory` (`..`) is refused rather than written.
    pub async fn download_bucket(
        &self,
        bucket_ern: &str,
        directory: impl AsRef<Path>,
        prefix: &str,
        recursive: bool,
        options: &TransferOptions,
    ) -> Result<Vec<PathBuf>> {
        let directory = directory.as_ref();
        let root = if directory.is_absolute() {
            directory.to_path_buf()
        } else {
            std::env::current_dir()?.join(directory)
        };
        tokio::fs::create_dir_all(&root).await?;

        let mut written = Vec::new();
        for object in self.list_all_objects(bucket_ern, prefix).await? {
            let key = object.key.unwrap_or_default();
            let remainder = key.strip_prefix(prefix).unwrap_or(&key);
            if !recursive && remainder.contains('/') {
                continue;
            }
            let Some(file) = safe_join(&root, remainder) else {
                return Err(Error::invalid(format!(
                    "refusing key '{key}': its path would escape {}",
                    root.display()
                )));
            };
            self.download_file(bucket_ern, &key, &file, options).await?;
            written.push(file);
        }
        Ok(written)
    }
}

fn push_attribute_headers(
    headers: &mut Vec<(String, String)>,
    attributes: &Attributes,
    system_attributes: &Attributes,
) -> Result<()> {
    if !attributes.is_empty() {
        headers.push(("x-euclid-attributes".into(), ascii_json(attributes)?));
    }
    if !system_attributes.is_empty() {
        headers.push(("x-euclid-system-attributes".into(), ascii_json(system_attributes)?));
    }
    Ok(())
}

/// JSON with every non-ASCII character escaped as `\uXXXX`, so it fits in an HTTP header and
/// still decodes to the same value.
fn ascii_json(value: &impl serde::Serialize) -> Result<String> {
    let json = serde_json::to_string(value)?;
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    Ok(out)
}

fn collect_files(directory: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_file() {
            out.push(path);
        } else if recursive && path.is_dir() {
            collect_files(&path, recursive, out)?;
        }
    }
    Ok(())
}

/// `root` joined with a key's remainder, or `None` if that would leave `root` or name it.
fn safe_join(root: &Path, remainder: &str) -> Option<PathBuf> {
    let relative = remainder.trim_start_matches('/');
    let mut file = root.to_path_buf();
    for part in relative.split('/') {
        match part {
            ".." => return None,
            "" | "." => {}
            part => {
                // A part that is itself a path (e.g. a Windows drive or separator) is refused.
                let mut components = Path::new(part).components();
                match (components.next(), components.next()) {
                    (Some(Component::Normal(_)), None) => file.push(part),
                    _ => return None,
                }
            }
        }
    }
    (file != root).then_some(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_json_escapes_non_ascii() {
        let mut attrs = Attributes::new();
        attrs.insert("name".into(), Variant::string("Grüße 😀"));
        let json = ascii_json(&attrs).unwrap();
        assert!(json.is_ascii());
        let expected = "{\"name\":{\"type\":\"string\",\"value\":\"Gr\\u00fc\\u00dfe \\ud83d\\ude00\"}}";
        assert_eq!(json, expected);
        let back: Attributes = serde_json::from_str(&json).unwrap();
        assert_eq!(back, attrs);
    }

    #[test]
    fn safe_join_refuses_escapes() {
        let root = Path::new("/data/out");
        assert_eq!(safe_join(root, "a/b.txt"), Some(PathBuf::from("/data/out/a/b.txt")));
        assert_eq!(safe_join(root, "/a//b.txt"), Some(PathBuf::from("/data/out/a/b.txt")));
        assert_eq!(safe_join(root, "a/../../etc/passwd"), None);
        assert_eq!(safe_join(root, ""), None);
        assert_eq!(safe_join(root, "./"), None);
    }
}

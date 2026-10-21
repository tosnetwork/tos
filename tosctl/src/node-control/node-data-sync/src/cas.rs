use crate::{
    model::{Object, RAW_LIMIT, TRANSFER_LIMIT, hash},
    safe_io::{Root, copy_hash, file_hash},
};
use anyhow::{Result, ensure};
use std::{fs::File, io::Write, path::Path};

/// Names identify compressed bytes; manifest hashes independently identify decoded bytes.
pub struct Objects {
    root: Root,
}
impl Objects {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self { root: Root::open(path)? })
    }
    pub fn create(path: &Path) -> Result<Self> {
        Ok(Self { root: Root::create(path)? })
    }
    pub fn object_name(object: &Object) -> Result<String> {
        validate_object(object)?;
        Ok(format!("objects/{}-{}-{}.zst", object.sha256, object.size, object.compressed_sha256))
    }
    pub fn root_path(&self) -> &Path {
        &self.root.path
    }
    pub fn writer(&self) -> Result<ObjectWriter<'_>> {
        Ok(ObjectWriter {
            objects: self,
            _capture: self.root.lock("capture.lock")?,
            raw: std::cell::Cell::new(0),
            compressed: std::cell::Cell::new(0),
        })
    }
    fn put(&self, path: &str, input: File, max: u64, compressed_limit: u64) -> Result<Object> {
        crate::paths::public_path(path)?;
        ensure!(max <= RAW_LIMIT, "object raw limit");
        let temporary = format!("incoming/{:032x}.zst", rand::random::<u128>());
        let mut out = self.root.create_file(&temporary)?;
        let encoded = (|| -> Result<(u64, String)> {
            let bounded = BoundedWrite { inner: &mut out, remaining: compressed_limit };
            let mut compressor = zstd::stream::write::Encoder::new(bounded, 3)?;
            let result = copy_hash(input, &mut compressor, max)?;
            compressor.finish()?;
            out.sync_all()?;
            Ok(result)
        })();
        let (size, sha256) = match encoded {
            Ok(v) => v,
            Err(e) => {
                self.root.unlink(&temporary)?;
                return Err(e);
            }
        };
        let (compressed_size, compressed_sha256) =
            file_hash(self.root.read(&temporary, TRANSFER_LIMIT)?, TRANSFER_LIMIT)?;
        let object = Object {
            kind: crate::model::ObjectKind::RegularFile,
            path: path.to_owned(),
            size,
            sha256,
            compressed_size,
            compressed_sha256: compressed_sha256.clone(),
            codec: "zstd".to_owned(),
        };
        let name = Self::object_name(&object)?;
        // Writers and pruners share this lock. Existing bytes are never trusted by name.
        let _lock = self.root.lock("catalog.lock")?;
        if self.root.path.join(&name).try_exists()? {
            let actual = file_hash(self.root.read(&name, compressed_size)?, compressed_size)?;
            ensure!(
                actual == (compressed_size, compressed_sha256.clone()),
                "existing content object is corrupt"
            );
            self.root.unlink(&temporary)?;
        } else {
            self.root.rename(&temporary, &name)?;
            self.root.sync_parent(&name)?;
        }
        Ok(object)
    }
    pub fn check(&self, object: &Object) -> Result<()> {
        validate_object(object)?;
        let name = Self::object_name(object)?;
        let actual =
            file_hash(self.root.read(&name, object.compressed_size)?, object.compressed_size)?;
        ensure!(
            actual == (object.compressed_size, object.compressed_sha256.clone()),
            "compressed object digest or size mismatch"
        );
        let mut decoder =
            zstd::stream::read::Decoder::new(self.root.read(&name, object.compressed_size)?)?;
        decoder.window_log_max(27)?;
        let decoded = copy_hash(decoder, std::io::sink(), object.size)?;
        ensure!(
            decoded == (object.size, object.sha256.clone()),
            "decoded object digest or size mismatch"
        );
        Ok(())
    }
    pub fn bytes(&self, object: &Object, max: u64) -> Result<Vec<u8>> {
        use std::io::Read;
        ensure!(object.size <= max, "decoded metadata byte limit");
        self.check(object)?;
        let mut decoder = zstd::stream::read::Decoder::new(
            self.root.read(&Self::object_name(object)?, object.compressed_size)?,
        )?;
        decoder.window_log_max(27)?;
        let mut bytes = Vec::new();
        decoder
            .take(
                object
                    .size
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("metadata bound overflow"))?,
            )
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == object.size && crate::model::sha256(&bytes) == object.sha256,
            "metadata changed during read"
        );
        Ok(bytes)
    }
    pub fn materialize(
        &self,
        object: &Object,
        destination: &Root,
        reuse: Option<&Root>,
    ) -> Result<bool> {
        self.materialize_inner(object, destination, reuse, false)
    }
    pub fn materialize_native(
        &self,
        object: &Object,
        destination: &Root,
        stopped_native: &Root,
    ) -> Result<bool> {
        self.materialize_inner(object, destination, Some(stopped_native), true)
    }
    fn materialize_inner(
        &self,
        object: &Object,
        destination: &Root,
        reuse: Option<&Root>,
        native: bool,
    ) -> Result<bool> {
        validate_object(object)?;
        let reuse_path = if native {
            object
                .path
                .strip_prefix("chain/")
                .ok_or_else(|| anyhow::anyhow!("native reuse requires a chain file"))?
        } else {
            &object.path
        };
        let mut out = destination.create_file(&object.path)?;
        let result = (|| -> Result<bool> {
            // Only immutable tables may be reused, by full identity and by copying.
            if crate::paths::immutable_sst(&object.path)
                && let Some(root) = reuse
            {
                match root.read(reuse_path, RAW_LIMIT) {
                    Ok(file) => {
                        let actual = file_hash(file, RAW_LIMIT)?;
                        if actual == (object.size, object.sha256.clone()) {
                            let copied = copy_hash(
                                root.read(reuse_path, object.size)?,
                                &mut out,
                                object.size,
                            )?;
                            ensure!(copied == actual, "reuse source changed during copy");
                            return Ok(true);
                        }
                    }
                    Err(error) => {
                        // Absence allows fetching; unsafe existing material does not.
                        match root.path.join(reuse_path).symlink_metadata() {
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            _ => return Err(error),
                        }
                    }
                }
            }
            self.check(object)?;
            let mut decoder = zstd::stream::read::Decoder::new(
                self.root.read(&Self::object_name(object)?, object.compressed_size)?,
            )?;
            decoder.window_log_max(27)?;
            let actual = copy_hash(decoder, &mut out, object.size)?;
            ensure!(
                actual == (object.size, object.sha256.clone()),
                "object changed during extraction"
            );
            Ok(false)
        })();
        match result {
            Ok(reused) => {
                out.sync_all()?;
                destination.sync_parent(&object.path)?;
                Ok(reused)
            }
            Err(e) => {
                drop(out);
                destination.unlink(&object.path)?;
                Err(e)
            }
        }
    }
    /// HTTP is only transport: a held signing key and both hashes remain authoritative.
    fn fetch(&self, base: &str, object: &Object, timeout: std::time::Duration) -> Result<()> {
        use std::time::Instant;
        validate_object(object)?;
        ensure!(
            !timeout.is_zero() && timeout <= std::time::Duration::from_secs(1800),
            "invalid total transfer deadline"
        );
        let mut url = reqwest::Url::parse(base)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid object source URL"
        );
        let name = Self::object_name(object)?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("source URL has no path"))?
            .pop_if_empty()
            .extend(name.split('/'));
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let temporary =
            format!("incoming/{}-{}.part", object.compressed_sha256, object.compressed_size);
        let started = Instant::now();
        let mut last_error = None;
        for _ in 0..3 {
            crate::budget::check_active()?;
            let remaining_time = timeout.saturating_sub(started.elapsed());
            ensure!(!remaining_time.is_zero(), "total object transfer deadline expired");
            let mut offset = match self.root.path.join(&temporary).symlink_metadata() {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    self.root.write_new(&temporary, &[])?;
                    0
                }
                Err(error) => return Err(error.into()),
                Ok(_) => self.root.read(&temporary, object.compressed_size)?.metadata()?.len(),
            };
            if offset < object.compressed_size {
                let mut request = client.get(url.clone()).timeout(remaining_time);
                if offset > 0 {
                    request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
                }
                let mut response = match request.send() {
                    Ok(response) => response,
                    Err(error) => {
                        last_error = Some(error.to_string());
                        continue;
                    }
                };
                #[cfg(all(test, feature = "native-lifecycle-tests"))]
                crate::test_hooks::boundary("during-download")?;
                if response.status().is_server_error() {
                    last_error = Some(format!("source returned {}", response.status()));
                    continue;
                }
                if response.status() == reqwest::StatusCode::OK && offset > 0 {
                    // A source without range support may restart the same immutable object, never append it.
                    self.root.unlink(&temporary)?;
                    self.root.write_new(&temporary, &[])?;
                    offset = 0;
                }
                if offset > 0 {
                    ensure!(
                        response.status() == reqwest::StatusCode::PARTIAL_CONTENT,
                        "resume response is not partial content"
                    );
                    let expected = format!(
                        "bytes {}-{}/{}",
                        offset,
                        object
                            .compressed_size
                            .checked_sub(1)
                            .ok_or_else(|| anyhow::anyhow!("empty encoded object"))?,
                        object.compressed_size
                    );
                    ensure!(
                        response
                            .headers()
                            .get(reqwest::header::CONTENT_RANGE)
                            .and_then(|v| v.to_str().ok())
                            == Some(expected.as_str()),
                        "resume range does not identify the exact signed object"
                    );
                } else {
                    ensure!(
                        response.status() == reqwest::StatusCode::OK,
                        "object response is not complete"
                    );
                }
                let remaining = object
                    .compressed_size
                    .checked_sub(offset)
                    .ok_or_else(|| anyhow::anyhow!("resume offset exceeds object size"))?;
                if let Some(length) = response.content_length() {
                    ensure!(length == remaining, "object response length mismatch");
                }
                let mut out = self.root.append_file(&temporary, offset)?;
                let copied = copy_hash(&mut response, &mut out, remaining);
                out.sync_all()?;
                match copied {
                    Ok((size, _)) if size == remaining => {}
                    Ok(_) => {
                        last_error = Some("short object response".to_owned());
                        continue;
                    }
                    Err(error) => {
                        last_error = Some(error.to_string());
                        continue;
                    }
                }
            }
            let actual = file_hash(
                self.root.read(&temporary, object.compressed_size)?,
                object.compressed_size,
            )?;
            if actual != (object.compressed_size, object.compressed_sha256.clone()) {
                self.root.unlink(&temporary)?;
                anyhow::bail!("download object digest or size mismatch");
            }
            let _lock = self.root.lock("catalog.lock")?;
            self.root.rename(&temporary, &name)?;
            self.root.sync_parent(&name)?;
            return self.check(object);
        }
        anyhow::bail!(
            "object transfer exhausted bounded retries: {}",
            last_error.as_deref().map_or("unknown transport failure", |error| error)
        )
    }
}
fn validate_object(object: &Object) -> Result<()> {
    crate::paths::public_path(&object.path)?;
    hash(&object.sha256)?;
    hash(&object.compressed_sha256)?;
    ensure!(
        object.codec == "zstd"
            && object.size <= RAW_LIMIT
            && object.compressed_size <= TRANSFER_LIMIT,
        "invalid object budget or codec"
    );
    ensure!(object.compressed_size > 0, "empty compressed object");
    Ok(())
}

/// Hold this for the complete assembly of a generation, not for individual files.
pub struct ObjectWriter<'a> {
    objects: &'a Objects,
    _capture: File,
    raw: std::cell::Cell<u64>,
    compressed: std::cell::Cell<u64>,
}
impl ObjectWriter<'_> {
    pub fn fetch(&self, base: &str, object: &Object, timeout: std::time::Duration) -> Result<()> {
        self.objects.fetch(base, object, timeout)
    }
    pub fn objects(&self) -> &Objects {
        self.objects
    }
    pub fn put(&self, path: &str, input: File, max: u64) -> Result<Object> {
        let remaining = RAW_LIMIT
            .checked_sub(self.raw.get())
            .ok_or_else(|| anyhow::anyhow!("raw generation budget overflow"))?;
        ensure!(max <= remaining, "raw generation budget exhausted");
        let compressed = TRANSFER_LIMIT
            .checked_sub(self.compressed.get())
            .ok_or_else(|| anyhow::anyhow!("transfer generation budget overflow"))?;
        let object = self.objects.put(path, input, max, compressed)?;
        self.raw.set(
            self.raw
                .get()
                .checked_add(object.size)
                .ok_or_else(|| anyhow::anyhow!("raw generation size overflow"))?,
        );
        self.compressed.set(
            self.compressed
                .get()
                .checked_add(object.compressed_size)
                .ok_or_else(|| anyhow::anyhow!("transfer generation size overflow"))?,
        );
        Ok(object)
    }
}

struct BoundedWrite<W> {
    inner: W,
    remaining: u64,
}
impl<W: Write> Write for BoundedWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.remaining {
            return Err(std::io::Error::other("compressed generation budget exhausted"));
        }
        let n = self.inner.write(bytes)?;
        self.remaining = self
            .remaining
            .checked_sub(n as u64)
            .ok_or_else(|| std::io::Error::other("compressed size overflow"))?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

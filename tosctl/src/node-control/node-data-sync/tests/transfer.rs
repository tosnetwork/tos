use anyhow::Result;
use node_data_sync::{cas::Objects, safe_io::Root};
use std::{
    io::{Read, Write},
    net::TcpListener,
};

#[test]
fn interrupted_transport_resumes_exact_object_and_verifies_complete_bytes() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let source = Objects::create(&directory.path().join("source"))?;
    let raw = Root::create(&directory.path().join("raw"))?;
    let bytes: Vec<_> =
        (0..100_000_u32).flat_map(|n| n.wrapping_mul(2382947).to_le_bytes()).collect();
    raw.write_new("input", &bytes)?;
    let object = source.writer()?.put(
        "chain/celldb/000001.sst",
        raw.read("input", bytes.len() as u64)?,
        bytes.len() as u64,
    )?;
    let encoded = Root::open(source.root_path())?
        .bytes(&Objects::object_name(&object)?, object.compressed_size)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let offset = encoded.len() / 2;
    let server = std::thread::spawn(move || -> Result<Vec<String>> {
        let mut requests = Vec::new();
        for index in 0..2 {
            let (mut socket, _) = listener.accept()?;
            socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte)?, 1, "request ended before headers");
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            requests.push(String::from_utf8(header)?);
            if index == 0 {
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    encoded.len()
                )?;
                socket.write_all(&encoded[..offset])?;
            } else {
                write!(
                    socket,
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                    encoded.len() - offset,
                    offset,
                    encoded.len() - 1,
                    encoded.len()
                )?;
                socket.write_all(&encoded[offset..])?;
            }
        }
        Ok(requests)
    });
    let target = Objects::create(&directory.path().join("target"))?;
    target.writer()?.fetch(
        &format!("http://{address}/"),
        &object,
        std::time::Duration::from_secs(20),
    )?;
    let requests = server.join().expect("server thread")?;
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].to_ascii_lowercase().contains(&format!("range: bytes={offset}-")),
        "the interrupted object was restarted instead of resumed"
    );
    target.check(&object)?;
    let output = Root::create(&directory.path().join("output"))?;
    target.materialize(&object, &output, None)?;
    assert_eq!(output.bytes(&object.path, object.size)?, bytes);
    Ok(())
}

#[test]
fn native_sst_reuse_uses_full_hash_and_size_not_file_number() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let objects = Objects::create(&directory.path().join("objects"))?;
    let raw = Root::create(&directory.path().join("raw"))?;
    raw.write_new("input", b"immutable exact bytes")?;
    let object = objects.writer()?.put("chain/celldb/000001.sst", raw.read("input", 100)?, 100)?;
    let own = Root::create(&directory.path().join("own"))?;
    own.write_new("celldb/000001.sst", b"same number wrong bytes")?;
    let first = Root::create(&directory.path().join("first"))?;
    assert!(!objects.materialize_native(&object, &first, &own)?);
    assert_eq!(first.bytes(&object.path, 100)?, b"immutable exact bytes");
    own.unlink("celldb/000001.sst")?;
    own.write_new("celldb/000001.sst", b"immutable exact bytes")?;
    let second = Root::create(&directory.path().join("second"))?;
    assert!(objects.materialize_native(&object, &second, &own)?);
    Ok(())
}

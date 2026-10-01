//! Linux datagram receiver. A startup allowlist, never an arriving packet,
//! establishes the full process epoch and the kernel credential identity.
use serde::{Deserialize, Serialize};
use std::{
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixDatagram,
        },
    },
    path::{Path, PathBuf},
};
use tos_health_core::wire::DiagnosticRecord;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub socket_path: PathBuf,
    pub node_id: String,
    pub native_pid: i32,
    pub native_uid: u32,
    pub native_gid: u32,
    pub process_epoch: String,
}
impl Mapping {
    pub fn epoch(&self) -> Result<[u8; 16], String> {
        if !crate::alias(&self.node_id)
            || self.native_pid <= 0
            || self.process_epoch.len() != 32
            || !self.process_epoch.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid diagnostic startup mapping".into());
        }
        let mut epoch = [0u8; 16];
        for (i, byte) in epoch.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.process_epoch[i * 2..i * 2 + 2], 16)
                .map_err(|_| "invalid process epoch")?;
        }
        Ok(epoch)
    }
}
pub struct Receiver {
    socket: UnixDatagram,
    mapping: Mapping,
    epoch: [u8; 16],
    inode: u64,
}
pub enum Received {
    Empty,
    Handshake,
    Record(DiagnosticRecord),
    Rejected(&'static str),
}
#[repr(align(16))]
struct Control([u8; 256]);
impl Receiver {
    pub fn bind(mapping: Mapping) -> Result<Self, String> {
        let epoch = mapping.epoch()?;
        let parent = mapping.socket_path.parent().ok_or("socket parent missing")?;
        let meta = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        // Same-UID local profile; separate service UIDs require another reviewed profile.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        if !mapping.socket_path.is_absolute()
            || mapping.socket_path.as_os_str().len() > 100
            || !meta.is_dir()
            || meta.uid() != uid
            || meta.permissions().mode() & 0o077 != 0
            || mapping.native_uid != uid
            || mapping.native_gid != gid
        {
            return Err("diagnostic socket requires a private same-UID directory".into());
        }
        let socket = UnixDatagram::bind(&mapping.socket_path).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&mapping.socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        socket.set_nonblocking(true).map_err(|e| e.to_string())?;
        let yes: libc::c_int = 1;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&yes as *const libc::c_int).cast(),
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let inode =
            std::fs::symlink_metadata(&mapping.socket_path).map_err(|e| e.to_string())?.ino();
        Ok(Self { socket, mapping, epoch, inode })
    }
    pub fn mapping(&self) -> &Mapping {
        &self.mapping
    }
    pub fn receive(&self) -> Result<Received, String> {
        let mut bytes = [0u8; 512];
        let mut control = Control([0; 256]);
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_un).cast();
        message.msg_namelen = std::mem::size_of_val(&address) as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = control.0.len();
        let count = unsafe {
            libc::recvmsg(
                self.socket.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
            )
        };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::WouldBlock {
                Ok(Received::Empty)
            } else {
                Err(error.to_string())
            };
        }
        let mut credential = None;
        let mut invalid = false;
        // recvmsg installs received descriptors even on rejected messages.
        // Close all delivered rights, including a truncated ancillary prefix.
        unsafe {
            let mut item = libc::CMSG_FIRSTHDR(&message);
            while !item.is_null() {
                let header = &*item;
                let minimum = libc::CMSG_LEN(0) as usize;
                if header.cmsg_len < minimum {
                    invalid = true;
                    break;
                }
                let length = header.cmsg_len - minimum;
                if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                    let descriptors = libc::CMSG_DATA(item).cast::<libc::c_int>();
                    for i in 0..length / std::mem::size_of::<libc::c_int>() {
                        libc::close(std::ptr::read_unaligned(descriptors.add(i)));
                    }
                    invalid = true;
                } else if header.cmsg_level == libc::SOL_SOCKET
                    && header.cmsg_type == libc::SCM_CREDENTIALS
                    && length == std::mem::size_of::<libc::ucred>()
                    && credential.is_none()
                {
                    credential =
                        Some(std::ptr::read_unaligned(libc::CMSG_DATA(item).cast::<libc::ucred>()));
                } else {
                    invalid = true;
                }
                item = libc::CMSG_NXTHDR(&message, item);
            }
        }
        if invalid || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Ok(Received::Rejected("ancillary_or_truncation"));
        }
        let Some(cred) = credential else {
            return Ok(Received::Rejected("credentials_missing"));
        };
        if cred.pid != self.mapping.native_pid
            || cred.uid != self.mapping.native_uid
            || cred.gid != self.mapping.native_gid
        {
            return Ok(Received::Rejected("credentials"));
        }
        let size = usize::try_from(count).map_err(|_| "negative datagram size")?;
        if size == 20 && &bytes[..4] == b"THS1" {
            if bytes[4..20] != self.epoch {
                return Ok(Received::Rejected("epoch"));
            }
            bytes[..4].copy_from_slice(b"THA1");
            let sent = unsafe {
                libc::sendto(
                    self.socket.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    20,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    (&address as *const libc::sockaddr_un).cast(),
                    message.msg_namelen,
                )
            };
            return Ok(if sent == 20 {
                Received::Handshake
            } else {
                Received::Rejected("handshake_send")
            });
        }
        if size < 64 || bytes[16..32] != self.epoch {
            return Ok(Received::Rejected("epoch_or_header"));
        }
        match DiagnosticRecord::decode(&bytes[..size]) {
            Ok(record) if record.source_catalog_id == 8 => Ok(Received::Record(record)),
            _ => Ok(Received::Rejected("wire_catalog")),
        }
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.mapping.socket_path).is_ok_and(|m| m.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.mapping.socket_path);
        }
    }
}
pub fn read_mapping(path: &Path) -> Result<Mapping, String> {
    serde_json::from_slice(&read_regular(path, 8192, true)?).map_err(|e| e.to_string())
}
pub(crate) fn read_regular(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>, String> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.len() > limit as u64
        || (private && meta.permissions().mode() & 0o077 != 0)
    {
        return Err("diagnostic file type, permission or size limit".into());
    }
    let capacity = limit.checked_add(1).ok_or("diagnostic file limit overflow")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(capacity as u64).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("diagnostic file grew beyond size limit".into());
    }
    Ok(bytes)
}
pub(crate) fn read_token(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_regular(path, 4096, true)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "diagnostic credential encoding")?
        .trim()
        .as_bytes()
        .to_vec();
    if text.len() < 32 || !text.iter().all(|b| b.is_ascii_graphic()) {
        return Err("diagnostic credential requires32 ASCII bytes".into());
    }
    Ok(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn mapping() -> Mapping {
        let parent = std::env::temp_dir().join(format!(
            "nhm-c06-ipc-{}-{}",
            std::process::id(),
            &crate::hex(&crate::random_token().unwrap())[..16]
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        Mapping {
            socket_path: parent.join("diagnostic.sock"),
            node_id: "node_a".into(),
            native_pid: std::process::id() as i32,
            native_uid: unsafe { libc::getuid() },
            native_gid: unsafe { libc::getgid() },
            process_epoch: "23".repeat(16),
        }
    }
    fn wire(epoch: [u8; 16]) -> Vec<u8> {
        DiagnosticRecord {
            record_type: 1,
            source_catalog_id: 8,
            epoch,
            sequence: 9,
            monotonic_ns: 10,
            wall_unix_ns: None,
            payload: vec![1, 0, 3, 0],
        }
        .encode()
        .unwrap()
    }
    #[test]
    fn real_credentials_and_epoch_are_separate_rejection_gates() {
        let config = mapping();
        let receiver = Receiver::bind(config.clone()).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        let valid = wire(config.epoch().unwrap());
        sender.send_to(&valid, &config.socket_path).unwrap();
        assert!(
            matches!(receiver.receive().unwrap(),Received::Record(record) if record.sequence==9)
        );
        sender.send_to(&wire([0; 16]), &config.socket_path).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Rejected("epoch_or_header")));
        let mut reserved = valid.clone();
        reserved[60] = 1;
        sender.send_to(&reserved, &config.socket_path).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Rejected("wire_catalog")));
        sender.send_to(&vec![0u8; 513], &config.socket_path).unwrap();
        assert!(matches!(
            receiver.receive().unwrap(),
            Received::Rejected("ancillary_or_truncation")
        ));
        // A real independent process provides a different SCM_CREDENTIALS PID.
        let child=std::process::Command::new("python3").arg("-c").arg("import socket,sys; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.sendto(bytes.fromhex(sys.argv[2]),sys.argv[1])")
            .arg(&config.socket_path).arg(crate::hex(&valid)).status().unwrap();
        assert!(child.success());
        assert!(matches!(receiver.receive().unwrap(), Received::Rejected("credentials")));
        // Ancillary rejection must close descriptors installed by recvmsg.
        let marker = config.socket_path.parent().unwrap().join("rights-marker");
        let file = std::fs::File::create(&marker).unwrap();
        let count_marker = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    std::fs::read_link(entry.path()).is_ok_and(|target| target == marker)
                })
                .count()
        };
        assert_eq!(count_marker(), 1);
        sender.connect(&config.socket_path).unwrap();
        for _ in 0..64 {
            let mut control = Control([0; 256]);
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec { iov_base: valid.as_ptr() as *mut _, iov_len: valid.len() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.0.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::c_int>(),
                    file.as_raw_fd(),
                );
                assert_eq!(
                    libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                    valid.len() as isize
                );
            }
            assert!(matches!(
                receiver.receive().unwrap(),
                Received::Rejected("ancillary_or_truncation")
            ));
        }
        assert_eq!(count_marker(), 1, "rejected SCM_RIGHTS must not leak installed descriptors");
        drop(file);
        std::fs::remove_file(&marker).unwrap();
        let token = config.socket_path.parent().unwrap().join("token");
        std::fs::write(&token, "x".repeat(32)).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_token(&token).unwrap(), vec![b'x'; 32]);
        let link = token.with_extension("link");
        std::os::unix::fs::symlink(&token, &link).unwrap();
        assert!(read_token(&link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&token, vec![b'x'; 4097]).unwrap();
        assert_eq!(
            read_token(&token).unwrap_err(),
            "diagnostic file type, permission or size limit"
        );
        std::fs::remove_file(&token).unwrap();
        let fifo = std::ffi::CString::new(token.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert_eq!(
            read_token(&token).unwrap_err(),
            "diagnostic file type, permission or size limit"
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        std::fs::remove_file(&token).unwrap();
        drop(receiver);
        std::fs::remove_dir(config.socket_path.parent().unwrap()).unwrap();
    }
    #[test]
    fn restart_needs_an_explicit_epoch_remap_and_drop_preserves_replaced_inode() {
        let config = mapping();
        let receiver = Receiver::bind(config.clone()).unwrap();
        assert!(Receiver::bind(config.clone()).is_err());
        std::fs::remove_file(&config.socket_path).unwrap();
        let replacement = UnixDatagram::bind(&config.socket_path).unwrap();
        let inode = std::fs::symlink_metadata(&config.socket_path).unwrap().ino();
        drop(receiver);
        assert_eq!(std::fs::symlink_metadata(&config.socket_path).unwrap().ino(), inode);
        drop(replacement);
        std::fs::remove_file(&config.socket_path).unwrap();
        let mut next = config.clone();
        next.process_epoch = "24".repeat(16);
        let receiver = Receiver::bind(next.clone()).unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender.send_to(&wire(config.epoch().unwrap()), &next.socket_path).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Rejected("epoch_or_header")));
        sender.send_to(&wire(next.epoch().unwrap()), &next.socket_path).unwrap();
        assert!(matches!(receiver.receive().unwrap(), Received::Record(_)));
        drop(receiver);
        std::fs::remove_dir(config.socket_path.parent().unwrap()).unwrap();
    }
}

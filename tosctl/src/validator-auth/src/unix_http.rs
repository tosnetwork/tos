use crate::{
    client::{HttpRequest, HttpResponse, Transport},
    codec::Error,
};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const MAX_BODY: usize = 4_194_304;
const MAX_HEAD: usize = 8192;
pub struct UnixHttp {
    path: PathBuf,
    uid: libc::uid_t,
}
impl UnixHttp {
    pub fn new(path: PathBuf, expected_server: libc::uid_t) -> Self {
        Self { path, uid: expected_server }
    }
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error("http-timeout"))
}
fn connect(path: &Path, expected: libc::uid_t, deadline: Instant) -> Result<UnixStream, Error> {
    // sockaddr_un is a plain C record. Its length is checked before copying.
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(Error("unix-path"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    // A successful socket() returns an owned descriptor, transferred to OwnedFd.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(Error("unix-socket"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // The descriptor remains owned and live across each C call.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0
    {
        return Err(Error("unix-socket"));
    }
    let status = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if status < 0 {
        let error = std::io::Error::last_os_error().raw_os_error();
        if error != Some(libc::EINPROGRESS) {
            return Err(Error("unix-connect"));
        }
        loop {
            let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            let timeout = remaining(deadline)?.as_millis().clamp(1, 5000) as libc::c_int;
            let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
            if ready < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if ready <= 0 {
                return Err(Error("unix-connect"));
            }
            let mut result: libc::c_int = 0;
            let mut len = mem::size_of_val(&result) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut result as *mut libc::c_int).cast(),
                    &mut len,
                )
            } < 0
                || result != 0
            {
                return Err(Error("unix-connect"));
            }
            break;
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let yes: libc::c_int = 1;
        // Suppress SIGPIPE on the raw socket before handing it to UnixStream.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&yes as *const libc::c_int).cast(),
                mem::size_of_val(&yes) as libc::socklen_t,
            )
        } != 0
        {
            return Err(Error("unix-socket"));
        }
    }
    authenticate(fd.as_raw_fd(), expected)?;
    Ok(UnixStream::from(fd))
}
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn authenticate(fd: libc::c_int, expected: libc::uid_t) -> Result<(), Error> {
    let mut uid = 0;
    let mut gid = 0;
    // getpeereid writes exactly the uid_t/gid_t objects supplied here.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(Error("unix-credentials"));
    }
    if uid != expected {
        return Err(Error("unix-unauthorized"));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn authenticate(fd: libc::c_int, expected: libc::uid_t) -> Result<(), Error> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut size = mem::size_of_val(&credentials) as libc::socklen_t;
    // SO_PEERCRED fills the bounded native ucred record; its size is verified.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || size as usize != mem::size_of_val(&credentials)
    {
        return Err(Error("unix-credentials"));
    }
    if credentials.uid != expected {
        return Err(Error("unix-unauthorized"));
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn authenticate(_: libc::c_int, _: libc::uid_t) -> Result<(), Error> {
    Err(Error("unix-platform"))
}
fn ready(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> Result<(), Error> {
    loop {
        let mut state = libc::pollfd { fd, events, revents: 0 };
        let timeout = remaining(deadline)?.as_millis().clamp(1, 5000) as libc::c_int;
        // poll writes the single live pollfd object and never retains its pointer.
        let result = unsafe { libc::poll(&mut state, 1, timeout) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result <= 0 {
            return Err(Error("http-timeout"));
        }
        // A closed peer can still have unread buffered bytes. Attempt the
        // nonblocking read before treating hangup as an empty stream.
        if state.revents & (events | libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(());
        }
        return Err(Error("http-io"));
    }
}
fn send(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        ready(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error("http-write-io")),
            Ok(n) => bytes = &bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(_) => return Err(Error("http-write-io")),
        }
    }
    Ok(())
}
fn receive(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        ready(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        match stream.read(bytes) {
            Ok(0) => return Err(Error("http-read-eof")),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Err(_) => return Err(Error("http-read-io")),
        }
    }
    Ok(())
}
impl Transport for UnixHttp {
    fn exchange(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        if !matches!(request.verb, "GET" | "POST")
            || request.path.is_empty()
            || request.path.len() > 256
            || !request.path.bytes().all(|c| (33..=126).contains(&c))
            || request.body.len() > MAX_BODY
            || request.content_type.len() > 256
            || !request.content_type.bytes().all(|c| (32..=126).contains(&c))
            || (request.verb == "GET" && !request.body.is_empty())
        {
            return Err(Error("http-request-bound"));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = connect(&self.path, self.uid, deadline)?;
        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
            request.verb,
            request.path,
            request.body.len()
        );
        if !request.content_type.is_empty() {
            head.push_str(&format!("Content-Type: {}\r\n", request.content_type));
        }
        head.push_str("\r\n");
        send(&mut stream, head.as_bytes(), deadline)?;
        send(&mut stream, request.body.as_bytes(), deadline)?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= MAX_HEAD {
                return Err(Error("http-header-bound"));
            }
            let mut b = [0u8; 1];
            receive(&mut stream, &mut b, deadline)?;
            header.push(b[0]);
        }
        let text = std::str::from_utf8(&header).map_err(|_| Error("http-header"))?;
        let mut lines = text.split("\r\n");
        let line = lines.next().ok_or(Error("http-response-line"))?;
        if !line.starts_with("HTTP/1.1 ")
            || line.len() < 12
            || !line.bytes().all(|c| (32..=126).contains(&c))
            || (line.len() > 12 && line.as_bytes()[12] != b' ')
        {
            return Err(Error("http-response-line"));
        }
        let status = line[9..12].parse::<u16>().map_err(|_| Error("http-response-status"))?;
        if !(200..=599).contains(&status) || (300..400).contains(&status) {
            return Err(Error("http-response-status"));
        }
        let mut fields = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if fields.len() >= 16 || !line.bytes().all(|c| (32..=126).contains(&c)) {
                return Err(Error("http-header"));
            }
            let (name, value) = line.split_once(':').ok_or(Error("http-header"))?;
            if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                return Err(Error("http-header"));
            }
            let name = name.to_ascii_lowercase();
            if matches!(
                name.as_str(),
                "transfer-encoding" | "content-encoding" | "upgrade" | "expect"
            ) {
                return Err(Error("http-unsupported-framing"));
            }
            if fields.insert(name, value.trim_matches(' ')).is_some() {
                return Err(Error("http-duplicate-header"));
            }
        }
        let length = fields.get("content-length").ok_or(Error("http-content-length"))?;
        if length.is_empty()
            || length.len() > 8
            || !length.bytes().all(|c| c.is_ascii_digit())
            || (length.len() > 1 && length.starts_with('0'))
        {
            return Err(Error("http-content-length"));
        }
        let size = length.parse::<usize>().map_err(|_| Error("http-content-length"))?;
        if size > MAX_BODY {
            return Err(Error("http-body-bound"));
        }
        let mut body = vec![0u8; size];
        receive(&mut stream, &mut body, deadline)?;
        Ok(HttpResponse {
            status,
            content_type: fields.get("content-type").copied().unwrap_or("").to_string(),
            body: String::from_utf8(body).map_err(|_| Error("http-body-utf8"))?,
        })
    }
}

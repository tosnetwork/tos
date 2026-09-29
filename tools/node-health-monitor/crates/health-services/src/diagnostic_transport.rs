//! Fixed HTTPS/mTLS destination with accounting at the encrypted TCP writer.
use std::{io, path::{Path,PathBuf}, pin::Pin, sync::{Arc,Mutex}, task::{Context,Poll}, time::{Duration,Instant}};
use serde::{Deserialize,Serialize};
use tokio::{io::{AsyncRead,AsyncReadExt,AsyncWrite,AsyncWriteExt,ReadBuf},net::TcpStream};
use tokio_rustls::{TlsConnector,rustls::{ClientConfig,RootCertStore,pki_types::{pem::PemObject,CertificateDer,PrivateKeyDer,ServerName}}};

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub origin:String,
    pub ca_file:PathBuf,
    pub identity_file:PathBuf,
    pub token_file:PathBuf,
}
const RATE:u64=65536;
const BURST:u64=262144;
pub struct Rate {at:Instant,tokens:u64,fraction:u128,pub written:u64}
impl Default for Rate {
    fn default()->Self {Self {at:Instant::now(),tokens:BURST,fraction:0,written:0}}
}
impl Rate {
    fn available(&mut self)->u64 {
        let now=Instant::now();
        let elapsed=now.duration_since(self.at).as_nanos().min(4_000_000_000);
        let credit=elapsed*u128::from(RATE)+self.fraction;
        self.tokens=self.tokens.saturating_add((credit/1_000_000_000) as u64).min(BURST);
        self.fraction=credit%1_000_000_000; self.at=now; self.tokens
    }
    fn charge(&mut self,count:usize)->io::Result<()> {
        let n=u64::try_from(count).map_err(|_|io::Error::other("egress count overflow"))?;
        self.tokens=self.tokens.checked_sub(n).ok_or_else(||io::Error::other("egress budget underflow"))?;
        self.written=self.written.checked_add(n).ok_or_else(||io::Error::other("egress count exhausted"))?;
        Ok(())
    }
}
struct CountedSocket {socket:TcpStream,rate:Arc<Mutex<Rate>>,wait:Option<Pin<Box<tokio::time::Sleep>>>}
impl AsyncRead for CountedSocket {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(cx,out)
    }
}
impl AsyncWrite for CountedSocket {
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>> {
        let available=match self.rate.lock() {Ok(mut rate)=>rate.available(),Err(_)=>return Poll::Ready(Err(io::Error::other("egress accounting unavailable")))};
        if available==0 && !bytes.is_empty() {
            if self.wait.is_none() {self.wait=Some(Box::pin(tokio::time::sleep(Duration::from_millis(1))));}
            if let Some(wait)=&mut self.wait {let _=std::future::Future::poll(wait.as_mut(),cx);}
            // A completed timer is replaced before returning Pending, so every
            // refusal has a future wake rather than a stalled connection.
            if self.wait.as_ref().is_some_and(|wait|wait.is_elapsed()) {
                self.wait=Some(Box::pin(tokio::time::sleep(Duration::from_millis(1))));
                if let Some(wait)=&mut self.wait {let _=std::future::Future::poll(wait.as_mut(),cx);}
            }
            return Poll::Pending;
        }
        self.wait=None;
        let limit=bytes.len().min(available as usize);
        match Pin::new(&mut self.socket).poll_write(cx,&bytes[..limit]) {
            Poll::Ready(Ok(count))=>{
                let charged=match self.rate.lock() {Ok(mut rate)=>rate.charge(count),Err(_)=>Err(io::Error::other("egress accounting unavailable"))};
                Poll::Ready(charged.map(|()|count))
            }
            other=>other,
        }
    }
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.socket).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.socket).poll_shutdown(cx)}
}
pub struct Transport {host:String,port:u16,authority:String,token:Vec<u8>,tls:Arc<ClientConfig>,pub rate:Arc<Mutex<Rate>>}
fn read(path:&Path)->Result<Vec<u8>,String> {
    crate::diagnostic_ipc::read_regular(path,262144,false)
}
impl Transport {
    pub fn new(config:&Destination)->Result<Self,String> {
        let url=reqwest::Url::parse(&config.origin).map_err(|e|e.to_string())?;
        if url.scheme()!="https" || !url.username().is_empty() || url.password().is_some()
            || url.query().is_some() || url.fragment().is_some() || url.path()!="/" {
            return Err("diagnostic destination must be a fixed HTTPS origin".into());
        }
        let host=url.host_str().ok_or("missing TLS hostname")?.trim_start_matches('[').trim_end_matches(']').to_owned();
        let port=url.port_or_known_default().ok_or("missing TLS port")?;
        let authority=url.as_str().strip_prefix("https://").and_then(|value|value.strip_suffix('/')).ok_or("invalid HTTPS authority")?.to_owned();
        let ca=read(&config.ca_file)?; let identity=crate::diagnostic_ipc::read_regular(&config.identity_file,262144,true)?;
        let mut roots=RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(&ca) {roots.add(certificate.map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;}
        if roots.is_empty() {return Err("empty diagnostic CA".into());}
        let chain=CertificateDer::pem_slice_iter(&identity).collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
        let key=PrivateKeyDer::from_pem_slice(&identity).map_err(|e|e.to_string())?;
        let tls=ClientConfig::builder().with_root_certificates(roots).with_client_auth_cert(chain,key).map_err(|e|e.to_string())?;
        Ok(Self {host,port,authority,token:crate::diagnostic_ipc::read_token(&config.token_file)?,tls:Arc::new(tls),rate:Arc::new(Mutex::new(Rate::default()))})
    }
    pub async fn post(&self,body:&[u8])->Result<(u16,Vec<u8>),String> {
        if body.len()>262144 {return Err("diagnostic JSON body limit".into());}
        tokio::time::timeout(Duration::from_secs(3),self.post_inner(body)).await.map_err(|_|"diagnostic transport deadline".to_owned())?
    }
    async fn post_inner(&self,body:&[u8])->Result<(u16,Vec<u8>),String> {
        let socket=TcpStream::connect((self.host.as_str(),self.port)).await.map_err(|e|e.to_string())?;
        socket.set_nodelay(true).map_err(|e|e.to_string())?;
        let counted=CountedSocket {socket,rate:self.rate.clone(),wait:None};
        let name=ServerName::try_from(self.host.clone()).map_err(|e|e.to_string())?;
        let mut stream=TlsConnector::from(self.tls.clone()).connect(name,counted).await.map_err(|e|e.to_string())?;
        let token=std::str::from_utf8(&self.token).map_err(|_|"invalid ingress credential")?;
        let header=format!("POST /v1/ingest/diagnostic-batches HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",self.authority,token,body.len());
        stream.write_all(header.as_bytes()).await.map_err(|e|e.to_string())?;
        stream.write_all(body).await.map_err(|e|e.to_string())?;
        stream.flush().await.map_err(|e|e.to_string())?;
        let mut response=Vec::with_capacity(16384); let mut buffer=[0u8;1024];
        loop {
            let count=stream.read(&mut buffer).await.map_err(|e|e.to_string())?;
            if count==0 {break;}
            if count>16384usize.saturating_sub(response.len()) {return Err("diagnostic ACK wire limit".into());}
            response.extend_from_slice(&buffer[..count]);
        }
        parse_response(&response)
    }
}
fn parse_response(response:&[u8])->Result<(u16,Vec<u8>),String> {
    let boundary=response.windows(4).position(|w|w==b"\r\n\r\n").ok_or("invalid ACK headers")?;
    if boundary>8192 {return Err("ACK header limit".into());}
    let header=std::str::from_utf8(&response[..boundary]).map_err(|_|"invalid ACK header text")?;
    let mut lines=header.split("\r\n");
    let mut status=lines.next().ok_or("missing ACK status")?.split(' ');
    if status.next()!=Some("HTTP/1.1") {return Err("invalid ACK protocol".into());}
    let code=status.next().ok_or("missing ACK status")?.parse::<u16>().map_err(|_|"invalid ACK status")?;
    let mut length=None; let mut chunked=false;
    for line in lines {
        let (name,value)=line.split_once(':').ok_or("invalid ACK header")?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {return Err("duplicate ACK length".into());}
            length=Some(value.trim().parse::<usize>().map_err(|_|"invalid ACK length")?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || value.trim()!="chunked" {return Err("invalid ACK transfer encoding".into());}
            chunked=true;
        } else if name.eq_ignore_ascii_case("content-encoding") {return Err("compressed ACK forbidden".into());}
    }
    let body=&response[boundary+4..];
    if chunked {
        if length.is_some() {return Err("ambiguous ACK length".into());}
        let mut rest=body; let mut decoded=Vec::with_capacity(4096);
        for _ in 0..128 {
            let end=rest.windows(2).position(|w|w==b"\r\n").ok_or("invalid ACK chunk")?;
            let text=std::str::from_utf8(&rest[..end]).map_err(|_|"invalid ACK chunk")?;
            if text.len()>8 || !text.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("invalid ACK chunk size".into());}
            let size=usize::from_str_radix(text,16).map_err(|_|"invalid ACK chunk size")?;
            rest=&rest[end+2..];
            if size==0 {return if rest==b"\r\n" {Ok((code,decoded))} else {Err("ACK trailers forbidden".into())};}
            if size>4096usize.saturating_sub(decoded.len()) || rest.len()<size+2 || &rest[size..size+2]!=b"\r\n" {return Err("ACK chunk limit".into());}
            decoded.extend_from_slice(&rest[..size]); rest=&rest[size+2..];
        }
        Err("ACK chunk count limit".into())
    } else if length.is_some_and(|n|n!=body.len()) || body.len()>4096 {
        Err("ACK body length".into())
    } else {Ok((code,body.to_vec()))}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ack_framing_has_independent_bounds() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),(200,b"{}".to_vec()));
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n").unwrap(),(200,b"{}".to_vec()));
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}").unwrap_err(),"duplicate ACK length");
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}").unwrap_err(),"ambiguous ACK length");
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}").unwrap_err(),"ACK body length");
        let mut oversized=b"HTTP/1.1 200 OK\r\n\r\n".to_vec();oversized.extend(vec![b'x';4097]);
        assert_eq!(parse_response(&oversized).unwrap_err(),"ACK body length");
    }
    #[tokio::test]
    async fn actual_tcp_writer_obeys_rate_and_counts_all_written_bytes() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        let receiving=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await.unwrap();let mut total=0;let mut bytes=[0u8;8192];
            loop {let count=socket.read(&mut bytes).await.unwrap();if count==0 {break;} total+=count;}
            total
        });
        let rate=Arc::new(Mutex::new(Rate::default()));
        let socket=TcpStream::connect(address).await.unwrap();
        let mut counted=CountedSocket {socket,rate:rate.clone(),wait:None};
        let bytes=vec![0u8;BURST as usize+RATE as usize/10];
        let start=Instant::now();counted.write_all(&bytes).await.unwrap();let elapsed=start.elapsed();counted.shutdown().await.unwrap();
        assert!(elapsed>=Duration::from_millis(90),"actual egress bypassed token rate: {elapsed:?}");
        assert_eq!(rate.lock().unwrap().written,bytes.len() as u64);
        assert_eq!(receiving.await.unwrap(),bytes.len());
    }
}

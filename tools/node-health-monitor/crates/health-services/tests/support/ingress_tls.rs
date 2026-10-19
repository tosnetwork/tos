use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
pub(crate) struct Temp(pub(crate) PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn openssl(dir: &Path, args: &[&str]) {
    assert!(
        Command::new("openssl")
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "openssl {args:?}"
    );
}
pub(crate) fn fixture() -> Temp {
    let p = std::env::temp_dir()
        .join(format!("health-tls-{}", crate::hex(&crate::random_token().unwrap())));
    std::fs::create_dir(&p).unwrap();
    let t = Temp(p);
    openssl(
        &t.0,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=health-ca",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    );
    for name in ["server", "client", "watchdog"] {
        openssl(
            &t.0,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        );
    }
    std::fs::write(
        t.0.join("server.ext"),
        "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    std::fs::write(
        t.0.join("client.ext"),
        "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    std::fs::write(
        t.0.join("watchdog.ext"),
        "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE\n",
    )
    .unwrap();
    for (name, csr, days, serial) in [
        ("server", "server", "1", "1"),
        ("client", "client", "1", "2"),
        ("expired", "client", "-1", "3"),
        ("unapproved", "client", "1", "4"),
        ("watchdog", "watchdog", "1", "5"),
    ] {
        openssl(
            &t.0,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{csr}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                serial,
                "-days",
                days,
                "-extfile",
                &format!("{csr}.ext"),
                "-out",
                &format!("{name}.pem"),
            ],
        );
    }
    t
}
pub(crate) fn fingerprint(dir: &Path, name: &str) -> String {
    let r = Command::new("openssl")
        .args(["x509", "-in", &format!("{name}.pem"), "-outform", "DER"])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(r.status.success());
    format!("{:x}", Sha256::digest(r.stdout))
}
pub(crate) fn client(dir: &Path, name: Option<&str>) -> reqwest::Client {
    client_with_timeout(dir, name, Duration::from_secs(3))
}
pub(crate) fn client_with_timeout(
    dir: &Path,
    name: Option<&str>,
    timeout: Duration,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(dir.join("ca.pem")).unwrap()).unwrap(),
        );
    if let Some(name) = name {
        let mut pem = std::fs::read(dir.join(format!("{name}.pem"))).unwrap();
        let key = if dir.join(format!("{name}.key")).is_file() { name } else { "client" };
        pem.extend(std::fs::read(dir.join(format!("{key}.key"))).unwrap());
        builder = builder.identity(reqwest::Identity::from_pem(&pem).unwrap());
    }
    builder.build().unwrap()
}
pub(crate) async fn idle_tls(
    dir: &Path,
    address: std::net::SocketAddr,
    name: &str,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(dir.join("ca.pem")).unwrap()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let certs =
        CertificateDer::pem_slice_iter(&std::fs::read(dir.join(format!("{name}.pem"))).unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(dir.join(format!("{name}.key"))).unwrap())
            .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    let stream = socket.connect(address).await.unwrap();
    connector.connect(ServerName::try_from("localhost".to_owned()).unwrap(), stream).await.unwrap()
}

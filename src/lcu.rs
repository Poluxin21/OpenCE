//! Cliente da API local do client (LCU — League Client Update) da secao
//! Kernel Exploring.
//!
//! O client da Riot expoe uma API REST em `https://127.0.0.1:<porta>` protegida
//! por Basic Auth (`riot:<token>`). Porta e token ficam no arquivo `lockfile`,
//! criado pelo client na sua pasta de instalacao. Descobrimos a pasta pelo
//! caminho do processo `LeagueClientUx.exe` (nao tocamos no processo: so lemos
//! o lockfile no disco), e falamos com a API por HTTPS aceitando o certificado
//! self-signed da Riot (loopback, ja autenticado pelo token).
//!
//! Acesso 100% legitimo e sem injecao — funciona apesar do anticheat kernel.

use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::oneshot;

use windows::core::PWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Conexao descoberta com o LCU.
#[derive(Clone)]
pub struct LcuConn {
    pub pid: u32,
    pub port: u16,
    pub token: String,
}

impl LcuConn {
    /// Cabecalho `Authorization: Basic ...` para `riot:<token>`.
    fn auth_header(&self) -> String {
        format!("Basic {}", base64(format!("riot:{}", self.token).as_bytes()))
    }
}

/// Procura o client em execucao e le seu lockfile.
pub fn discover() -> Result<LcuConn, String> {
    let pid = find_pid("LeagueClientUx.exe")
        .or_else(|| find_pid("LeagueClient.exe"))
        .ok_or("Client (LeagueClientUx.exe) nao encontrado em execucao.")?;

    let dir = process_dir(pid).ok_or(
        "Nao consegui obter a pasta do client. Rode o Quarry como Administrador.",
    )?;
    let lockfile = dir.join("lockfile");
    let content = std::fs::read_to_string(&lockfile)
        .map_err(|e| format!("Falha ao ler {}: {e}", lockfile.display()))?;

    parse_lockfile(&content)
}

/// Formato do lockfile: `LeagueClient:<pid>:<porta>:<token>:<protocolo>`.
fn parse_lockfile(content: &str) -> Result<LcuConn, String> {
    let parts: Vec<&str> = content.trim().split(':').collect();
    if parts.len() < 5 {
        return Err("lockfile em formato inesperado.".into());
    }
    let pid = parts[1].parse::<u32>().map_err(|_| "pid invalido no lockfile")?;
    let port = parts[2].parse::<u16>().map_err(|_| "porta invalida no lockfile")?;
    let token = parts[3].to_string();
    Ok(LcuConn { pid, port, token })
}

/// PID do primeiro processo com o nome dado (case-insensitive).
fn find_pid(exe: &str) -> Option<u32> {
    crate::process::list_processes()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(exe))
        .map(|p| p.pid)
}

/// Pasta do executavel de um processo (via QueryFullProcessImageNameW).
fn process_dir(pid: u32) -> Option<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        res.ok()?;
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        PathBuf::from(path).parent().map(|p| p.to_path_buf())
    }
}

/// Resultado de uma chamada ao LCU.
pub struct LcuResult {
    pub status: u16,
    pub body: String,
}

pub type LcuRx = oneshot::Receiver<Result<LcuResult, String>>;

pub enum LcuPoll {
    Pending,
    Done(Result<LcuResult, String>),
    Closed,
}

/// Verifica (sem bloquear) se a chamada ja respondeu.
pub fn poll(rx: &mut LcuRx) -> LcuPoll {
    match rx.try_recv() {
        Ok(r) => LcuPoll::Done(r),
        Err(oneshot::error::TryRecvError::Empty) => LcuPoll::Pending,
        Err(_) => LcuPoll::Closed,
    }
}

/// Dispara uma chamada ao LCU numa thread/runtime proprios.
pub fn request(conn: &LcuConn, method: String, path: String, body: String) -> LcuRx {
    let (tx, rx) = oneshot::channel();
    let port = conn.port;
    let auth = conn.auth_header();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(Err(format!("runtime tokio: {e}")));
                return;
            }
        };
        let res = rt.block_on(do_request(port, auth, method, path, body));
        let _ = tx.send(res);
    });

    rx
}

async fn do_request(
    port: u16,
    auth: String,
    method: String,
    path: String,
    body: String,
) -> Result<LcuResult, String> {
    let method = Method::from_bytes(method.trim().to_uppercase().as_bytes())
        .map_err(|_| "metodo HTTP invalido".to_string())?;
    let path = if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    };
    let uri = format!("https://127.0.0.1:{port}{path}");

    let mut builder = Request::builder()
        .method(method)
        .uri(&uri)
        .header("Authorization", auth)
        .header("Accept", "application/json");
    if !body.is_empty() {
        builder = builder.header("Content-Type", "application/json");
    }
    let req = builder
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("montar requisicao: {e}"))?;

    let config = tls_config_insecure();
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("conexao com o LCU: {e}"))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("ler resposta: {e}"))?
        .to_bytes();
    Ok(LcuResult {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Config TLS de cliente que aceita qualquer certificado (loopback ja
/// autenticado pelo token do lockfile — o cert da Riot e self-signed).
fn tls_config_insecure() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocolos TLS padrao")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth()
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Base64 padrao (sem dependencia externa).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

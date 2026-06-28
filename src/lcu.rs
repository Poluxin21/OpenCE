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
    pub fn auth_header(&self) -> String {
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

/// Descobre o **Riot Client** (RiotClientServices.exe) — o orquestrador que
/// cobre conta/entitlements e os outros jogos da Riot (VALORANT, LoR). Tem o
/// proprio lockfile, em `%LOCALAPPDATA%\Riot Games\Riot Client\Config\lockfile`.
/// Mesma forma de auth do LCU (`riot:<token>` Basic), porta propria.
pub fn discover_riot_client() -> Result<LcuConn, String> {
    let local = std::env::var("LOCALAPPDATA")
        .map_err(|_| "variavel LOCALAPPDATA nao definida".to_string())?;
    let lockfile = PathBuf::from(local)
        .join("Riot Games")
        .join("Riot Client")
        .join("Config")
        .join("lockfile");
    let content = std::fs::read_to_string(&lockfile).map_err(|e| {
        format!(
            "Riot Client nao encontrado ({}): {e}. O Riot Client precisa estar aberto.",
            lockfile.display()
        )
    })?;
    parse_lockfile(&content)
}

/// Um endpoint catalogado a partir do OpenAPI/swagger do LCU.
#[derive(Clone)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub summary: String,
}

/// Faz o parse do `openapi.json` (paths → metodos → summary) num catalogo
/// ordenado por caminho. Tolerante: ignora o que nao reconhece.
pub fn parse_openapi(json: &str) -> Result<Vec<Endpoint>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("JSON invalido do swagger: {e}"))?;
    let paths = v
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or("swagger sem objeto 'paths'")?;

    let mut out = Vec::new();
    for (path, item) in paths {
        let Some(methods) = item.as_object() else {
            continue;
        };
        for (method, op) in methods {
            // chaves que nao sao verbos HTTP (ex.: "parameters") sao ignoradas
            if !matches!(
                method.as_str(),
                "get" | "post" | "put" | "patch" | "delete" | "head" | "options"
            ) {
                continue;
            }
            let summary = op
                .get("summary")
                .or_else(|| op.get("description"))
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            out.push(Endpoint {
                method: method.to_uppercase(),
                path: path.clone(),
                summary,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    Ok(out)
}

/// Um achado da auditoria de exposicao de segredos.
pub struct Finding {
    pub label: String,
    pub path: String,
    pub status: u16,
    /// true = o endpoint devolveu algo sensivel (token/PII) com a credencial do lockfile.
    pub leaked: bool,
    pub note: String,
}

/// Relatorio da auditoria de exposicao de token/segredos (item C do painel VDP).
pub struct AuditReport {
    /// Observacao sobre o lockfile (caminho + que o token esta em texto puro).
    pub lockfile_note: String,
    pub findings: Vec<Finding>,
}

/// Endpoints sensiveis sondados: qualquer processo local que leia o lockfile
/// (token em texto puro no disco) consegue puxar isto. E exatamente a narrativa
/// de um report de VDP sobre a superficie local.
const PROBES: &[(&str, &str)] = &[
    ("Access token RSO (JWT da conta)", "/lol-rso-auth/v1/authorization/access-token"),
    ("Entitlements + access token", "/entitlements/v1/token"),
    ("Summoner atual (PII: nome, puuid)", "/lol-summoner/v1/current-summoner"),
    ("Sessao de login (account/puuid)", "/lol-login/v1/session"),
    ("Perfil de chat (PII)", "/lol-chat/v1/me"),
];

/// Roda a auditoria numa thread propria; o resultado chega pelo `Receiver`.
pub fn audit(conn: &LcuConn) -> std::sync::mpsc::Receiver<AuditReport> {
    let (tx, rx) = std::sync::mpsc::channel();
    let port = conn.port;
    let auth = conn.auth_header();
    let lockfile_note = lockfile_location_note();

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => {
                let _ = tx.send(AuditReport {
                    lockfile_note,
                    findings: Vec::new(),
                });
                return;
            }
        };
        let findings = rt.block_on(async {
            let mut out = Vec::new();
            for (label, path) in PROBES {
                let res = do_request(
                    port,
                    Some(auth.clone()),
                    "GET".into(),
                    path.to_string(),
                    String::new(),
                    Vec::new(),
                )
                .await;
                let f = match res {
                    Ok(r) => {
                        let body = r.body.trim();
                        let leaked = (200..300).contains(&r.status)
                            && body.len() > 2
                            && body != "{}"
                            && body != "[]";
                        Finding {
                            label: label.to_string(),
                            path: path.to_string(),
                            status: r.status,
                            leaked,
                            note: if leaked {
                                format!("expos {} bytes de dados", body.len())
                            } else {
                                "sem conteudo sensivel / nao autorizado".into()
                            },
                        }
                    }
                    Err(e) => Finding {
                        label: label.to_string(),
                        path: path.to_string(),
                        status: 0,
                        leaked: false,
                        note: e,
                    },
                };
                out.push(f);
            }
            out
        });
        let _ = tx.send(AuditReport {
            lockfile_note,
            findings,
        });
    });

    rx
}

/// Texto sobre onde o token vive em texto puro (parte da narrativa do report).
fn lockfile_location_note() -> String {
    match find_pid("LeagueClientUx.exe").or_else(|| find_pid("LeagueClient.exe")) {
        Some(pid) => match process_dir(pid) {
            Some(dir) => format!(
                "Token em TEXTO PURO no lockfile: {} — legivel por qualquer processo do usuario.",
                dir.join("lockfile").display()
            ),
            None => "Client em execucao, mas a pasta nao foi obtida (rode como Admin).".into(),
        },
        None => "Client nao esta em execucao.".into(),
    }
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
    /// Cabecalhos da resposta (nome, valor) — usados na auditoria de seguranca.
    pub headers: Vec<(String, String)>,
}

impl LcuResult {
    /// Valor (primeiro) do cabecalho de resposta com este nome (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
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
    http_request(
        conn.port,
        Some(conn.auth_header()),
        method,
        path,
        body,
        Vec::new(),
    )
}

/// Versao generica do disparo HTTPS para loopback (127.0.0.1):
///
/// - `auth`: cabecalho `Authorization` ja montado, ou `None` (a API in-game da
///   porta 2999 nao usa auth).
/// - `extra_headers`: cabecalhos adicionais — usados para *forjar* `Origin`/`Host`
///   nos testes de CSRF / DNS-rebinding do painel de seguranca.
///
/// Aceita o certificado self-signed da Riot (loopback). Roda numa thread propria.
pub fn http_request(
    port: u16,
    auth: Option<String>,
    method: String,
    path: String,
    body: String,
    extra_headers: Vec<(String, String)>,
) -> LcuRx {
    let (tx, rx) = oneshot::channel();

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
        let res = rt.block_on(do_request(port, auth, method, path, body, extra_headers));
        let _ = tx.send(res);
    });

    rx
}

async fn do_request(
    port: u16,
    auth: Option<String>,
    method: String,
    path: String,
    body: String,
    extra_headers: Vec<(String, String)>,
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
        .header("Accept", "application/json");
    if let Some(auth) = auth {
        builder = builder.header("Authorization", auth);
    }
    if !body.is_empty() {
        builder = builder.header("Content-Type", "application/json");
    }
    // Cabecalhos forjados (Origin/Host/...) sobrepoem os padrao quando informados.
    for (k, v) in &extra_headers {
        builder = builder.header(k.as_str(), v.as_str());
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
        .map_err(|e| format!("conexao com 127.0.0.1:{port}: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("ler resposta: {e}"))?
        .to_bytes();
    Ok(LcuResult {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        headers,
    })
}

/// Config TLS de cliente que aceita qualquer certificado (loopback ja
/// autenticado pelo token do lockfile — o cert da Riot e self-signed).
pub fn tls_config_insecure() -> rustls::ClientConfig {
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

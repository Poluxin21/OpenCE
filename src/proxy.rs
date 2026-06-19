//! Proxy HTTPS de interceptacao (MITM) da secao Kernel Exploring.
//!
//! Gera/persiste uma CA propria (`quarry-ca.pem` + `quarry-ca.key.pem` no
//! diretorio de trabalho), assina um certificado por host sob demanda e
//! registra cada requisicao/resposta ja em texto puro. Roda num runtime tokio
//! em thread separada; a GUI consome os flows via [`Flows`] (Arc<Mutex<...>>).
//!
//! Para interceptar HTTPS o usuario precisa instalar `quarry-ca.pem` como
//! Autoridade Certificadora Raiz confiavel e apontar o proxy do sistema/jogo
//! para 127.0.0.1:<porta>.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type ProxyClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Uma requisicao/resposta capturada, ja decodificada para exibicao.
#[derive(Clone)]
pub struct FlowRecord {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub req_headers: String,
    pub req_body: String,
    pub resp_headers: String,
    pub resp_body: String,
    pub req_len: usize,
    pub resp_len: usize,
}

pub type Flows = Arc<Mutex<Vec<FlowRecord>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InterceptKind {
    Request,
    Response,
}

/// Decisao da GUI sobre um item interceptado.
pub enum Decision {
    /// Encaminha (com headers/body possivelmente editados). Para requests,
    /// `intercept_response` pausa tambem a resposta correspondente.
    Forward {
        headers: String,
        body: String,
        intercept_response: bool,
    },
    Drop,
}

/// Snapshot de um item pausado, para a GUI exibir/editar.
#[derive(Clone)]
pub struct PendingView {
    pub id: u64,
    pub kind: InterceptKind,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub headers: String,
    pub body: String,
}

/// Item pausado aguardando decisao da GUI (lado interno).
struct Pending {
    view: PendingView,
    tx: oneshot::Sender<Decision>,
}

/// Resultado de um disparo do Repeater.
pub struct RepeaterResult {
    pub status: u16,
    pub headers: String,
    pub body: String,
}

pub type RepeaterRx = oneshot::Receiver<RepeaterResult>;

pub enum RepeaterPoll {
    Pending,
    Done(RepeaterResult),
    Closed,
}

/// Verifica (sem bloquear) se o Repeater ja respondeu.
pub fn poll_repeater(rx: &mut RepeaterRx) -> RepeaterPoll {
    match rx.try_recv() {
        Ok(r) => RepeaterPoll::Done(r),
        Err(oneshot::error::TryRecvError::Empty) => RepeaterPoll::Pending,
        Err(_) => RepeaterPoll::Closed,
    }
}

struct RepeaterJob {
    method: String,
    url: String,
    headers: String,
    body: String,
    reply: oneshot::Sender<RepeaterResult>,
}

/// Parte da mensagem em que uma regra Match & Replace atua.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
}

impl RuleTarget {
    pub const ALL: [RuleTarget; 4] = [
        RuleTarget::RequestHeaders,
        RuleTarget::RequestBody,
        RuleTarget::ResponseHeaders,
        RuleTarget::ResponseBody,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RuleTarget::RequestHeaders => "Headers da requisição",
            RuleTarget::RequestBody => "Body da requisição",
            RuleTarget::ResponseHeaders => "Headers da resposta",
            RuleTarget::ResponseBody => "Body da resposta",
        }
    }
}

/// Regra Match & Replace aplicada automaticamente a cada mensagem.
#[derive(Clone)]
pub struct Rule {
    pub enabled: bool,
    pub target: RuleTarget,
    pub is_regex: bool,
    pub pattern: String,
    pub replacement: String,
}

/// Aplica as regras de um alvo ao texto; devolve `Some` se houve mudanca.
fn apply_rules(rules: &[Rule], target: RuleTarget, text: &str) -> Option<String> {
    let mut out = text.to_string();
    let mut changed = false;
    for r in rules {
        if !r.enabled || r.target != target || r.pattern.is_empty() {
            continue;
        }
        if r.is_regex {
            if let Ok(re) = regex::Regex::new(&r.pattern) {
                let new = re.replace_all(&out, r.replacement.as_str()).into_owned();
                if new != out {
                    out = new;
                    changed = true;
                }
            }
        } else if out.contains(&r.pattern) {
            out = out.replace(&r.pattern, &r.replacement);
            changed = true;
        }
    }
    changed.then_some(out)
}

/// Estado compartilhado entre a GUI e o runtime do proxy.
pub struct Shared {
    pub flows: Flows,
    intercept: AtomicBool,
    pending: Mutex<Vec<Pending>>,
    rules: Mutex<Vec<Rule>>,
    counter: AtomicU64,
}

impl Shared {
    pub fn intercept_on(&self) -> bool {
        self.intercept.load(Ordering::Relaxed)
    }

    pub fn set_intercept(&self, on: bool) {
        self.intercept.store(on, Ordering::Relaxed);
    }

    /// Primeiro item pausado (FIFO), se houver.
    pub fn first_pending(&self) -> Option<PendingView> {
        self.pending.lock().unwrap().first().map(|p| p.view.clone())
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Resolve o item `id` com a decisao da GUI, liberando a task do proxy.
    pub fn resolve(&self, id: u64, decision: Decision) {
        let mut q = self.pending.lock().unwrap();
        if let Some(pos) = q.iter().position(|p| p.view.id == id) {
            let p = q.remove(pos);
            let _ = p.tx.send(decision);
        }
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.rules.lock().unwrap().clone()
    }

    pub fn set_rules(&self, rules: Vec<Rule>) {
        *self.rules.lock().unwrap() = rules;
    }
}

/// Handle do proxy em execucao, mantido pela GUI.
pub struct ProxyHandle {
    pub ca_path: PathBuf,
    pub shared: Arc<Shared>,
    status: Arc<Mutex<String>>,
    repeater_tx: mpsc::UnboundedSender<RepeaterJob>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ProxyHandle {
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }

    /// Dispara uma requisicao avulsa (Repeater) e devolve o receptor da resposta.
    pub fn repeater(&self, method: String, url: String, headers: String, body: String) -> RepeaterRx {
        let (tx, rx) = oneshot::channel();
        let _ = self.repeater_tx.send(RepeaterJob {
            method,
            url,
            headers,
            body,
            reply: tx,
        });
        rx
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sobe o proxy numa thread/runtime proprios e devolve o handle imediatamente.
pub fn start(port: u16) -> ProxyHandle {
    let shared = Arc::new(Shared {
        flows: Arc::new(Mutex::new(Vec::new())),
        intercept: AtomicBool::new(false),
        pending: Mutex::new(Vec::new()),
        rules: Mutex::new(Vec::new()),
        counter: AtomicU64::new(1),
    });
    let status = Arc::new(Mutex::new(String::from("iniciando…")));
    let (tx, rx) = oneshot::channel();
    let (rep_tx, rep_rx) = mpsc::unbounded_channel();
    let ca_path = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("quarry-ca.pem");

    let shared_t = shared.clone();
    let status_t = status.clone();
    let ca_path_t = ca_path.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                *status_t.lock().unwrap() = format!("falha no runtime tokio: {e}");
                return;
            }
        };
        rt.block_on(async move {
            if let Err(e) = serve(port, shared_t, ca_path_t, status_t.clone(), rx, rep_rx).await {
                *status_t.lock().unwrap() = format!("erro: {e}");
            }
        });
    });

    ProxyHandle {
        ca_path,
        shared,
        status,
        repeater_tx: rep_tx,
        shutdown: Some(tx),
    }
}

#[derive(Clone)]
struct Ctx {
    shared: Arc<Shared>,
    client: ProxyClient,
    ca_cert: Arc<Certificate>,
    ca_key: Arc<KeyPair>,
    tls_cache: Arc<Mutex<HashMap<String, Arc<ServerConfig>>>>,
}

impl Ctx {
    /// Pausa um item, publica-o para a GUI e aguarda a decisao.
    async fn pause(&self, view: PendingView) -> Decision {
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().push(Pending { view, tx });
        rx.await.unwrap_or(Decision::Drop)
    }

    fn next_id(&self) -> u64 {
        self.shared.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Ctx {
    /// Config TLS de servidor para um host, com cert assinado pela nossa CA.
    fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>, BoxErr> {
        if let Some(cfg) = self.tls_cache.lock().unwrap().get(host) {
            return Ok(cfg.clone());
        }
        let cfg = Arc::new(make_leaf_config(&self.ca_cert, &self.ca_key, host)?);
        self.tls_cache
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

async fn serve(
    port: u16,
    shared: Arc<Shared>,
    ca_path: PathBuf,
    status: Arc<Mutex<String>>,
    mut shutdown: oneshot::Receiver<()>,
    mut repeater_rx: mpsc::UnboundedReceiver<RepeaterJob>,
) -> Result<(), BoxErr> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (ca_cert, ca_key) = load_or_create_ca(&ca_path)?;

    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: ProxyClient = Client::builder(TokioExecutor::new()).build(https);

    let ctx = Ctx {
        shared,
        client,
        ca_cert: Arc::new(ca_cert),
        ca_key: Arc::new(ca_key),
        tls_cache: Arc::new(Mutex::new(HashMap::new())),
    };

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = TcpListener::bind(addr).await?;
    *status.lock().unwrap() = format!("ouvindo em 127.0.0.1:{port}");

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(job) = repeater_rx.recv() => {
                let ctx = ctx.clone();
                tokio::spawn(async move { run_repeater(ctx, job).await; });
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .serve_connection(io, service_fn(move |req| handle(req, ctx.clone())))
                        .with_upgrades()
                        .await;
                });
            }
        }
    }

    *status.lock().unwrap() = "parado".into();
    Ok(())
}

// Servicos hyper sao infaliveis: erros internos viram resposta 502. Usar
// `Box<dyn Error>` como tipo de erro do servico nao satisfaz o bound HRTB do
// hyper, por isso mapeamos tudo para `Infallible`.
async fn handle(req: Request<Incoming>, ctx: Ctx) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        // Tunel HTTPS: respondemos 200, fazemos upgrade e terminamos o TLS aqui.
        if let Some(authority) = req.uri().authority().cloned() {
            let host = authority.host().to_string();
            tokio::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    let _ = mitm(upgraded, host, ctx).await;
                }
            });
            return Ok(Response::new(Full::new(Bytes::new())));
        }
        return Ok(error_response(StatusCode::BAD_REQUEST, "CONNECT sem authority"));
    }
    // HTTP em claro (forma absoluta http://host/...).
    Ok(forward(req, "http", None, ctx)
        .await
        .unwrap_or_else(|e| error_response(StatusCode::BAD_GATEWAY, &e.to_string())))
}

/// Termina o TLS do cliente com um cert nosso e serve as requisicoes do tunel.
async fn mitm(upgraded: hyper::upgrade::Upgraded, host: String, ctx: Ctx) -> Result<(), BoxErr> {
    let cfg = ctx.server_config_for(&host)?;
    let tls = TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await?;
    let io = TokioIo::new(tls);
    let svc = service_fn(move |req| {
        let ctx = ctx.clone();
        let host = host.clone();
        async move {
            Ok::<_, Infallible>(
                forward(req, "https", Some(host), ctx)
                    .await
                    .unwrap_or_else(|e| error_response(StatusCode::BAD_GATEWAY, &e.to_string())),
            )
        }
    });
    hyper::server::conn::http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(io, svc)
        .await?;
    Ok(())
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Encaminha a requisicao ao servidor real, captura tudo e devolve a resposta.
async fn forward(
    req: Request<Incoming>,
    scheme: &'static str,
    host_override: Option<String>,
    ctx: Ctx,
) -> Result<Response<Full<Bytes>>, BoxErr> {
    let (parts, body) = req.into_parts();
    let req_bytes = body.collect().await?.to_bytes();

    let authority = match host_override {
        Some(h) => h,
        None => match parts.uri.authority() {
            Some(a) => a.to_string(),
            None => return Ok(error_response(StatusCode::BAD_REQUEST, "sem host")),
        },
    };
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{scheme}://{authority}{pq}");
    let target: Uri = url.parse()?;
    let method = parts.method.clone();

    // Headers/body a enviar — possivelmente reescritos por Match & Replace
    // e depois editados no intercept.
    let mut req_headers = fmt_headers(&parts.headers);
    let mut req_body = req_bytes;
    let mut intercept_resp = false;

    let rules = ctx.shared.rules();
    if !rules.is_empty() {
        if let Some(h) = apply_rules(&rules, RuleTarget::RequestHeaders, &req_headers) {
            req_headers = h;
        }
        let body_str = String::from_utf8_lossy(&req_body);
        if let Some(nb) = apply_rules(&rules, RuleTarget::RequestBody, &body_str) {
            req_body = Bytes::from(nb.into_bytes());
        }
    }

    if ctx.shared.intercept_on() {
        let orig = String::from_utf8_lossy(&req_body).into_owned();
        let view = PendingView {
            id: ctx.next_id(),
            kind: InterceptKind::Request,
            method: method.to_string(),
            url: url.clone(),
            status: 0,
            headers: req_headers.clone(),
            body: orig.clone(),
        };
        match ctx.pause(view).await {
            Decision::Drop => return Ok(error_response(StatusCode::FORBIDDEN, "request dropado")),
            Decision::Forward {
                headers,
                body,
                intercept_response,
            } => {
                req_headers = headers;
                if body != orig {
                    req_body = Bytes::from(body.into_bytes());
                }
                intercept_resp = intercept_response;
            }
        }
    }

    let out_req = build_request(&method, target, &req_headers, req_body.clone())?;
    let upstream = match ctx.client.request(out_req).await {
        Ok(r) => r,
        Err(e) => {
            record(&ctx, &method.to_string(), &url, 0, &req_headers, &req_body, "", b"");
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("upstream falhou: {e}"),
            ));
        }
    };

    let (rparts, rbody) = upstream.into_parts();
    let resp_bytes = rbody.collect().await?.to_bytes();
    let mut resp_headers = fmt_headers(&rparts.headers);
    let mut resp_body = resp_bytes;
    let status = rparts.status;

    if !rules.is_empty() {
        if let Some(h) = apply_rules(&rules, RuleTarget::ResponseHeaders, &resp_headers) {
            resp_headers = h;
        }
        let body_str = String::from_utf8_lossy(&resp_body);
        if let Some(nb) = apply_rules(&rules, RuleTarget::ResponseBody, &body_str) {
            resp_body = Bytes::from(nb.into_bytes());
        }
    }

    if intercept_resp {
        let orig = String::from_utf8_lossy(&resp_body).into_owned();
        let view = PendingView {
            id: ctx.next_id(),
            kind: InterceptKind::Response,
            method: method.to_string(),
            url: url.clone(),
            status: status.as_u16(),
            headers: resp_headers.clone(),
            body: orig.clone(),
        };
        match ctx.pause(view).await {
            Decision::Drop => return Ok(error_response(StatusCode::FORBIDDEN, "response dropado")),
            Decision::Forward { headers, body, .. } => {
                resp_headers = headers;
                if body != orig {
                    resp_body = Bytes::from(body.into_bytes());
                }
            }
        }
    }

    record(
        &ctx,
        &method.to_string(),
        &url,
        status.as_u16(),
        &req_headers,
        &req_body,
        &resp_headers,
        &resp_body,
    );
    build_response(status, &resp_headers, resp_body)
}

/// Reconstroi uma requisicao a partir do texto de headers editavel.
fn build_request(
    method: &Method,
    uri: Uri,
    headers_text: &str,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, BoxErr> {
    let mut b = Request::builder().method(method.clone()).uri(uri);
    for (k, v) in filtered_header_lines(headers_text) {
        b = b.header(k, v);
    }
    Ok(b.body(Full::new(body))?)
}

/// Reconstroi a resposta a partir do texto de headers editavel.
fn build_response(
    status: StatusCode,
    headers_text: &str,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, BoxErr> {
    let mut b = Response::builder().status(status);
    for (k, v) in filtered_header_lines(headers_text) {
        b = b.header(k, v);
    }
    Ok(b.body(Full::new(body))?)
}

/// Linhas "Chave: Valor" validas, pulando hop-by-hop e content-length
/// (recalculado a partir do corpo coletado).
fn filtered_header_lines(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        let kl = k.to_ascii_lowercase();
        if k.is_empty() || HOP_BY_HOP.contains(&kl.as_str()) || kl == "content-length" {
            continue;
        }
        out.push((k.to_string(), v.to_string()));
    }
    out
}

async fn run_repeater(ctx: Ctx, job: RepeaterJob) {
    let result = do_repeater(&ctx, &job)
        .await
        .unwrap_or_else(|e| RepeaterResult {
            status: 0,
            headers: String::new(),
            body: format!("erro: {e}"),
        });
    let _ = job.reply.send(result);
}

async fn do_repeater(ctx: &Ctx, job: &RepeaterJob) -> Result<RepeaterResult, BoxErr> {
    let method: Method = job.method.trim().parse()?;
    let uri: Uri = job.url.trim().parse()?;
    let body = Bytes::from(job.body.clone().into_bytes());
    let req = build_request(&method, uri, &job.headers, body)?;
    let resp = ctx.client.request(req).await?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok(RepeaterResult {
        status: parts.status.as_u16(),
        headers: fmt_headers(&parts.headers),
        body: body_preview(&bytes),
    })
}

#[allow(clippy::too_many_arguments)]
fn record(
    ctx: &Ctx,
    method: &str,
    url: &str,
    status: u16,
    req_headers: &str,
    req_bytes: &[u8],
    resp_headers: &str,
    resp_bytes: &[u8],
) {
    let rec = FlowRecord {
        id: ctx.next_id(),
        method: method.to_string(),
        url: url.to_string(),
        status,
        req_headers: req_headers.to_string(),
        req_body: body_preview(req_bytes),
        resp_headers: resp_headers.to_string(),
        resp_body: body_preview(resp_bytes),
        req_len: req_bytes.len(),
        resp_len: resp_bytes.len(),
    };
    let mut flows = ctx.shared.flows.lock().unwrap();
    flows.push(rec);
    const CAP: usize = 2000;
    if flows.len() > CAP {
        let excess = flows.len() - CAP;
        flows.drain(0..excess);
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(format!("Quarry proxy: {msg}"))));
    *resp.status_mut() = status;
    resp
}

fn fmt_headers(h: &HeaderMap) -> String {
    let mut s = String::new();
    for (k, v) in h.iter() {
        s.push_str(k.as_str());
        s.push_str(": ");
        s.push_str(v.to_str().unwrap_or("<binário>"));
        s.push('\n');
    }
    s
}

fn body_preview(b: &[u8]) -> String {
    const MAX: usize = 8192;
    let mut s = String::from_utf8_lossy(&b[..b.len().min(MAX)]).into_owned();
    if b.len() > MAX {
        s.push_str(&format!("\n… (+{} bytes)", b.len() - MAX));
    }
    s
}

/// Parametros fixos da CA. Reconstruidos de forma deterministica para que a
/// CA carregada (mesma chave) seja equivalente a salva em disco.
fn ca_params() -> Result<CertificateParams, BoxErr> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Quarry Proxy CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Quarry");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Ok(params)
}

/// Carrega a CA persistida (reusa a chave salva) ou cria uma nova.
fn load_or_create_ca(cert_path: &Path) -> Result<(Certificate, KeyPair), BoxErr> {
    let key_path = cert_path.with_extension("key.pem");
    if cert_path.exists() && key_path.exists() {
        let key = KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?;
        return Ok((ca_params()?.self_signed(&key)?, key));
    }

    let key = KeyPair::generate()?;
    let cert = ca_params()?.self_signed(&key)?;
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(&key_path, key.serialize_pem())?;
    Ok((cert, key))
}

/// Gera a config TLS de servidor com um cert para `host` assinado pela CA.
fn make_leaf_config(ca: &Certificate, ca_key: &KeyPair, host: &str) -> Result<ServerConfig, BoxErr> {
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    let key = KeyPair::generate()?;
    let leaf = params.signed_by(&key, ca, ca_key)?;

    let cert_der: CertificateDer<'static> = leaf.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?)
}

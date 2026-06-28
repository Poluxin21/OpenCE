//! Stream de eventos do LCU via WebSocket (protocolo WAMP da Riot).
//!
//! O LCU expoe um WebSocket na **mesma porta e com o mesmo token** da API REST.
//! Depois de conectar (Basic auth + cert self-signed aceito), assinamos *todos*
//! os eventos enviando o frame WAMP `[5, "OnJsonApiEvent"]`. A partir dai o
//! client empurra, ao vivo, toda mudanca de estado como
//! `[8, "OnJsonApiEvent", { "uri", "eventType", "data" }]`.
//!
//! Isso transforma o painel de "polling manual" em um feed em tempo real — util
//! para mapear fluxos e flagrar exposicao de dados sensiveis cruzando a fronteira
//! local. Tudo legitimo: nenhuma injecao, mesma credencial do lockfile.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

use crate::lcu::{self, LcuConn};

/// Um evento recebido do LCU.
#[derive(Clone)]
pub struct WsEvent {
    /// Tipo: "Create" | "Update" | "Delete".
    pub event_type: String,
    /// Recurso afetado (ex.: `/lol-gameflow/v1/gameflow-phase`).
    pub uri: String,
    /// Previa do payload `data` (JSON compactado, truncado).
    pub data: String,
}

/// Quantos eventos manter no buffer (descarta os mais antigos).
const MAX_EVENTS: usize = 1000;

/// Conexao viva com o WebSocket do LCU. Solte (`drop`) para encerrar.
pub struct WsHandle {
    stop: Arc<AtomicBool>,
    pub events: Arc<Mutex<Vec<WsEvent>>>,
    pub status: Arc<Mutex<String>>,
}

impl WsHandle {
    /// Sinaliza o encerramento da thread de fundo.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Mensagem de status corrente (conectando / conectado / erro).
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }
}

impl Drop for WsHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Abre o stream de eventos. Retorna imediatamente; a conexao acontece na thread.
pub fn start(conn: &LcuConn) -> WsHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let events = Arc::new(Mutex::new(Vec::<WsEvent>::new()));
    let status = Arc::new(Mutex::new("conectando…".to_string()));

    let port = conn.port;
    let auth = conn.auth_header();
    let (s_stop, s_events, s_status) = (stop.clone(), events.clone(), status.clone());

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                *s_status.lock().unwrap() = format!("erro: runtime tokio: {e}");
                return;
            }
        };
        rt.block_on(run(port, auth, s_stop, s_events, s_status.clone()));
        // se saiu sem erro registrado, marca como desconectado
        let mut st = s_status.lock().unwrap();
        if !st.starts_with("erro") {
            *st = "desconectado".into();
        }
    });

    WsHandle {
        stop,
        events,
        status,
    }
}

async fn run(
    port: u16,
    auth: String,
    stop: Arc<AtomicBool>,
    events: Arc<Mutex<Vec<WsEvent>>>,
    status: Arc<Mutex<String>>,
) {
    let url = format!("wss://127.0.0.1:{port}/");
    let mut req = match url.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            *status.lock().unwrap() = format!("erro: url invalida: {e}");
            return;
        }
    };
    match HeaderValue::from_str(&auth) {
        Ok(v) => {
            req.headers_mut().insert("Authorization", v);
        }
        Err(e) => {
            *status.lock().unwrap() = format!("erro: auth invalido: {e}");
            return;
        }
    }

    let connector = Connector::Rustls(Arc::new(lcu::tls_config_insecure()));
    let ws = match tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(connector),
    )
    .await
    {
        Ok((ws, _resp)) => ws,
        Err(e) => {
            *status.lock().unwrap() = format!("erro: conexao WS: {e}");
            return;
        }
    };

    let (mut write, mut read) = ws.split();
    // WAMP: 5 = SUBSCRIBE. Assina todos os eventos da API.
    if let Err(e) = write
        .send(Message::Text("[5,\"OnJsonApiEvent\"]".into()))
        .await
    {
        *status.lock().unwrap() = format!("erro: subscribe: {e}");
        return;
    }
    *status.lock().unwrap() = "conectado — recebendo eventos".into();

    loop {
        if stop.load(Ordering::Relaxed) {
            let _ = write.send(Message::Close(None)).await;
            break;
        }
        // timeout curto para revisitar a flag de parada mesmo sem trafego
        let next = tokio::time::timeout(Duration::from_millis(250), read.next()).await;
        let msg = match next {
            Err(_) => continue,        // timeout: volta a checar `stop`
            Ok(None) => break,         // stream encerrado
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                *status.lock().unwrap() = format!("erro: leitura: {e}");
                break;
            }
        };
        if let Message::Text(t) = msg {
            if let Some(ev) = parse_event(t.as_str()) {
                let mut buf = events.lock().unwrap();
                buf.push(ev);
                let overflow = buf.len().saturating_sub(MAX_EVENTS);
                if overflow > 0 {
                    buf.drain(0..overflow);
                }
            }
        }
    }
}

/// Faz o parse de um frame WAMP `[8, "OnJsonApiEvent", {payload}]`.
fn parse_event(text: &str) -> Option<WsEvent> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let arr = v.as_array()?;
    // [opcode, "OnJsonApiEvent", payload]
    if arr.len() < 3 {
        return None;
    }
    let payload = &arr[2];
    let uri = payload.get("uri").and_then(|u| u.as_str()).unwrap_or("?");
    let event_type = payload
        .get("eventType")
        .and_then(|e| e.as_str())
        .unwrap_or("?");
    let data = match payload.get("data") {
        Some(d) => {
            let s = d.to_string();
            if s.len() > 240 {
                format!("{}…", &s[..240])
            } else {
                s
            }
        }
        None => String::new(),
    };
    Some(WsEvent {
        event_type: event_type.to_string(),
        uri: uri.to_string(),
        data,
    })
}
